import sqlite3
import json
import os
import re
import time
from datetime import datetime
from zoneinfo import ZoneInfo
import csv
from io import StringIO
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from dotenv import load_dotenv
from catalog_categories import CATALOG_CATEGORIES

load_dotenv()

LOW_STOCK_THRESHOLD = 10
LOW_STOCK_PREVIEW_LIMIT = 10

PHONE_PATTERN = re.compile(r'^0[17]\d{8}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
ACCEPTABLE_EMAIL_EXAMPLES = [
    'name@example.com',
    'name@company.co.ke',
    'firstname.lastname@domain.org',
]

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-me')

# Auto-logout after inactivity (forces re-authentication).
# Cart will still be restored from browser localStorage on return to /sales.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Ensure server runs in EAT (Africa/Nairobi)
os.environ['TZ'] = 'Africa/Nairobi'
try:
    time.tzset()
except AttributeError:
    # Not available on some platforms; safe to ignore
    pass

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"


@app.before_request
def make_session_permanent():
    session.permanent = True

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT id, username, role FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], role=user_data['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.errorhandler(403)
def forbidden(e):
    return render_template('unauthorized.html'), 403

def get_db_connection():
    db_path = os.environ.get('DB_PATH', 'pos_system.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def validate_phone(phone: str) -> str | None:
    """Return an error message if phone is invalid, else None."""
    phone = (phone or '').strip()
    if not phone:
        return None
    if not PHONE_PATTERN.match(phone):
        return 'Please input a valid phone number'
    return None


def validate_email(email: str) -> str | None:
    """Return an error message if email is invalid, else None."""
    email = (email or '').strip()
    if not email:
        return None
    if not EMAIL_PATTERN.match(email):
        return 'Please enter a valid email address (e.g. name@example.com, name@company.co.ke)'
    return None


def init_db():
    """
    Create all tables if missing (fresh deploy / empty SQLite file on Azure).
    Matches schema from database_setup.py, plus cashier_username on sales.
    Seeds default categories, walk-in customer, and first admin when DB is empty.
    """
    conn = get_db_connection()
    conn.executescript(
        '''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            code TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            sku TEXT UNIQUE,
            price INTEGER NOT NULL DEFAULT 0,
            buying_price REAL DEFAULT 0,
            quantity INTEGER NOT NULL DEFAULT 0,
            low_stock_since DATETIME,
            category_id INTEGER,
            FOREIGN KEY (category_id) REFERENCES categories (id)
        );

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT,
            email TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Worker'
        );

        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_amount REAL NOT NULL,
            payment_status TEXT NOT NULL DEFAULT 'Paid',
            customer_id INTEGER,
            cashier_username TEXT,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        );

        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity_sold INTEGER NOT NULL,
            price_per_unit INTEGER NOT NULL,
            FOREIGN KEY (sale_id) REFERENCES sales (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        );

        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            amount_paid REAL NOT NULL,
            payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sale_id) REFERENCES sales (id)
        );

        CREATE TABLE IF NOT EXISTS special_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            details TEXT,
            order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'Pending',
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        );
        '''
    )

    for name, code in CATALOG_CATEGORIES:
        try:
            conn.execute('INSERT INTO categories (name, code) VALUES (?, ?)', (name, code))
        except sqlite3.IntegrityError:
            pass

    # Default walk-in customer (id=1 expected by templates / credit checks)
    if conn.execute('SELECT 1 FROM customers LIMIT 1').fetchone() is None:
        conn.execute(
            "INSERT INTO customers (name, phone) VALUES ('Cash Sale / Walk-in', 'N/A')",
        )

    # First admin only when no users exist (e.g. new Azure deploy)
    if conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() is None:
        admin_user = os.environ.get('INITIAL_ADMIN_USERNAME', 'admin')
        admin_pass_plain = os.environ.get('INITIAL_ADMIN_PASSWORD', 'ChangeThisPassword!')
        conn.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (admin_user, generate_password_hash(admin_pass_plain), 'Admin'),
        )

    conn.commit()
    conn.close()


def ensure_audit_logs_table():
    conn = get_db_connection()
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            role TEXT,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id TEXT,
            details TEXT
        )
        '''
    )
    conn.commit()
    conn.close()


def audit_log(action, entity_type=None, entity_id=None, details=None):
    try:
        username = current_user.username if getattr(current_user, "is_authenticated", False) else None
        role = current_user.role if getattr(current_user, "is_authenticated", False) else None
    except Exception:
        username = None
        role = None

    ts = datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    conn.execute(
        '''
        INSERT INTO audit_logs (timestamp, username, role, action, entity_type, entity_id, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (ts, username, role, action, entity_type, str(entity_id) if entity_id is not None else None, details),
    )
    conn.commit()
    conn.close()


def ensure_sales_has_cashier_username_column():
    """
    Ensure `sales` table has `cashier_username` to print correct served-by info on receipts.
    Safe to run on every app start; it only adds the column if missing.
    """
    conn = get_db_connection()
    cols = conn.execute('PRAGMA table_info(sales)').fetchall()
    existing = {c['name'] for c in cols}
    if 'cashier_username' not in existing:
        conn.execute('ALTER TABLE sales ADD COLUMN cashier_username TEXT')
        conn.commit()
    conn.close()


def ensure_products_has_buying_price_column():
    conn = get_db_connection()
    cols = conn.execute('PRAGMA table_info(products)').fetchall()
    existing = {c['name'] for c in cols}
    if 'buying_price' not in existing:
        conn.execute('ALTER TABLE products ADD COLUMN buying_price REAL DEFAULT 0')
        conn.commit()
    conn.close()


def ensure_products_has_low_stock_since_column():
    conn = get_db_connection()
    cols = conn.execute('PRAGMA table_info(products)').fetchall()
    existing = {c['name'] for c in cols}
    if 'low_stock_since' not in existing:
        conn.execute('ALTER TABLE products ADD COLUMN low_stock_since DATETIME')
        conn.commit()
    # Backfill existing low-stock rows so sorting works immediately
    now = datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        f'''
        UPDATE products
        SET low_stock_since = ?
        WHERE quantity <= ? AND low_stock_since IS NULL
        ''',
        (now, LOW_STOCK_THRESHOLD),
    )
    conn.execute(
        f'''
        UPDATE products
        SET low_stock_since = NULL
        WHERE quantity > ?
        ''',
        (LOW_STOCK_THRESHOLD,),
    )
    conn.commit()
    conn.close()


def _now_eat() -> str:
    return datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y-%m-%d %H:%M:%S")


def sync_product_low_stock_marker(conn, product_id: int, previous_quantity: int | None = None):
    """
    Keep low_stock_since accurate:
    - set when stock first drops to <= threshold
    - clear when stock rises above threshold
    """
    row = conn.execute(
        'SELECT quantity, low_stock_since FROM products WHERE id = ?',
        (product_id,),
    ).fetchone()
    if row is None:
        return

    qty = row['quantity']
    if qty <= LOW_STOCK_THRESHOLD:
        entered_low = previous_quantity is None or previous_quantity > LOW_STOCK_THRESHOLD
        if entered_low or row['low_stock_since'] is None:
            conn.execute(
                'UPDATE products SET low_stock_since = ? WHERE id = ?',
                (_now_eat(), product_id),
            )
    else:
        if row['low_stock_since'] is not None:
            conn.execute(
                'UPDATE products SET low_stock_since = NULL WHERE id = ?',
                (product_id,),
            )


def fetch_low_stock_items(conn, limit: int | None = None):
    sql = '''
        SELECT id, sku, name, quantity, low_stock_since
        FROM products
        WHERE quantity <= ?
        ORDER BY
            CASE WHEN low_stock_since IS NULL THEN 1 ELSE 0 END,
            low_stock_since DESC,
            quantity ASC,
            name ASC
    '''
    params: list = [LOW_STOCK_THRESHOLD]
    if limit is not None:
        sql += ' LIMIT ?'
        params.append(limit)
    return conn.execute(sql, params).fetchall()


def count_low_stock_items(conn) -> int:
    row = conn.execute(
        'SELECT COUNT(*) AS total FROM products WHERE quantity <= ?',
        (LOW_STOCK_THRESHOLD,),
    ).fetchone()
    return row['total'] if row else 0


def _pdf_safe_text(value: str) -> str:
    """Normalize common plumbing symbols for PDF Latin-1 text."""
    text = value or ''
    replacements = {
        '½': '1/2',
        '¼': '1/4',
        '¾': '3/4',
        '″': '"',
        '”': '"',
        '“': '"',
        '’': "'",
        '‘': "'",
        '…': '...',
        '–': '-',
        '—': '-',
        '\\': '',
        '(': '[',
        ')': ']',
    }
    for src, dest in replacements.items():
        text = text.replace(src, dest)
    return text.encode('latin-1', 'replace').decode('latin-1')


def build_low_stock_pdf(items) -> bytes:
    """Build a simple multi-page PDF without extra dependencies."""
    header_lines = [
        'Aqua Tech - Low Stock List',
        f'Generated: {_now_eat()} (EAT)',
        f'Threshold: quantity <= {LOW_STOCK_THRESHOLD}',
        f'Total items: {len(items)}',
        '',
        f"{'SKU':<16} {'QTY':>4}  {'LOW SINCE':<19}  PRODUCT",
        '-' * 90,
    ]
    row_lines = []
    for item in items:
        sku = _pdf_safe_text(item['sku'] or '-')[:16]
        name = _pdf_safe_text(item['name'] or '')[:48]
        since = str(item['low_stock_since'] or '-')[:19]
        qty = str(item['quantity'])
        row_lines.append(f'{sku:<16} {qty:>4}  {since:<19}  {name}')

    all_lines = header_lines + row_lines
    lines_per_page = 48
    pages = [all_lines[i:i + lines_per_page] for i in range(0, max(len(all_lines), 1), lines_per_page)]
    if not pages:
        pages = [['(no items)']]

    objects = []
    objects.append(b'1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n')

    page_object_nums = []
    content_object_nums = []
    next_obj = 3
    for _ in pages:
        page_object_nums.append(next_obj)
        content_object_nums.append(next_obj + 1)
        next_obj += 2
    font_obj = next_obj

    kids = ' '.join(f'{n} 0 R' for n in page_object_nums)
    objects.append(
        f'2 0 obj<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>endobj\n'.encode('latin-1')
    )

    for page_num, (page_obj, content_obj) in enumerate(zip(page_object_nums, content_object_nums), start=1):
        page_lines = pages[page_num - 1]
        content_cmds = ['BT', '/F1 10 Tf', '50 780 Td', '14 TL']
        for idx, line in enumerate(page_lines):
            safe = _pdf_safe_text(line)
            if idx == 0:
                content_cmds.append(f'({safe}) Tj')
            else:
                content_cmds.append(f'T* ({safe}) Tj')
        content_cmds.append('ET')
        stream = '\n'.join(content_cmds).encode('latin-1')
        objects.append(
            (
                f'{page_obj} 0 obj<< /Type /Page /Parent 2 0 R '
                f'/MediaBox [0 0 612 792] /Contents {content_obj} 0 R '
                f'/Resources << /Font << /F1 {font_obj} 0 R >> >> >>endobj\n'
            ).encode('latin-1')
        )
        objects.append(
            f'{content_obj} 0 obj<< /Length {len(stream)} >>stream\n'.encode('latin-1')
            + stream
            + b'\nendstream\nendobj\n'
        )

    objects.append(
        f'{font_obj} 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>endobj\n'.encode('latin-1')
    )

    pdf = bytearray(b'%PDF-1.4\n')
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_pos = len(pdf)
    pdf.extend(f'xref\n0 {len(offsets)}\n'.encode('latin-1'))
    pdf.extend(b'0000000000 65535 f \n')
    for off in offsets[1:]:
        pdf.extend(f'{off:010d} 00000 n \n'.encode('latin-1'))
    pdf.extend(
        f'trailer<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n'.encode('latin-1')
    )
    return bytes(pdf)


# Order matters: full schema first, then migrations for older DBs, then audit table.
init_db()
ensure_sales_has_cashier_username_column()
ensure_products_has_buying_price_column()
ensure_products_has_low_stock_since_column()
ensure_audit_logs_table()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(id=user_data['id'], username=user_data['username'], role=user_data['role'])
            login_user(user)
            audit_log("login")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    audit_log("logout")
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    sales_today = conn.execute("SELECT SUM(total_amount) AS total FROM sales WHERE date(timestamp) = date('now', 'localtime')").fetchone()['total'] or 0
    total_debt = conn.execute("SELECT SUM(total_amount) AS total FROM sales WHERE payment_status = 'On Credit'").fetchone()['total'] or 0
    low_stock_total = count_low_stock_items(conn)
    low_stock_items = fetch_low_stock_items(conn, limit=LOW_STOCK_PREVIEW_LIMIT)
    conn.close()
    return render_template(
        'dashboard.html',
        sales_today=sales_today,
        total_debt=total_debt,
        low_stock_items=low_stock_items,
        low_stock_total=low_stock_total,
        low_stock_preview_limit=LOW_STOCK_PREVIEW_LIMIT,
        low_stock_threshold=LOW_STOCK_THRESHOLD,
    )


@app.route('/low_stock')
@login_required
def low_stock_list():
    conn = get_db_connection()
    items = fetch_low_stock_items(conn)
    total = len(items)
    conn.close()
    return render_template(
        'low_stock.html',
        items=items,
        total=total,
        low_stock_threshold=LOW_STOCK_THRESHOLD,
    )


@app.route('/low_stock/download')
@login_required
def low_stock_download():
    conn = get_db_connection()
    items = fetch_low_stock_items(conn)
    conn.close()
    pdf_bytes = build_low_stock_pdf(items)
    filename = f"low_stock_list_{_now_eat().replace(' ', '_').replace(':', '')}.pdf"
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )

# --- WORKER-ACCESSIBLE ROUTES ---
#the following are what could be accessed by both the admin and the workers.
#they are the only things workers can access 
@app.route('/sales')
@login_required
def sales():
    conn = get_db_connection()
    products_from_db = conn.execute(
        'SELECT * FROM products WHERE quantity > 0 AND price > 0 ORDER BY name'
    ).fetchall()
    customers_from_db = conn.execute('SELECT * FROM customers ORDER BY name').fetchall()
    conn.close()
    return render_template('sales.html', products=products_from_db, customers=customers_from_db)

@app.route('/process_sale', methods=['POST'])
@login_required
def process_sale():
    total_amount = request.form['total_amount']
    cart_data = json.loads(request.form['cart_data'])
    customer_id = request.form['customer_id']
    payment_status = request.form['payment_status']
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        'INSERT INTO sales (total_amount, customer_id, payment_status, timestamp, cashier_username) VALUES (?, ?, ?, ?, ?)',
        (total_amount, customer_id, payment_status, timestamp, current_user.username),
    )
    sale_id = cursor.lastrowid
    for product_id, item_details in cart_data.items():
        quantity_sold = item_details['quantity']
        price_per_unit = item_details['price']
        previous = cursor.execute(
            'SELECT quantity FROM products WHERE id = ?', (product_id,)
        ).fetchone()
        previous_qty = previous['quantity'] if previous else None
        cursor.execute(
            'INSERT INTO sale_items (sale_id, product_id, quantity_sold, price_per_unit) VALUES (?, ?, ?, ?)',
            (sale_id, product_id, quantity_sold, price_per_unit),
        )
        cursor.execute(
            'UPDATE products SET quantity = quantity - ? WHERE id = ?',
            (quantity_sold, product_id),
        )
        sync_product_low_stock_marker(conn, int(product_id), previous_quantity=previous_qty)
    conn.commit()
    conn.close()
    audit_log(
        "sale_created",
        entity_type="sale",
        entity_id=sale_id,
        details=f"customer_id={customer_id}; status={payment_status}; total={total_amount}",
    )
    # After processing a sale, go to printable receipt view
    return redirect(url_for('sale_receipt', sale_id=sale_id))

@app.route('/customers')
@login_required
def customers():
    conn = get_db_connection()
    search = request.args.get('q')

    if search:
        customers_from_db = conn.execute(
            'SELECT * FROM customers WHERE name LIKE ? OR phone LIKE ? OR email LIKE ? ORDER BY name',
            (f"%{search}%", f"%{search}%", f"%{search}%"),
        ).fetchall()
    else:
        customers_from_db = conn.execute('SELECT * FROM customers ORDER BY name').fetchall()
    conn.close()
    return render_template(
        'customers.html',
        customers=customers_from_db,
        search=search or '',
        email_examples=ACCEPTABLE_EMAIL_EXAMPLES,
    )

@app.route('/add_customer', methods=['POST'])
@login_required
def add_customer():
    name = request.form['name'].strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()

    if not name:
        flash('Customer name is required.', 'error')
        return redirect(url_for('customers'))

    phone_error = validate_phone(phone)
    if phone_error:
        flash(phone_error, 'error')
        return redirect(url_for('customers'))

    email_error = validate_email(email)
    if email_error:
        flash(email_error, 'error')
        return redirect(url_for('customers'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO customers (name, phone, email) VALUES (?, ?, ?)',
        (name, phone or None, email or None),
    )
    conn.commit()
    conn.close()
    flash('Customer added successfully.', 'success')
    return redirect(url_for('customers'))


#the following function is to help in the creation of reports of each customer that is needed. This is generated for the purpose of letting the clients/customers get some sort of report of their results as a whole
#its allowed that even normal workers can generate these reports for the customers.
@app.route('/customer_report/<int:customer_id>')
@login_required
def customer_report(customer_id):
    conn = get_db_connection()
    
    # Get the customer's details
    customer = conn.execute('SELECT * FROM customers WHERE id = ?', (customer_id,)).fetchone()
    
    # Get all sales for this specific customer
    sales = conn.execute('SELECT * FROM sales WHERE customer_id = ? ORDER BY timestamp DESC', 
                         (customer_id,)).fetchall()
                         
    conn.close()
    
    # Abort with a 404 error if a non-existent customer ID is entered in the URL
    if customer is None:
        abort(404)
        
    return render_template('customer_report.html', customer=customer, sales=sales)


#now the following functions are the responsible for the special orders part to work on the customers needs

@app.route('/special_orders', methods=['GET', 'POST'])
@login_required
def special_orders():
    conn = get_db_connection()

    if request.method == 'POST':
        # This is the logic for creating a new order
        customer_id = request.form['customer_id']
        product_name = request.form['product_name']
        quantity = request.form['quantity']
        details = request.form['details']
        
        conn.execute('INSERT INTO special_orders (customer_id, product_name, quantity, details) VALUES (?, ?, ?, ?)',
                     (customer_id, product_name, quantity, details))
        conn.commit()
        flash("Special order created successfully!")
        return redirect(url_for('special_orders'))

    # This is the logic for displaying the page (GET request)
    customers = conn.execute('SELECT * FROM customers ORDER BY name').fetchall()
    
    # We use a JOIN to get the customer's name for the display table
    base_query = '''
        SELECT so.*, c.name AS customer_name 
        FROM special_orders so
        JOIN customers c ON so.customer_id = c.id
    '''
    
    pending_orders = conn.execute(f"{base_query} WHERE so.status = 'Pending' ORDER BY so.order_date DESC").fetchall()
    arrived_orders = conn.execute(f"{base_query} WHERE so.status = 'Arrived' ORDER BY so.order_date DESC").fetchall()
    
    conn.close()
    return render_template('special_orders.html', customers=customers, pending_orders=pending_orders, arrived_orders=arrived_orders)




#That marks the end of what is authorized for the normal workers, the rest is supposed to be what is the extra things that are allowed for the admins
# --- ADMIN-ONLY ROUTES ---
@app.route('/products')
@login_required
@admin_required
def products():
    conn = get_db_connection()
    categories = conn.execute('SELECT * FROM categories ORDER BY name').fetchall()
    search = request.args.get('q')

    if search:
        products_from_db = conn.execute(
            'SELECT * FROM products WHERE name LIKE ? OR description LIKE ? OR sku LIKE ? ORDER BY name',
            (f"%{search}%", f"%{search}%", f"%{search}%"),
        ).fetchall()
    else:
        products_from_db = conn.execute('SELECT * FROM products ORDER BY name').fetchall()
    conn.close()
    return render_template('products.html', products=products_from_db, categories=categories, search=search or '')

@app.route('/add_product', methods=['POST'])
@login_required
@admin_required
def add_product():
    name = request.form['name']
    description = request.form['description']
    price = request.form.get('price') or 0
    buying_price = request.form.get('buying_price') or 0
    quantity = request.form['quantity']
    category_id = request.form['category_id']
    conn = get_db_connection()
    category = conn.execute('SELECT code FROM categories WHERE id = ?', (category_id,)).fetchone()
    category_code = category['code']
    name_part = name[:3].upper()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO products (name, description, price, buying_price, quantity, category_id) VALUES (?, ?, ?, ?, ?, ?)',
        (name, description, price, buying_price, quantity, category_id),
    )
    new_product_id = cursor.lastrowid
    generated_sku = f"{category_code}-{name_part}-{new_product_id}"
    conn.execute('UPDATE products SET sku = ? WHERE id = ?', (generated_sku, new_product_id))
    sync_product_low_stock_marker(conn, new_product_id, previous_quantity=None)
    conn.commit()
    conn.close()
    return redirect(url_for('products'))

@app.route('/reports')
@login_required
@admin_required
def reports():
    conn = get_db_connection()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    payment_status = request.args.get('payment_status')
    customer_query = request.args.get('customer')

    base_sql = """
        SELECT s.id, s.timestamp, s.total_amount, s.payment_status,
               c.name AS customer_name
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        WHERE 1=1
    """
    params = []

    if start_date:
        base_sql += " AND date(s.timestamp) >= ?"
        params.append(start_date)
    if end_date:
        base_sql += " AND date(s.timestamp) <= ?"
        params.append(end_date)
    if payment_status and payment_status != 'All':
        base_sql += " AND s.payment_status = ?"
        params.append(payment_status)
    if customer_query:
        base_sql += " AND c.name LIKE ?"
        params.append(f"%{customer_query}%")

    base_sql += " ORDER BY s.timestamp DESC"

    sales_from_db = conn.execute(base_sql, params).fetchall()
    conn.close()
    return render_template(
        'reports.html',
        sales=sales_from_db,
        start_date=start_date or '',
        end_date=end_date or '',
        payment_status=payment_status or 'All',
        customer_query=customer_query or '',
    )


@app.route('/reports/export')
@login_required
@admin_required
def export_reports():
    conn = get_db_connection()

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    payment_status = request.args.get('payment_status')
    customer_query = request.args.get('customer')

    base_sql = """
        SELECT s.id, s.timestamp, c.name AS customer_name,
               s.payment_status, s.total_amount
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        WHERE 1=1
    """
    params = []

    if start_date:
        base_sql += " AND date(s.timestamp) >= ?"
        params.append(start_date)
    if end_date:
        base_sql += " AND date(s.timestamp) <= ?"
        params.append(end_date)
    if payment_status and payment_status != 'All':
        base_sql += " AND s.payment_status = ?"
        params.append(payment_status)
    if customer_query:
        base_sql += " AND c.name LIKE ?"
        params.append(f"%{customer_query}%")

    base_sql += " ORDER BY s.timestamp DESC"
    rows = conn.execute(base_sql, params).fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Sale ID", "Timestamp", "Customer", "Payment Status", "Total Amount"])

    for r in rows:
        writer.writerow([r["id"], r["timestamp"], r["customer_name"], r["payment_status"], r["total_amount"]])

    csv_data = output.getvalue()
    output.close()

    filename = "sales_report.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@app.route('/sale/<int:sale_id>')
@login_required
@admin_required
def sale_details(sale_id):
    conn = get_db_connection()
    sale = conn.execute(
        'SELECT s.*, c.name AS customer_name, c.phone AS customer_phone, c.email AS customer_email '
        'FROM sales s JOIN customers c ON s.customer_id = c.id WHERE s.id = ?',
        (sale_id,),
    ).fetchone()
    items_from_db = conn.execute(
        "SELECT p.sku, p.name, si.quantity_sold, si.price_per_unit "
        "FROM sale_items si JOIN products p ON p.id = si.product_id WHERE si.sale_id = ?",
        (sale_id,),
    ).fetchall()
    conn.close()
    if sale is None:
        abort(404)
    return render_template('sale_details.html', sale=sale, items=items_from_db)


@app.route('/receipt/<int:sale_id>')
@login_required
def sale_receipt(sale_id):
    conn = get_db_connection()
    sale = conn.execute(
        'SELECT s.*, c.name AS customer_name, c.phone AS customer_phone, c.email AS customer_email '
        'FROM sales s JOIN customers c ON s.customer_id = c.id WHERE s.id = ?',
        (sale_id,),
    ).fetchone()
    items_from_db = conn.execute(
        "SELECT p.sku, p.name, si.quantity_sold, si.price_per_unit "
        "FROM sale_items si JOIN products p ON p.id = si.product_id WHERE si.sale_id = ?",
        (sale_id,),
    ).fetchall()
    conn.close()
    if sale is None:
        abort(404)
    return render_template('receipt.html', sale=sale, items=items_from_db)



#I have edited this next function so that it will incorporate the partial payments part of the debts
@app.route('/debt_report')
@login_required
@admin_required
def debt_report():
    conn = get_db_connection()
    customer_query = request.args.get('customer')

    base_sql = '''
        SELECT 
            s.id,
            s.timestamp,
            s.total_amount,
            c.name,
            c.phone,
            COALESCE(SUM(p.amount_paid), 0) AS amount_paid,
            (s.total_amount - COALESCE(SUM(p.amount_paid), 0)) AS balance
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        LEFT JOIN payments p ON s.id = p.sale_id
        WHERE s.payment_status = 'On Credit'
    '''
    params = []
    if customer_query:
        base_sql += " AND c.name LIKE ?"
        params.append(f"%{customer_query}%")

    base_sql += '''
        GROUP BY s.id
        HAVING balance > 0
        ORDER BY s.timestamp DESC
    '''

    debts_from_db = conn.execute(base_sql, params).fetchall()
    total_debt = sum(debt['balance'] for debt in debts_from_db)
    conn.close()
    return render_template(
        'debt_report.html',
        debts=debts_from_db,
        total_debt_amount=total_debt,
        customer_query=customer_query or '',
    )


@app.route('/debt_report/export')
@login_required
@admin_required
def export_debt_report():
    conn = get_db_connection()
    customer_query = request.args.get('customer')

    base_sql = '''
        SELECT 
            s.id,
            s.timestamp,
            s.total_amount,
            c.name,
            c.phone,
            COALESCE(SUM(p.amount_paid), 0) AS amount_paid,
            (s.total_amount - COALESCE(SUM(p.amount_paid), 0)) AS balance
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        LEFT JOIN payments p ON s.id = p.sale_id
        WHERE s.payment_status = 'On Credit'
    '''
    params = []
    if customer_query:
        base_sql += " AND c.name LIKE ?"
        params.append(f"%{customer_query}%")

    base_sql += '''
        GROUP BY s.id
        HAVING balance > 0
        ORDER BY s.timestamp DESC
    '''

    rows = conn.execute(base_sql, params).fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["Sale ID", "Timestamp", "Customer", "Phone", "Original Amount", "Amount Paid", "Balance"],
    )

    for d in rows:
        writer.writerow(
            [
                d["id"],
                d["timestamp"],
                d["name"],
                d["phone"],
                d["total_amount"],
                d["amount_paid"],
                d["balance"],
            ],
        )

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=debt_report.csv"},
    )


@app.route('/audit_logs')
@login_required
@admin_required
def audit_logs():
    conn = get_db_connection()
    q = request.args.get('q')
    if q:
        rows = conn.execute(
            '''
            SELECT * FROM audit_logs
            WHERE username LIKE ? OR action LIKE ? OR entity_type LIKE ? OR details LIKE ?
            ORDER BY timestamp DESC
            LIMIT 500
            ''',
            (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 500'
        ).fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=rows, q=q or '')



#The following function is an addition, for me to be able to get to the destination of partial debt payments.
#it is working on the feature of customers paying their debts partially
#juu ofcourse sio kila mtu anaweza lipa deni once,
#itapea POS yetu the best vibe
@app.route('/record_payment/<int:sale_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def record_payment(sale_id):
    conn = get_db_connection()

    if request.method == 'POST':
        amount = float(request.form['amount'])
        
        # 1. Record the new payment in the 'payments' table
        conn.execute('INSERT INTO payments (sale_id, amount_paid) VALUES (?, ?)', (sale_id, amount))
        
        # 2. Check if the debt is now fully paid
        balance_check = conn.execute('''
            SELECT (s.total_amount - COALESCE(SUM(p.amount_paid), 0)) AS balance
            FROM sales s
            LEFT JOIN payments p ON s.id = p.sale_id
            WHERE s.id = ?
            GROUP BY s.id
        ''', (sale_id,)).fetchone()

        if balance_check and balance_check['balance'] <= 0:
            # 3. If balance is 0 or less, update the sale status
            conn.execute("UPDATE sales SET payment_status = 'Paid' WHERE id = ?", (sale_id,))
        
        conn.commit()
        conn.close()
        audit_log("payment_recorded", entity_type="sale", entity_id=sale_id, details=f"amount={amount}")
        return redirect(url_for('debt_report'))

    # This is the GET request part: display the form
    debt_details = conn.execute('''
        SELECT 
            s.id, s.total_amount, c.name,
            COALESCE(SUM(p.amount_paid), 0) AS amount_paid,
            (s.total_amount - COALESCE(SUM(p.amount_paid), 0)) AS balance
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        LEFT JOIN payments p ON s.id = p.sale_id
        WHERE s.id = ?
        GROUP BY s.id
    ''', (sale_id,)).fetchone()
    
    conn.close()
    return render_template('record_payment.html', debt=debt_details)

@app.route('/settle_debt/<int:sale_id>', methods=['POST'])
@login_required
@admin_required
def settle_debt(sale_id):
    conn = get_db_connection()
    conn.execute("UPDATE sales SET payment_status = 'Paid' WHERE id = ?", (sale_id,))
    conn.commit()
    conn.close()
    audit_log("debt_settled", entity_type="sale", entity_id=sale_id)
    return redirect(url_for('debt_report'))

def _validate_new_password_pair(new_pw, confirm_pw):
    """Return (ok, error_message)."""
    if not new_pw or len(new_pw) < 8:
        return False, "New password must be at least 8 characters."
    if new_pw != confirm_pw:
        return False, "New password and confirmation do not match."
    return True, None


@app.route('/change_my_password', methods=['GET', 'POST'])
@login_required
@admin_required
def change_my_password():
    """Admin must enter current password before setting a new one."""
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        conn = get_db_connection()
        row = conn.execute(
            'SELECT password_hash FROM users WHERE id = ?',
            (current_user.id,),
        ).fetchone()
        conn.close()

        if not row or not check_password_hash(row['password_hash'], current_pw):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_my_password'))

        ok, err = _validate_new_password_pair(new_pw, confirm_pw)
        if not ok:
            flash(err, 'error')
            return redirect(url_for('change_my_password'))

        new_hash = generate_password_hash(new_pw)
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_hash, current_user.id),
        )
        conn.commit()
        conn.close()
        audit_log('password_changed_self', entity_type='user', entity_id=current_user.id)
        flash('Your password has been updated.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_my_password.html')


@app.route('/reset_user_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    """Admin sets a new password for another user (no current password required)."""
    if user_id == current_user.id:
        flash('To change your own password, use “Change my password”.', 'error')
        return redirect(url_for('change_my_password'))

    conn = get_db_connection()
    target = conn.execute(
        'SELECT id, username, role FROM users WHERE id = ?',
        (user_id,),
    ).fetchone()
    conn.close()

    if target is None:
        abort(404)

    if request.method == 'POST':
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        ok, err = _validate_new_password_pair(new_pw, confirm_pw)
        if not ok:
            flash(err, 'error')
            return redirect(url_for('reset_user_password', user_id=user_id))

        new_hash = generate_password_hash(new_pw)
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (new_hash, user_id),
        )
        conn.commit()
        conn.close()
        audit_log(
            'password_reset_by_admin',
            entity_type='user',
            entity_id=user_id,
            details=f"target_username={target['username']}",
        )
        flash(f"Password updated for user “{target['username']}”.", 'success')
        return redirect(url_for('manage_users'))

    return render_template('reset_user_password.html', target=target)


@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users ORDER BY username').fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, password_hash, role))
        conn.commit()
        audit_log('user_created', entity_type='user', details=f"username={username}; role={role}")
    except sqlite3.IntegrityError:
        flash(f"Username '{username}' already exists.")
    finally:
        conn.close()
    return redirect(url_for('manage_users'))


#the following two functions; i have addded them for the sole purpose of being able to make some edits on our products and such,
#since nothing is fully fully permanent.

#this one is for editing the properties of the products, things like the description and name
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()

    if product is None:
        conn.close()
        abort(404)

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form.get('price') or 0
        buying_price = request.form.get('buying_price') or 0
        sku = request.form['sku']

        conn.execute(
            'UPDATE products SET name = ?, description = ?, price = ?, buying_price = ?, sku = ? WHERE id = ?',
            (name, description, price, buying_price, sku, product_id),
        )
        conn.commit()
        conn.close()
        audit_log(
            "product_edited",
            entity_type="product",
            entity_id=product_id,
            details=f"name={name}; price={price}; buying_price={buying_price}; sku={sku}",
        )
        flash("Product details updated.", "success")
        return redirect(url_for('products'))

    conn.close()
    return render_template('edit_product.html', product=product)


@app.route('/restock_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def restock_product(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()

    if product is None:
        conn.close()
        abort(404)

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
        except (TypeError, ValueError):
            flash("Restock amount must be a valid integer.", "error")
            conn.close()
            return redirect(url_for('restock_product', product_id=product_id))

        if amount <= 0:
            flash("Restock amount must be greater than zero.", "error")
            conn.close()
            return redirect(url_for('restock_product', product_id=product_id))

        previous_qty = product['quantity']
        conn.execute(
            'UPDATE products SET quantity = quantity + ? WHERE id = ?',
            (amount, product_id),
        )
        sync_product_low_stock_marker(conn, product_id, previous_quantity=previous_qty)
        conn.commit()
        conn.close()
        audit_log(
            "product_restocked",
            entity_type="product",
            entity_id=product_id,
            details=f"amount={amount}",
        )
        flash(f"Restocked {amount} units of {product['name']}.", "success")
        return redirect(url_for('products'))

    conn.close()
    return render_template('restock_product.html', product=product)

#this following function is for deleting some products. This should be allowed to only the admins since sometimes one can add some product wrongly and they want to do away with that
#also if they might have stopped reallly selling the product. WANAWEZA WACHA KUUZA KITU SO THEY CAN JUST DELETE
@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def delete_product(product_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('products'))



#Now i came to realise there would come a time when you need to delete some certain customers,This is only done by admin therefore the main reason i have it here under ADMIN only part
#The following function is what helps when dealing with deleting customers from our database,
#on top of that we delete all the associated records for the customers so we dont have orphaned details.

@app.route('/delete_customer/<int:customer_id>', methods=['POST'])
@login_required
@admin_required
def delete_customer(customer_id):
    conn = get_db_connection()
    customer = conn.execute('SELECT * FROM customers WHERE id = ?', (customer_id,)).fetchone()
    if customer is None:
        conn.close()
        abort(404)

    # Prevent deleting default cash sale customer (assumed id=1)
    if customer_id == 1:
        conn.close()
        flash("The default cash-sale customer cannot be deleted.", "error")
        return redirect(url_for('customers'))

    # Check outstanding debt
    debt_row = conn.execute(
        '''
        SELECT SUM(remaining) AS total_balance
        FROM (
            SELECT
                (s.total_amount - COALESCE(SUM(p.amount_paid), 0)) AS remaining
            FROM sales s
            LEFT JOIN payments p ON s.id = p.sale_id
            WHERE s.customer_id = ? AND s.payment_status = 'On Credit'
            GROUP BY s.id
        ) t
        ''',
        (customer_id,),
    ).fetchone()

    outstanding = debt_row['total_balance'] if debt_row and debt_row['total_balance'] is not None else 0

    if outstanding > 0:
        conn.close()
        flash("Customer cannot be deleted because they have outstanding debt.", "error")
        return redirect(url_for('customers'))

    # No outstanding debt -> delete associated records as before
    sales_to_delete = conn.execute('SELECT id FROM sales WHERE customer_id = ?', (customer_id,)).fetchall()
    sale_ids = [sale['id'] for sale in sales_to_delete]

    if sale_ids:
        placeholders = ','.join('?' for _ in sale_ids)
        conn.execute(f"DELETE FROM payments WHERE sale_id IN ({placeholders})", sale_ids)
        conn.execute(f"DELETE FROM sale_items WHERE sale_id IN ({placeholders})", sale_ids)
        conn.execute('DELETE FROM sales WHERE customer_id = ?', (customer_id,))

    conn.execute('DELETE FROM customers WHERE id = ?', (customer_id,))

    conn.commit()
    conn.close()
    audit_log("customer_deleted", entity_type="customer", entity_id=customer_id)
    flash("Customer and all associated records have been deleted.", "success")
    return redirect(url_for('customers'))

#just to make sure we can also delete a sale, we add these part of enabling the admin to delete a sale transaction.
#this is not really sth that should be practiced so if the admin agree one can remove this part 

@app.route('/delete_sale/<int:sale_id>', methods=['POST'])
@login_required
@admin_required
def delete_sale(sale_id):
    conn = get_db_connection()
    # A transaction ensures all deletes succeed or none do
    try:
        conn.execute('BEGIN TRANSACTION')
        # Delete associated payments first
        conn.execute('DELETE FROM payments WHERE sale_id = ?', (sale_id,))
        # Delete associated sale items
        conn.execute('DELETE FROM sale_items WHERE sale_id = ?', (sale_id,))
        # Delete the main sale record
        conn.execute('DELETE FROM sales WHERE id = ?', (sale_id,))
        conn.commit() # Commit all changes if successful
        audit_log("sale_deleted", entity_type="sale", entity_id=sale_id)
        flash(f"Sale #{sale_id} and all its records have been deleted.", "success")
    except conn.Error as e:
        conn.rollback() # Roll back changes if any error occurs
        flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('reports'))


#this is for the admin to be able to update the status of the special orders

@app.route('/update_order_status/<int:order_id>', methods=['POST'])
@login_required
@admin_required # Only Admins can change the status
def update_order_status(order_id):
    new_status = request.form['new_status']
    
    conn = get_db_connection()
    conn.execute('UPDATE special_orders SET status = ? WHERE id = ?', (new_status, order_id))
    conn.commit()
    conn.close()
    
    flash(f"Order #{order_id} status updated to {new_status}.")
    return redirect(url_for('special_orders'))

if __name__ == '__main__':
    app.run(debug=True)