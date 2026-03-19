import sqlite3

conn = sqlite3.connect('pos_system.db')
cursor = conn.cursor()

# --- CREATE TABLES ---

# Same categories table as before
cursor.execute('''
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL UNIQUE
)
''')

# Same products table as before
cursor.execute('''
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    sku TEXT UNIQUE,
    price INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    category_id INTEGER,
    FOREIGN KEY (category_id) REFERENCES categories (id)
)
''')

# NEW: Create the customers table
cursor.execute('''
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT
)
''')

# NEW: Create the users table for authentication
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Worker'
)
''')


# UPDATED: The sales table now links to customers and tracks payment
cursor.execute('''
CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_amount REAL NOT NULL,
    payment_status TEXT NOT NULL DEFAULT 'Paid',
    customer_id INTEGER,
    FOREIGN KEY (customer_id) REFERENCES customers (id)
)
''')

# Same sale_items table as before
cursor.execute('''
CREATE TABLE IF NOT EXISTS sale_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity_sold INTEGER NOT NULL,
    price_per_unit INTEGER NOT NULL,
    FOREIGN KEY (sale_id) REFERENCES sales (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
)
''')




# NEW: Create the payments table to track partial debt payments
cursor.execute('''
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL,
    amount_paid REAL NOT NULL,
    payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sale_id) REFERENCES sales (id)
)
''')

#the following table is created for the sole purpose of having some order section for the customers who make special orders or orders if we dont have them in the stock section
#this is more of the extra features to help in the smooth running of the business
cursor.execute('''
CREATE TABLE IF NOT EXISTS special_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    product_name TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    details TEXT,
    order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'Pending',
    FOREIGN KEY (customer_id) REFERENCES customers (id)
)
''')


# --- PRE-POPULATE DATA ---

# Add default categories
try:
    cursor.execute("INSERT INTO categories (name, code) VALUES ('Pipes', 'PP'), ('Taps', 'TAP'), ('Sinks', 'SNK'), ('Toilet Bowls', 'TB'), ('Accessories', 'ACC')")
except sqlite3.IntegrityError:
    pass # Categories already exist

# Add a default "Cash Sale" customer for sales that are not on credit
try:
    cursor.execute("INSERT INTO customers (name, phone) VALUES ('Cash Sale / Walk-in', 'N/A')")
except sqlite.IntegrityError:
    pass # Default customer already exists

conn.commit()
conn.close()

print("Database with Customers and Debt Tracking created successfully.")
print("i have also edited for the part of user accounts so that we can have admin and normal users using the system")
print("Just added the part of the table that would be used for partial debt payments")
print("Just added the special orders table so that it coud help out in matters of special orders in the case of custom needs or we are out of stock!!!")