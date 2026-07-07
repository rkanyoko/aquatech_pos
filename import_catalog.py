#!/usr/bin/env python3
"""
One-time import of products from PRICE LIST.doc into the POS database.
Items with a buying price are inserted; items without are written to data/items_pending_prices.md
"""
import os
import re
import subprocess
import sqlite3
import sys
from pathlib import Path

from catalog_categories import CATALOG_CATEGORIES, SECTION_TO_CATEGORY, SUBSECTION_HEADERS, TOP_LEVEL_HEADERS
from dotenv import load_dotenv

load_dotenv()

# Bootstrap schema before import (reuses app migrations)
from app import init_db, ensure_products_has_buying_price_column  # noqa: E402

DOC_PATH = Path(__file__).resolve().parent.parent / 'PRICE LIST.doc'
PENDING_PATH = Path(__file__).resolve().parent / 'data' / 'items_pending_prices.md'
SKIP_LINES = {'PRICE LIST', 'PARTICULARS\tBUYING PRICE\tSELLING PRICE'}


def extract_doc_text() -> str:
    if not DOC_PATH.exists():
        raise FileNotFoundError(f'Price list not found: {DOC_PATH}')
    result = subprocess.run(['catdoc', str(DOC_PATH)], capture_output=True, text=True, check=True)
    return result.stdout


def normalize_header(line: str) -> str:
    return re.sub(r'\s+', ' ', line.strip().upper())


def parse_price_line(line: str):
    """Return (name, buying_price) if line ends with a price, else None."""
    m = re.search(r'[\t.]+\s*([\d,]+(?:\.\d+)?)\s*$', line)
    if not m:
        m = re.search(r'\s+([\d,]+(?:\.\d+)?)\s*$', line)
    if not m:
        return None
    price_str = m.group(1).replace(',', '')
    try:
        price = float(price_str)
    except ValueError:
        return None
    if price <= 0:
        return None
    name = line[: m.start()].strip()
    name = re.split(r'[.…]{2,}', name)[0].strip(' .\t"\'')
    name = re.sub(r'\s+', ' ', name)
    if not name or not re.search(r'[a-zA-Z0-9]', name):
        return None
    return name, price


def is_page_number(line: str) -> bool:
    return bool(re.fullmatch(r'\d{1,2}', line.strip()))


def parse_catalog(text: str):
    with_price = []
    without_price = []
    current_section = 'Accessories'
    current_subsection = ''

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line in SKIP_LINES or is_page_number(line):
            continue

        normalized = normalize_header(line)
        if normalized in TOP_LEVEL_HEADERS:
            current_section = SECTION_TO_CATEGORY[normalized]
            current_subsection = ''
            continue
        if normalized in SUBSECTION_HEADERS:
            current_subsection = line.strip()
            continue

        parsed = parse_price_line(line)
        if parsed:
            name, buying_price = parsed
            description = current_subsection or None
            with_price.append({
                'category': current_section,
                'name': name,
                'description': description,
                'buying_price': buying_price,
            })
            continue

        if re.search(r'[a-zA-Z]', line):
            without_price.append({
                'category': current_section,
                'subsection': current_subsection,
                'name': re.sub(r'\s+', ' ', line).strip(' .\t'),
            })

    return with_price, without_price


def ensure_categories(conn: sqlite3.Connection) -> dict[str, int]:
    mapping = {}
    for name, code in CATALOG_CATEGORIES:
        conn.execute('INSERT OR IGNORE INTO categories (name, code) VALUES (?, ?)', (name, code))
    conn.commit()
    rows = conn.execute('SELECT id, name FROM categories').fetchall()
    for row in rows:
        mapping[row['name']] = row['id']
    return mapping


def generate_sku(category_code: str, name: str, product_id: int) -> str:
    name_part = re.sub(r'[^A-Za-z0-9]', '', name)[:3].upper() or 'ITM'
    return f'{category_code}-{name_part}-{product_id}'


def write_pending_doc(items: list[dict]) -> None:
    PENDING_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '# Items Pending Buying Prices',
        '',
        'These items were found in PRICE LIST.doc without a buying price.',
        'Review and add them manually once prices are confirmed.',
        '',
    ]
    current_category = None
    for item in items:
        if item['category'] != current_category:
            current_category = item['category']
            lines.append(f'\n## {current_category}\n')
        subsection = f" ({item['subsection']})" if item.get('subsection') else ''
        lines.append(f'- {item["name"]}{subsection}')
    PENDING_PATH.write_text('\n'.join(lines).strip() + '\n', encoding='utf-8')


def import_products(conn: sqlite3.Connection, items: list[dict]) -> tuple[int, int]:
    category_ids = ensure_categories(conn)
    inserted = 0
    skipped = 0

    for item in items:
        existing = conn.execute(
            'SELECT id FROM products WHERE name = ? AND category_id = ?',
            (item['name'], category_ids.get(item['category'])),
        ).fetchone()
        if existing:
            skipped += 1
            continue

        category_id = category_ids.get(item['category'])
        if category_id is None:
            category_id = category_ids.get('Accessories')

        category_code = conn.execute(
            'SELECT code FROM categories WHERE id = ?', (category_id,)
        ).fetchone()['code']

        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO products (name, description, price, buying_price, quantity, category_id)
            VALUES (?, ?, 0, ?, 0, ?)
            ''',
            (item['name'], item.get('description'), item['buying_price'], category_id),
        )
        product_id = cursor.lastrowid
        sku = generate_sku(category_code, item['name'], product_id)
        conn.execute('UPDATE products SET sku = ? WHERE id = ?', (sku, product_id))
        inserted += 1

    conn.commit()
    return inserted, skipped


def main():
    db_path = os.environ.get('DB_PATH', 'pos_system.db')
    init_db()
    text = extract_doc_text()
    with_price, without_price = parse_catalog(text)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    ensure_products_has_buying_price_column()
    inserted, skipped = import_products(conn, with_price)
    conn.close()

    write_pending_doc(without_price)

    print(f'Database: {db_path}')
    print(f'Imported: {inserted} products (skipped {skipped} duplicates)')
    print(f'Pending (no buying price): {len(without_price)} items -> {PENDING_PATH}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
