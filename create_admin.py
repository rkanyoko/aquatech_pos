import sqlite3
from werkzeug.security import generate_password_hash

# Get user input
username = input("Enter admin username: ")
password = input("Enter admin password: ")

# Generate a secure hash of the password
password_hash = generate_password_hash(password)

# Connect to the database
conn = sqlite3.connect('pos_system.db')
cursor = conn.cursor()

try:
    # Insert the new admin user
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'Admin')",
                   (username, password_hash))
    conn.commit()
    print(f"Admin user '{username}' created successfully.")
except sqlite3.IntegrityError:
    print(f"Error: Username '{username}' already exists.")
finally:
    conn.close()