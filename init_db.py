import sqlite3

# Connect to the database
connection = sqlite3.connect('database.db')
cursor = connection.cursor()

# Create the users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    permissions TEXT NOT NULL
)
''')

connection.commit()
connection.close()


