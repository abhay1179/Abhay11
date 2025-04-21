import sqlite3
from werkzeug.security import generate_password_hash

db_file = "expenses.db"

def get_db_connection():
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn

def close_connection(conn):
    conn.close()

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Create expenses table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL,
        description TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Migration check: If old expenses table exists, migrate data
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='expenses_old'")
    if cursor.fetchone() is None:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='expenses'")
        if cursor.fetchone():
            cursor.execute("SELECT COUNT(*) FROM expenses")
            count = cursor.fetchone()[0]
            
            if count > 0:
                cursor.execute("SELECT id FROM users WHERE username = 'admin'")
                admin = cursor.fetchone()
                if not admin:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                                   ('admin', generate_password_hash('admin')))
                    admin_id = cursor.lastrowid
                else:
                    admin_id = admin[0]
                
                cursor.execute('''
                INSERT INTO expenses (user_id, amount, category, date, description)
                SELECT ?, amount, category, date, description FROM expenses
                ''', (admin_id,))
                
                cursor.execute("ALTER TABLE expenses RENAME TO expenses_old")
    
    conn.commit()
    close_connection(conn)

# Initialize database
init_db()
