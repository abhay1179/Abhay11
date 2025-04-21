from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime
import os
from database import init_db, get_db_connection, close_connection
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64
from werkzeug.security import generate_password_hash, check_password_hash
import functools

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

# Initialize database
init_db()

# Category list
CATEGORIES = [
    'Food', 'Transport', 'Shopping', 'Bills', 'Entertainment', 
    'Health', 'Education', 'Travel', 'Others'
]

# Login required decorator
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

# Initialize user table in database
def init_user_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Modify expenses table to include user_id
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS expenses_with_user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL,
        description TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Check if we need to migrate existing data
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='expenses'")
    if cursor.fetchone():
        # Check if we have existing data to migrate
        cursor.execute("SELECT COUNT(*) FROM expenses")
        count = cursor.fetchone()[0]
        
        if count > 0:
            # Create admin user if migrating data
            cursor.execute("SELECT id FROM users WHERE username = 'admin'")
            admin = cursor.fetchone()
            if not admin:
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    ('admin', generate_password_hash('admin'))
                )
                admin_id = cursor.lastrowid
            else:
                admin_id = admin[0]
            
            # Migrate data
            cursor.execute('''
            INSERT INTO expenses_with_user (user_id, amount, category, date, description)
            SELECT ?, amount, category, date, description FROM expenses
            ''', (admin_id,))
            
            # Rename tables
            cursor.execute("ALTER TABLE expenses RENAME TO expenses_old")
            cursor.execute("ALTER TABLE expenses_with_user RENAME TO expenses")
    
    conn.commit()
    close_connection(conn)

# Call to initialize user database
init_user_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        error = None
        
        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'
        else:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone() is not None:
                error = f"User {username} is already registered"
        
        if error is None:
            cursor.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            conn.commit()
            close_connection(conn)
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        
        flash(error)
        close_connection(conn)
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        error = None
        
        cursor.execute('SELECT id, password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        close_connection(conn)
        
        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user[1], password):
            error = 'Incorrect password'
        
        if error is None:
            session.clear()
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('index'))
        
        flash(error)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get recent expenses for the logged-in user
    cursor.execute(
        "SELECT id, amount, category, date, description FROM expenses WHERE user_id = ? ORDER BY date DESC LIMIT 10",
        (session['user_id'],)
    )
    recent_expenses = cursor.fetchall()
    
    # Get total expenses for the logged-in user
    cursor.execute("SELECT SUM(amount) FROM expenses WHERE user_id = ?", 
                  (session['user_id'],))
    total_expense = cursor.fetchone()[0] or 0
    
    # Get expenses by category for the logged-in user
    cursor.execute(
        "SELECT category, SUM(amount) FROM expenses WHERE user_id = ? GROUP BY category",
        (session['user_id'],)
    )
    category_totals = cursor.fetchall()
    
    # Current month expenses for the logged-in user
    current_month = datetime.now().strftime('%Y-%m')
    cursor.execute(
        "SELECT SUM(amount) FROM expenses WHERE user_id = ? AND date LIKE ?", 
        (session['user_id'], f"{current_month}%")
    )
    monthly_expense = cursor.fetchone()[0] or 0
    
    close_connection(conn)
    
    return render_template(
        'index.html', 
        recent_expenses=recent_expenses,
        total_expense=total_expense,
        monthly_expense=monthly_expense,
        category_totals=category_totals,
        categories=CATEGORIES,
        username=session.get('username')
    )

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        date = request.form['date']
        description = request.form['description']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO expenses (user_id, amount, category, date, description) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], amount, category, date, description)
        )
        conn.commit()
        close_connection(conn)
        
        flash('Expense added successfully!')
        return redirect(url_for('index'))
    
    return render_template('add_expense.html', categories=CATEGORIES)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # First check if the expense belongs to the logged-in user
    cursor.execute("SELECT * FROM expenses WHERE id=? AND user_id=?", (id, session['user_id']))
    expense = cursor.fetchone()
    
    if expense is None:
        close_connection(conn)
        flash('Expense not found or you do not have permission to edit it!')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        date = request.form['date']
        description = request.form['description']
        
        cursor.execute(
            "UPDATE expenses SET amount=?, category=?, date=?, description=? WHERE id=? AND user_id=?",
            (amount, category, date, description, id, session['user_id'])
        )
        conn.commit()
        close_connection(conn)
        
        flash('Expense updated successfully!')
        return redirect(url_for('index'))
    
    close_connection(conn)
    
    return render_template('edit_expense.html', expense=expense, categories=CATEGORIES)

@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # First check if the expense belongs to the logged-in user
    cursor.execute("SELECT id FROM expenses WHERE id=? AND user_id=?", (id, session['user_id']))
    if cursor.fetchone() is None:
        close_connection(conn)
        flash('Expense not found or you do not have permission to delete it!')
        return redirect(url_for('index'))
    
    cursor.execute("DELETE FROM expenses WHERE id=? AND user_id=?", (id, session['user_id']))
    conn.commit()
    close_connection(conn)
    
    flash('Expense deleted successfully!')
    return redirect(url_for('index'))





































@app.route('/reports')
@login_required
def reports():
    # Date range filters
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    category = request.args.get('category', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Base query - include user_id filter
    query = "SELECT id, amount, category, date, description FROM expenses WHERE user_id = ?"
    params = [session['user_id']]
    
    # Add filters
    conditions = []
    if start_date:
        conditions.append("date >= ?")
        params.append(start_date)
    if end_date:
        conditions.append("date <= ?")
        params.append(end_date)
    if category and category != 'All':
        conditions.append("category = ?")
        params.append(category)
    
    if conditions:
        query += " AND " + " AND ".join(conditions)
    
    query += " ORDER BY date DESC"
    
    cursor.execute(query, params)
    expenses = cursor.fetchall()
    
    # Generate charts
    charts = {}
    if expenses:
        # Convert to pandas DataFrame for visualization
        df = pd.DataFrame(expenses, columns=['id', 'amount', 'category', 'date', 'description'])
        
        # Category pie chart
        plt.figure(figsize=(8, 6))
        category_data = df.groupby('category')['amount'].sum()
        plt.pie(category_data, labels=category_data.index, autopct='%1.1f%%')
        plt.title('Expenses by Category')
        
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        charts['category_pie'] = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        # Time series chart
        if len(df) > 1:
            plt.figure(figsize=(10, 6))
            df['date'] = pd.to_datetime(df['date'])
            time_data = df.groupby(df['date'].dt.strftime('%Y-%m-%d'))['amount'].sum()
            plt.plot(time_data.index, time_data.values, marker='o')
            plt.title('Expenses Over Time')
            plt.xlabel('Date')
            plt.ylabel('Amount')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            charts['time_series'] = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
    
    close_connection(conn)
    
    return render_template(
        'reports.html', 
        expenses=expenses, 
        categories=['All'] + CATEGORIES,
        start_date=start_date,
        end_date=end_date,
        selected_category=category,
        charts=charts,
        username=session.get('username')
    )

@app.template_filter('currency')
def currency_filter(value):
    return f"₹{value:.2f}"

if __name__ == '__main__':
    app.run(debug=True)