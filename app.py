from flask import Flask, request, redirect, url_for, render_template, session
import sqlite3
import hashlib
from auth_system import generate_token as auth_generate_token, validate_token
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

def get_user_details(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_details = cursor.fetchone()
    conn.close()
    return user_details

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))

        return 'Invalid credentials'

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        permissions = request.form['permissions']
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO users (username, password_hash, permissions) VALUES (?, ?, ?)', (username, password_hash, permissions))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return 'Username already exists. Please choose a different username.'
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    user_details = get_user_details(username)
    return render_template('dashboard.html', user_details=user_details)

@app.route('/generate_token')
def generate_token_route():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    user_details = get_user_details(username)
    token = auth_generate_token(username, user_details[3], 'MySystem') 
    return render_template('generate_token.html', token=token)

@app.route('/validate_token', methods=['GET', 'POST'])
def validate_token_route():
    if request.method == 'POST':
        token = request.form['token']
        valid, payload = validate_token(token)
        if valid:
            issue_date = datetime.fromtimestamp(payload['iat']).strftime('%Y-%m-%d %H:%M:%S')
            expiry_date = datetime.fromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S')
            return render_template('token_validation_result.html', valid=True, issue_date=issue_date, expiry_date=expiry_date)
        else:
            return render_template('token_validation_result.html', valid=False)
    
    return render_template('validate_token.html')

if __name__ == '__main__':
    app.run(debug=True)
