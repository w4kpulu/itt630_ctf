from flask import Flask, render_template, request, redirect, url_for, session, make_response
import sqlite3
import hashlib
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = 'database.db'

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    
    # Insert default users if not exists
    users = [
        ('alice', hashlib.md5('Password123!'.encode()).hexdigest(), 'user'),
        ('bob', hashlib.md5('SecurePass456'.encode()).hexdigest(), 'user'),
        ('charlie', hashlib.md5('Charlie789!'.encode()).hexdigest(), 'user'),
        ('david', hashlib.md5('DavidPass000'.encode()).hexdigest(), 'user'),
        ('admin', hashlib.md5('SuperSecretAdminPass!@#'.encode()).hexdigest(), 'admin'),
        ('TUAH_admin', hashlib.md5('FlagBearer2026!'.encode()).hexdigest(), 'superadmin')
    ]
    
    for user in users:
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", user)
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()

# Check if user exists (VULNERABLE TO USER ENUMERATION)
def user_exists(username):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    
    # VULNERABILITY: Different responses for existing vs non-existing users
    if result:
        return True, "User exists in our system"
    else:
        return False, "User not found"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            
            if user[3] == 'superadmin':
                return redirect(url_for('admin_portal'))
            elif user[3] == 'admin':
                return render_template('user.html', username=user[1], message="Regular admin access only")
            else:
                return render_template('user.html', username=user[1], message="Regular user access")
        else:
            return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

# VULNERABLE ENDPOINT FOR USER ENUMERATION
@app.route('/api/check_user', methods=['POST'])
def check_user():
    username = request.form.get('username', '')
    
    # VULNERABILITY: Timing difference + different messages
    exists, message = user_exists(username)
    
    # Additional vulnerability: Different responses for admin users
    if 'admin' in username.lower():
        return {"exists": exists, "message": message, "hint": "Administrative accounts follow special naming conventions"}
    
    return {"exists": exists, "message": message}

# HIDDEN ADMIN PORTAL (not linked anywhere)
@app.route('/TUAH_admin_portal_2024')
def admin_portal():
    if 'username' in session and session.get('role') == 'superadmin':
        return render_template('admin.html', flag="tuah{h0h0h0_n0w_y0u_4r3_adm1n}")
    else:
        return redirect(url_for('login'))

@app.route('/robots.txt')
def robots():
    response = make_response("""User-agent: *
Disallow: /this_is_not_the_admin_portal
Disallow: /definitely_not_admin_here
Disallow: /dont_even_try_admin
Disallow: /fake_admin_panel
Disallow: /admin_test_do_not_use
Disallow: /TUAH_admin_portal_2024  
Disallow: /real_admin_secret_path
Disallow: /super_secret_admin_area

# Backup files (archived)
Disallow: /backup_2023.zip
Disallow: /backup_2024_march.tar.gz
Disallow: /db_backup.sql

# Configuration files
Disallow: /config.ini
Disallow: /settings.json
Disallow: /secrets.txt

# API Documentation
Disallow: /api_docs/
Disallow: /swagger/

# Debug information
Disallow: /debug/
Disallow: /phpinfo.php
Disallow: /test.php

# Development
Disallow: /.git/
Disallow: /vendor/
Disallow: /node_modules/
Disallow: /composer.json

# Public Access
Allow: /index.html
Allow: /login.php
Allow: /register.php
Allow: /contact.php

# Note for developers: 
# - Remove test credentials before production
# - Disable /api/check_user endpoint
# - Change default admin password from 'SyntOrnere2024!'""")
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)