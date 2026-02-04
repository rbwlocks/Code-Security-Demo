from flask import Flask, request, render_template_string, redirect, session, send_file
import sqlite3
import os
import subprocess
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# AWS Credentials from environment variables
AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
S3_BUCKET = os.environ.get('S3_BUCKET')

# Database Credentials from environment variables
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS documents 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, content TEXT)''')
    # Store passwords in plaintext (Vulnerability)
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO documents VALUES (1, 1, 'secret.txt', 'Secret admin document')")
    c.execute("INSERT OR IGNORE INTO documents VALUES (2, 2, 'public.txt', 'Public user document')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
        <h1>Vulnerable Security Training App</h1>
        <ul>
            <li><a href="/login">Login</a></li>
            <li><a href="/search">Search Users</a></li>
            <li><a href="/document">View Document</a></li>
            <li><a href="/ping">Ping Tool</a></li>
            <li><a href="/upload">File Upload</a></li>
            <li><a href="/redirect">Redirect</a></li>
            <li><a href="/info">System Info</a></li>
        </ul>
    ''')

# SQL Injection Vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        # Vulnerable SQL query
        sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
        c.execute(sql)
        results = c.fetchall()
        conn.close()
        return render_template_string(f'<h2>Search Results for: {query}</h2><pre>{results}</pre><br><a href="/">Home</a>')
    return '<form><input name="q" placeholder="Search username"><button>Search</button></form><a href="/">Home</a>'

# XSS Vulnerability
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user_comment = request.form.get('comment', '')
        # Reflected XSS - no sanitization
        return render_template_string(f'<h2>Your comment:</h2><div>{user_comment}</div><br><a href="/comment">Back</a>')
    return '<form method="post"><textarea name="comment"></textarea><button>Submit</button></form><a href="/">Home</a>'

# Weak Authentication & Plaintext Password Storage
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        # SQL Injection + Plaintext password comparison
        c.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect('/dashboard')
        return 'Login failed<br><a href="/login">Try again</a>'
    return '<form method="post">Username: <input name="username"><br>Password: <input name="password" type="password"><br><button>Login</button></form><a href="/">Home</a>'

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return f'<h2>Welcome {session["username"]}</h2><a href="/logout">Logout</a><br><a href="/">Home</a>'

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Insecure Direct Object Reference (IDOR)
@app.route('/document')
def document():
    doc_id = request.args.get('id', '1')
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    # No authorization check - IDOR vulnerability
    c.execute(f"SELECT * FROM documents WHERE id={doc_id}")
    doc = c.fetchone()
    conn.close()
    if doc:
        return f'<h2>Document: {doc[2]}</h2><p>{doc[3]}</p><br><a href="/">Home</a>'
    return 'Document not found<br><a href="/">Home</a>'

# Command Injection Vulnerability
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host', '')
        # Command injection vulnerability
        result = subprocess.getoutput(f'ping -c 1 {host}')
        return render_template_string(f'<h2>Ping Results:</h2><pre>{result}</pre><br><a href="/ping">Back</a>')
    return '<form method="post">Host: <input name="host"><button>Ping</button></form><a href="/">Home</a>'

# Insecure File Upload
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # No validation on file type or content
            filename = file.filename
            file.save(os.path.join('/tmp', filename))
            return f'File {filename} uploaded successfully!<br><a href="/upload">Back</a>'
    return '<form method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form><a href="/">Home</a>'

# Information Disclosure
@app.route('/info')
def info():
    # Exposing sensitive system information
    info_data = f'''
    <h2>System Information</h2>
    <pre>
    AWS Access Key: {AWS_ACCESS_KEY}
    AWS Secret Key: {AWS_SECRET_KEY}
    Database Host: {DB_HOST}
    Database User: {DB_USER}
    Database Password: {DB_PASSWORD}
    Environment: {os.environ}
    </pre>
    <a href="/">Home</a>
    '''
    return render_template_string(info_data)

# Unvalidated Redirect
@app.route('/redirect')
def unvalidated_redirect():
    url = request.args.get('url', 'https://example.com')
    # No validation of redirect URL
    return redirect(url)

if __name__ == '__main__':
    init_db()
    # Running in debug mode exposes sensitive information
    app.run(host='0.0.0.0', port=5000, debug=True)
