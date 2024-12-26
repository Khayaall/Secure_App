from flask import Flask, render_template, request, redirect, session
import sqlite3
import html
import secrets
import logging
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

# Generate encryption key and cipher suite
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

def encrypt_data(data):
    """Encrypt the given data."""
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(data):
    """Decrypt the given data."""
    decrypted_data = cipher.decrypt(data.encode())
    return decrypted_data.decode()

def not_valid_input(input_string):
    """Check if the input contains any malicious characters."""
    return bool(re.search(r'[<>]', input_string))

def is_valid_email(email):
    """Validate the email format."""
    email_pattern = r"[^@]+@[^@]+\.[^@]+"
    return bool(re.match(email_pattern, email))

def is_valid_password(password):
    """Validate the password strength."""
    return (
        len(password) >= 8 and
        re.search(r"\d", password) and
        re.search(r"[A-Z]", password)
    )

def log_suspicious_activity(activity_type, details, app):
    """Log suspicious activity."""
    app.logger.warning(f"Suspicious activity detected: {activity_type} - {details}")

def hash_password(password):
    """Hash the given password."""
    return generate_password_hash(password)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Rate limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Helper functions
def log_rate_limit_exceeded(response):
    app.logger.error("Rate limit exceeded: %s", response)
    return response

def get_user_from_db(username):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

# CSRF protection
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            app.logger.error("CSRF token missing or incorrect!")
            return "CSRF token missing or incorrect!", 400

# Routes
@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        user_comment = request.form['comment']
        if "<script>" in user_comment.lower():
            log_suspicious_activity("XSS attempt", user_comment, app)
        sanitized_comment = html.escape(user_comment)
        with open('comments.txt', 'a') as f:
            f.write(sanitized_comment + "\n")
    with open('comments.txt', 'r') as f:
        comments = f.readlines()
    return render_template('comments.html', comments=comments, csrf_token=generate_csrf_token())

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        recipient = request.form['recipient']
        amount = request.form['amount']
        if not_valid_input(recipient) or not_valid_input(amount):
            app.logger.error("Invalid input for transfer: recipient=%s, amount=%s", recipient, amount)
            log_suspicious_activity("Invalid transfer input", f"recipient={recipient}, amount={amount}", app)
            return 'Invalid input!', 400
        encrypted_recipient = encrypt_data(recipient)
        encrypted_amount = encrypt_data(amount)
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {encrypted_recipient}, Amount: {encrypted_amount}\n")
    return render_template('transfer.html', success=False, csrf_token=generate_csrf_token())

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not_valid_input(username) or not_valid_input(password):
            app.logger.error("Invalid input for login: username=%s", username)
            log_suspicious_activity("Invalid login input", f"username={username}", app)
            return 'Invalid input!', 400
        user = get_user_from_db(username)
        if user and check_password_hash(user[1], password):
            return redirect('/home')
        else:
            log_suspicious_activity("Failed login attempt", f"username={username}", app)
            return render_template('login.html', csrf_token=generate_csrf_token() ,message = "ZByyy"), 400
    return render_template('login.html', csrf_token=generate_csrf_token(), message='')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not_valid_input(username) or not is_valid_email(email) or not is_valid_password(password):
            app.logger.error("Invalid input for registration: username=%s, email=%s", username, email)
            log_suspicious_activity("Invalid registration input", f"username={username}, email={email}", app)
            return 'Invalid input!', 400
        if get_user_from_db(username):
            app.logger.error("User already exists: username=%s", username)
            log_suspicious_activity("Duplicate registration attempt", f"username={username}", app)
            return 'User already exists!', 400
        hashed_password = hash_password(password)
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        return redirect('/login')
    return render_template('signup.html', csrf_token=generate_csrf_token())

@app.route('/admin_dashboard')
def admin_dashboard():
    logs = []
    user_activities = []
    with open('app.log', 'r') as f:
        for line in f:
            parts = line.split(' ')
            if len(parts) > 2:
                timestamp = parts[0]
                event = parts[1]
                details = ' '.join(parts[2:])
                logs.append({'timestamp': timestamp, 'event': event, 'details': details})
                user_activities.append({'timestamp': timestamp, 'username': event, 'activity': details})
    return render_template('admin_dashboard.html', logs=logs, user_activities=user_activities)

# Error handlers
@app.errorhandler(400)
def bad_request_error(error):
    app.logger.error(f"Bad Request: {error}")
    return ('Bad Request!', 400)

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"Not Found: {error}")
    return ('Bad Request!', 404)

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Server Error: {error}")
    return ('Bad Request!', 500)

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.error("Rate limit exceeded: %s", e.description)
    return ('Bad Request!', 429)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)