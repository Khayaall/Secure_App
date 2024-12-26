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