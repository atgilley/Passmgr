import os
from cryptography.fernet import Fernet

# Constants
SECURE_DIR = "/etc/password_manager"
PASSWORD_STORAGE_FILE = f"{SECURE_DIR}/passwords.secure"
KEY_FILE = f"{SECURE_DIR}/key.key"

# Ensure the directory exists
if not os.path.exists(SECURE_DIR):
    os.makedirs(SECURE_DIR, mode=0o700)

# Generate or load the encryption key
def load_or_generate_key():
    
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        os.chmod(KEY_FILE, 0o600)  # Restrict access to the key file
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

# Load the encryption key
key = load_or_generate_key()
cipher = Fernet(key)

# Encryption and decryption functions
def encrypt_password(password):
    
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    
    return cipher.decrypt(encrypted_password.encode()).decode()

# Store and retrieve password functions
def store_password(username, site_or_program, password):
   
    encrypted_password = encrypt_password(password)
    with open(PASSWORD_STORAGE_FILE, "a") as file:
        file.write(f"{username},{site_or_program},{encrypted_password}\n")

def retrieve_password(username, site_or_program):
    
    try:
        with open(PASSWORD_STORAGE_FILE, "r") as file:
            for line in file:
                # Ensure each line has exactly 3 parts: username, site, encrypted_password
                parts = line.strip().split(",", maxsplit=2)
                if len(parts) != 3:
                    continue  # Skip malformed lines
                stored_username, stored_site, encrypted_password = parts
                if stored_username == username and stored_site == site_or_program:
                    return decrypt_password(encrypted_password)
    except FileNotFoundError:
        raise FileNotFoundError("Password storage file not found.")
    return None

