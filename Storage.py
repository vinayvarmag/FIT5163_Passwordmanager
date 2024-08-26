import sqlite3
import Encrypt_Decrypt
from Crypto.Random import get_random_bytes

Database = 'password_manager.sqlite'

def initialize_db():
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def store_password(service, username, password, master_password):
    salt = get_random_bytes(16).hex()  # Generate a random salt
    encrypted_password = Encrypt_Decrypt.encrypt_password(password, master_password, salt)

    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO passwords (service, username, password, salt)
        VALUES (?, ?, ?, ?)
    ''', (service, username, encrypted_password, salt))

    conn.commit()
    conn.close()
    print("Password stored successfully!")

def retrieve_password(service, master_password):
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT username, password, salt FROM passwords WHERE service = ?
    ''', (service,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        raise ValueError("Service not found!")

    username, encrypted_password, salt = row
    decrypted_password = Encrypt_Decrypt.decrypt_password(encrypted_password, master_password, bytes.fromhex(salt))

    return username, decrypted_password