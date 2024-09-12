import sqlite3
import Encrypt_Decrypt
from Crypto.Random import get_random_bytes

Database = 'password_manager.sqlite'

def initialize_db():
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()
    # Create the passwords table if it does not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')

    # Create the master password table if it does not exist
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_password TEXT NOT NULL,
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
    print(username)
    print(encrypted_password)
    print(salt)
    decrypted_password = Encrypt_Decrypt.decrypt_password(encrypted_password, master_password, salt)

    return username, decrypted_password

def set_master_password():
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM master_password")
    row = cursor.fetchone()

    # Check if the master password is already set
    if row:
        print("Master password is already set.")
        return

    master_password = input("Set a new master password: ")
    salt = get_random_bytes(16).hex()
    encrypted_password = Encrypt_Decrypt.encrypt_password(master_password, master_password, salt)

    # Insert the hashed password and salt into the database
    cursor.execute('''
        INSERT INTO master_password (encrypted_password, salt)
        VALUES (?, ?)
    ''', (encrypted_password, salt))

    conn.commit()
    conn.close()
    print("Master password has been set.")

def verify_master_password_on_login():
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    # Retrieve the stored encrypted password and salt from the database
    cursor.execute("SELECT encrypted_password, salt FROM master_password")
    row = cursor.fetchone()
    conn.close()

    # If no master password is set, prompt to set it
    if not row:
        print("No master password set. You must set it first.")
        set_master_password()
        return verify_master_password_on_login()

    encrypted_password, salt = row
    master_password = input("Enter your master password: ")

    # Attempt to decrypt the stored encrypted password
    try:
        decrypted_password = Encrypt_Decrypt.decrypt_password(encrypted_password, master_password, salt)
        encrypted_password = Encrypt_Decrypt.encrypt_password(master_password, master_password, salt)
        print("Decrypted password: ",decrypted_password)
        print(encrypted_password)
        print(master_password)
    except Exception as e:
        print("Decryption failed:", e)
        return None

    # Check if the decrypted password matches the input
    if decrypted_password == master_password:
        print("Master password verified.")
        return master_password
    else:
        print("Incorrect master password.")
        return None