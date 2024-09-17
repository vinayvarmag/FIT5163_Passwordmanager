import sqlite3
import Encrypt_Decrypt
import pyotp
import qrcode
from Crypto.Random import get_random_bytes

Database = 'password_manager.sqlite'
BLOCK_SIZE = 16 #AES Block size

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
                salt TEXT NOT NULL,
                totp_secret TEXT
            )
        ''')
    conn.commit()
    conn.close()

def store_password(service, username, password, master_password):
    salt = get_random_bytes(BLOCK_SIZE).hex()  # Generate a random salt
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

def display_services():
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    cursor.execute(''' SELECT id, service FROM passwords''', )
    rows = cursor.fetchall()
    conn.close()
    return rows

def retrieve_password(id, master_password):
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT username, password, salt FROM passwords WHERE id = ?
    ''', (id,))
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
    salt = get_random_bytes(BLOCK_SIZE).hex()
    encrypted_password = Encrypt_Decrypt.encrypt_password(master_password, master_password, salt)
    totp_secret = setup_totp_secret()
    if totp_secret:
        conn = sqlite3.connect(Database)
        cursor = conn.cursor()

        cursor.execute('''
        INSERT INTO master_password (encrypted_password, salt, totp_secret)
        VALUES (?, ?, ?)
        ''', (encrypted_password, salt, totp_secret))
        conn.commit()
        conn.close()
        print("Master password and authenticator setup complete.")
    else:
        print("Failed to set up authenticator. Please try again.")

def verify_master_password_on_login():
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    # Retrieve the stored encrypted password and salt from the database
    cursor.execute("SELECT encrypted_password, salt, totp_secret FROM master_password")
    row = cursor.fetchone()
    conn.close()

    # If no master password is set, prompt to set it
    if not row:
        print("No master password set. You must set it first.")
        set_master_password()
        return verify_master_password_on_login()

    encrypted_password, salt, totp_secret = row
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
        totp = pyotp.TOTP(totp_secret)
        otp_input = input("Enter the OTP from your authenticator app: ")
        if not totp.verify(otp_input):
            print("Invalid OTP.")
            conn.close()
            return None
        print("Login successful.")
        return master_password
    else:
        print("Incorrect master password.")
        return None



def change_master_password(old_master_password):
    conn = sqlite3.connect(Database)
    cursor = conn.cursor()

    # Retrieve the old encrypted master password and salt from the database
    cursor.execute("SELECT encrypted_password, salt FROM master_password")
    row = cursor.fetchone()

    if not row:
        print("Master password not found. Please set a master password first.")
        return

    encrypted_master_password, salt = row
    print(encrypted_master_password)
    print(salt)

    # Verify the old master password
    try:
        decrypted_master_password = Encrypt_Decrypt.decrypt_password(encrypted_master_password, old_master_password,
                                                     salt)
    except Exception as e:
        print("Failed to decrypt master password. Incorrect password.")
        return

    if decrypted_master_password != old_master_password:
        print("Incorrect master password.")
        return

    # Ask the user to input a new master password
    new_master_password = input("Enter new master password: ")
    confirm_password = input("Confirm new master password: ")

    if new_master_password != confirm_password:
        print("Passwords do not match. Try again.")
        return

    # Re-encrypt all stored passwords with the new master password
    cursor.execute("SELECT service, username, password, salt FROM passwords")
    rows = cursor.fetchall()

    for row in rows:
        service, username, encrypted_password, password_salt = row

        # Decrypt the existing password with the old master password
        decrypted_password = Encrypt_Decrypt.decrypt_password(encrypted_password, old_master_password, password_salt)

        # Encrypt the password with the new master password
        new_salt = get_random_bytes(BLOCK_SIZE).hex()
        print(new_salt)
        new_encrypted_password = Encrypt_Decrypt.encrypt_password(decrypted_password, new_master_password, new_salt)

        # Update the password in the database
        cursor.execute('''
            UPDATE passwords
            SET password = ?, salt = ?
            WHERE service = ?
        ''', (new_encrypted_password, new_salt, service))

    # Encrypt and store the new master password with a new salt
    new_salt = get_random_bytes(BLOCK_SIZE).hex()
    encrypted_new_master_password = Encrypt_Decrypt.encrypt_password(new_master_password, new_master_password, new_salt)
    new_totp_secret = setup_totp_secret()

    cursor.execute('''
        UPDATE master_password
        SET encrypted_password = ?, salt = ?, totp_secret = ?
        WHERE id = 1
    ''', (encrypted_new_master_password, new_salt, new_totp_secret))

    conn.commit()
    conn.close()
    print("Master password changed successfully.")
    return new_master_password

def setup_totp_secret():
    # Generate a new TOTP secret
    totp_secret = pyotp.random_base32()

    # Create a TOTP object
    totp = pyotp.TOTP(totp_secret)

    # Generate a URL to display as a QR code, which can be scanned by Google Authenticator
    qr_url = totp.provisioning_uri("MyPasswordManager", issuer_name="PasswordManager")

    # Generate and display a QR code
    qr = qrcode.QRCode()
    qr.add_data(qr_url)
    qr.print_ascii()

    while True:
        otp_input = input("Enter the OTP from your authenticator app to verify setup: ")

        if totp.verify(otp_input):
            print("Authenticator setup successful!")
            return totp_secret  # Return the secret only if the OTP is verified
        else:
            print("Invalid OTP. Please try again.")

