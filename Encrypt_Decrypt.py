from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os

# Constants
BLOCK_SIZE = 16  # AES block size
KEY_LENGTH = 32  # AES-256 key size

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def generate_key(master_password, salt):
    # Derive a key from the master password
    return PBKDF2(master_password, salt, dkLen=KEY_LENGTH)

def encrypt_password(plaintext, master_password, salt):
    key = generate_key(master_password, salt)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_password(ciphertext, master_password, salt):
    key = generate_key(master_password, salt)
    raw_data = base64.b64decode(ciphertext)
    iv = raw_data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(raw_data[BLOCK_SIZE:]))
    return plaintext.decode()