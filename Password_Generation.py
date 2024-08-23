import secrets
import string

def generate_password(length=16, use_uppercase=True, use_numbers=True, use_symbols=True):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    return ''.join(secrets.choice(characters) for _ in range(length))