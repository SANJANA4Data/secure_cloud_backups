import os
from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_PATH = os.path.join(BASE_DIR, "data", "encryption.key")


def _load_or_create_key():
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as key_file:
            return key_file.read()

    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as key_file:
        key_file.write(key)
    return key


def _get_fernet():
    return Fernet(_load_or_create_key())


def encrypt_file(input_path, output_path):
    fernet = _get_fernet()
    with open(input_path, "rb") as source:
        plaintext = source.read()
    ciphertext = fernet.encrypt(plaintext)
    with open(output_path, "wb") as target:
        target.write(ciphertext)


def decrypt_file(input_path, output_path):
    fernet = _get_fernet()
    with open(input_path, "rb") as source:
        ciphertext = source.read()

    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise ValueError("Encrypted backup is invalid or key does not match") from exc

    with open(output_path, "wb") as target:
        target.write(plaintext)
