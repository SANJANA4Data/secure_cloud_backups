import os
from cryptography.fernet import Fernet, InvalidToken

from utils import config


def _load_key_from_env() -> bytes | None:
    key = os.getenv("SCB_ENCRYPTION_KEY")
    return key.encode("utf-8") if key else None


def _load_key_from_file() -> bytes | None:
    if config.SECRET_KEY_PATH.exists():
        return config.SECRET_KEY_PATH.read_bytes()
    return None


def _write_key_to_file(key: bytes) -> None:
    config.SECRET_KEY_PATH.write_bytes(key)


def get_or_create_key() -> bytes:
    config.ensure_data_dirs()
    key = _load_key_from_env() or _load_key_from_file()
    if key:
        return key
    key = Fernet.generate_key()
    _write_key_to_file(key)
    return key


def encrypt_file(input_path: str, output_path: str) -> None:
    key = get_or_create_key()
    fernet = Fernet(key)
    with open(input_path, "rb") as infile:
        plaintext = infile.read()
    ciphertext = fernet.encrypt(plaintext)
    with open(output_path, "wb") as outfile:
        outfile.write(ciphertext)


def decrypt_file(input_path: str, output_path: str) -> None:
    key = get_or_create_key()
    fernet = Fernet(key)
    with open(input_path, "rb") as infile:
        ciphertext = infile.read()
    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken as exc:
        raise ValueError("Invalid encryption key or corrupted file") from exc
    with open(output_path, "wb") as outfile:
        outfile.write(plaintext)
