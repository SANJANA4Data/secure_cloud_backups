import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_key() -> bytes:
    raw_key = os.getenv("SCB_AES_KEY")
    if not raw_key:
        raise ValueError("SCB_AES_KEY environment variable must be set to a 32-byte value.")
    key = raw_key.encode("utf-8")
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")
    return key


def encrypt_file(input_path: str, output_path: str) -> None:
    key = _get_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with open(output_path, "wb") as f:
        f.write(nonce + ciphertext)


def decrypt_file(input_path: str, output_path: str) -> None:
    key = _get_key()
    with open(input_path, "rb") as f:
        payload = f.read()
    nonce, ciphertext = payload[:12], payload[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_path, "wb") as f:
        f.write(plaintext)
