from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Simple demo key (32 bytes = AES-256)
BACKUP_KEY = b"a" * 32  

def encrypt_file(src, dst, key: bytes = BACKUP_KEY):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    with open(src, "rb") as f:
        data = f.read()
    encrypted = aesgcm.encrypt(nonce, data, None)
    with open(dst, "wb") as f:
        f.write(nonce + encrypted)

def decrypt_file(src, dst, key: bytes = BACKUP_KEY):
    aesgcm = AESGCM(key)
    with open(src, "rb") as f:
        raw = f.read()
    nonce, encrypted = raw[:12], raw[12:]
    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    with open(dst, "wb") as f:
        f.write(decrypted)
