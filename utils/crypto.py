"""AES-256-GCM file encryption / decryption.

The 32-byte key is read from the environment variable ``BACKUP_ENCRYPTION_KEY``
as a 64-character hexadecimal string.  Generate a suitable key once with::

    python -c "import os; print(os.urandom(32).hex())"

and export it before running any backup or restore operation::

    export BACKUP_ENCRYPTION_KEY=<64-hex-chars>

Wire format of an encrypted file:
    [12 bytes – random GCM nonce][ciphertext + 16-byte authentication tag]
"""
import os
import logging

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_ENV_KEY = "BACKUP_ENCRYPTION_KEY"
_NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM


def _get_key() -> bytes:
    """Return the 32-byte AES key from the environment, raising if absent/malformed."""
    hex_key = os.environ.get(_ENV_KEY, "")
    if not hex_key:
        raise EnvironmentError(
            f"Encryption key not set. "
            f"Export {_ENV_KEY} as a 64-character hex string before running backups."
        )
    try:
        key = bytes.fromhex(hex_key)
    except ValueError as exc:
        raise ValueError(f"{_ENV_KEY} is not a valid hex string: {exc}") from exc
    if len(key) != 32:
        raise ValueError(
            f"{_ENV_KEY} must decode to exactly 32 bytes (64 hex chars); "
            f"got {len(key)} bytes."
        )
    return key


def encrypt_file(src: str, dst: str) -> None:
    """Encrypt *src* with AES-256-GCM and write the result to *dst*.

    A fresh random nonce is prepended to the ciphertext so that every
    encryption produces a unique output even for identical inputs.
    """
    key = _get_key()
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    with open(src, "rb") as f:
        plaintext = f.read()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with open(dst, "wb") as f:
        f.write(nonce + ciphertext)
    logger.debug("Encrypted %s -> %s", src, dst)


def decrypt_file(src: str, dst: str) -> None:
    """Decrypt *src* (produced by :func:`encrypt_file`) and write plaintext to *dst*.

    Raises ``cryptography.exceptions.InvalidTag`` if the ciphertext has been
    tampered with or the wrong key is used.
    """
    key = _get_key()
    aesgcm = AESGCM(key)
    with open(src, "rb") as f:
        blob = f.read()
    if len(blob) < _NONCE_SIZE:
        raise ValueError(f"Encrypted file is too short to be valid: {src!r}")
    nonce = blob[:_NONCE_SIZE]
    ciphertext = blob[_NONCE_SIZE:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(dst, "wb") as f:
        f.write(plaintext)
    logger.debug("Decrypted %s -> %s", src, dst)
