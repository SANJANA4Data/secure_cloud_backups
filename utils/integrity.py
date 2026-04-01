"""SHA-256 integrity helpers for backup archives."""
import hashlib
import logging

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536  # 64 KiB


def sha256_file(path: str) -> str:
    """Return the lowercase hex SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    digest = h.hexdigest()
    logger.debug("SHA-256 of %s: %s", path, digest)
    return digest


def verify_integrity(path: str, expected: str) -> None:
    """Verify that *path* matches *expected* SHA-256 digest.

    Raises ``ValueError`` with a descriptive message on mismatch so callers
    can treat it the same as other validation errors.
    """
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(
            f"Integrity check failed for {path!r}: "
            f"expected {expected!r}, got {actual!r}"
        )
    logger.info("Integrity OK: %s", path)
