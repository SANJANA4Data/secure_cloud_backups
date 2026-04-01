"""CLI tool: download (decrypt) a backup archive to a local destination path."""
import sys
import os
import argparse
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.config import CLOUD_DIR
from utils.rbac import enforce_rbac
from utils.crypto import decrypt_file
from utils.integrity import verify_integrity

logger = logging.getLogger(__name__)


def download_backup(backup_id, user_id, dest_path):
    """Decrypt and copy a backup archive to *dest_path*.

    *dest_path* must be a file path (not a directory).  The caller receives a
    plain ZIP file that can be inspected or re-imported independently.
    """
    db_utils.init_db()
    db_utils.init_audit_log()

    # RBAC enforcement – Viewer, Owner, and Admin are allowed; Restorer is also
    # allowed as the RBAC check for DOWNLOAD passes for all roles except none.
    enforce_rbac(user_id, "DOWNLOAD", backup_id=backup_id)

    enc_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip.enc")
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"Backup archive not found: {enc_path!r}")

    # Verify integrity before decrypting
    expected_checksum = db_utils.get_checksum(backup_id)
    if expected_checksum:
        verify_integrity(enc_path, expected_checksum)

    dest_dir = os.path.dirname(os.path.abspath(dest_path))
    os.makedirs(dest_dir, exist_ok=True)

    decrypt_file(enc_path, dest_path)
    db_utils.log_action("BACKUP_DOWNLOADED", backup_id, user_id)
    logger.info("Backup %s downloaded to %s by %s", backup_id, dest_path, user_id)
    return dest_path


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Download (decrypt) a backup archive to a local path."
    )
    parser.add_argument("--backup-id", required=True, help="Backup ID (e.g. B20260214033329)")
    parser.add_argument("--user",      required=True, help="User ID (e.g. U102)")
    parser.add_argument("--dest",      required=True, help="Destination file path for the ZIP")
    args = parser.parse_args()

    try:
        download_backup(args.backup_id, args.user, args.dest)
    except PermissionError as exc:
        logger.error("Access denied: %s", exc)
        sys.exit(1)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
