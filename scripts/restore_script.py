import sys
import os
import zipfile
import logging
import argparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.config import CLOUD_DIR, RESTORE_DIR
from utils.rbac import enforce_rbac

logger = logging.getLogger(__name__)


def restore_backup(backup_id, user_id):
    # Ensure DB tables exist
    db_utils.init_db()
    db_utils.init_audit_log()

    # RBAC enforcement (raises PermissionError if denied)
    enforce_rbac(user_id, "RESTORE", backup_id=backup_id)

    os.makedirs(RESTORE_DIR, exist_ok=True)

    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"Backup archive not found: {zip_path!r}")

    # Safe extraction – reject any entry whose resolved path escapes RESTORE_DIR
    restore_dir_real = os.path.realpath(RESTORE_DIR)
    with zipfile.ZipFile(zip_path, "r") as zipf:
        for member in zipf.infolist():
            dest_path = os.path.realpath(os.path.join(RESTORE_DIR, member.filename))
            if os.path.commonpath([dest_path, restore_dir_real]) != restore_dir_real:
                raise ValueError(f"Unsafe zip entry rejected: {member.filename!r}")
            zipf.extract(member, RESTORE_DIR)

    db_utils.increment_restore_count(backup_id)
    db_utils.log_action("BACKUP_RESTORED", backup_id, user_id)
    logger.info("Backup %s restored to %s", backup_id, RESTORE_DIR)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Restore a backup from cloud storage.")
    parser.add_argument("--backup-id", required=True, help="Backup ID (e.g. B20260214033329)")
    parser.add_argument("--user",      required=True, help="User ID (e.g. U103)")
    args = parser.parse_args()

    try:
        restore_backup(args.backup_id, args.user)
    except PermissionError as exc:
        logger.error("Access denied: %s", exc)
        sys.exit(1)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
