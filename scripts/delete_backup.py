"""CLI tool: delete a backup record from the database and remove its ZIP archive."""
import sys
import os
import argparse
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.config import CLOUD_DIR
from utils.rbac import enforce_rbac

logger = logging.getLogger(__name__)


def delete_backup(backup_id, user_id):
    # RBAC enforcement (raises PermissionError if denied)
    enforce_rbac(user_id, "DELETE", backup_id=backup_id)

    # Remove database record first
    db_utils.delete_backup(backup_id)

    # Remove the ZIP archive if it exists
    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")
    if os.path.exists(zip_path):
        os.remove(zip_path)
        logger.info("Removed archive %s", zip_path)

    db_utils.log_action("BACKUP_DELETED", backup_id, user_id)
    logger.info("Backup %s deleted by %s", backup_id, user_id)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Delete a backup record and its archive.")
    parser.add_argument("--backup-id", required=True, help="Backup ID to delete (e.g. B20260214033329)")
    parser.add_argument("--user",      required=True, help="User ID performing the deletion (e.g. U101)")
    args = parser.parse_args()

    db_utils.init_db()
    db_utils.init_audit_log()

    try:
        delete_backup(args.backup_id, args.user)
    except PermissionError as exc:
        logger.error("Access denied: %s", exc)
        sys.exit(1)
    except ValueError as exc:
        logger.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
