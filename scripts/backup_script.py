import sys
import os
import zipfile
import logging
import argparse
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.config import CLOUD_DIR
from utils.rbac import enforce_rbac

logger = logging.getLogger(__name__)


def backup_folder(user_id, folder_path):
    # Input validation
    if not os.path.isdir(folder_path):
        raise ValueError(f"Folder not found: {folder_path!r}")

    # RBAC enforcement (raises PermissionError if denied)
    enforce_rbac(user_id, "BACKUP")

    # Ensure DB tables and cloud storage directory exist
    db_utils.init_db()
    db_utils.init_audit_log()
    os.makedirs(CLOUD_DIR, exist_ok=True)

    # Auto-increment version for this (user, folder) combination
    abs_folder = os.path.abspath(folder_path)
    version = db_utils.get_next_version(user_id, abs_folder)

    # Create backup archive
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    backup_id = f"B{timestamp}"
    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")

    with zipfile.ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

    size = os.path.getsize(zip_path)
    db_utils.insert_backup(backup_id, user_id, version, size, folder_path=abs_folder)
    db_utils.log_action("BACKUP_CREATED", backup_id, user_id)

    logger.info("Backup created: %s  size=%d bytes  version=%d", backup_id, size, version)
    return backup_id


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Create a secure backup of a folder.")
    parser.add_argument("--user",   required=True, help="User ID (e.g. U101)")
    parser.add_argument("--folder", required=True, help="Path to the folder to back up")
    args = parser.parse_args()

    try:
        backup_folder(args.user, args.folder)
    except PermissionError as exc:
        logger.error("Access denied: %s", exc)
        sys.exit(1)
    except ValueError as exc:
        logger.error("Invalid input: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
