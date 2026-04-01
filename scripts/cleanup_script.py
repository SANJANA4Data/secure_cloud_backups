"""CLI tool: manually trigger retention cleanup for a specific user / folder pair."""
import sys
import os
import argparse
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.retention import apply_retention

logger = logging.getLogger(__name__)


def cleanup(user_id, folder_path):
    """Apply the retention policy for *user_id* / *folder_path* and return deleted IDs."""
    db_utils.init_db()
    db_utils.init_audit_log()
    deleted = apply_retention(user_id, os.path.abspath(folder_path))
    if deleted:
        logger.info("Cleaned up %d old backup(s): %s", len(deleted), ", ".join(deleted))
    else:
        logger.info("No old backups to clean up.")
    return deleted


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(
        description="Manually apply the retention policy for a user/folder pair."
    )
    parser.add_argument("--user",   required=True, help="User ID (e.g. U101)")
    parser.add_argument("--folder", required=True, help="Folder path whose backups to prune")
    args = parser.parse_args()

    cleanup(args.user, args.folder)


if __name__ == "__main__":
    main()
