"""CLI tool: list backup records and audit log entries from the database."""
import sys
import os
import argparse
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils import db_utils

logger = logging.getLogger(__name__)


def print_backups():
    rows = db_utils.list_backups()
    if not rows:
        print("No backups found.")
        return
    header = f"{'BACKUP_ID':<22} {'USER_ID':<8} {'FOLDER':<30} {'TIMESTAMP':<25} {'VER':>3} {'SIZE':>10} {'RESTORES':>8}"
    print(header)
    print("-" * len(header))
    for row in rows:
        print(f"{row[0]:<22} {row[1]:<8} {str(row[2]):<30} {row[3]:<25} {row[4]:>3} {row[5]:>10} {row[6]:>8}")


def print_audit_log():
    rows = db_utils.list_audit_log()
    if not rows:
        print("No audit log entries found.")
        return
    header = f"{'ID':>4} {'ACTION':<20} {'BACKUP_ID':<22} {'USER_ID':<8} {'TIMESTAMP'}"
    print(header)
    print("-" * len(header))
    for row in rows:
        print(f"{row[0]:>4} {row[1]:<20} {str(row[2]):<22} {str(row[3]):<8} {row[4]}")


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="List backups and audit log entries.")
    parser.add_argument(
        "--table",
        choices=["backups", "audit", "all"],
        default="all",
        help="Which table to display (default: all)",
    )
    args = parser.parse_args()

    db_utils.init_db()
    db_utils.init_audit_log()

    if args.table in ("backups", "all"):
        print("\n=== Backups ===")
        print_backups()
    if args.table in ("audit", "all"):
        print("\n=== Audit Log ===")
        print_audit_log()


if __name__ == "__main__":
    main()
