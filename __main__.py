"""Entry point: python -m secure_cloud_backups <command> [options]

Commands:
  backup   Create a backup of a folder
  restore  Restore a backup
  delete   Delete a backup
  list     List backups and audit log
  audit    Replay access_log.csv against RBAC rules
"""
import sys
import os
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def main():
    parser = argparse.ArgumentParser(
        prog="python -m secure_cloud_backups",
        description="Secure Cloud Backup System",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_backup = subparsers.add_parser("backup", help="Back up a folder")
    p_backup.add_argument("--user",   required=True, help="User ID")
    p_backup.add_argument("--folder", required=True, help="Folder path to back up")

    p_restore = subparsers.add_parser("restore", help="Restore a backup")
    p_restore.add_argument("--backup-id", required=True, help="Backup ID")
    p_restore.add_argument("--user",      required=True, help="User ID")

    p_delete = subparsers.add_parser("delete", help="Delete a backup")
    p_delete.add_argument("--backup-id", required=True, help="Backup ID")
    p_delete.add_argument("--user",      required=True, help="User ID")

    p_list = subparsers.add_parser("list", help="List backups or audit log")
    p_list.add_argument(
        "--table",
        choices=["backups", "audit", "all"],
        default="all",
        help="Table to display",
    )

    subparsers.add_parser("audit", help="Replay access_log.csv against RBAC rules")

    args = parser.parse_args()

    if args.command == "backup":
        from scripts.backup_script import main as _main
        sys.argv = ["backup_script", "--user", args.user, "--folder", args.folder]
        _main()
    elif args.command == "restore":
        from scripts.restore_script import main as _main
        sys.argv = ["restore_script", "--backup-id", args.backup_id, "--user", args.user]
        _main()
    elif args.command == "delete":
        from scripts.delete_backup import main as _main
        sys.argv = ["delete_backup", "--backup-id", args.backup_id, "--user", args.user]
        _main()
    elif args.command == "list":
        from scripts.list_backups import main as _main
        sys.argv = ["list_backups", "--table", args.table]
        _main()
    elif args.command == "audit":
        from scripts.rbac_check import run_audit
        import logging
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        run_audit()


if __name__ == "__main__":
    main()
