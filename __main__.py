"""Entry point: python -m secure_cloud_backups <command> [options]

Commands:
  backup   Create a backup of a folder
  restore  Restore a backup
  delete   Delete a backup
  download Download (decrypt) a backup archive to a local path
  list     List backups and audit log
  audit    Replay access_log.csv against RBAC rules
  verify   Verify the SHA-256 integrity of a stored backup
  cleanup  Apply retention policy for a user/folder pair
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

    p_download = subparsers.add_parser("download", help="Download a decrypted backup archive")
    p_download.add_argument("--backup-id", required=True, help="Backup ID")
    p_download.add_argument("--user",      required=True, help="User ID")
    p_download.add_argument("--dest",      required=True, help="Destination file path")

    p_list = subparsers.add_parser("list", help="List backups or audit log")
    p_list.add_argument(
        "--table",
        choices=["backups", "audit", "all"],
        default="all",
        help="Table to display",
    )

    subparsers.add_parser("audit", help="Replay access_log.csv against RBAC rules")

    p_verify = subparsers.add_parser("verify", help="Verify integrity of a stored backup")
    p_verify.add_argument("--backup-id", required=True, help="Backup ID")

    p_cleanup = subparsers.add_parser(
        "cleanup", help="Manually apply retention policy for a user/folder pair"
    )
    p_cleanup.add_argument("--user",   required=True, help="User ID")
    p_cleanup.add_argument("--folder", required=True, help="Folder path")

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
    elif args.command == "download":
        from scripts.download_script import main as _main
        sys.argv = [
            "download_script",
            "--backup-id", args.backup_id,
            "--user", args.user,
            "--dest", args.dest,
        ]
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
    elif args.command == "verify":
        import logging
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
        from utils import db_utils
        from utils.config import CLOUD_DIR
        from utils.integrity import verify_integrity
        db_utils.init_db()
        enc_path = os.path.join(CLOUD_DIR, f"{args.backup_id}.zip.enc")
        expected = db_utils.get_checksum(args.backup_id)
        if not expected:
            print(f"No checksum on record for {args.backup_id!r}. Cannot verify.")
            sys.exit(1)
        try:
            verify_integrity(enc_path, expected)
            print(f"Integrity OK: {args.backup_id}")
        except (ValueError, FileNotFoundError) as exc:
            print(f"Integrity FAILED: {exc}")
            sys.exit(1)
    elif args.command == "cleanup":
        from scripts.cleanup_script import main as _main
        sys.argv = ["cleanup_script", "--user", args.user, "--folder", args.folder]
        _main()


if __name__ == "__main__":
    main()
