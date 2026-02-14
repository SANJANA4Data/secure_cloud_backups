import sys
import os
import zipfile

# Ensure Python can find the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils import db_utils

# Initialize both tables at startup
db_utils.init_db()
db_utils.init_audit_log()

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")
RESTORE_DIR = os.path.join(BASE_DIR, "data", "restore_output")

def restore_backup(backup_id, user_id="U101"):
    # Ensure restore folder exists
    os.makedirs(RESTORE_DIR, exist_ok=True)

    # Path to the backup ZIP
    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")
    if not os.path.exists(zip_path):
        print(f"Backup {backup_id} not found.")
        return

    # Extract the ZIP into restore_output
    with zipfile.ZipFile(zip_path, "r") as zipf:
        zipf.extractall(RESTORE_DIR)

    # Increment restore count in database
    db_utils.increment_restore_count(backup_id)

    # Log the restore action in audit_log
    db_utils.log_action("BACKUP_RESTORED", backup_id, user_id)

    print(f"Backup {backup_id} restored to {RESTORE_DIR}")

if __name__ == "__main__":
    # Replace with the actual backup_id you saw in backups.db
    restore_backup("B20260214033329")
