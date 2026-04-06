import sys
import os
import zipfile

# Ensure Python can find the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils import db_utils
from utils.crypto import decrypt_file   # <-- NEW import

# Initialize both tables at startup
db_utils.init_db()
db_utils.init_audit_log()

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")
RESTORE_DIR = os.path.join(BASE_DIR, "data", "restore_output")

def restore_backup(backup_id, user_id="U101"):
    # Ensure restore folder exists
    os.makedirs(RESTORE_DIR, exist_ok=True)

    # Path to the encrypted backup
    enc_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip.enc")
    if not os.path.exists(enc_path):
        print(f"Encrypted backup {backup_id} not found.")
        return

    # Temporary decrypted ZIP
    temp_zip = os.path.join(RESTORE_DIR, "temp_restore.zip")

    # Decrypt the backup first
    decrypt_file(enc_path, temp_zip)

    # Extract the decrypted ZIP into restore_output
    with zipfile.ZipFile(temp_zip, "r") as zipf:
        zipf.extractall(RESTORE_DIR)

    # Clean up temp file
    os.remove(temp_zip)

    # Increment restore count in database
    db_utils.increment_restore_count(backup_id)

    # Log the restore action in audit_log
    db_utils.log_action("BACKUP_RESTORED", backup_id, user_id)

    print(f"Backup {backup_id} restored to {RESTORE_DIR}")

if __name__ == "__main__":
    # Replace with the actual backup_id you saw in backups.db
    restore_backup("B20260214033329")
