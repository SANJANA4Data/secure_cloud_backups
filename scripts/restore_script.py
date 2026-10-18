import sys
import os
import zipfile

# Ensure Python can find the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils import db_utils
from utils.crypto import decrypt_file
from utils.integrity import calculate_checksum   # <-- NEW import

# Initialize both tables at startup
db_utils.init_db()
db_utils.init_audit_log()

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")
RESTORE_DIR = os.path.join(BASE_DIR, "data", "restore_output")

def restore_backup(backup_id, user_id="U101"):
    os.makedirs(RESTORE_DIR, exist_ok=True)

    # Path to encrypted backup
    enc_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip.enc")
    if not os.path.exists(enc_path):
        print(f"Encrypted backup {backup_id} not found.")
        return

    # 🔑 Integrity check before restore
    stored_checksum = db_utils.get_checksum(backup_id)   # implement in db_utils
    current_checksum = calculate_checksum(enc_path)

    if stored_checksum != current_checksum:
        print("Integrity check failed! Backup may be corrupted or tampered.")
        return

    # Temporary decrypted ZIP
    temp_zip = os.path.join(RESTORE_DIR, "temp_restore.zip")

    # Decrypt the backup
    decrypt_file(enc_path, temp_zip)

    # Extract files
    with zipfile.ZipFile(temp_zip, "r") as zipf:
        zipf.extractall(RESTORE_DIR)

    os.remove(temp_zip)

    # Update DB
    db_utils.increment_restore_count(backup_id)
    db_utils.log_action("BACKUP_RESTORED", backup_id, user_id)

    print(f"Backup {backup_id} restored to {RESTORE_DIR}")

if __name__ == "__main__":
    latest_id = db_utils.get_latest_backup_id()
    restore_backup(latest_id)
print("Restored files:", os.listdir(RESTORE_DIR))

