import os
import sys
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from utils import db_utils
from utils.crypto import decrypt_file


db_utils.init_db()
db_utils.init_audit_log()

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")
RESTORE_DIR = os.path.join(BASE_DIR, "data", "restore_output")


def restore_backup(backup_id, user_id="U101"):
    os.makedirs(RESTORE_DIR, exist_ok=True)

    enc_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip.enc")
    if not os.path.exists(enc_path):
        print(f"Encrypted backup {backup_id} not found.")
        return False

    temp_zip = os.path.join(RESTORE_DIR, "temp_restore.zip")

    decrypt_file(enc_path, temp_zip)

    with zipfile.ZipFile(temp_zip, "r") as zipf:
        zipf.extractall(RESTORE_DIR)

    os.remove(temp_zip)

    db_utils.increment_restore_count(backup_id)
    db_utils.log_action("BACKUP_RESTORED", backup_id, user_id)

    print(f"Backup {backup_id} restored to {RESTORE_DIR}")
    return True


if __name__ == "__main__":
    restore_backup("B20260214033329")
