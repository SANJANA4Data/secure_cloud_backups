from utils.crypto import encrypt_file
from utils.integrity import calculate_checksum   # <-- NEW import
import os
import sys
import zipfile
from datetime import datetime
import utils

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")

def backup_folder(user_id, folder_path):
    utils.db_utils.init_db()
    utils.db_utils.init_audit_log()
    os.makedirs(CLOUD_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_id = f"B{timestamp}"
    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")

    # Zip the folder
    with zipfile.ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

    # Encrypt the ZIP
    enc_path = zip_path + ".enc"
    encrypt_file(zip_path, enc_path)
    os.remove(zip_path)

    # 🔑 Integrity check happens here
    checksum = calculate_checksum(enc_path)

    # Get size of encrypted file
    size = os.path.getsize(enc_path)

    # Insert metadata into backups.db (make sure backups table has a checksum column)
    utils.db_utils.insert_backup(backup_id, user_id, version=1, size=size, checksum=checksum)

    print(f"Encrypted backup created: {backup_id}, size={size} bytes, checksum={checksum}")

if __name__ == "__main__":
    test_folder = os.path.join(BASE_DIR, "data", "test_data")
    backup_folder("U101", test_folder)
