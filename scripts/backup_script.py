import sys, os
import zipfile
from datetime import datetime

# Ensure Python can find the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils.crypto import encrypt_file
from utils.integrity import calculate_checksum
from utils import db_utils

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")

def backup_folder(user_id, folder_path):
    # Initialize DB tables
    db_utils.init_db()
    db_utils.init_audit_log()
    os.makedirs(CLOUD_DIR, exist_ok=True)

    # Generate unique backup ID
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_id = f"B{timestamp}"
    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")

    # 📦 Zip the entire folder (including subfolders and all files)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

    # 🔒 Encrypt the ZIP
    enc_path = zip_path + ".enc"
    encrypt_file(zip_path, enc_path)
    os.remove(zip_path)

    # 🔑 Integrity check
    checksum = calculate_checksum(enc_path)

    # File size
    size = os.path.getsize(enc_path)

    # Insert metadata into DB
    db_utils.insert_backup(backup_id, user_id, version=1, size=size, checksum=checksum)

    print(f"Encrypted backup created: {backup_id}, size={size} bytes, checksum={checksum}")

if __name__ == "__main__":
    test_folder = os.path.join(BASE_DIR, "data", "test_data")
    backup_folder("U101", test_folder)
