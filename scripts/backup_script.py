import os
import sys
import zipfile
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from utils.crypto import encrypt_file
from utils.integrity import calculate_checksum
from utils import db_utils

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")


def backup_folder(user_id, folder_path):
    db_utils.init_db()
    db_utils.init_audit_log()
    os.makedirs(CLOUD_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_id = f"B{timestamp}"
    zip_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip")

    with zipfile.ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

    enc_path = zip_path + ".enc"
    encrypt_file(zip_path, enc_path)
    os.remove(zip_path)

    checksum = calculate_checksum(enc_path)
    size = os.path.getsize(enc_path)

    db_utils.insert_backup(backup_id, user_id, version=1, size=size, checksum=checksum)

    print(f"Encrypted backup created: {backup_id}, size={size} bytes, checksum={checksum}")
    return backup_id


if __name__ == "__main__":
    test_folder = os.path.join(BASE_DIR, "data", "test_data")
    backup_folder("U101", test_folder)
