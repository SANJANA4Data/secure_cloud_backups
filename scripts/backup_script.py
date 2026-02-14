import sys
import os

# Make sure Python can find the project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils import db_utils
import zipfile
from datetime import datetime

CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")

def backup_folder(user_id, folder_path):
    # Ensure database and cloud storage exist
    db_utils.init_db()
    os.makedirs(CLOUD_DIR, exist_ok=True)

    # Create backup filename
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

    # Get size of the ZIP
    size = os.path.getsize(zip_path)

    # Insert metadata into backups.db
    db_utils.insert_backup(backup_id, user_id, version=1, size=size)

    print(f"Backup created: {backup_id}, size={size} bytes")

if __name__ == "__main__":
    # Example usage: back up a test folder
    test_folder = os.path.join(BASE_DIR, "data", "test_data")
    backup_folder("U101", test_folder)
