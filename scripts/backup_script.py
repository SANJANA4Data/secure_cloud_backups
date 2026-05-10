import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from services.backup_service import backup_folder
from utils import config

if __name__ == "__main__":
    config.ensure_data_dirs()
    result = backup_folder("U101", folder_key="test_data")
    print(
        f"Encrypted backup created: {result['backup_id']}, size={result['size']} bytes, checksum={result['checksum']}"
    )
