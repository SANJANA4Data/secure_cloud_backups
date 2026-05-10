import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from services.backup_service import backup_folder
from utils import config

if __name__ == "__main__":
    test_folder = os.path.join(BASE_DIR, "data", "test_data")
    config.ensure_data_dirs()
    result = backup_folder("U101", test_folder)
    print(
        f"Encrypted backup created: {result['backup_id']}, size={result['size']} bytes, checksum={result['checksum']}"
    )
