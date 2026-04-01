import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "backups.db")
CLOUD_DIR = os.path.join(DATA_DIR, "cloud_storage")
RESTORE_DIR = os.path.join(DATA_DIR, "restore_output")

# Maximum number of backup versions to retain per (user, folder) pair.
# Older versions beyond this limit are pruned automatically after each backup.
MAX_VERSIONS = 3
