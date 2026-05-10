import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "backups.db"
CSV_USERS_PATH = DATA_DIR / "users.csv"
CSV_BACKUPS_PATH = DATA_DIR / "backups.csv"
CSV_ACCESS_LOG_PATH = DATA_DIR / "access_log.csv"
CLOUD_DIR = DATA_DIR / "cloud_storage"
RESTORE_DIR = DATA_DIR / "restore_output"
SECRET_KEY_PATH = DATA_DIR / "secret.key"


def ensure_data_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CLOUD_DIR.mkdir(parents=True, exist_ok=True)
    RESTORE_DIR.mkdir(parents=True, exist_ok=True)

