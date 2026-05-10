from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory

from utils import config


class TempConfig:
    def __init__(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self._originals = {}

    def __enter__(self):
        self._originals = {
            "DATA_DIR": config.DATA_DIR,
            "DB_PATH": config.DB_PATH,
            "SECRET_KEY_PATH": config.SECRET_KEY_PATH,
            "CLOUD_DIR": config.CLOUD_DIR,
            "RESTORE_DIR": config.RESTORE_DIR,
            "CSV_USERS_PATH": config.CSV_USERS_PATH,
            "CSV_BACKUPS_PATH": config.CSV_BACKUPS_PATH,
            "CSV_ACCESS_LOG_PATH": config.CSV_ACCESS_LOG_PATH,
        }

        data_dir = Path(self.temp_dir.name)
        config.DATA_DIR = data_dir
        config.DB_PATH = data_dir / "backups.db"
        config.SECRET_KEY_PATH = data_dir / "secret.key"
        config.CLOUD_DIR = data_dir / "cloud_storage"
        config.RESTORE_DIR = data_dir / "restore_output"
        config.CSV_USERS_PATH = data_dir / "users.csv"
        config.CSV_BACKUPS_PATH = data_dir / "backups.csv"
        config.CSV_ACCESS_LOG_PATH = data_dir / "access_log.csv"
        return data_dir

    def __exit__(self, exc_type, exc, tb):
        for key, value in self._originals.items():
            setattr(config, key, value)
        self.temp_dir.cleanup()
        os.environ.pop("SCB_ENCRYPTION_KEY", None)
