"""Unit tests for utils/db_utils.py using a temporary SQLite database."""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
import utils.db_utils as db_utils


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Redirect DB_PATH to a fresh temp database for each test."""
    db_file = str(tmp_path / "test_backups.db")
    monkeypatch.setattr(db_utils, "DB_PATH", db_file)
    db_utils.init_db()
    db_utils.init_audit_log()
    return db_file


class TestInsertAndList:
    def test_insert_and_list_backup(self):
        db_utils.insert_backup("B001", "U101", version=1, size=1024, folder_path="/data")
        rows = db_utils.list_backups()
        assert len(rows) == 1
        assert rows[0][0] == "B001"
        assert rows[0][1] == "U101"

    def test_list_backups_empty(self):
        assert db_utils.list_backups() == []


class TestGetNextVersion:
    def test_first_backup_is_version_1(self):
        v = db_utils.get_next_version("U101", "/data/project")
        assert v == 1

    def test_second_backup_is_version_2(self):
        db_utils.insert_backup("B001", "U101", version=1, size=512, folder_path="/data/project")
        v = db_utils.get_next_version("U101", "/data/project")
        assert v == 2

    def test_different_folder_resets_version(self):
        db_utils.insert_backup("B001", "U101", version=1, size=512, folder_path="/data/a")
        v = db_utils.get_next_version("U101", "/data/b")
        assert v == 1

    def test_different_user_resets_version(self):
        db_utils.insert_backup("B001", "U101", version=1, size=512, folder_path="/data/shared")
        v = db_utils.get_next_version("U102", "/data/shared")
        assert v == 1


class TestIncrementRestoreCount:
    def test_increment_restore_count(self):
        db_utils.insert_backup("B002", "U102", version=1, size=200, folder_path="/docs")
        db_utils.increment_restore_count("B002")
        rows = db_utils.list_backups()
        assert rows[0][6] == 1


class TestGetBackupOwner:
    def test_get_backup_owner(self):
        db_utils.insert_backup("B003", "U103", version=1, size=100, folder_path="/tmp/x")
        assert db_utils.get_backup_owner("B003") == "U103"

    def test_get_backup_owner_missing(self):
        assert db_utils.get_backup_owner("NONEXISTENT") is None


class TestDeleteBackup:
    def test_delete_backup(self):
        db_utils.insert_backup("B004", "U104", version=1, size=100, folder_path="/tmp/y")
        db_utils.delete_backup("B004")
        assert db_utils.list_backups() == []

    def test_delete_nonexistent_raises(self):
        with pytest.raises(ValueError, match="not found"):
            db_utils.delete_backup("NOSUCHBACKUP")


class TestAuditLog:
    def test_log_and_list(self):
        db_utils.log_action("BACKUP_CREATED", "B001", "U101")
        rows = db_utils.list_audit_log()
        assert len(rows) == 1
        assert rows[0][1] == "BACKUP_CREATED"
        assert rows[0][2] == "B001"
        assert rows[0][3] == "U101"

    def test_audit_log_empty(self):
        assert db_utils.list_audit_log() == []
