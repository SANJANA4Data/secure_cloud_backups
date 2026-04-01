"""Tests for scripts/delete_backup.py."""
import sys
import os
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
import utils.db_utils as db_utils
from scripts.delete_backup import delete_backup

_TEST_KEY = "b" * 64


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    cloud = tmp_path / "cloud"
    cloud.mkdir()

    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr(db_utils, "DB_PATH", db_file)
    monkeypatch.setattr("scripts.delete_backup.CLOUD_DIR", str(cloud))
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", _TEST_KEY)

    db_utils.init_db()
    db_utils.init_audit_log()
    return {"cloud": cloud}


def _seed_backup(cloud_dir, backup_id="BDEL001"):
    """Create a fake encrypted archive and DB record."""
    enc_path = os.path.join(str(cloud_dir), f"{backup_id}.zip.enc")
    # Write random bytes as a stand-in for a real encrypted archive
    with open(enc_path, "wb") as f:
        f.write(os.urandom(128))
    db_utils.insert_backup(backup_id, "U101", 1, 128, folder_path="/tmp/x", checksum="abc")
    return enc_path


class TestDeleteBackup:
    def test_successful_delete_removes_record_and_archive(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.delete_backup.enforce_rbac", lambda *a, **kw: None)
        enc_path = _seed_backup(workspace["cloud"])

        delete_backup("BDEL001", "U101")

        assert db_utils.list_backups() == [], "DB record should be removed"
        assert not os.path.exists(enc_path), "Encrypted archive should be removed"

        actions = [row[1] for row in db_utils.list_audit_log()]
        assert "BACKUP_DELETED" in actions

    def test_delete_nonexistent_backup_raises(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.delete_backup.enforce_rbac", lambda *a, **kw: None)
        with pytest.raises(ValueError, match="not found"):
            delete_backup("NOSUCHBACKUP", "U101")

    def test_delete_without_archive_succeeds(self, workspace, monkeypatch):
        """DB record exists but no archive file – delete should still succeed."""
        monkeypatch.setattr("scripts.delete_backup.enforce_rbac", lambda *a, **kw: None)
        db_utils.insert_backup("BDEL002", "U101", 1, 0, folder_path="/tmp/y", checksum="")
        # No file on disk
        delete_backup("BDEL002", "U101")
        assert db_utils.list_backups() == []

    def test_rbac_denial_raises_permission_error(self, workspace):
        _seed_backup(workspace["cloud"])
        # U104 is a Viewer in users.csv – cannot delete
        with pytest.raises(PermissionError):
            delete_backup("BDEL001", "U104")
