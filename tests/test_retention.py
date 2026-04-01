"""Tests for utils/retention.py and its integration with backup_script.py."""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
import utils.db_utils as db_utils
from utils import config as cfg
from utils.retention import apply_retention
from scripts.backup_script import backup_folder

_TEST_KEY = "e" * 64


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    source = tmp_path / "source"
    cloud  = tmp_path / "cloud"
    source.mkdir(); cloud.mkdir()

    (source / "file.txt").write_text("content")

    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr(db_utils, "DB_PATH", db_file)
    monkeypatch.setattr("scripts.backup_script.CLOUD_DIR", str(cloud))
    monkeypatch.setattr("utils.retention.CLOUD_DIR",       str(cloud))
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", _TEST_KEY)

    db_utils.init_db()
    db_utils.init_audit_log()
    return {"source": source, "cloud": cloud}


class TestApplyRetention:
    def test_no_pruning_within_limit(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        # Create MAX_VERSIONS backups – nothing should be pruned
        for _ in range(cfg.MAX_VERSIONS):
            backup_folder("U101", str(workspace["source"]))
        assert len(db_utils.list_backups()) == cfg.MAX_VERSIONS

    def test_oldest_version_pruned_when_limit_exceeded(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        backup_ids = []
        for _ in range(cfg.MAX_VERSIONS + 1):
            bid = backup_folder("U101", str(workspace["source"]))
            backup_ids.append(bid)

        remaining = [row[0] for row in db_utils.list_backups()]
        # Oldest backup should have been removed
        assert backup_ids[0] not in remaining
        # Newest MAX_VERSIONS backups should remain
        for bid in backup_ids[1:]:
            assert bid in remaining

    def test_pruned_archive_file_removed(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        backup_ids = []
        for _ in range(cfg.MAX_VERSIONS + 1):
            bid = backup_folder("U101", str(workspace["source"]))
            backup_ids.append(bid)

        oldest_enc = workspace["cloud"] / f"{backup_ids[0]}.zip.enc"
        assert not oldest_enc.exists(), "Archive of pruned backup must be deleted"

    def test_apply_retention_returns_deleted_ids(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        backup_ids = []
        for _ in range(cfg.MAX_VERSIONS + 1):
            bid = backup_folder("U101", str(workspace["source"]))
            backup_ids.append(bid)

        # apply_retention should have already run; call directly with different folder
        # to test the return value of the utility itself
        folder = os.path.abspath(str(workspace["source"]))
        deleted = apply_retention("U101", folder)
        # All excess versions already pruned; second call should return []
        assert deleted == []

    def test_retention_audit_log_entries(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        for _ in range(cfg.MAX_VERSIONS + 1):
            backup_folder("U101", str(workspace["source"]))

        actions = [row[1] for row in db_utils.list_audit_log()]
        assert "BACKUP_DELETED_RETENTION" in actions

    def test_independent_users_do_not_interfere(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        # Both users back up the same folder; their version counts are independent
        for _ in range(cfg.MAX_VERSIONS + 1):
            backup_folder("U101", str(workspace["source"]))
        for _ in range(cfg.MAX_VERSIONS):
            backup_folder("U102", str(workspace["source"]))

        u102_rows = [r for r in db_utils.list_backups() if r[1] == "U102"]
        assert len(u102_rows) == cfg.MAX_VERSIONS, "U102 backups should not be pruned"
