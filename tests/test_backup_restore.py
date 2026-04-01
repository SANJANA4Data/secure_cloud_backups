"""Integration tests for backup_script.py and restore_script.py."""
import sys
import os
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
import utils.db_utils as db_utils
from scripts.backup_script import backup_folder
from scripts.restore_script import restore_backup


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """Set up an isolated workspace with temporary directories and database."""
    source  = tmp_path / "source"
    cloud   = tmp_path / "cloud"
    restore = tmp_path / "restore"
    source.mkdir(); cloud.mkdir(); restore.mkdir()

    (source / "file1.txt").write_text("Hello backup!")
    (source / "sub").mkdir()
    (source / "sub" / "file2.txt").write_text("Nested file.")

    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr(db_utils, "DB_PATH", db_file)
    monkeypatch.setattr("scripts.backup_script.CLOUD_DIR",    str(cloud))
    monkeypatch.setattr("scripts.restore_script.CLOUD_DIR",   str(cloud))
    monkeypatch.setattr("scripts.restore_script.RESTORE_DIR", str(restore))

    db_utils.init_db()
    db_utils.init_audit_log()

    return {"source": source, "cloud": cloud, "restore": restore}


def test_backup_creates_zip_and_db_record(workspace, monkeypatch):
    monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
    backup_id = backup_folder("U101", str(workspace["source"]))

    zip_path = workspace["cloud"] / f"{backup_id}.zip"
    assert zip_path.exists(), "ZIP archive was not created"

    with zipfile.ZipFile(str(zip_path)) as zf:
        names = zf.namelist()
    assert "file1.txt" in names
    assert os.path.join("sub", "file2.txt") in names

    rows = db_utils.list_backups()
    assert len(rows) == 1
    assert rows[0][0] == backup_id
    assert rows[0][1] == "U101"

    actions = [row[1] for row in db_utils.list_audit_log()]
    assert "BACKUP_CREATED" in actions


def test_backup_version_increments(workspace, monkeypatch):
    monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
    backup_folder("U101", str(workspace["source"]))
    backup_folder("U101", str(workspace["source"]))

    rows = sorted(db_utils.list_backups(), key=lambda r: r[4])
    assert rows[0][4] == 1
    assert rows[1][4] == 2


def test_restore_extracts_files(workspace, monkeypatch):
    monkeypatch.setattr("scripts.backup_script.enforce_rbac",  lambda *a, **kw: None)
    monkeypatch.setattr("scripts.restore_script.enforce_rbac", lambda *a, **kw: None)

    backup_id = backup_folder("U101", str(workspace["source"]))
    restore_backup(backup_id, "U103")

    restored = workspace["restore"]
    assert (restored / "file1.txt").exists()
    assert (restored / "sub" / "file2.txt").exists()
    assert (restored / "file1.txt").read_text() == "Hello backup!"

    rows = db_utils.list_backups()
    assert rows[0][6] == 1  # restore_count == 1

    actions = [row[1] for row in db_utils.list_audit_log()]
    assert "BACKUP_RESTORED" in actions


def test_restore_rejects_path_traversal(workspace, monkeypatch):
    """A malicious ZIP entry that escapes RESTORE_DIR must raise ValueError."""
    monkeypatch.setattr("scripts.restore_script.enforce_rbac", lambda *a, **kw: None)

    evil_zip = workspace["cloud"] / "BEVIL.zip"
    with zipfile.ZipFile(str(evil_zip), "w") as zf:
        zf.writestr("../../evil.txt", "pwned")

    with pytest.raises(ValueError, match="Unsafe zip entry"):
        restore_backup("BEVIL", "U103")


def test_backup_invalid_folder_raises(monkeypatch):
    monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
    with pytest.raises(ValueError, match="Folder not found"):
        backup_folder("U101", "/nonexistent/path/that/does/not/exist")
