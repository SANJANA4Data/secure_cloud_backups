"""Tests for scripts/download_script.py."""
import sys
import os
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
import utils.db_utils as db_utils
from scripts.backup_script import backup_folder
from scripts.download_script import download_backup

_TEST_KEY = "c" * 64


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    source = tmp_path / "source"
    cloud  = tmp_path / "cloud"
    source.mkdir(); cloud.mkdir()

    (source / "report.txt").write_text("Quarterly report data.")
    (source / "images").mkdir()
    (source / "images" / "logo.png").write_bytes(b"\x89PNG\r\n" + b"\x00" * 20)

    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr(db_utils, "DB_PATH", db_file)
    monkeypatch.setattr("scripts.backup_script.CLOUD_DIR",    str(cloud))
    monkeypatch.setattr("scripts.download_script.CLOUD_DIR",  str(cloud))
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", _TEST_KEY)

    db_utils.init_db()
    db_utils.init_audit_log()
    return {"source": source, "cloud": cloud, "tmp": tmp_path}


def test_download_decrypts_to_valid_zip(workspace, monkeypatch):
    monkeypatch.setattr("scripts.backup_script.enforce_rbac",   lambda *a, **kw: None)
    monkeypatch.setattr("scripts.download_script.enforce_rbac", lambda *a, **kw: None)

    backup_id = backup_folder("U101", str(workspace["source"]))
    dest = str(workspace["tmp"] / "output.zip")
    download_backup(backup_id, "U102", dest)

    assert os.path.exists(dest), "Downloaded file must exist"
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
    assert "report.txt" in names
    assert os.path.join("images", "logo.png") in names

    actions = [row[1] for row in db_utils.list_audit_log()]
    assert "BACKUP_DOWNLOADED" in actions


def test_download_viewer_allowed(workspace, monkeypatch):
    """Viewer role can download (DOWNLOAD is not blocked for Viewer in check_rbac)."""
    monkeypatch.setattr("scripts.backup_script.enforce_rbac",   lambda *a, **kw: None)
    monkeypatch.setattr("scripts.download_script.enforce_rbac", lambda *a, **kw: None)

    backup_id = backup_folder("U101", str(workspace["source"]))
    dest = str(workspace["tmp"] / "viewer_download.zip")
    # Should not raise
    download_backup(backup_id, "U104", dest)
    assert os.path.exists(dest)


def test_download_missing_backup_raises(workspace, monkeypatch):
    monkeypatch.setattr("scripts.download_script.enforce_rbac", lambda *a, **kw: None)
    # Seed a DB record but no file on disk
    db_utils.insert_backup("BDOWN99", "U101", 1, 0, folder_path="/tmp/x", checksum="")
    with pytest.raises(FileNotFoundError):
        download_backup("BDOWN99", "U101", str(workspace["tmp"] / "out.zip"))


def test_download_rbac_denial(workspace, monkeypatch):
    monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
    backup_id = backup_folder("U101", str(workspace["source"]))
    # Monkeypatch download enforce_rbac to raise PermissionError
    monkeypatch.setattr(
        "scripts.download_script.enforce_rbac",
        lambda *a, **kw: (_ for _ in ()).throw(PermissionError("Denied")),
    )
    with pytest.raises(PermissionError):
        download_backup(backup_id, "U104", str(workspace["tmp"] / "out.zip"))
