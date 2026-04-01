"""Tests for utils/integrity.py and integration with backup/restore."""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
import utils.db_utils as db_utils
from utils.integrity import sha256_file, verify_integrity
from utils.crypto import encrypt_file
from scripts.backup_script import backup_folder
from scripts.restore_script import restore_backup

_TEST_KEY = "d" * 64


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    source  = tmp_path / "source"
    cloud   = tmp_path / "cloud"
    restore = tmp_path / "restore"
    source.mkdir(); cloud.mkdir(); restore.mkdir()

    (source / "data.txt").write_text("Important data.")

    db_file = str(tmp_path / "test.db")
    monkeypatch.setattr(db_utils, "DB_PATH", db_file)
    monkeypatch.setattr("scripts.backup_script.CLOUD_DIR",    str(cloud))
    monkeypatch.setattr("scripts.restore_script.CLOUD_DIR",   str(cloud))
    monkeypatch.setattr("scripts.restore_script.RESTORE_DIR", str(restore))
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", _TEST_KEY)

    db_utils.init_db()
    db_utils.init_audit_log()
    return {"source": source, "cloud": cloud, "restore": restore}


class TestSha256File:
    def test_returns_64_char_hex(self, tmp_path):
        f = tmp_path / "sample.bin"
        f.write_bytes(b"hello world")
        digest = sha256_file(str(f))
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_different_contents_different_digest(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("aaa")
        b.write_text("bbb")
        assert sha256_file(str(a)) != sha256_file(str(b))

    def test_same_content_same_digest(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_bytes(b"identical")
        b.write_bytes(b"identical")
        assert sha256_file(str(a)) == sha256_file(str(b))


class TestVerifyIntegrity:
    def test_matching_checksum_passes(self, tmp_path):
        f = tmp_path / "file.bin"
        f.write_bytes(b"good content")
        digest = sha256_file(str(f))
        verify_integrity(str(f), digest)  # must not raise

    def test_mismatched_checksum_raises(self, tmp_path):
        f = tmp_path / "file.bin"
        f.write_bytes(b"original content")
        with pytest.raises(ValueError, match="Integrity check failed"):
            verify_integrity(str(f), "0" * 64)

    def test_tampered_file_raises(self, tmp_path, monkeypatch):
        f = tmp_path / "file.bin"
        f.write_bytes(b"original")
        digest = sha256_file(str(f))
        f.write_bytes(b"tampered")  # modify after recording hash
        with pytest.raises(ValueError, match="Integrity check failed"):
            verify_integrity(str(f), digest)


class TestIntegrityInPipeline:
    def test_checksum_stored_at_backup(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac", lambda *a, **kw: None)
        backup_id = backup_folder("U101", str(workspace["source"]))
        stored = db_utils.get_checksum(backup_id)
        enc_path = str(workspace["cloud"] / f"{backup_id}.zip.enc")
        assert stored == sha256_file(enc_path)

    def test_restore_passes_on_intact_archive(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac",  lambda *a, **kw: None)
        monkeypatch.setattr("scripts.restore_script.enforce_rbac", lambda *a, **kw: None)
        backup_id = backup_folder("U101", str(workspace["source"]))
        restore_backup(backup_id, "U103")  # must not raise
        assert (workspace["restore"] / "data.txt").exists()

    def test_restore_fails_on_tampered_archive(self, workspace, monkeypatch):
        monkeypatch.setattr("scripts.backup_script.enforce_rbac",  lambda *a, **kw: None)
        monkeypatch.setattr("scripts.restore_script.enforce_rbac", lambda *a, **kw: None)
        backup_id = backup_folder("U101", str(workspace["source"]))
        enc_path = workspace["cloud"] / f"{backup_id}.zip.enc"
        # Corrupt the archive
        enc_path.write_bytes(b"\xff" * 64)
        with pytest.raises(ValueError, match="Integrity check failed"):
            restore_backup(backup_id, "U103")
