import importlib
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.append(REPO_ROOT)

from utils import db_utils
from utils.integrity import calculate_checksum


class SecureBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="backup-tests-")
        self.db_path = os.path.join(self.temp_dir, "backups.db")
        self.cloud_dir = os.path.join(self.temp_dir, "cloud_storage")
        self.restore_dir = os.path.join(self.temp_dir, "restore_output")
        self.source_dir = os.path.join(self.temp_dir, "source")
        os.makedirs(self.cloud_dir, exist_ok=True)
        os.makedirs(self.restore_dir, exist_ok=True)
        os.makedirs(self.source_dir, exist_ok=True)

        self.original_db_path = db_utils.DB_PATH
        db_utils.DB_PATH = self.db_path

        db_utils.init_db()
        db_utils.init_audit_log()
        db_utils.init_users()

        conn = sqlite3.connect(db_utils.DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
            ("U001", "Test Admin", "Admin", "IT", "Office", "Corporate"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
            ("U002", "Test Owner", "Owner", "Finance", "Office", "Corporate"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
            ("U003", "Test Restorer", "Restorer", "HR", "Remote", "Corporate"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
            ("U004", "Personal Restorer", "Restorer", "HR", "Remote", "Personal"),
        )
        conn.commit()
        conn.close()

        self.backup_script = importlib.import_module("scripts.backup_script")
        self.restore_script = importlib.import_module("scripts.restore_script")
        importlib.reload(self.backup_script)
        importlib.reload(self.restore_script)

        self.backup_script.CLOUD_DIR = self.cloud_dir
        self.restore_script.CLOUD_DIR = self.cloud_dir
        self.restore_script.RESTORE_DIR = self.restore_dir

    def tearDown(self):
        db_utils.DB_PATH = self.original_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_backup_and_restore_flow(self):
        input_file = os.path.join(self.source_dir, "notes.txt")
        original_content = "hello secure backup"
        with open(input_file, "w", encoding="utf-8") as handle:
            handle.write(original_content)

        backup_id = self.backup_script.backup_folder("U001", self.source_dir)
        encrypted_path = os.path.join(self.cloud_dir, f"{backup_id}.zip.enc")

        self.assertTrue(os.path.exists(encrypted_path))

        conn = sqlite3.connect(db_utils.DB_PATH)
        row = conn.execute(
            "SELECT backup_id, restore_count, checksum FROM backups WHERE backup_id = ?", (backup_id,)
        ).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], backup_id)
        self.assertEqual(row[1], 0)
        self.assertEqual(row[2], calculate_checksum(encrypted_path))

        restored = self.restore_script.restore_backup(backup_id, user_id="U001")
        self.assertTrue(restored)

        restored_file = os.path.join(self.restore_dir, "notes.txt")
        self.assertTrue(os.path.exists(restored_file))
        with open(restored_file, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original_content)

        conn = sqlite3.connect(db_utils.DB_PATH)
        restore_count = conn.execute(
            "SELECT restore_count FROM backups WHERE backup_id = ?", (backup_id,)
        ).fetchone()[0]
        conn.close()
        self.assertEqual(restore_count, 1)

    def test_rbac_access_rules(self):
        self.assertTrue(db_utils.check_access("U001", "backup", department="IT"))
        self.assertTrue(db_utils.check_access("U002", "backup", department="Finance"))
        self.assertFalse(db_utils.check_access("U002", "backup", department="HR"))
        self.assertTrue(db_utils.check_access("U003", "restore", department="HR"))
        self.assertFalse(db_utils.check_access("U004", "restore", department="HR"))

    def test_checksum_changes_on_file_change(self):
        path = os.path.join(self.source_dir, "hash.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("version-one")

        checksum_one = calculate_checksum(path)

        with open(path, "w", encoding="utf-8") as handle:
            handle.write("version-two")

        checksum_two = calculate_checksum(path)
        self.assertNotEqual(checksum_one, checksum_two)


if __name__ == "__main__":
    unittest.main()
