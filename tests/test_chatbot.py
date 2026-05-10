import sqlite3
import unittest

from chatbot import handle_message
from tests.test_helpers import TempConfig
from utils import config, db_utils


class ChatbotTests(unittest.TestCase):
    def test_list_backups_intent(self):
        with TempConfig():
            db_utils.init_all()
            with sqlite3.connect(config.DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
                    ("U001", "Admin User", "Admin", "IT", "Office", "Corporate"),
                )
                conn.execute(
                    """
                    INSERT INTO backups_catalog
                    (backup_id, user_id, backup_time, version, file_list, size, restore_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("B001", "U001", "2026-01-01 00:00:00", "v1", "file.txt", "12MB", 0),
                )
            response = handle_message("U001", "list backups")
            self.assertEqual(response["status"], "ok")
            self.assertIn("catalog", response["data"])

    def test_audit_log_denied_for_viewer(self):
        with TempConfig():
            db_utils.init_all()
            with sqlite3.connect(config.DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
                    ("U010", "Viewer User", "Viewer", "IT", "Office", "Corporate"),
                )
            response = handle_message("U010", "show audit log")
            self.assertEqual(response["status"], "denied")


if __name__ == "__main__":
    unittest.main()
