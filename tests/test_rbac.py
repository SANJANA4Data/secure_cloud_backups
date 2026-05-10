import sqlite3
import unittest

from tests.test_helpers import TempConfig
from utils import config, db_utils


class RbacTests(unittest.TestCase):
    def test_owner_restricted_to_own_backup(self):
        with TempConfig():
            db_utils.init_all()
            with sqlite3.connect(config.DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
                    ("U100", "Owner User", "Owner", "IT", "Office", "Corporate"),
                )
            allowed, reason = db_utils.check_access("U100", "RESTORE", backup_owner_id="U200")
            self.assertFalse(allowed)
            self.assertIn("Owner can only manage own backups", reason)

    def test_restorer_requires_corporate_device(self):
        with TempConfig():
            db_utils.init_all()
            with sqlite3.connect(config.DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO users (user_id, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?)",
                    ("U200", "Restorer User", "Restorer", "IT", "Office", "Personal"),
                )
            allowed, reason = db_utils.check_access("U200", "RESTORE", backup_owner_id="U200")
            self.assertFalse(allowed)
            self.assertIn("corporate", reason.lower())


if __name__ == "__main__":
    unittest.main()
