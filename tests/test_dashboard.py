import csv
import os
import sqlite3
import tempfile
import unittest

from scripts.dashboard import collect_dashboard_data, render_dashboard_html


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="dashboard-tests-")

        self._write_csv(
            "users.csv",
            ["User_ID", "Name", "Role", "Department", "Location", "Device"],
            [
                ["U001", "A", "Admin", "IT", "Office", "Corporate"],
                ["U002", "B", "Owner", "Finance", "Remote", "Personal"],
                ["U003", "C", "Viewer", "HR", "Office", "Personal"],
            ],
        )
        self._write_csv(
            "backups.csv",
            ["Backup_ID", "User_ID", "Backup_Time", "Version", "File_List", "Size", "Restore_Count"],
            [
                ["B001", "U001", "2026-01-01 10:00:00", "v1", "a.txt", "10MB", "2"],
                ["B002", "U002", "2026-01-02 11:00:00", "v1", "b.txt", "20MB", "0"],
            ],
        )
        self._write_csv(
            "access_log.csv",
            ["User_ID", "Backup_ID", "Action", "Timestamp", "IP", "Device", "Status", "Reason"],
            [
                ["U001", "B001", "Restore", "2026-01-02 10:00:00", "1.1.1.1", "Corporate", "Allowed", "Access granted"],
                ["U002", "B002", "Delete", "2026-01-02 10:05:00", "1.1.1.2", "Personal", "Denied", "RBAC rule"],
                ["U002", "B002", "List", "2026-01-02 10:06:00", "1.1.1.3", "Personal", "Denied", "RBAC rule"],
            ],
        )

        conn = sqlite3.connect(os.path.join(self.temp_dir, "backups.db"))
        conn.execute(
            "CREATE TABLE backups (backup_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, timestamp TEXT NOT NULL, version INTEGER NOT NULL, size INTEGER NOT NULL, restore_count INTEGER DEFAULT 0, checksum TEXT)"
        )
        conn.execute(
            "INSERT INTO backups (backup_id, user_id, timestamp, version, size, restore_count, checksum) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("B001", "U001", "2026-01-01T10:00:00", 1, 100, 1, "abc"),
        )
        conn.execute(
            "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, backup_id TEXT, user_id TEXT, timestamp TEXT, result TEXT, role TEXT, department TEXT)"
        )
        conn.execute(
            "INSERT INTO audit_log (action, backup_id, user_id, timestamp, result, role, department) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("BACKUP_RESTORED", "B001", "U001", "2026-01-01T10:30:00", "SUCCESS", "Admin", "IT"),
        )
        conn.commit()
        conn.close()

    def _write_csv(self, name, headers, rows):
        path = os.path.join(self.temp_dir, name)
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerows(rows)

    def test_collect_dashboard_data(self):
        data = collect_dashboard_data(data_dir=self.temp_dir)

        self.assertEqual(data["total_users"], 3)
        self.assertEqual(data["total_backups_csv"], 2)
        self.assertEqual(data["allowed_count"], 1)
        self.assertEqual(data["denied_count"], 2)
        self.assertEqual(data["avg_restore_count"], 1.0)
        self.assertEqual(data["db_backups"], 1)
        self.assertEqual(data["db_checksums"], 1)
        self.assertEqual(data["db_audit_events"], 1)
        self.assertEqual(data["top_denied_users"], [("U002", 2)])

    def test_render_dashboard_html(self):
        html_output = render_dashboard_html(collect_dashboard_data(data_dir=self.temp_dir))
        self.assertIn("Secure Cloud Backups Dashboard", html_output)
        self.assertIn("User role distribution", html_output)
        self.assertIn("Top denied users", html_output)


if __name__ == "__main__":
    unittest.main()
