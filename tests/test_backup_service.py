import os
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

from services.backup_service import backup_folder, restore_backup
from tests.test_helpers import TempConfig


class BackupServiceTests(unittest.TestCase):
    def test_backup_and_restore_roundtrip(self):
        with TempConfig() as data_dir:
            os.environ["SCB_ENCRYPTION_KEY"] = Fernet.generate_key().decode("utf-8")
            sample_dir = Path(data_dir) / "sample_data"
            sample_dir.mkdir(parents=True, exist_ok=True)
            (sample_dir / "file.txt").write_text("backup content", encoding="utf-8")

            result = backup_folder("U001", str(sample_dir))
            self.assertIn("backup_id", result)

            restore_result = restore_backup(result["backup_id"], "U001")
            self.assertEqual(restore_result["status"], "restored")


if __name__ == "__main__":
    unittest.main()
