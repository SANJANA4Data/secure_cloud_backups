import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from services.backup_service import restore_backup
from utils import config, db_utils

if __name__ == "__main__":
    # Replace with the actual backup_id you saw in backups.db
    config.ensure_data_dirs()
    backup_id = "B20260214033329"
    owner_id = db_utils.get_backup_owner(backup_id)
    allowed, reason = db_utils.check_access("U101", "RESTORE", backup_owner_id=owner_id)
    if not allowed:
        db_utils.log_action("RESTORE_DENIED", backup_id, "U101", result=reason)
        print(reason)
    else:
        result = restore_backup(backup_id, user_id="U101")
        print(result.get("message") or f"Backup {backup_id} restored to {result['restore_dir']}")
