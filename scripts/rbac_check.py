import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from utils import db_utils

ACTION_MAP = {
    "RESTORE": "RESTORE",
    "DELETE": "DELETE",
    "DOWNLOAD": "VIEW_BACKUP",
    "LIST": "LIST_BACKUPS",
}

db_utils.seed_from_csv()
logs = db_utils.list_access_log()

for i, log_entry in enumerate(logs, start=1):
    user_id = log_entry["user_id"]
    backup_id = log_entry["backup_id"]
    action = log_entry["action"].upper()
    mapped_action = ACTION_MAP.get(action, action)

    backup_owner_id = db_utils.get_backup_owner(backup_id)
    allowed, reason = db_utils.check_access(user_id, mapped_action, backup_owner_id=backup_owner_id)

    user_role = db_utils.get_user_role(user_id)
    print(
        f"Log {i}: User {user_id} ({user_role}) tried {action} on {backup_id} → {allowed} ({reason})"
    )
