"""Role-Based Access Control helpers.

Provides:
- check_rbac()   – pure rule logic, no I/O
- get_user_role() – looks up a user's role from users.csv
- enforce_rbac()  – combines the above and raises PermissionError on denial
"""
import csv
import os
import logging

from utils.config import DATA_DIR
from utils import db_utils

logger = logging.getLogger(__name__)


def get_user_role(user_id):
    """Return the ROLE string for *user_id* from users.csv, or None if not found."""
    users_csv = os.path.join(DATA_DIR, "users.csv")
    with open(users_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row = {k.strip().upper(): v.strip() for k, v in row.items()}
            if row.get("USER_ID") == user_id:
                return row["ROLE"].upper()
    return None


def check_rbac(user_role, action, backup_owner_id, user_id):
    """Pure RBAC logic – no I/O.

    Rules:
    - Viewer  : cannot BACKUP, RESTORE, or DELETE
    - Owner   : can only manage own backups (backup_owner_id must equal user_id;
                if backup_owner_id is None – e.g. when creating a new backup – allowed)
    - Restorer: can restore but not delete
    - Admin   : full access
    """
    role = user_role.strip().upper()
    act = action.strip().upper()

    if role == "VIEWER":
        if act in ("BACKUP", "RESTORE", "DELETE"):
            return False, f"Denied: Viewer cannot {act.lower()}"
    elif role == "OWNER":
        if backup_owner_id is not None and user_id != backup_owner_id:
            return False, "Denied: Owner can only manage own backups"
    elif role == "RESTORER":
        if act == "DELETE":
            return False, "Denied: Restorer cannot delete backups"
    # Admin (and any unrecognised role) has full access
    return True, "Allowed"


def enforce_rbac(user_id, action, backup_id=None):
    """Resolve role + backup owner, call check_rbac(), and raise PermissionError on denial."""
    role = get_user_role(user_id)
    if role is None:
        raise PermissionError(f"Unknown user: {user_id}")

    backup_owner_id = None
    if backup_id is not None:
        backup_owner_id = db_utils.get_backup_owner(backup_id)

    allowed, reason = check_rbac(role, action, backup_owner_id, user_id)
    if not allowed:
        raise PermissionError(reason)
    logger.info("RBAC ALLOW: user=%s action=%s backup=%s", user_id, action, backup_id)
