import os
import pandas as pd

# Build absolute path to the data folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Load CSV files
users = pd.read_csv(os.path.join(DATA_DIR, "users.csv"))
backups = pd.read_csv(os.path.join(DATA_DIR, "backups.csv"))
logs = pd.read_csv(os.path.join(DATA_DIR, "access_log.csv"))  # match your actual filename

# Normalize headers: strip spaces and force uppercase
users.columns = users.columns.str.strip().str.upper()
backups.columns = backups.columns.str.strip().str.upper()
logs.columns = logs.columns.str.strip().str.upper()

def check_rbac(user_role, action, backup_owner_id, user_id):
    """
    RBAC rules:
    - Viewer: cannot restore or delete
    - Owner: can only manage own backups
    - Restorer: can restore but not delete
    - Admin: full access
    """
    role = user_role.upper()
    act = action.upper()

    if role == "VIEWER":
        if act in ["RESTORE", "DELETE"]:
            return False, "Denied: Viewer cannot restore or delete"
    elif role == "OWNER":
        if user_id != backup_owner_id:
            return False, "Denied: Owner can only manage own backups"
    elif role == "RESTORER":
        if act == "DELETE":
            return False, "Denied: Restorer cannot delete backups"
    # Admin has full access
    return True, "Allowed"

# Iterate through log entries and apply RBAC checks
for i, log_entry in logs.iterrows():
    user_id = log_entry["USER_ID"]
    backup_id = log_entry["BACKUP_ID"]
    action = log_entry["ACTION"]

    # Look up user role and backup owner
    user_role = users.loc[users["USER_ID"] == user_id, "ROLE"].values[0]
    backup_owner_id = backups.loc[backups["BACKUP_ID"] == backup_id, "USER_ID"].values[0]

    result, reason = check_rbac(user_role, action, backup_owner_id, user_id)
    print(f"Log {i+1}: User {user_id} ({user_role}) tried {action} on {backup_id} → {result} ({reason})")
