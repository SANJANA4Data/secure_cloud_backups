import csv
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def check_rbac(user_role, action, backup_owner_id, user_id):
    role = user_role.upper()
    act = action.upper()

    if role == "VIEWER" and act in ["RESTORE", "DELETE"]:
        return False, "Denied: Viewer cannot restore or delete"
    if role == "OWNER" and user_id != backup_owner_id:
        return False, "Denied: Owner can only manage own backups"
    if role == "RESTORER" and act == "DELETE":
        return False, "Denied: Restorer cannot delete backups"
    return True, "Allowed"


def run_rbac_check(users_csv=None, backups_csv=None, logs_csv=None):
    users_csv = users_csv or os.path.join(DATA_DIR, "users.csv")
    backups_csv = backups_csv or os.path.join(DATA_DIR, "backups.csv")
    logs_csv = logs_csv or os.path.join(DATA_DIR, "access_log.csv")

    users = {}
    backups = {}

    with open(users_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            users[row["User_ID"]] = row

    with open(backups_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            backups[row["Backup_ID"]] = row

    results = []
    with open(logs_csv, newline="", encoding="utf-8") as f:
        for idx, log in enumerate(csv.DictReader(f), start=1):
            uid = log["User_ID"]
            bid = log["Backup_ID"]
            action = log["Action"]
            user_role = users.get(uid, {}).get("Role", "Viewer")
            backup_owner = backups.get(bid, {}).get("User_ID", "")
            allowed, reason = check_rbac(user_role, action, backup_owner, uid)
            results.append((idx, uid, user_role, action, bid, allowed, reason))
    return results


if __name__ == "__main__":
    for item in run_rbac_check()[:20]:
        i, uid, role, action, bid, ok, reason = item
        print(f"Log {i}: User {uid} ({role}) tried {action} on {bid} -> {ok} ({reason})")
