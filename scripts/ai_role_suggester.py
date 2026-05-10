import csv
import os
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def suggest_roles(users_csv=None, access_log_csv=None, output_csv=None):
    users_csv = users_csv or os.path.join(DATA_DIR, "users.csv")
    access_log_csv = access_log_csv or os.path.join(DATA_DIR, "access_log.csv")
    output_csv = output_csv or os.path.join(DATA_DIR, "role_suggestions.csv")

    users = {}
    with open(users_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            users[row["User_ID"]] = row

    stats = defaultdict(lambda: {
        "allowed": 0,
        "denied": 0,
        "restore_allowed": 0,
        "delete_denied": 0,
        "list_allowed": 0,
    })

    with open(access_log_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            uid = row["User_ID"]
            action = row["Action"].strip().lower()
            status = row["Status"].strip().lower()
            if status == "allowed":
                stats[uid]["allowed"] += 1
            else:
                stats[uid]["denied"] += 1
            if action == "restore" and status == "allowed":
                stats[uid]["restore_allowed"] += 1
            if action == "delete" and status == "denied":
                stats[uid]["delete_denied"] += 1
            if action == "list" and status == "allowed":
                stats[uid]["list_allowed"] += 1

    suggestions = []
    for user_id, user in users.items():
        role = user["Role"]
        user_stats = stats[user_id]
        total = user_stats["allowed"] + user_stats["denied"]
        denied_rate = (user_stats["denied"] / total) if total else 0

        suggested_role = role
        reason = "Role is consistent with observed behavior"

        if denied_rate >= 0.6 and user_stats["denied"] >= 8:
            suggested_role = "Viewer"
            reason = "High denied-rate indicates overly privileged role"
        elif role == "Viewer" and user_stats["restore_allowed"] >= 3:
            suggested_role = "Restorer"
            reason = "Viewer repeatedly performing allowed restore-like workflow"
        elif role == "Restorer" and user_stats["restore_allowed"] >= 8 and user_stats["delete_denied"] == 0:
            suggested_role = "Owner"
            reason = "Strong restore usage with compliant access behavior"
        elif role == "Owner" and user_stats["list_allowed"] >= 10 and user_stats["restore_allowed"] == 0:
            suggested_role = "Viewer"
            reason = "Read-heavy access pattern fits Viewer responsibilities"

        suggestions.append({
            "User_ID": user_id,
            "Current_Role": role,
            "Suggested_Role": suggested_role,
            "Denied_Rate": round(denied_rate, 3),
            "Reason": reason,
        })

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["User_ID", "Current_Role", "Suggested_Role", "Denied_Rate", "Reason"],
        )
        writer.writeheader()
        writer.writerows(suggestions)

    return suggestions, output_csv


if __name__ == "__main__":
    suggestions, out = suggest_roles()
    changed = [s for s in suggestions if s["Current_Role"] != s["Suggested_Role"]]
    print(f"Generated {len(suggestions)} suggestions in {out}")
    print(f"Users with role changes recommended: {len(changed)}")
    for row in changed[:5]:
        print(row)
