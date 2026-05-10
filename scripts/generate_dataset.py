import csv
import os
import random
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

FIRST_NAMES = ["Alex", "Sam", "Jordan", "Taylor", "Riley", "Casey", "Morgan", "Avery"]
LAST_NAMES = ["Sharma", "Lee", "Patel", "Singh", "Miller", "Kim", "Garcia", "Brown"]


def _random_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def generate_dataset(user_count=100, backup_count=300, log_count=800):
    os.makedirs(DATA_DIR, exist_ok=True)

    users_file = os.path.join(DATA_DIR, "users.csv")
    backups_file = os.path.join(DATA_DIR, "backups.csv")
    logs_file = os.path.join(DATA_DIR, "access_log.csv")

    roles = ["Admin", "Owner", "Restorer", "Viewer"]
    departments = ["IT", "Finance", "HR", "Marketing", "Sales"]
    devices = ["Corporate", "Personal"]
    locations = ["Office", "Remote"]

    users = []
    for i in range(user_count):
        users.append({
            "User_ID": f"U{i+1:03}",
            "Name": _random_name(),
            "Role": random.choice(roles),
            "Department": random.choice(departments),
            "Location": random.choice(locations),
            "Device": random.choice(devices),
        })

    with open(users_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(users[0].keys()))
        writer.writeheader()
        writer.writerows(users)

    backups = []
    start = datetime(2026, 1, 1)
    for i in range(backup_count):
        backups.append({
            "Backup_ID": f"B{i+1:03}",
            "User_ID": random.choice(users)["User_ID"],
            "Backup_Time": (start + timedelta(hours=i)).isoformat(),
            "Version": f"v{random.randint(1, 3)}",
            "File_List": ";".join([f"file_{random.randint(1,999)}.txt" for _ in range(random.randint(1, 3))]),
            "Size": f"{random.randint(1,500)}MB",
            "Restore_Count": random.randint(0, 5),
        })

    with open(backups_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(backups[0].keys()))
        writer.writeheader()
        writer.writerows(backups)

    actions = ["Restore", "Download", "Delete", "List"]
    logs = []
    for i in range(log_count):
        status = random.choice(["Allowed", "Denied", "Allowed"])
        logs.append({
            "User_ID": random.choice(users)["User_ID"],
            "Backup_ID": random.choice(backups)["Backup_ID"],
            "Action": random.choice(actions),
            "Timestamp": (start + timedelta(minutes=i)).isoformat(),
            "IP": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "Device": random.choice(devices),
            "Status": status,
            "Reason": "Access granted" if status == "Allowed" else "RBAC rule",
        })

    with open(logs_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(logs[0].keys()))
        writer.writeheader()
        writer.writerows(logs)

    print("Synthetic datasets generated in /data: users.csv, backups.csv, access_log.csv")


if __name__ == "__main__":
    generate_dataset()
