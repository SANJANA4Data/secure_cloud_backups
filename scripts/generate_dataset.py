import pandas as pd
import random
from faker import Faker
from pathlib import Path

fake = Faker()

# Paths
data_path = Path(__file__).parent.parent / "data"
users_file = data_path / "users.csv"
backups_file = data_path / "backups.csv"
logs_file = data_path / "access_log.csv"

# --- USERS ---
roles = ["Admin", "Owner", "Restorer", "Viewer"]
departments = ["IT", "Finance", "HR", "Marketing", "Sales"]
devices = ["Corporate", "Personal"]

users = []
for i in range(100):
    users.append([f"U{i+1:03}", fake.name(), random.choice(roles),
                  random.choice(departments), random.choice(["Office","Remote"]),
                  random.choice(devices)])

users_df = pd.DataFrame(users, columns=["User_ID","Name","Role","Department","Location","Device"])
users_df.to_csv(users_file, index=False)

# --- BACKUPS ---
backups = []
for i in range(300):
    user_id = random.choice(users_df["User_ID"])
    backups.append([f"B{i+1:03}", user_id, fake.date_time_this_year(),
                    f"v{random.randint(1,3)}",
                    ";".join([fake.file_name(extension="txt") for _ in range(random.randint(1,3))]),
                    f"{random.randint(1,500)}MB",
                    random.randint(0,5)])

backups_df = pd.DataFrame(backups, columns=["Backup_ID","User_ID","Backup_Time","Version","File_List","Size","Restore_Count"])
backups_df.to_csv(backups_file, index=False)

# --- ACCESS LOGS ---
actions = ["Restore","Download","Delete","List"]
logs = []
for i in range(800):
    user_id = random.choice(users_df["User_ID"])
    backup_id = random.choice(backups_df["Backup_ID"])
    action = random.choice(actions)
    status = random.choice(["Allowed","Denied"])
    reason = "RBAC rule" if status=="Denied" else "Access granted"
    logs.append([user_id, backup_id, action, fake.date_time_this_year(),
                 fake.ipv4(), random.choice(devices), status, reason])

logs_df = pd.DataFrame(logs, columns=["User_ID","Backup_ID","Action","Timestamp","IP","Device","Status","Reason"])
logs_df.to_csv(logs_file, index=False)

print("Synthetic datasets generated in /data: users.csv, backups.csv, access_log.csv")
