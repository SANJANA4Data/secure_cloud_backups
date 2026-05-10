import csv
import os
import random
import time
from datetime import datetime, timedelta

from scripts.anomaly_detector import detect_anomalies

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def _read_ids(path, key):
    with open(path, newline="", encoding="utf-8") as f:
        return [row[key] for row in csv.DictReader(f)]


def generate_large_access_log(event_count=5000, output_csv=None):
    output_csv = output_csv or os.path.join(DATA_DIR, f"access_log_large_{event_count}.csv")

    users = _read_ids(os.path.join(DATA_DIR, "users.csv"), "User_ID")
    backups = _read_ids(os.path.join(DATA_DIR, "backups.csv"), "Backup_ID")

    actions = ["Restore", "Download", "Delete", "List"]
    devices = ["Corporate", "Personal"]

    start_time = datetime(2026, 1, 1)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["User_ID", "Backup_ID", "Action", "Timestamp", "IP", "Device", "Status", "Reason"])
        for i in range(event_count):
            uid = random.choice(users)
            bid = random.choice(backups)
            action = random.choice(actions)
            status = random.choice(["Allowed", "Denied", "Allowed", "Allowed"])
            reason = "Access granted" if status == "Allowed" else "RBAC rule"
            ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            ts = start_time + timedelta(seconds=i)
            writer.writerow([uid, bid, action, ts.isoformat(), ip, random.choice(devices), status, reason])

    return output_csv


def run_scalability_test(event_count=5000):
    large_log = generate_large_access_log(event_count=event_count)
    start = time.perf_counter()
    result, _ = detect_anomalies(access_log_csv=large_log, output_json=os.path.join(DATA_DIR, "anomalies_large.json"))
    elapsed = time.perf_counter() - start
    return {
        "event_count": event_count,
        "anomalies": result["anomaly_count"],
        "elapsed_seconds": round(elapsed, 4),
        "events_per_second": round(event_count / elapsed, 2) if elapsed > 0 else "inf",
        "log_file": large_log,
    }


if __name__ == "__main__":
    report = run_scalability_test(5000)
    print(report)
