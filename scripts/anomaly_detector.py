import csv
import json
import os
from collections import Counter, defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def detect_anomalies(access_log_csv=None, output_json=None):
    access_log_csv = access_log_csv or os.path.join(DATA_DIR, "access_log.csv")
    output_json = output_json or os.path.join(DATA_DIR, "anomalies.json")

    denied_counter = Counter()
    unique_backup_access = defaultdict(set)
    personal_restore_allowed = []
    repeated_denied_delete = Counter()

    with open(access_log_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    for row in rows:
        uid = row["User_ID"]
        action = row["Action"].strip().lower()
        backup_id = row["Backup_ID"]
        status = row["Status"].strip().lower()
        device = row["Device"].strip().lower()

        unique_backup_access[uid].add(backup_id)
        if status == "denied":
            denied_counter[uid] += 1
        if action == "restore" and status == "allowed" and device == "personal":
            personal_restore_allowed.append(row)
        if action == "delete" and status == "denied":
            repeated_denied_delete[uid] += 1

    anomalies = []

    for uid, count in denied_counter.items():
        if count >= 12:
            anomalies.append({
                "type": "HIGH_DENIED_ATTEMPTS",
                "user_id": uid,
                "details": f"{count} denied attempts",
                "severity": "HIGH",
            })

    for uid, backups in unique_backup_access.items():
        if len(backups) >= 30:
            anomalies.append({
                "type": "BROAD_BACKUP_ACCESS",
                "user_id": uid,
                "details": f"Accessed {len(backups)} unique backups",
                "severity": "MEDIUM",
            })

    for uid, count in repeated_denied_delete.items():
        if count >= 5:
            anomalies.append({
                "type": "REPEATED_DENIED_DELETE",
                "user_id": uid,
                "details": f"{count} denied delete attempts",
                "severity": "MEDIUM",
            })

    for row in personal_restore_allowed:
        anomalies.append({
            "type": "PERSONAL_DEVICE_RESTORE",
            "user_id": row["User_ID"],
            "details": f"Allowed restore on personal device for {row['Backup_ID']}",
            "severity": "HIGH",
        })

    result = {
        "total_events": len(rows),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result, output_json


if __name__ == "__main__":
    result, out = detect_anomalies()
    print(f"Detected {result['anomaly_count']} anomalies from {result['total_events']} events")
    print(f"Saved anomaly report to {out}")
