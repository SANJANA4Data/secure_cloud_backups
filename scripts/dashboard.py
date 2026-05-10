import json
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "backups.db")


def _count_table_rows(conn, table_name):
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table_name}")
    return cur.fetchone()[0]


def build_dashboard(anomalies_json=None):
    anomalies_json = anomalies_json or os.path.join(DATA_DIR, "anomalies.json")

    conn = sqlite3.connect(DB_PATH)
    backups_count = _count_table_rows(conn, "backups")
    audit_count = _count_table_rows(conn, "audit_log")

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_log WHERE action='BACKUP_RESTORED'")
    restore_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM audit_log WHERE result LIKE 'RBAC/%' OR action='RESTORE_DENIED'")
    denied_count = cur.fetchone()[0]
    conn.close()

    anomaly_count = 0
    if os.path.exists(anomalies_json):
        with open(anomalies_json, encoding="utf-8") as f:
            anomaly_count = json.load(f).get("anomaly_count", 0)

    summary = {
        "backups_total": backups_count,
        "audit_events_total": audit_count,
        "restores_total": restore_count,
        "denied_events_total": denied_count,
        "anomalies_total": anomaly_count,
    }

    dashboard_txt = os.path.join(DATA_DIR, "dashboard_summary.txt")
    with open(dashboard_txt, "w", encoding="utf-8") as f:
        for k, v in summary.items():
            f.write(f"{k}: {v}\n")

    return summary, dashboard_txt


if __name__ == "__main__":
    summary, dashboard_txt = build_dashboard()
    print("Dashboard summary:")
    for key, val in summary.items():
        print(f"- {key}: {val}")
    print(f"Saved to {dashboard_txt}")
