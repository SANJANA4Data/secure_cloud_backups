import os
import secrets

from scripts.ai_role_suggester import suggest_roles
from scripts.anomaly_detector import detect_anomalies
from scripts.backup_script import backup_folder
from scripts.chatbot_interface import run_chatbot
from scripts.dashboard import build_dashboard
from scripts.restore_script import restore_backup
from scripts.scalability_test import run_scalability_test
from utils import db_utils

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
TEST_DATA_DIR = os.path.join(DATA_DIR, "test_data")


def run_demo():
    print("=== SECURE CLOUD BACKUPS DEMO START ===")
    if "SCB_AES_KEY" not in os.environ:
        os.environ["SCB_AES_KEY"] = secrets.token_hex(16)
        print("SCB_AES_KEY not set. Generated ephemeral demo key.")

    db_utils.init_db()
    db_utils.init_audit_log()
    db_utils.init_users()
    db_utils.load_users_from_csv(os.path.join(DATA_DIR, "users.csv"))

    ingested = db_utils.ingest_access_log_csv(os.path.join(DATA_DIR, "access_log.csv"))
    print(f"Ingested {ingested} access-log records into SQLite audit_log")

    backup_id, checksum = backup_folder("U005", TEST_DATA_DIR)
    print(f"Created backup -> id={backup_id}, checksum={checksum}")

    restored = restore_backup(backup_id, user_id="U005")
    print(f"Restore status for {backup_id}: {'SUCCESS' if restored else 'FAILED'}")

    suggestions, role_output = suggest_roles()
    changed = [s for s in suggestions if s["Current_Role"] != s["Suggested_Role"]]
    print(f"Role suggestions generated: {len(suggestions)} (changes recommended: {len(changed)})")
    print(f"Role suggestions file: {role_output}")

    anomaly_report, anomaly_output = detect_anomalies()
    print(f"Anomalies detected: {anomaly_report['anomaly_count']} from {anomaly_report['total_events']} events")
    print(f"Anomaly report file: {anomaly_output}")

    dashboard_summary, dashboard_file = build_dashboard(anomaly_output)
    print(f"Dashboard file: {dashboard_file}")
    print("Dashboard summary:", dashboard_summary)

    bot_responses = run_chatbot([
        "help",
        f"status {backup_id}",
        "suggest_role U005",
        "anomalies",
    ])
    print("Chatbot sample responses:")
    for response in bot_responses:
        print("-", response)

    scalability_report = run_scalability_test(5000)
    print("Scalability test:", scalability_report)

    print("=== SECURE CLOUD BACKUPS DEMO COMPLETE ===")


if __name__ == "__main__":
    run_demo()
