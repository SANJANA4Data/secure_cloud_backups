import json
import os

from scripts.ai_role_suggester import suggest_roles
from scripts.anomaly_detector import detect_anomalies
from utils import db_utils

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def _find_suggestion(user_id):
    suggestions, _ = suggest_roles()
    for row in suggestions:
        if row["User_ID"].upper() == user_id.upper():
            return row
    return None


def _get_anomaly_overview():
    report, _ = detect_anomalies()
    return f"Anomalies: {report['anomaly_count']} out of {report['total_events']} events"


def handle_command(command):
    parts = command.strip().split()
    if not parts:
        return "Type help to see available commands."

    cmd = parts[0].lower()

    if cmd == "help":
        return "Commands: help | status <backup_id> | suggest_role <user_id> | anomalies"

    if cmd == "status" and len(parts) == 2:
        backup_id = parts[1]
        rows = db_utils.list_backups()
        for row in rows:
            if row[0] == backup_id:
                return f"Backup {backup_id}: user={row[1]}, version={row[3]}, size={row[4]}, restore_count={row[5]}"
        return f"Backup {backup_id} not found"

    if cmd == "suggest_role" and len(parts) == 2:
        user_id = parts[1]
        suggestion = _find_suggestion(user_id)
        if not suggestion:
            return f"No role suggestion found for {user_id}"
        return (
            f"{user_id}: current={suggestion['Current_Role']}, "
            f"suggested={suggestion['Suggested_Role']} "
            f"(denied_rate={suggestion['Denied_Rate']}, reason={suggestion['Reason']})"
        )

    if cmd == "anomalies":
        return _get_anomaly_overview()

    return "Unknown command. Type help to see available commands."


def run_chatbot(commands=None):
    if commands is not None:
        return [handle_command(c) for c in commands]

    print("Secure Cloud Backups Chatbot. Type 'help' or 'exit'.")
    while True:
        command = input("scb> ").strip()
        if command.lower() in {"exit", "quit"}:
            print("Goodbye.")
            break
        print(handle_command(command))


if __name__ == "__main__":
    sample = ["help", "anomalies", "suggest_role U005"]
    for response in run_chatbot(sample):
        print(response)
