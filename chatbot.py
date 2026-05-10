from __future__ import annotations

import re

from services.backup_service import restore_backup
from utils import db_utils


def _deny(action: str, backup_id: str | None, user_id: str, reason: str) -> dict:
    db_utils.log_action(f"{action}_DENIED", backup_id, user_id, result=reason)
    return {"intent": action, "status": "denied", "response": reason}


def handle_message(user_id: str, message: str) -> dict:
    text = message.strip().lower()

    if "audit" in text and "log" in text:
        allowed, reason = db_utils.check_access(user_id, "AUDIT_LOG")
        if not allowed:
            return _deny("AUDIT_LOG", None, user_id, reason)
        db_utils.log_action("AUDIT_LOG_VIEWED", None, user_id)
        return {
            "intent": "audit_log",
            "status": "ok",
            "response": "Here are the latest audit log entries.",
            "data": db_utils.list_audit_log(limit=50),
        }

    if "anomal" in text:
        allowed, reason = db_utils.check_access(user_id, "ANOMALIES")
        if not allowed:
            return _deny("ANOMALIES", None, user_id, reason)
        db_utils.log_action("ANOMALIES_VIEWED", None, user_id)
        return {
            "intent": "anomalies",
            "status": "ok",
            "response": "Detected anomalies from audit logs.",
            "data": db_utils.detect_anomalies(),
        }

    if "list backups" in text or "show backups" in text or text.startswith("backups"):
        allowed, reason = db_utils.check_access(user_id, "LIST_BACKUPS")
        if not allowed:
            return _deny("LIST_BACKUPS", None, user_id, reason)
        db_utils.log_action("BACKUPS_LISTED", None, user_id)
        return {
            "intent": "list_backups",
            "status": "ok",
            "response": "Here are the latest backups.",
            "data": {
                "catalog": db_utils.list_backups_catalog()[:50],
                "records": db_utils.list_backups()[:50],
            },
        }

    restore_match = re.search(r"restore\s+(b\d+)", text)
    if restore_match:
        backup_id = restore_match.group(1).upper()
        owner_id = db_utils.get_backup_owner(backup_id)
        allowed, reason = db_utils.check_access(user_id, "RESTORE", backup_owner_id=owner_id)
        if not allowed:
            return _deny("RESTORE", backup_id, user_id, reason)
        result = restore_backup(backup_id, user_id)
        return {
            "intent": "restore",
            "status": result["status"],
            "response": result.get("message", f"Restore status: {result['status']}"),
            "data": result,
        }

    return {
        "intent": "help",
        "status": "ok",
        "response": (
            "Try: 'list backups', 'show audit log', 'show anomalies', or 'restore B001'."
        ),
    }
