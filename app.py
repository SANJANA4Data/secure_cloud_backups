from __future__ import annotations

import time
from typing import Any

from flask import Flask, jsonify, render_template, request

from chatbot import handle_message
from services.backup_service import backup_folder, restore_backup
from utils import config, db_utils

app = Flask(__name__)

RATE_LIMIT_PER_MINUTE = 60
_request_log: dict[str, list[float]] = {}


def _get_user_id() -> str | None:
    return (
        request.headers.get("X-User-Id")
        or request.args.get("user_id")
        or (request.json or {}).get("user_id")
    )


def _rate_limit() -> tuple[bool, Any]:
    user_id = _get_user_id()
    if not user_id or request.path == "/api/health":
        return True, None

    now = time.time()
    window_start = now - 60
    history = _request_log.setdefault(user_id, [])
    history[:] = [ts for ts in history if ts >= window_start]
    if len(history) >= RATE_LIMIT_PER_MINUTE:
        return False, jsonify({"error": "rate_limit", "message": "Too many requests"})
    history.append(now)
    return True, None


@app.before_request
def enforce_rate_limit():
    if request.path.startswith("/api/"):
        allowed, response = _rate_limit()
        if not allowed:
            return response, 429
    return None


def ensure_seed_data() -> None:
    db_utils.init_all()
    if not db_utils.list_users() and config.CSV_USERS_PATH.exists():
        db_utils.load_users_from_csv()
    if not db_utils.list_backups_catalog() and config.CSV_BACKUPS_PATH.exists():
        db_utils.load_backups_catalog_from_csv()
    if not db_utils.list_access_log() and config.CSV_ACCESS_LOG_PATH.exists():
        db_utils.load_access_log_from_csv()


@app.route("/")
def dashboard():
    ensure_seed_data()
    return render_template("dashboard.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/init-data", methods=["POST"])
def init_data():
    db_utils.seed_from_csv()
    return jsonify(
        {
            "users": len(db_utils.list_users()),
            "backups_catalog": len(db_utils.list_backups_catalog()),
            "access_log": len(db_utils.list_access_log()),
        }
    )


@app.route("/api/users")
def list_users():
    ensure_seed_data()
    return jsonify(db_utils.list_users())


@app.route("/api/backups/catalog")
def list_backups_catalog():
    ensure_seed_data()
    user_id = _get_user_id()
    if not user_id:
        return jsonify({"error": "missing_user", "message": "user_id is required"}), 400
    allowed, reason = db_utils.check_access(user_id, "LIST_BACKUPS")
    if not allowed:
        db_utils.log_action("BACKUPS_LIST_DENIED", None, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    db_utils.log_action("BACKUPS_LISTED", None, user_id)
    return jsonify(db_utils.list_backups_catalog())


@app.route("/api/backups/records")
def list_backup_records():
    ensure_seed_data()
    user_id = _get_user_id()
    if not user_id:
        return jsonify({"error": "missing_user", "message": "user_id is required"}), 400
    allowed, reason = db_utils.check_access(user_id, "LIST_BACKUPS")
    if not allowed:
        db_utils.log_action("BACKUPS_LIST_DENIED", None, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    db_utils.log_action("BACKUPS_LISTED", None, user_id)
    return jsonify(db_utils.list_backups())


@app.route("/api/access-log")
def list_access_log():
    ensure_seed_data()
    user_id = _get_user_id()
    if not user_id:
        return jsonify({"error": "missing_user", "message": "user_id is required"}), 400
    allowed, reason = db_utils.check_access(user_id, "AUDIT_LOG")
    if not allowed:
        db_utils.log_action("ACCESS_LOG_DENIED", None, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    db_utils.log_action("ACCESS_LOG_VIEWED", None, user_id)
    return jsonify(db_utils.list_access_log(limit=200))


@app.route("/api/audit-log")
def list_audit_log():
    ensure_seed_data()
    user_id = _get_user_id()
    if not user_id:
        return jsonify({"error": "missing_user", "message": "user_id is required"}), 400
    allowed, reason = db_utils.check_access(user_id, "AUDIT_LOG")
    if not allowed:
        db_utils.log_action("AUDIT_LOG_DENIED", None, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    db_utils.log_action("AUDIT_LOG_VIEWED", None, user_id)
    return jsonify(db_utils.list_audit_log(limit=200))


@app.route("/api/anomalies")
def list_anomalies():
    ensure_seed_data()
    user_id = _get_user_id()
    if not user_id:
        return jsonify({"error": "missing_user", "message": "user_id is required"}), 400
    allowed, reason = db_utils.check_access(user_id, "ANOMALIES")
    if not allowed:
        db_utils.log_action("ANOMALIES_DENIED", None, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    db_utils.log_action("ANOMALIES_VIEWED", None, user_id)
    return jsonify(db_utils.detect_anomalies())


@app.route("/api/backup", methods=["POST"])
def create_backup():
    payload = request.json or {}
    user_id = payload.get("user_id")
    folder_path = payload.get("folder_path")
    if not user_id or not folder_path:
        return jsonify({"error": "missing_fields", "message": "user_id and folder_path required"}), 400
    allowed, reason = db_utils.check_access(user_id, "BACKUP", backup_owner_id=user_id)
    if not allowed:
        db_utils.log_action("BACKUP_DENIED", None, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    try:
        safe_path = config.resolve_under_data(folder_path)
    except ValueError as exc:
        return jsonify({"error": "invalid_path", "message": str(exc)}), 400
    result = backup_folder(user_id, str(safe_path))
    return jsonify(result)


@app.route("/api/restore", methods=["POST"])
def restore_backup_api():
    payload = request.json or {}
    user_id = payload.get("user_id")
    backup_id = payload.get("backup_id")
    if not user_id or not backup_id:
        return jsonify({"error": "missing_fields", "message": "user_id and backup_id required"}), 400
    backup_owner_id = db_utils.get_backup_owner(backup_id)
    allowed, reason = db_utils.check_access(user_id, "RESTORE", backup_owner_id=backup_owner_id)
    if not allowed:
        db_utils.log_action("RESTORE_DENIED", backup_id, user_id, result=reason)
        return jsonify({"error": "forbidden", "message": reason}), 403
    result = restore_backup(backup_id, user_id)
    return jsonify(result)


@app.route("/api/chat", methods=["POST"])
def chat():
    payload = request.json or {}
    user_id = payload.get("user_id")
    message = payload.get("message", "")
    if not user_id:
        return jsonify({"error": "missing_fields", "message": "user_id required"}), 400
    ensure_seed_data()
    response = handle_message(user_id, message)
    return jsonify(response)


if __name__ == "__main__":
    ensure_seed_data()
    app.run(debug=False, host="0.0.0.0", port=8000)
