import sqlite3
import csv
from datetime import datetime
from typing import Any, Iterable

from utils import config


def _connect() -> sqlite3.Connection:
    config.ensure_data_dirs()
    return sqlite3.connect(config.DB_PATH)


def _rows_to_dicts(cursor: sqlite3.Cursor, rows: Iterable[tuple]) -> list[dict[str, Any]]:
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in rows]


# -----------------------------
# Initialization
# -----------------------------
def init_backups_table() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backups (
                backup_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                version INTEGER NOT NULL,
                size INTEGER NOT NULL,
                restore_count INTEGER DEFAULT 0,
                checksum TEXT
            )
            """
        )


def init_users() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                name TEXT,
                role TEXT,
                department TEXT,
                location TEXT,
                device TEXT
            )
            """
        )


def init_audit_log() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                backup_id TEXT,
                user_id TEXT,
                timestamp TEXT NOT NULL,
                result TEXT,
                role TEXT,
                department TEXT
            )
            """
        )


def init_backups_catalog() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backups_catalog (
                backup_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                backup_time TEXT,
                version TEXT,
                file_list TEXT,
                size TEXT,
                restore_count INTEGER
            )
            """
        )


def init_access_log() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                backup_id TEXT,
                action TEXT,
                timestamp TEXT,
                ip TEXT,
                device TEXT,
                status TEXT,
                reason TEXT
            )
            """
        )


def init_all() -> None:
    init_backups_table()
    init_users()
    init_audit_log()
    init_backups_catalog()
    init_access_log()


# -----------------------------
# CSV loaders
# -----------------------------
def load_users_from_csv(csv_path: str | None = None) -> None:
    csv_path = csv_path or str(config.CSV_USERS_PATH)
    with _connect() as conn, open(csv_path, newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            conn.execute(
                """
                INSERT OR REPLACE INTO users (user_id, name, role, department, location, device)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    row.get("User_ID"),
                    row.get("Name"),
                    row.get("Role"),
                    row.get("Department"),
                    row.get("Location"),
                    row.get("Device"),
                ),
            )


def load_backups_catalog_from_csv(csv_path: str | None = None) -> None:
    csv_path = csv_path or str(config.CSV_BACKUPS_PATH)
    with _connect() as conn, open(csv_path, newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            conn.execute(
                """
                INSERT OR REPLACE INTO backups_catalog
                (backup_id, user_id, backup_time, version, file_list, size, restore_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.get("Backup_ID"),
                    row.get("User_ID"),
                    row.get("Backup_Time"),
                    row.get("Version"),
                    row.get("File_List"),
                    row.get("Size"),
                    int((row.get("Restore_Count") or "0").strip() or "0"),
                ),
            )


def load_access_log_from_csv(csv_path: str | None = None) -> None:
    csv_path = csv_path or str(config.CSV_ACCESS_LOG_PATH)
    with _connect() as conn, open(csv_path, newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            conn.execute(
                """
                INSERT INTO access_log
                (user_id, backup_id, action, timestamp, ip, device, status, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.get("User_ID"),
                    row.get("Backup_ID"),
                    row.get("Action"),
                    row.get("Timestamp"),
                    row.get("IP"),
                    row.get("Device"),
                    row.get("Status"),
                    row.get("Reason"),
                ),
            )


def seed_from_csv() -> None:
    init_all()
    with _connect() as conn:
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM backups_catalog")
        conn.execute("DELETE FROM access_log")
    load_users_from_csv()
    load_backups_catalog_from_csv()
    load_access_log_from_csv()


# -----------------------------
# Backup metadata functions
# -----------------------------
def insert_backup(backup_id: str, user_id: str, version: int, size: int, checksum: str | None = None) -> None:
    with _connect() as conn:
        timestamp = datetime.now().isoformat()
        conn.execute(
            "INSERT INTO backups VALUES (?, ?, ?, ?, ?, ?, ?)",
            (backup_id, user_id, timestamp, version, size, 0, checksum),
        )


def list_backups() -> list[dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute("SELECT * FROM backups ORDER BY timestamp DESC")
        return _rows_to_dicts(cursor, cursor.fetchall())


def get_backup_record(backup_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        cursor = conn.execute("SELECT * FROM backups WHERE backup_id = ?", (backup_id,))
        rows = _rows_to_dicts(cursor, cursor.fetchall())
        return rows[0] if rows else None


def increment_restore_count(backup_id: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE backups SET restore_count = restore_count + 1 WHERE backup_id = ?",
            (backup_id,),
        )


def get_checksum(backup_id: str) -> str | None:
    with _connect() as conn:
        cursor = conn.execute("SELECT checksum FROM backups WHERE backup_id = ?", (backup_id,))
        row = cursor.fetchone()
        return row[0] if row else None


# -----------------------------
# Catalog and logs
# -----------------------------
def list_backups_catalog() -> list[dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute("SELECT * FROM backups_catalog ORDER BY backup_time DESC")
        return _rows_to_dicts(cursor, cursor.fetchall())


def list_users() -> list[dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute("SELECT * FROM users ORDER BY user_id")
        return _rows_to_dicts(cursor, cursor.fetchall())


def get_backup_catalog(backup_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        cursor = conn.execute("SELECT * FROM backups_catalog WHERE backup_id = ?", (backup_id,))
        rows = _rows_to_dicts(cursor, cursor.fetchall())
        return rows[0] if rows else None


def list_access_log(limit: int | None = None) -> list[dict[str, Any]]:
    with _connect() as conn:
        if limit:
            cursor = conn.execute(
                "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT ?",
                (int(limit),),
            )
        else:
            cursor = conn.execute("SELECT * FROM access_log ORDER BY timestamp DESC")
        return _rows_to_dicts(cursor, cursor.fetchall())


def log_action(action: str, backup_id: str | None, user_id: str | None, result: str = "SUCCESS") -> None:
    role, dept, _, _ = get_user_attributes(user_id) if user_id else (None, None, None, None)
    with _connect() as conn:
        timestamp = datetime.now().isoformat()
        conn.execute(
            """
            INSERT INTO audit_log (action, backup_id, user_id, timestamp, result, role, department)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (action, backup_id, user_id, timestamp, result, role, dept),
        )


def list_audit_log(limit: int | None = None) -> list[dict[str, Any]]:
    with _connect() as conn:
        if limit:
            cursor = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (int(limit),),
            )
        else:
            cursor = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
        return _rows_to_dicts(cursor, cursor.fetchall())


# -----------------------------
# User / RBAC functions
# -----------------------------
def get_user_role(user_id: str) -> str | None:
    with _connect() as conn:
        cursor = conn.execute("SELECT role FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        return row[0] if row else None


def get_user_attributes(user_id: str) -> tuple[str | None, str | None, str | None, str | None]:
    with _connect() as conn:
        cursor = conn.execute(
            "SELECT role, department, location, device FROM users WHERE user_id = ?",
            (user_id,),
        )
        row = cursor.fetchone()
        return row if row else (None, None, None, None)


def get_backup_owner(backup_id: str) -> str | None:
    record = get_backup_record(backup_id)
    if record:
        return record.get("user_id")
    catalog = get_backup_catalog(backup_id)
    return catalog.get("user_id") if catalog else None


def check_access(user_id: str, action: str, backup_owner_id: str | None = None) -> tuple[bool, str]:
    role, _, _, device = get_user_attributes(user_id)
    if not role:
        return False, "Denied: Unknown user"

    role = role.upper()
    action = action.upper()

    if role == "ADMIN":
        return True, "Allowed"

    if action in {"AUDIT_LOG", "ANOMALIES"}:
        return False, "Denied: Admin only"

    if role == "VIEWER":
        if action in {"RESTORE", "DELETE", "BACKUP"}:
            return False, "Denied: Viewer cannot restore, delete, or backup"
        return True, "Allowed"

    if role == "OWNER":
        if backup_owner_id and backup_owner_id != user_id:
            return False, "Denied: Owner can only manage own backups"
        if action in {"BACKUP", "RESTORE", "DELETE", "LIST_BACKUPS", "VIEW_BACKUP"}:
            return True, "Allowed"
        return False, "Denied: action not permitted"

    if role == "RESTORER":
        if action == "DELETE":
            return False, "Denied: Restorer cannot delete backups"
        if action == "RESTORE":
            if device != "Corporate":
                return False, "Denied: Restorer must use a corporate device"
            return True, "Allowed"
        if action in {"LIST_BACKUPS", "VIEW_BACKUP"}:
            return True, "Allowed"
        return False, "Denied: action not permitted"

    return False, "Denied: action not permitted"


# -----------------------------
# Anomaly detection
# -----------------------------
def detect_anomalies() -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    with _connect() as conn:
        cursor = conn.execute("SELECT * FROM audit_log WHERE role='Viewer' AND result='SUCCESS'")
        anomalies.extend(_rows_to_dicts(cursor, cursor.fetchall()))

        cursor = conn.execute("SELECT * FROM audit_log WHERE action='RESTORE_DENIED' AND role='Owner'")
        anomalies.extend(_rows_to_dicts(cursor, cursor.fetchall()))

        cursor = conn.execute(
            """
            SELECT backup_id, COUNT(*) as cnt FROM audit_log
            WHERE action='BACKUP_RESTORED'
            GROUP BY backup_id HAVING cnt > 5
            """
        )
        anomalies.extend(_rows_to_dicts(cursor, cursor.fetchall()))

    return anomalies
