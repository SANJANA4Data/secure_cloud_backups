import sqlite3
import logging
from datetime import datetime

from utils.config import DB_PATH as _DEFAULT_DB_PATH

# Module-level path – tests can override via monkeypatch
DB_PATH = _DEFAULT_DB_PATH

logger = logging.getLogger(__name__)


def _connect():
    return sqlite3.connect(DB_PATH)


# -----------------------------
# Schema initialisation
# -----------------------------

def init_db():
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backups (
                backup_id    TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                folder_path  TEXT NOT NULL DEFAULT '',
                timestamp    TEXT NOT NULL,
                version      INTEGER NOT NULL,
                size         INTEGER NOT NULL,
                restore_count INTEGER DEFAULT 0,
                checksum     TEXT NOT NULL DEFAULT ''
            )
        """)
        # Migrate existing databases that pre-date the checksum column
        cursor.execute("PRAGMA table_info(backups)")
        cols = [row[1] for row in cursor.fetchall()]
        if "checksum" not in cols:
            cursor.execute(
                "ALTER TABLE backups ADD COLUMN checksum TEXT NOT NULL DEFAULT ''"
            )
            logger.info("Migrated backups table: added checksum column")
        conn.commit()
        conn.close()
        logger.debug("backups table initialised")
    except sqlite3.Error as exc:
        logger.error("Failed to initialise backups table: %s", exc)
        raise


def init_audit_log():
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                action    TEXT NOT NULL,
                backup_id TEXT,
                user_id   TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        logger.debug("audit_log table initialised")
    except sqlite3.Error as exc:
        logger.error("Failed to initialise audit_log table: %s", exc)
        raise


# -----------------------------
# Backup metadata functions
# -----------------------------

def insert_backup(backup_id, user_id, version, size, folder_path="", checksum=""):
    try:
        conn = _connect()
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO backups "
            "(backup_id, user_id, folder_path, timestamp, version, size, restore_count, checksum) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (backup_id, user_id, folder_path, timestamp, version, size, 0, checksum),
        )
        conn.commit()
        conn.close()
        logger.info("Inserted backup record %s (user=%s, version=%d)", backup_id, user_id, version)
    except sqlite3.Error as exc:
        logger.error("Failed to insert backup %s: %s", backup_id, exc)
        raise


def get_next_version(user_id, folder_path):
    """Return the next version number for a (user_id, folder_path) pair."""
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT MAX(version) FROM backups WHERE user_id = ? AND folder_path = ?",
            (user_id, folder_path),
        )
        row = cursor.fetchone()
        conn.close()
        return (row[0] or 0) + 1
    except sqlite3.Error as exc:
        logger.error("Failed to get next version for user=%s folder=%s: %s", user_id, folder_path, exc)
        raise


def list_versions_for_folder(user_id, folder_path):
    """Return backup IDs for (user_id, folder_path) sorted by version ascending."""
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT backup_id FROM backups "
            "WHERE user_id = ? AND folder_path = ? "
            "ORDER BY version ASC",
            (user_id, folder_path),
        )
        rows = cursor.fetchall()
        conn.close()
        return [row[0] for row in rows]
    except sqlite3.Error as exc:
        logger.error(
            "Failed to list versions for user=%s folder=%s: %s", user_id, folder_path, exc
        )
        raise


def get_checksum(backup_id):
    """Return the stored SHA-256 checksum for *backup_id*, or None if not found."""
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT checksum FROM backups WHERE backup_id = ?", (backup_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except sqlite3.Error as exc:
        logger.error("Failed to get checksum for backup %s: %s", backup_id, exc)
        raise


def get_backup_owner(backup_id):
    """Return the user_id that owns *backup_id*, or None if the record does not exist."""
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM backups WHERE backup_id = ?", (backup_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except sqlite3.Error as exc:
        logger.error("Failed to look up owner of backup %s: %s", backup_id, exc)
        raise


def list_backups():
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM backups")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as exc:
        logger.error("Failed to list backups: %s", exc)
        raise


def increment_restore_count(backup_id):
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE backups SET restore_count = restore_count + 1 WHERE backup_id = ?",
            (backup_id,),
        )
        conn.commit()
        conn.close()
        logger.debug("Incremented restore_count for %s", backup_id)
    except sqlite3.Error as exc:
        logger.error("Failed to increment restore count for %s: %s", backup_id, exc)
        raise


def delete_backup(backup_id):
    """Remove a backup record from the database. Raises ValueError if not found."""
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM backups WHERE backup_id = ?", (backup_id,))
        if cursor.rowcount == 0:
            conn.close()
            raise ValueError(f"Backup {backup_id!r} not found in database")
        conn.commit()
        conn.close()
        logger.info("Deleted backup record %s", backup_id)
    except sqlite3.Error as exc:
        logger.error("Failed to delete backup %s: %s", backup_id, exc)
        raise


# -----------------------------
# Audit log functions
# -----------------------------

def log_action(action, backup_id, user_id):
    try:
        conn = _connect()
        cursor = conn.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO audit_log (action, backup_id, user_id, timestamp) VALUES (?, ?, ?, ?)",
            (action, backup_id, user_id, timestamp),
        )
        conn.commit()
        conn.close()
        logger.debug("Audit: %s by %s on %s", action, user_id, backup_id)
    except sqlite3.Error as exc:
        logger.error("Failed to log action %s: %s", action, exc)
        raise


def list_audit_log():
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as exc:
        logger.error("Failed to list audit log: %s", exc)
        raise
