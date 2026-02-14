import sqlite3
from datetime import datetime

DB_PATH = "data/backups.db"

# -----------------------------
# Backup metadata functions
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backups (
            backup_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            version INTEGER NOT NULL,
            size INTEGER NOT NULL,
            restore_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def insert_backup(backup_id, user_id, version, size):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute("INSERT INTO backups VALUES (?, ?, ?, ?, ?, ?)",
                   (backup_id, user_id, timestamp, version, size, 0))
    conn.commit()
    conn.close()

def list_backups():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM backups")
    rows = cursor.fetchall()
    conn.close()
    return rows

def increment_restore_count(backup_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE backups SET restore_count = restore_count + 1 WHERE backup_id = ?", (backup_id,))
    conn.commit()
    conn.close()

# -----------------------------
# Audit log functions
# -----------------------------
def init_audit_log():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            backup_id TEXT,
            user_id TEXT,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_action(action, backup_id, user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute("INSERT INTO audit_log (action, backup_id, user_id, timestamp) VALUES (?, ?, ?, ?)",
                   (action, backup_id, user_id, timestamp))
    conn.commit()
    conn.close()

def list_audit_log():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log")
    rows = cursor.fetchall()
    conn.close()
    return rows
