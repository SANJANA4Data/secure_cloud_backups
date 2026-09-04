import csv
import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "backups.db")

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
            restore_count INTEGER DEFAULT 0,
            checksum TEXT
        )
    """)
    cursor.execute("PRAGMA table_info(backups)")
    columns = {row[1] for row in cursor.fetchall()}
    if "checksum" not in columns:
        cursor.execute("ALTER TABLE backups ADD COLUMN checksum TEXT")
    conn.commit()
    conn.close()

def insert_backup(backup_id, user_id, version, size, checksum=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute("INSERT INTO backups VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (backup_id, user_id, timestamp, version, size, 0, checksum))
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

def get_checksum(backup_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT checksum FROM backups WHERE backup_id=?", (backup_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

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
            timestamp TEXT NOT NULL,
            result TEXT,
            role TEXT,
            department TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_action(action, backup_id, user_id, result="SUCCESS"):
    role, dept, _, _ = get_user_attributes(user_id)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO audit_log (action, backup_id, user_id, timestamp, result, role, department)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (action, backup_id, user_id, timestamp, result, role, dept))
    conn.commit()
    conn.close()

def list_audit_log():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log")
    rows = cursor.fetchall()
    conn.close()
    return rows

# -----------------------------
# User / RBAC functions
# -----------------------------
def init_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            department TEXT,
            location TEXT,
            device TEXT
        )
    """)
    conn.commit()
    conn.close()

def load_users_from_csv(csv_path="data/test_data/users.csv"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cursor.execute("""
                INSERT OR REPLACE INTO users (user_id, name, role, department, location, device)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (row["User_ID"], row["Name"], row["Role"], row["Department"], row["Location"], row["Device"]))
    conn.commit()
    conn.close()

def get_user_role(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def get_user_attributes(user_id):
    init_users()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT role, department, location, device FROM users WHERE user_id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else (None, None, None, None)

def check_access(user_id, action, department=None):
    role, dept, location, device = get_user_attributes(user_id)

    if not role:
        return False

    # RBAC rules
    if role == "Admin":
        return True
    if action == "backup" and role == "Owner" and dept == department:
        return True
    if action == "restore" and role == "Restorer" and device == "Corporate":
        return True

    return False

# -----------------------------
# Anomaly detection
# -----------------------------
def detect_anomalies():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    anomalies = []

    # Rule 1: Viewers doing restricted actions
    cursor.execute("SELECT * FROM audit_log WHERE role='Viewer' AND result='SUCCESS'")
    anomalies.extend(cursor.fetchall())

    # Rule 2: Owners restoring outside their department
    cursor.execute("SELECT * FROM audit_log WHERE action='RESTORE_DENIED' AND role='Owner'")
    anomalies.extend(cursor.fetchall())

    # Rule 3: Excessive restores
    cursor.execute("""
        SELECT backup_id, COUNT(*) as cnt FROM audit_log
        WHERE action='BACKUP_RESTORED'
        GROUP BY backup_id HAVING cnt > 5
    """)
    anomalies.extend(cursor.fetchall())

    conn.close()
    return anomalies
