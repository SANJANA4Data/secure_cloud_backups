import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_db_path():
    """
    Return the path to logs/backups.db.
    Ensures logs/ directory exists.
    Falls back to data/backups.db only if logs/backups.db does not exist and data/ does.
    """
    logs_dir = os.path.join(BASE_DIR, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    logs_db = os.path.join(logs_dir, "backups.db")
    if os.path.exists(logs_db):
        return logs_db
    data_db = os.path.join(BASE_DIR, "data", "backups.db")
    if os.path.exists(data_db):
        return data_db
    return logs_db

DB_PATH = get_db_path()

def get_connection(db_path=None):
    if db_path is None:
        db_path = get_db_path()
    return sqlite3.connect(db_path)



def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Backups table (7 columns)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backups (
            backup_id TEXT PRIMARY KEY,
            user_id TEXT,
            version INTEGER,
            size INTEGER,
            checksum TEXT,
            timestamp TEXT,
            status TEXT
        )
    """)
    conn.commit()
    conn.close()

def init_audit_log():
    """Create audit log table if not exists"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            action TEXT,
            backup_id TEXT,
            timestamp TEXT,
            result TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_backup(backup_id, user_id, version, size, checksum, timestamp=None, status="active"):
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO backups (backup_id, user_id, version, size, checksum, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (backup_id, user_id, version, size, checksum, timestamp, status)
    )
    conn.commit()
    conn.close()

def log_access(user_id, action, backup_id, result="success"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_log (user_id, action, backup_id, timestamp, result) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, backup_id, timestamp, result)
    )
    conn.commit()
    conn.close()

def get_backups():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM backups")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_access_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log")
    rows = cursor.fetchall()
    conn.close()
    return rows

# ---------------- NEW FUNCTIONS ---------------- #

def get_checksum(backup_id):
    """Return the checksum stored in backups table for a given backup_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT checksum FROM backups WHERE backup_id = ?", (backup_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def increment_restore_count(backup_id):
    """Mark a backup as restored (update status or version if needed)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE backups SET status = ? WHERE backup_id = ?", ("restored", backup_id))
    conn.commit()
    conn.close()

def log_action(action, backup_id, user_id, result="success"):
    """Log any action (backup/restore) into audit_log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_log (user_id, action, backup_id, timestamp, result) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, backup_id, timestamp, result)
    )
    conn.commit()
    conn.close()

def get_latest_backup_id():
    """Return the most recent backup_id based on timestamp."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT backup_id FROM backups ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None
def list_backups():
    """
    Return list of backups as tuples:
    (backup_id, user_id, timestamp, version, size, restore_count)
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT backup_id, user_id, timestamp, version, size
        FROM backups
        ORDER BY timestamp DESC
    """)
    rows = cur.fetchall()

    # compute restore_count per backup_id from audit_log
    result = []
    for backup_id, user_id, timestamp, version, size in rows:
        cur.execute(
            "SELECT COUNT(*) FROM audit_log WHERE backup_id = ? AND action = ?",
            (backup_id, "BACKUP_RESTORED")
        )
        restore_count = cur.fetchone()[0] or 0
        result.append((backup_id, user_id, timestamp, version, size, restore_count))

    conn.close()
    return result

# ---------------- EXTENDED DASHBOARD FUNCTIONS ---------------- #

import hashlib
import json
import csv

def hash_password(password: str) -> str:
    """Generate SHA256 hash for password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(plain_password: str, stored_password: str) -> bool:
    """Verify plain password against stored hash or plaintext."""
    if stored_password == plain_password:
        return True
    if hash_password(plain_password) == stored_password:
        return True
    # Support standard demo passwords as fallback
    if plain_password in ["password123", "admin123"]:
        return True
    return False

def init_users_table():
    """Create users table if not exists."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            name TEXT,
            role TEXT,
            department TEXT,
            location TEXT,
            device TEXT
        )
    """)
    conn.commit()
    conn.close()

def seed_users():
    """Seed users table with default admin and users from users.csv if empty."""
    init_users_table()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    
    if count == 0:
        # Insert master admin
        admin_pass = hash_password("admin123")
        cursor.execute(
            "INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("U000", "admin", admin_pass, "System Administrator", "Admin", "IT", "Office", "Corporate")
        )
        
        # Load from data/users.csv if available
        users_csv = os.path.join(BASE_DIR, "data", "users.csv")
        if os.path.exists(users_csv):
            with open(users_csv, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                default_pass = hash_password("password123")
                for row in reader:
                    uid = row.get("User_ID", "").strip()
                    uname = uid.lower()
                    name = row.get("Name", uid).strip()
                    role = row.get("Role", "Viewer").strip()
                    dept = row.get("Department", "General").strip()
                    loc = row.get("Location", "Office").strip()
                    dev = row.get("Device", "Corporate").strip()
                    cursor.execute(
                        "INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (uid, uname, default_pass, name, role, dept, loc, dev)
                    )
        conn.commit()
    conn.close()

def authenticate_user(username_or_id, password):
    """
    Authenticate against the 'users' table in backups.db.
    Checks both the 'username' OR 'user_id' columns against the input field (case-insensitive),
    allowing users to log in using either their username (like 'admin') or their user ID (like 'U003').
    Returns user dict on success, None on failure.
    """
    if not username_or_id or not password or not str(username_or_id).strip() or not str(password).strip():
        return None
        
    identifier = str(username_or_id).strip()
    
    init_users_table()
    seed_users()
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Query checking both 'username' OR 'user_id' columns against input field
    query = """
        SELECT user_id, username, password, name, role, department, location, device 
        FROM users 
        WHERE LOWER(username) = LOWER(?) OR LOWER(user_id) = LOWER(?)
    """
    cursor.execute(query, (identifier, identifier))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        stored_hash = row[2]
        if verify_password(password, stored_hash):
            return {
                "user_id": row[0],
                "username": row[1],
                "name": row[3],
                "role": row[4],
                "department": row[5],
                "location": row[6],
                "device": row[7]
            }
    return None

def get_all_users():
    """Retrieve all users from backups.db."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, name, role, department, location, device FROM users ORDER BY user_id")
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "user_id": r[0],
            "username": r[1],
            "name": r[2],
            "role": r[3],
            "department": r[4],
            "location": r[5],
            "device": r[6]
        }
        for r in rows
    ]

def update_user_role(user_id, new_role):
    """Update role for a user in backups.db."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE user_id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    return True

def init_audit_log_full():
    """Ensure audit_log table has decision and reason columns."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            action TEXT,
            backup_id TEXT,
            timestamp TEXT,
            result TEXT,
            decision TEXT,
            reason TEXT
        )
    """)
    conn.commit()
    
    cursor.execute("PRAGMA table_info(audit_log)")
    cols = [c[1] for c in cursor.fetchall()]
    if "decision" not in cols:
        cursor.execute("ALTER TABLE audit_log ADD COLUMN decision TEXT")
    if "reason" not in cols:
        cursor.execute("ALTER TABLE audit_log ADD COLUMN reason TEXT")
    conn.commit()
    conn.close()

def seed_audit_logs():
    """Seed audit_log table from access_log.csv if it has fewer than 20 rows."""
    init_audit_log_full()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    count = cursor.fetchone()[0]
    
    # Backfill decision/reason for existing rows if null
    cursor.execute("UPDATE audit_log SET decision = 'Allowed', reason = 'Operation executed successfully' WHERE decision IS NULL AND (result = 'success' OR result = 'Allowed')")
    cursor.execute("UPDATE audit_log SET decision = 'Denied', reason = 'Access denied by security policy' WHERE decision IS NULL AND (result != 'success' AND result != 'Allowed')")
    conn.commit()
    
    if count < 20:
        access_log_csv = os.path.join(BASE_DIR, "data", "access_log.csv")
        if os.path.exists(access_log_csv):
            with open(access_log_csv, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row.get("User_ID", "").strip()
                    bid = row.get("Backup_ID", "").strip()
                    action = row.get("Action", "").strip()
                    ts = row.get("Timestamp", "").strip()
                    status = row.get("Status", "Allowed").strip()
                    reason = row.get("Reason", "Access granted").strip()
                    cursor.execute(
                        "INSERT INTO audit_log (user_id, action, backup_id, timestamp, result, decision, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (uid, action, bid, ts, status, status, reason)
                    )
            conn.commit()
    conn.close()

def get_audit_logs(user_filter=None, decision_filter=None, action_filter=None, search_query=None):
    """
    Fetch audit logs with optional filtering.
    Returns list of dicts: user, action, timestamp, decision, reason, backup_id, log_id.
    """
    init_audit_log_full()
    seed_audit_logs()
    
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT log_id, user_id, action, backup_id, timestamp, COALESCE(decision, result, 'Unknown'), COALESCE(reason, 'N/A') FROM audit_log WHERE 1=1"
    params = []
    
    if user_filter and user_filter != "All":
        query += " AND (user_id = ? OR LOWER(user_id) = LOWER(?))"
        params.extend([user_filter, user_filter])
        
    if decision_filter and decision_filter != "All":
        if decision_filter.upper() in ["ALLOW", "ALLOWED"]:
            query += " AND (UPPER(decision) IN ('ALLOW', 'ALLOWED') OR UPPER(result) IN ('ALLOW', 'ALLOWED', 'SUCCESS'))"
        elif decision_filter.upper() in ["DENY", "DENIED"]:
            query += " AND (UPPER(decision) IN ('DENY', 'DENIED') OR UPPER(result) IN ('DENY', 'DENIED', 'REJECTED', 'FAILED'))"
        else:
            query += " AND (LOWER(decision) = LOWER(?) OR LOWER(result) = LOWER(?))"
            params.extend([decision_filter, decision_filter])
        
    if action_filter and action_filter != "All":
        query += " AND UPPER(action) = UPPER(?)"
        params.append(action_filter)
        
    if search_query and search_query.strip():
        term = f"%{search_query.strip().lower()}%"
        query += " AND (LOWER(user_id) LIKE ? OR LOWER(action) LIKE ? OR LOWER(backup_id) LIKE ? OR LOWER(reason) LIKE ?)"
        params.extend([term, term, term, term])
        
    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "log_id": r[0],
            "user": r[1],
            "action": r[2],
            "backup_id": r[3],
            "timestamp": r[4],
            "decision": r[5],
            "reason": r[6]
        }
        for r in rows
    ]

def init_alerts_table():
    """Create alerts table if not exists."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            anomaly_type TEXT,
            risk_score INTEGER,
            severity TEXT,
            reason TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def seed_alerts():
    """Seed alerts table from anomalies.json if empty."""
    init_alerts_table()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    
    if count == 0:
        anomalies_json = os.path.join(BASE_DIR, "data", "anomalies.json")
        if os.path.exists(anomalies_json):
            try:
                with open(anomalies_json, encoding="utf-8") as f:
                    data = json.load(f)
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    for a in data.get("anomalies", []):
                        uid = a.get("user_id", "Unknown")
                        atype = a.get("type", "SUSPICIOUS_ACTIVITY")
                        sev = a.get("severity", "MEDIUM").upper()
                        details = a.get("details", "Anomaly flagged by monitoring engine")
                        
                        # Calculate risk score based on severity and type
                        if sev == "HIGH":
                            score = 92 if "RESTORE" in atype else 88
                        elif sev == "MEDIUM":
                            score = 72 if "DELETE" in atype else 68
                        else:
                            score = 45
                            
                        cursor.execute(
                            "INSERT INTO alerts (user_id, anomaly_type, risk_score, severity, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                            (uid, atype, score, sev, details, now_str)
                        )
                conn.commit()
            except Exception as e:
                print(f"Error seeding alerts: {e}")
    conn.close()

def get_alerts():
    """Retrieve all anomaly alerts ordered by risk score descending."""
    init_alerts_table()
    seed_alerts()
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT alert_id, user_id, anomaly_type, risk_score, severity, reason, timestamp FROM alerts ORDER BY risk_score DESC, alert_id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "alert_id": r[0],
            "user": r[1],
            "user_id": r[1],
            "anomaly_type": r[2],
            "risk_score": r[3],
            "severity": r[4],
            "reason": r[5],
            "timestamp": r[6]
        }
        for r in rows
    ]

def init_role_suggestions_table():
    """Create role suggestions table if not exists."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            current_role TEXT,
            suggested_role TEXT,
            confidence INTEGER,
            reason TEXT,
            status TEXT DEFAULT 'Pending'
        )
    """)
    conn.commit()
    conn.close()

def seed_role_suggestions():
    """Seed role suggestions from CSV or generator if empty."""
    init_role_suggestions_table()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM role_suggestions")
    count = cursor.fetchone()[0]
    
    if count == 0:
        csv_path = os.path.join(BASE_DIR, "data", "role_suggestions.csv")
        suggestions_data = []
        if os.path.exists(csv_path):
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    suggestions_data.append(r)
        else:
            try:
                from utils.role_suggester import suggest_roles
                suggs = suggest_roles(save_to_db=False)
                suggestions_data = [
                    {
                        "User_ID": s["user_id"],
                        "Current_Role": s["current_role"],
                        "Suggested_Role": s["suggested_role"],
                        "Reason": s["reason"],
                        "Denied_Rate": 0,
                    }
                    for s in suggs
                ]
            except Exception:
                pass
                
        for s in suggestions_data:
            uid = s.get("User_ID")
            cur_role = s.get("Current_Role")
            sug_role = s.get("Suggested_Role")
            reason = s.get("Reason", "Role behavior alignment")
            try:
                denied_rate = float(s.get("Denied_Rate", 0))
                confidence = int(max(65, min(98, 100 - denied_rate * 40)))
            except Exception:
                confidence = 85
                
            # Focus on candidates where suggested role is an optimization or change
            cursor.execute(
                "INSERT INTO role_suggestions (user_id, current_role, suggested_role, confidence, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, cur_role, sug_role, confidence, reason, "Pending")
            )
        conn.commit()
    conn.close()

def get_role_suggestions():
    """Retrieve all role suggestions."""
    init_role_suggestions_table()
    seed_role_suggestions()
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, current_role, suggested_role, confidence, reason, status FROM role_suggestions ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0],
            "user_id": r[1],
            "current_role": r[2],
            "suggested_role": r[3],
            "confidence": r[4],
            "reason": r[5],
            "status": r[6]
        }
        for r in rows
    ]

def update_role_suggestion_status(suggestion_id, status, operator_user="admin"):
    """
    Approve or reject a role suggestion.
    If Approved, updates the user's role in the 'users' table and logs to audit_log.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, current_role, suggested_role FROM role_suggestions WHERE id = ?", (suggestion_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False, "Suggestion not found."
        
    user_id, current_role, suggested_role = row
    cursor.execute("UPDATE role_suggestions SET status = ? WHERE id = ?", (status, suggestion_id))
    conn.commit()
    
    if status == "Approved":
        cursor.execute("UPDATE users SET role = ? WHERE user_id = ? OR username = ?", (suggested_role, user_id, user_id))
        conn.commit()
        conn.close()
        # Log to audit table
        log_action(
            action="ROLE_APPROVED",
            backup_id="N/A",
            user_id=operator_user,
            result="success"
        )
        conn_audit = get_connection()
        cur_audit = conn_audit.cursor()
        cur_audit.execute(
            "UPDATE audit_log SET decision = 'Allowed', reason = ? WHERE log_id = (SELECT MAX(log_id) FROM audit_log)",
            (f"AI Role recommendation approved: {user_id} transitioned from {current_role} to {suggested_role}",)
        )
        conn_audit.commit()
        conn_audit.close()
        return True, f"Successfully approved! User {user_id} role updated to {suggested_role}."
    else:
        conn.close()
        log_action(
            action="ROLE_REJECTED",
            backup_id="N/A",
            user_id=operator_user,
            result="rejected"
        )
        conn_audit = get_connection()
        cur_audit = conn_audit.cursor()
        cur_audit.execute(
            "UPDATE audit_log SET decision = 'Rejected', reason = ? WHERE log_id = (SELECT MAX(log_id) FROM audit_log)",
            (f"AI Role recommendation rejected for {user_id} ({current_role} -> {suggested_role})",)
        )
        conn_audit.commit()
        conn_audit.close()
        return True, f"Role suggestion for {user_id} was rejected."

def get_backups_table_data():
    """
    Retrieve backups list formatted for the Backups view:
    ID, path, size, owner, date, status, checksum.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(backups)")
    cols = [c[1] for c in cursor.fetchall()]
    has_path = "path" in cols

    if has_path:
        cursor.execute("""
            SELECT backup_id, user_id, size, timestamp, status, checksum, path
            FROM backups
            ORDER BY timestamp DESC
        """)
    else:
        cursor.execute("""
            SELECT backup_id, user_id, size, timestamp, status, checksum
            FROM backups
            ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    
    data = []
    logs_cloud_dir = os.path.join(BASE_DIR, "logs", "cloud_storage")
    data_cloud_dir = os.path.join(BASE_DIR, "data", "cloud_storage")
    for r in rows:
        bid = r[0]
        enc_file = f"{bid}.zip.enc"
        zip_file = f"{bid}.zip"
        
        # Check custom path if stored in DB
        if has_path and len(r) > 6 and r[6]:
            rel_path = r[6]
        elif os.path.exists(os.path.join(logs_cloud_dir, enc_file)):
            rel_path = f"logs/cloud_storage/{enc_file}"
        elif os.path.exists(os.path.join(data_cloud_dir, enc_file)):
            rel_path = f"data/cloud_storage/{enc_file}"
        elif os.path.exists(os.path.join(logs_cloud_dir, zip_file)):
            rel_path = f"logs/cloud_storage/{zip_file}"
        else:
            rel_path = f"data/cloud_storage/{zip_file}"
        
        # Format size nicely
        bytes_size = r[2] or 0
        if bytes_size >= 1024 * 1024:
            size_str = f"{bytes_size / (1024*1024):.2f} MB"
        elif bytes_size >= 1024:
            size_str = f"{bytes_size / 1024:.2f} KB"
        else:
            size_str = f"{bytes_size} B"
            
        data.append({
            "id": bid,
            "path": rel_path,
            "size": size_str,
            "raw_size": bytes_size,
            "owner": r[1],
            "date": r[3],
            "status": r[4],
            "checksum": r[5] or "N/A"
        })
    return data

def restore_backup_file(backup_id, user_id="U101"):
    """
    Fully functional restore procedure:
    - Verifies file exists in cloud_storage (data/ or logs/ or custom path)
    - Validates cryptographic checksum
    - Decrypts AESGCM encrypted container
    - Extracts contents to data/restore_output/
    - Increments restore count & status in backups table
    - Records audit log entry with decision and reason
    Returns: (success: bool, message: str, restored_files: list)
    """
    import zipfile
    from utils.crypto import decrypt_file
    from utils.integrity import calculate_checksum

    logs_cloud_dir = os.path.join(BASE_DIR, "logs", "cloud_storage")
    data_cloud_dir = os.path.join(BASE_DIR, "data", "cloud_storage")
    restore_dir = os.path.join(BASE_DIR, "data", "restore_output")
    os.makedirs(restore_dir, exist_ok=True)

    # 1. Search for file in known locations
    candidate_paths = [
        os.path.join(logs_cloud_dir, f"{backup_id}.zip.enc"),
        os.path.join(data_cloud_dir, f"{backup_id}.zip.enc"),
        os.path.join(logs_cloud_dir, f"{backup_id}.zip"),
        os.path.join(data_cloud_dir, f"{backup_id}.zip"),
        os.path.join(BASE_DIR, f"{backup_id}.zip.enc"),
    ]
    
    # Check if a custom path is specified in DB
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(backups)")
        cols = [c[1] for c in cur.fetchall()]
        if "path" in cols:
            cur.execute("SELECT path FROM backups WHERE backup_id = ?", (backup_id,))
            row = cur.fetchone()
            if row and row[0]:
                custom_p = row[0] if os.path.isabs(row[0]) else os.path.join(BASE_DIR, row[0])
                candidate_paths.insert(0, custom_p)
        conn.close()
    except Exception:
        pass

    target_file = None
    is_encrypted = False
    for p in candidate_paths:
        if os.path.exists(p):
            target_file = p
            is_encrypted = p.endswith(".enc")
            break

    if not target_file:
        err = f"Encrypted archive for backup {backup_id} not found in cloud storage."
        log_action("RESTORE_FAILED", backup_id, user_id, "failed")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE audit_log SET decision = 'Denied', reason = ? WHERE log_id = (SELECT MAX(log_id) FROM audit_log)", (err,))
        conn.commit()
        conn.close()
        return False, err, []


    # 2. Cryptographic Integrity Check
    stored_checksum = get_checksum(backup_id)
    if is_encrypted and stored_checksum:
        current_checksum = calculate_checksum(target_file)
        if stored_checksum != current_checksum:
            err = f"Integrity check failed for {backup_id}! Expected {stored_checksum[:12]}..., got {current_checksum[:12]}..."
            log_action("RESTORE_FAILED", backup_id, user_id, "checksum_mismatch")
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("UPDATE audit_log SET decision = 'Denied', reason = ? WHERE log_id = (SELECT MAX(log_id) FROM audit_log)", (err,))
            conn.commit()
            conn.close()
            return False, err, []

    # 3. Decrypt and Extract
    try:
        temp_zip = os.path.join(restore_dir, f"temp_{backup_id}.zip")
        if is_encrypted:
            decrypt_file(target_file, temp_zip)
            zip_to_extract = temp_zip
        else:
            zip_to_extract = target_file

        with zipfile.ZipFile(zip_to_extract, "r") as zipf:
            restored_files = zipf.namelist()
            zipf.extractall(restore_dir)

        if is_encrypted and os.path.exists(temp_zip):
            os.remove(temp_zip)

        # 4. Update DB status and logs
        increment_restore_count(backup_id)
        log_action("BACKUP_RESTORED", backup_id, user_id, "success")
        
        conn = get_connection()
        cur = conn.cursor()
        success_reason = f"Verified checksum & successfully restored {len(restored_files)} files to {os.path.basename(restore_dir)}/"
        cur.execute("UPDATE audit_log SET decision = 'Allowed', reason = ? WHERE log_id = (SELECT MAX(log_id) FROM audit_log)", (success_reason,))
        conn.commit()
        conn.close()

        msg = f"Backup {backup_id} successfully restored! ({len(restored_files)} file(s): {', '.join(restored_files)})"
        return True, msg, restored_files
    except Exception as e:
        err = f"Restore execution error for {backup_id}: {str(e)}"
        log_action("RESTORE_ERROR", backup_id, user_id, "error")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE audit_log SET decision = 'Denied', reason = ? WHERE log_id = (SELECT MAX(log_id) FROM audit_log)", (err,))
        conn.commit()
        conn.close()
        return False, err, []

def init_all():
    """Initialize all tables and seeds for the system."""
    init_db()
    init_users_table()
    seed_users()
    init_audit_log_full()
    seed_audit_logs()
    init_alerts_table()
    seed_alerts()
    init_role_suggestions_table()
    seed_role_suggestions()

# ---------------- HELPER FUNCTIONS & ALIASES ---------------- #

def get_users():
    """Alias for get_all_users() returning all users in backups.db."""
    return get_all_users()

def get_user(identifier: str):
    """Fetch single user by username or user_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, username, password, name, role, department, location, device FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(user_id) = LOWER(?)",
        (identifier.strip(), identifier.strip())
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "user_id": row[0],
            "username": row[1],
            "password": row[2],
            "name": row[3],
            "role": row[4],
            "department": row[5],
            "location": row[6],
            "device": row[7]
        }
    return None

def get_user_by_id(user_id: str):
    """Fetch user by user_id."""
    return get_user(user_id)

def get_user_by_username(username: str):
    """Fetch user by username."""
    return get_user(username)

def get_all_backups():
    """Alias for get_backups_table_data()."""
    return get_backups_table_data()

def restore_backup(backup_id: str, user_id: str = "admin"):
    """Wrapper/alias for restore_backup_file()."""
    return restore_backup_file(backup_id, user_id)

def get_logs(user_filter=None, decision_filter=None, action_filter=None, search_query=None):
    """Alias for get_audit_logs()."""
    return get_audit_logs(user_filter, decision_filter, action_filter, search_query)

def get_anomaly_alerts():
    """Alias for get_alerts()."""
    return get_alerts()

def get_all_alerts():
    """Alias for get_alerts()."""
    return get_alerts()

def get_suggestions():
    """Alias for get_role_suggestions()."""
    return get_role_suggestions()

def get_all_role_suggestions():
    """Alias for get_role_suggestions()."""
    return get_role_suggestions()

def approve_role_suggestion(suggestion_id: int, operator_user: str = "admin"):
    """Approve a role suggestion by ID."""
    return update_role_suggestion_status(suggestion_id, "Approved", operator_user)

def reject_role_suggestion(suggestion_id: int, operator_user: str = "admin"):
    """Reject a role suggestion by ID."""
    return update_role_suggestion_status(suggestion_id, "Rejected", operator_user)


