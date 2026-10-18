import os
import sys
import sqlite3
import hashlib
import zipfile
import random
from datetime import datetime, timedelta

# Ensure project root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from utils.crypto import encrypt_file
from utils.integrity import calculate_checksum

LOGS_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(LOGS_DIR, "backups.db")
CLOUD_DIR = os.path.join(LOGS_DIR, "cloud_storage")
DATA_CLOUD_DIR = os.path.join(BASE_DIR, "data", "cloud_storage")
TEMP_DIR = os.path.join(LOGS_DIR, "temp_data")

def hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def create_tables(conn):
    """Create all necessary database tables if they do not exist."""
    cursor = conn.cursor()
    
    # 1. Users table
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
    
    # 2. Backups table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backups (
            backup_id TEXT PRIMARY KEY,
            user_id TEXT,
            version INTEGER,
            size INTEGER,
            checksum TEXT,
            timestamp TEXT,
            status TEXT,
            path TEXT
        )
    """)
    
    # Check if 'path' column exists in backups table
    cursor.execute("PRAGMA table_info(backups)")
    cols = [c[1] for c in cursor.fetchall()]
    if "path" not in cols:
        cursor.execute("ALTER TABLE backups ADD COLUMN path TEXT")
    
    # 3. Audit log table
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
    
    # 4. Alerts table
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
    
    # 5. Role suggestions table
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

def populate_users(conn):
    """Populate 5 realistic users: alice, bob, charlie, admin, guest."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    
    users = [
        ("U000", "admin", hash_password("admin123"), "System Administrator", "Admin", "IT Security", "HQ Office", "Corporate"),
        ("U001", "alice", hash_password("alice123"), "Alice Smith", "Owner", "Engineering", "Office", "Corporate"),
        ("U002", "bob", hash_password("bob123"), "Bob Jones", "Restorer", "Site Reliability", "Remote", "Corporate"),
        ("U003", "charlie", hash_password("charlie123"), "Charlie Davis", "Viewer", "Finance & Audit", "Office", "Corporate"),
        ("U005", "guest", hash_password("guest123"), "Guest Auditor", "Viewer", "External Audit", "Remote", "Personal"),
        # Also support U-prefix legacy identifiers as aliases
        ("U-ADMIN", "admin_sec", hash_password("admin123"), "System Administrator", "Admin", "IT Security", "HQ Office", "Corporate"),
        ("U-ALICE", "alice_eng", hash_password("alice123"), "Alice Smith", "Owner", "Engineering", "Office", "Corporate"),
        ("U-BOB", "bob_sre", hash_password("bob123"), "Bob Jones", "Restorer", "Site Reliability", "Remote", "Corporate"),
        ("U-CHARLIE", "charlie_fin", hash_password("charlie123"), "Charlie Davis", "Viewer", "Finance & Audit", "Office", "Corporate"),
        ("U-GUEST", "guest_aud", hash_password("guest123"), "Guest Auditor", "Viewer", "External Audit", "Remote", "Personal"),
    ]
    
    cursor.executemany(
        "INSERT INTO users (user_id, username, password, name, role, department, location, device) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        users
    )
    conn.commit()
    print(f"[OK] Populated {len(users)} users (alice/U001, bob/U002, charlie/U003, admin/U000, guest/U005)")

def create_physical_backup_file(backup_id: str, sample_filenames: list) -> tuple:
    """Create a real encrypted container for the backup with verified checksum."""
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(CLOUD_DIR, exist_ok=True)
    os.makedirs(DATA_CLOUD_DIR, exist_ok=True)
    
    # Step 1: Create a zip with sample files
    temp_zip = os.path.join(TEMP_DIR, f"{backup_id}.zip")
    with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in sample_filenames:
            dummy_content = f"--- SECURE BACKUP PAYLOAD FOR {backup_id} ---\nFile: {fname}\nCreated: {datetime.now().isoformat()}\nConfidential encrypted contents.\n" * 20
            zf.writestr(fname, dummy_content.encode("utf-8"))
            
    # Step 2: Encrypt the zip
    enc_path_logs = os.path.join(CLOUD_DIR, f"{backup_id}.zip.enc")
    enc_path_data = os.path.join(DATA_CLOUD_DIR, f"{backup_id}.zip.enc")
    
    encrypt_file(temp_zip, enc_path_logs)
    encrypt_file(temp_zip, enc_path_data)
    
    if os.path.exists(temp_zip):
        os.remove(temp_zip)
        
    # Step 3: Compute exact sha256 and size
    checksum = calculate_checksum(enc_path_logs)
    actual_size = os.path.getsize(enc_path_logs)
    
    return enc_path_logs, checksum, actual_size

def populate_backups(conn):
    """Populate 10 realistic backups (BK-001 to BK-010) with physical files & checksums."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM backups")
    
    backup_specs = [
        ("BK-001", "alice", 1, ["core_api_dump.sql", "app_manifest.json"], "2026-10-10 09:15:22", "active", 1485760),
        ("BK-002", "bob", 1, ["k8s_cluster_state.yaml", "helm_values.yaml"], "2026-10-11 11:30:45", "active", 3670016),
        ("BK-003", "admin", 2, ["finance_ledger_q3.xlsx", "tax_returns.pdf"], "2026-10-12 14:05:10", "restored", 10485760),
        ("BK-004", "alice", 1, ["customer_database.sql", "users_export.csv"], "2026-10-13 16:42:19", "active", 5242880),
        ("BK-005", "bob", 2, ["telemetry_logs.parquet", "syslog_archive.gz"], "2026-10-14 18:20:00", "restored", 2097152),
        ("BK-006", "admin", 1, ["pki_certificates.pem", "vault_backup.tar"], "2026-10-15 08:12:33", "active", 8388608),
        ("BK-007", "alice", 1, ["ml_model_weights.bin", "model_params.json"], "2026-10-16 10:45:51", "active", 12582912),
        ("BK-008", "bob", 3, ["production_redis.rdb", "cache_snapshot.bin"], "2026-10-17 13:22:15", "restored", 4194304),
        ("BK-009", "charlie", 1, ["quarterly_audit_records.pdf", "compliance_sheet.csv"], "2026-10-17 19:55:04", "active", 6291456),
        ("BK-010", "admin", 1, ["enterprise_active_directory.ldif", "iam_policies.json"], "2026-10-18 07:10:28", "active", 15728640),
    ]
    
    rows = []
    for bid, owner, ver, files, dt_str, status, nominal_size in backup_specs:
        rel_path = f"logs/cloud_storage/{bid}.zip.enc"
        _, checksum, actual_size = create_physical_backup_file(bid, files)
        
        # Use nominal size for realistic large file display or actual_size
        display_size = nominal_size if nominal_size > actual_size else actual_size
        rows.append((bid, owner, ver, display_size, checksum, dt_str, status, rel_path))
        
    cursor.executemany(
        "INSERT INTO backups (backup_id, user_id, version, size, checksum, timestamp, status, path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows
    )
    conn.commit()
    print(f"[OK] Populated {len(rows)} backups (BK-001 to BK-010) with verified encrypted archives")

def populate_access_logs(conn):
    """Populate 50 access logs with a realistic mix of actions and decisions."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_log")
    
    users = ["alice", "bob", "charlie", "admin", "guest"]
    backup_ids = [f"BK-{i:03d}" for i in range(1, 11)]
    
    # Concrete realistic scenarios
    scenarios = [
        # Admin operations (mostly ALLOW)
        ("admin", "BK-006", "RESTORE", "ALLOW", "Disaster recovery dry-run authorization confirmed"),
        ("admin", "BK-010", "DOWNLOAD", "ALLOW", "Routine security compliance audit review"),
        ("admin", "BK-003", "DELETE", "ALLOW", "Authorized retention lifecycle decommissioning"),
        ("admin", "BK-001", "DOWNLOAD", "ALLOW", "Cross-department incident triage access"),
        
        # Alice (Owner) operations
        ("alice", "BK-001", "DOWNLOAD", "ALLOW", "Owner downloaded latest core API backup container"),
        ("alice", "BK-004", "RESTORE", "ALLOW", "Owner verified customer database restoration"),
        ("alice", "BK-007", "DOWNLOAD", "ALLOW", "Model engineering deployment bundle pull"),
        ("alice", "BK-002", "DELETE", "DENY", "Denied: Alice is not the owner of BK-002"),
        ("alice", "BK-010", "DOWNLOAD", "DENY", "Denied: Admin security clearances required for IAM backup"),
        
        # Bob (Restorer) operations
        ("bob", "BK-002", "RESTORE", "ALLOW", "Restorer role authorized for cluster state restoration"),
        ("bob", "BK-005", "RESTORE", "ALLOW", "Restorer executed telemetry restoration to staging"),
        ("bob", "BK-008", "DOWNLOAD", "ALLOW", "Routine validation download of Redis snapshot"),
        ("bob", "BK-001", "RESTORE", "ALLOW", "Operational recovery ticket #INC-8921 verified"),
        ("bob", "BK-006", "DELETE", "DENY", "Denied: Restorers do not possess deletion privileges"),
        ("bob", "BK-004", "DELETE", "DENY", "Denied: Delete action restricted to Admin and Owner"),
        
        # Charlie (Viewer) operations
        ("charlie", "BK-009", "DOWNLOAD", "ALLOW", "Viewer read-only download of compliance records"),
        ("charlie", "BK-003", "DOWNLOAD", "ALLOW", "Authorized download of financial audit reports"),
        ("charlie", "BK-001", "RESTORE", "DENY", "Denied: Viewer role is not permitted to execute restores"),
        ("charlie", "BK-002", "RESTORE", "DENY", "Denied: Viewer cannot trigger restore pipeline"),
        ("charlie", "BK-005", "DELETE", "DENY", "Denied: Viewer cannot delete backup assets"),
        ("charlie", "BK-007", "DELETE", "DENY", "Denied: Deletion attempted without requisite permissions"),
        
        # Guest operations (high denial rate)
        ("guest", "BK-009", "DOWNLOAD", "ALLOW", "Read-only audit inspection granted"),
        ("guest", "BK-001", "DELETE", "DENY", "Denied: Guest accounts are strictly forbidden from deleting backups"),
        ("guest", "BK-002", "DELETE", "DENY", "Denied: Unauthorized delete request blocked by RBAC engine"),
        ("guest", "BK-004", "DELETE", "DENY", "Denied: Zero-trust policy revoked unauthenticated delete token"),
        ("guest", "BK-006", "RESTORE", "DENY", "Denied: Guest lacks restoration privileges for PKI assets"),
        ("guest", "BK-010", "DOWNLOAD", "DENY", "Denied: Guest access barred from IAM infrastructure archives"),
        ("guest", "BK-008", "RESTORE", "DENY", "Denied: Unregistered device attempted restore invocation"),
    ]
    
    # Fill remaining entries to reach exactly 50 with balanced timestamps
    actions = ["DOWNLOAD", "RESTORE", "DELETE"]
    base_time = datetime(2026, 10, 18, 20, 0, 0)
    
    logs_data = []
    
    # Add predetermined scenarios first
    for i, (u, bid, act, dec, reas) in enumerate(scenarios):
        ts = (base_time - timedelta(hours=i * 2.2 + random.randint(10, 45))).strftime("%Y-%m-%d %H:%M:%S")
        logs_data.append((u, act, bid, ts, dec, dec, reas))
        
    # Generate remainder up to 50
    needed = 50 - len(logs_data)
    for j in range(needed):
        u = random.choice(users)
        bid = random.choice(backup_ids)
        act = random.choice(actions)
        
        # Realistic policy check
        if u == "admin":
            dec = "ALLOW"
            reas = f"Admin authorized operation ({act}) on {bid}"
        elif act == "DELETE":
            dec = "DENY"
            reas = f"Denied: Role '{u}' prohibited from executing DELETE on {bid}"
        elif act == "RESTORE" and u in ["charlie", "guest"]:
            dec = "DENY"
            reas = f"Denied: Viewers and Guests cannot initiate restore operations"
        elif u == "guest" and act == "DOWNLOAD" and random.random() < 0.5:
            dec = "DENY"
            reas = "Denied: Guest rate-limit quota exceeded for session"
        else:
            dec = "ALLOW"
            reas = f"Access granted by standard RBAC policy for {act}"
            
        ts = (base_time - timedelta(hours=(len(logs_data) + j) * 1.8 + random.randint(5, 30))).strftime("%Y-%m-%d %H:%M:%S")
        logs_data.append((u, act, bid, ts, dec, dec, reas))
        
    # Sort chronologically descending
    logs_data.sort(key=lambda x: x[3], reverse=True)
    
    cursor.executemany(
        "INSERT INTO audit_log (user_id, action, backup_id, timestamp, result, decision, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
        logs_data
    )
    conn.commit()
    print(f"[OK] Populated {len(logs_data)} access logs with DOWNLOAD, RESTORE, DELETE and ALLOW/DENY decisions")

def populate_anomaly_alerts(conn):
    """Populate 5 anomaly alerts with varying risk scores and reasons."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    
    alerts_data = [
        ("guest", "UNAUTHORIZED_DELETE_SPIKE", 95, "HIGH", "Guest user triggered 14 unauthorized DELETE requests within 3 minutes on sensitive databases.", "2026-10-18 19:42:10"),
        ("charlie", "PERSONAL_DEVICE_RESTORE", 88, "HIGH", "Restore attempt initiated on personal untrusted endpoint for backup BK-003.", "2026-10-18 17:15:33"),
        ("bob", "OFF_HOURS_BULK_DOWNLOAD", 76, "MEDIUM", "Unusual bulk download of 8 encrypted containers detected at 02:45 AM local time.", "2026-10-18 02:45:19"),
        ("alice", "RAPID_IP_GEOLOCATION_SHIFT", 65, "MEDIUM", "Access sessions initiated from two disparate countries (US and NL) within 20 minutes.", "2026-10-17 22:10:04"),
        ("charlie", "UNEXPECTED_READ_FREQUENCY", 42, "LOW", "Read query volume is 2.5x above standard baseline for user's peer group.", "2026-10-17 15:30:45"),
    ]
    
    cursor.executemany(
        "INSERT INTO alerts (user_id, anomaly_type, risk_score, severity, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        alerts_data
    )
    conn.commit()
    print(f"[OK] Populated {len(alerts_data)} anomaly alerts with varying risk scores (42–95)")

def populate_role_suggestions(conn):
    """Populate role suggestions data for the AI Role Suggestions page."""
    cursor = conn.cursor()
    cursor.execute("DELETE FROM role_suggestions")
    
    suggestions_data = [
        ("charlie", "Viewer", "Restorer", 88, "User executed 12 verified recovery verifications in the last 14 days without incident; promoting to Restorer aligns with workload.", "Pending"),
        ("bob", "Restorer", "Owner", 91, "Consistent creation and management of departmental backup sets with zero policy violations across 90 days.", "Pending"),
        ("guest", "Viewer", "Restricted Viewer", 96, "Multiple denied delete and export attempts detected; recommend stripping download rights to metadata-only viewing.", "Pending"),
        ("alice", "Owner", "Admin", 84, "Manages multi-region backup topologies and infrastructure configs; elevated role streamlines maintenance operations.", "Pending")
    ]
    
    cursor.executemany(
        "INSERT INTO role_suggestions (user_id, current_role, suggested_role, confidence, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
        suggestions_data
    )
    conn.commit()
    print(f"[OK] Populated {len(suggestions_data)} AI role suggestions with pending review actions")

def main():
    print(f"--- Generating Dummy Data in {DB_PATH} ---")
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    try:
        create_tables(conn)
        populate_users(conn)
        populate_backups(conn)
        populate_access_logs(conn)
        populate_anomaly_alerts(conn)
        populate_role_suggestions(conn)
        print("--- All Data Generated Successfully! ---")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
