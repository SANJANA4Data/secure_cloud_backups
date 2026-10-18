import os
import sys
import sqlite3
import re
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

# Ensure project root is accessible
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils import db_utils

# ==============================================================================
# CONFIGURATION & RECOGNIZED CORPORATE NETWORKS
# ==============================================================================

# Standard corporate approved IP ranges
DEFAULT_APPROVED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Localhost Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private Class A (Corporate VPN/LAN)
    ipaddress.ip_network("172.16.0.0/12"),    # Private Class B (Corporate Cloud VPC)
    ipaddress.ip_network("192.168.0.0/16"),   # Private Class C (Office Subnets)
    ipaddress.ip_network("155.103.1.0/24"),   # Corporate HQ Gateway
    ipaddress.ip_network("123.93.62.0/24"),   # Branch Office Gateway
    ipaddress.ip_network("63.72.60.0/24"),    # Corporate Partner Network
]

def is_approved_ip(ip_str: Optional[str], approved_networks=None) -> bool:
    """
    Check if an IP address belongs to recognized corporate subnets.
    Returns True if approved, False if unrecognized/unapproved.
    """
    if not ip_str:
        return True  # If no IP is present, do not flag under IP rule
        
    clean_ip = str(ip_str).strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        # Invalid IP string is treated as unapproved
        return False
        
    networks = approved_networks if approved_networks is not None else DEFAULT_APPROVED_NETWORKS
    for net in networks:
        net_obj = ipaddress.ip_network(net) if isinstance(net, str) else net
        if ip_obj in net_obj:
            return True
    return False

def parse_timestamp(ts_val: Any) -> Optional[datetime]:
    """Parse string or datetime object into a datetime object."""
    if isinstance(ts_val, datetime):
        return ts_val
    if not ts_val:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(str(ts_val).strip(), fmt)
        except ValueError:
            continue
    return None

def is_outside_business_hours(dt: datetime) -> bool:
    """
    Check if a datetime falls outside standard business hours (9:00 AM - 6:00 PM).
    Business hours: 09:00:00 to 18:00:00 inclusive.
    Outside hours: hour < 9 or hour > 18 or (hour == 18 and (minute > 0 or second > 0)).
    """
    if dt.hour < 9:
        return True
    if dt.hour > 18:
        return True
    if dt.hour == 18 and (dt.minute > 0 or dt.second > 0):
        return True
    return False

# ==============================================================================
# ANOMALY DETECTION RULES
# ==============================================================================

def check_burst_downloads_restores(logs: List[Dict]) -> List[Dict]:
    """
    Rule 1 (High Risk): >20 downloads/restores by a user within a 10-minute window.
    """
    anomalies = []
    user_events: Dict[str, List] = {}
    
    # Filter downloads and restores with valid timestamps
    for log in logs:
        action = str(log.get("action", "")).strip().upper()
        if action in ["DOWNLOAD", "RESTORE", "BACKUP_RESTORED"]:
            ts = parse_timestamp(log.get("timestamp"))
            if ts:
                uid = str(log.get("user") or log.get("user_id") or "Unknown").strip()
                user_events.setdefault(uid, []).append((ts, log))
                
    # Evaluate rolling 10-minute window per user
    for uid, events in user_events.items():
        events.sort(key=lambda x: x[0])
        n = len(events)
        left = 0
        reported_intervals = set()
        
        for right in range(n):
            # Shrink window from the left if time delta exceeds 10 minutes
            while (events[right][0] - events[left][0]) > timedelta(minutes=10):
                left += 1
            count = right - left + 1
            if count > 20:
                win_start = events[left][0].strftime("%Y-%m-%d %H:%M:%S")
                win_end = events[right][0].strftime("%Y-%m-%d %H:%M:%S")
                key = (uid, win_start)
                if key not in reported_intervals:
                    reported_intervals.add(key)
                    anomalies.append({
                        "user_id": uid,
                        "user": uid,
                        "anomaly_type": "BURST_DOWNLOAD_RESTORE",
                        "risk_score": 92,
                        "severity": "HIGH",
                        "reason": f"High volume activity: User {uid} executed {count} download/restore operations within 10 minutes ({win_start} to {win_end}).",
                        "timestamp": win_end
                    })
    return anomalies

def check_off_hours_access(logs: List[Dict]) -> List[Dict]:
    """
    Rule 2 (Medium Risk): Any system access outside standard business hours (9 AM - 6 PM).
    """
    anomalies = []
    seen = set()
    for log in logs:
        ts = parse_timestamp(log.get("timestamp"))
        if ts and is_outside_business_hours(ts):
            uid = str(log.get("user") or log.get("user_id") or "Unknown").strip()
            action = str(log.get("action", "ACCESS")).strip().upper()
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
            key = (uid, ts_str, action)
            if key not in seen:
                seen.add(key)
                anomalies.append({
                    "user_id": uid,
                    "user": uid,
                    "anomaly_type": "OFF_HOURS_ACCESS",
                    "risk_score": 70,
                    "severity": "MEDIUM",
                    "reason": f"Off-hours system access: User {uid} initiated {action} at {ts_str} outside standard business hours (09:00 - 18:00).",
                    "timestamp": ts_str
                })
    return anomalies

def check_unapproved_ips(logs: List[Dict], approved_networks=None) -> List[Dict]:
    """
    Rule 3 (High Risk): Access from unapproved/unrecognized IP addresses.
    """
    anomalies = []
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    seen = set()
    
    for log in logs:
        ip_val = log.get("ip") or log.get("ip_address")
        if not ip_val:
            # Fallback: check if an IP address string is embedded in the reason field
            reason_str = str(log.get("reason", ""))
            match = ip_pattern.search(reason_str)
            if match:
                ip_val = match.group(0)
                
        if ip_val and not is_approved_ip(ip_val, approved_networks):
            uid = str(log.get("user") or log.get("user_id") or "Unknown").strip()
            action = str(log.get("action", "ACCESS")).strip().upper()
            ts = parse_timestamp(log.get("timestamp"))
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            key = (uid, ip_val, ts_str)
            if key not in seen:
                seen.add(key)
                anomalies.append({
                    "user_id": uid,
                    "user": uid,
                    "anomaly_type": "UNAPPROVED_IP_ACCESS",
                    "risk_score": 90,
                    "severity": "HIGH",
                    "reason": f"Unrecognized IP access: User {uid} executed {action} from unapproved IP address {ip_val}.",
                    "timestamp": ts_str
                })
    return anomalies

# ==============================================================================
# MAIN DETECTION & STORAGE ENGINE
# ==============================================================================

def detect_anomalies(
    db_path: Optional[str] = None,
    access_logs: Optional[List[Dict]] = None,
    save_to_db: bool = True,
    approved_networks: Optional[List[Any]] = None
) -> List[Dict]:
    """
    Core anomaly detection routine:
    1. Evaluates logs against Rule 1 (>20 downloads/restores in 10-minute window).
    2. Evaluates logs against Rule 2 (Off-hours access outside 9 AM - 6 PM).
    3. Evaluates logs against Rule 3 (Access from unapproved/unrecognized IP addresses).
    4. Saves generated alerts to the 'alerts' table in logs/backups.db (or specified db_path).
    
    Returns:
        List of generated anomaly alert dictionaries.
    """
    target_db = db_path if db_path else db_utils.get_db_path()
    
    # 1. Fetch access logs if not explicitly passed
    logs_to_check: List[Dict] = []
    if access_logs is not None:
        logs_to_check = access_logs
    else:
        # Load logs from target database audit_log table
        if os.path.exists(target_db):
            conn = sqlite3.connect(target_db)
            cur = conn.cursor()
            
            # Check table schema
            cur.execute("PRAGMA table_info(audit_log)")
            cols = [c[1] for c in cur.fetchall()]
            
            if cols:
                has_ip = "ip" in cols
                if has_ip:
                    cur.execute("SELECT user_id, action, backup_id, timestamp, decision, reason, ip FROM audit_log ORDER BY timestamp ASC")
                    rows = cur.fetchall()
                    for r in rows:
                        logs_to_check.append({
                            "user_id": r[0],
                            "user": r[0],
                            "action": r[1],
                            "backup_id": r[2],
                            "timestamp": r[3],
                            "decision": r[4],
                            "reason": r[5],
                            "ip": r[6]
                        })
                else:
                    cur.execute("SELECT user_id, action, backup_id, timestamp, decision, reason FROM audit_log ORDER BY timestamp ASC")
                    rows = cur.fetchall()
                    for r in rows:
                        logs_to_check.append({
                            "user_id": r[0],
                            "user": r[0],
                            "action": r[1],
                            "backup_id": r[2],
                            "timestamp": r[3],
                            "decision": r[4],
                            "reason": r[5],
                            "ip": None
                        })
            conn.close()

    # 2. Execute Detection Rules
    all_anomalies: List[Dict] = []
    all_anomalies.extend(check_burst_downloads_restores(logs_to_check))
    all_anomalies.extend(check_off_hours_access(logs_to_check))
    all_anomalies.extend(check_unapproved_ips(logs_to_check, approved_networks))

    # 3. Store into 'alerts' table in database if requested
    if save_to_db and all_anomalies:
        os.makedirs(os.path.dirname(os.path.abspath(target_db)), exist_ok=True)
        conn = sqlite3.connect(target_db)
        cur = conn.cursor()
        
        # Ensure alerts table exists
        cur.execute("""
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
        
        # Fetch existing alerts for deduplication
        cur.execute("SELECT user_id, anomaly_type, reason FROM alerts")
        existing_keys = {(r[0], r[1], r[2]) for r in cur.fetchall()}
        
        to_insert = []
        for a in all_anomalies:
            key = (a["user_id"], a["anomaly_type"], a["reason"])
            if key not in existing_keys:
                existing_keys.add(key)
                to_insert.append((
                    a["user_id"],
                    a["anomaly_type"],
                    a["risk_score"],
                    a["severity"],
                    a["reason"],
                    a["timestamp"]
                ))
                
        if to_insert:
            cur.executemany(
                "INSERT INTO alerts (user_id, anomaly_type, risk_score, severity, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                to_insert
            )
            conn.commit()
        conn.close()

    return all_anomalies

if __name__ == "__main__":
    alerts = detect_anomalies()
    print(f"[OK] Detection executed. Total detected alerts: {len(alerts)}")
    for a in alerts[:5]:
        print(f" - [{a['severity']} | Score {a['risk_score']}] User {a['user_id']}: {a['reason']}")
