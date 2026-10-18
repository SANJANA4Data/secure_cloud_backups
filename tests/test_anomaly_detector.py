"""
Unit tests for the Anomaly Detection module (utils/anomaly_detector.py).
Covers all 3 detection rules and database persistence / deduplication:
1. High Risk: >20 downloads/restores by a user within a 10-minute window.
2. Medium Risk: Any system access outside standard business hours (9 AM - 6 PM).
3. High Risk: Access from unapproved/unrecognized IP addresses.
4. Database Storage: Inserting generated alerts into the 'alerts' table and deduplication.
"""

import os
import sys
import sqlite3
import pytest
from datetime import datetime, timedelta

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.anomaly_detector import (
    detect_anomalies,
    check_burst_downloads_restores,
    check_off_hours_access,
    check_unapproved_ips,
    is_approved_ip,
    is_outside_business_hours,
)


# ==============================================================================
# RULE 1 TESTS: >20 DOWNLOADS/RESTORES WITHIN A 10-MINUTE WINDOW (HIGH RISK)
# ==============================================================================

def test_rule1_burst_downloads_triggers_high_risk():
    """
    Test Rule 1: User performing >20 downloads within a 10-minute window
    must trigger a High Risk alert (score >= 80, severity 'HIGH').
    """
    base_time = datetime(2026, 10, 18, 10, 0, 0)
    # Generate 21 downloads over 5 minutes (well within the 10-minute window)
    logs = [
        {
            "user_id": "alice",
            "action": "DOWNLOAD",
            "timestamp": (base_time + timedelta(seconds=i * 12)).strftime("%Y-%m-%d %H:%M:%S")
        }
        for i in range(21)
    ]

    anomalies = check_burst_downloads_restores(logs)
    assert len(anomalies) >= 1, "Expected at least 1 burst download anomaly"
    
    alert = anomalies[0]
    assert alert["user_id"] == "alice"
    assert alert["anomaly_type"] == "BURST_DOWNLOAD_RESTORE"
    assert alert["severity"] == "HIGH"
    assert alert["risk_score"] >= 80
    assert "21" in alert["reason"]


def test_rule1_under_threshold_no_alert():
    """
    Test Rule 1: User performing exactly 20 downloads within 10 minutes
    must NOT trigger an anomaly alert (threshold is strictly >20).
    """
    base_time = datetime(2026, 10, 18, 10, 0, 0)
    # Generate exactly 20 downloads
    logs = [
        {
            "user_id": "alice",
            "action": "DOWNLOAD",
            "timestamp": (base_time + timedelta(seconds=i * 15)).strftime("%Y-%m-%d %H:%M:%S")
        }
        for i in range(20)
    ]

    anomalies = check_burst_downloads_restores(logs)
    assert len(anomalies) == 0, "20 downloads should not trigger >20 threshold alert"


def test_rule1_burst_spread_over_time_no_alert():
    """
    Test Rule 1: User performing 25 downloads spaced across 50 minutes
    (at most 5 per 10-minute window) must NOT trigger an anomaly alert.
    """
    base_time = datetime(2026, 10, 18, 10, 0, 0)
    # 25 downloads spaced 2 minutes apart -> 48 minutes total span
    logs = [
        {
            "user_id": "alice",
            "action": "DOWNLOAD",
            "timestamp": (base_time + timedelta(minutes=i * 2)).strftime("%Y-%m-%d %H:%M:%S")
        }
        for i in range(25)
    ]

    anomalies = check_burst_downloads_restores(logs)
    assert len(anomalies) == 0, "Downloads spread beyond 10-min window should not trigger alert"


def test_rule1_mixed_downloads_and_restores_triggers_alert():
    """
    Test Rule 1: Mixed downloads (12) and restores (11) summing to 23 operations
    within 6 minutes must trigger a High Risk burst anomaly.
    """
    base_time = datetime(2026, 10, 18, 11, 0, 0)
    logs = []
    # 12 downloads
    for i in range(12):
        logs.append({
            "user_id": "bob",
            "action": "DOWNLOAD",
            "timestamp": (base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%d %H:%M:%S")
        })
    # 11 restores
    for i in range(11):
        logs.append({
            "user_id": "bob",
            "action": "RESTORE",
            "timestamp": (base_time + timedelta(seconds=120 + i * 10)).strftime("%Y-%m-%d %H:%M:%S")
        })

    anomalies = check_burst_downloads_restores(logs)
    assert len(anomalies) >= 1
    alert = anomalies[0]
    assert alert["user_id"] == "bob"
    assert alert["severity"] == "HIGH"
    assert alert["risk_score"] >= 80
    assert alert["anomaly_type"] == "BURST_DOWNLOAD_RESTORE"


# ==============================================================================
# RULE 2 TESTS: ACCESS OUTSIDE BUSINESS HOURS 9 AM - 6 PM (MEDIUM RISK)
# ==============================================================================

def test_rule2_off_hours_night_and_early_morning():
    """
    Test Rule 2: Access at 22:30 (night) and 04:15 (early morning)
    must trigger Medium Risk alerts (score 60-79, severity 'MEDIUM').
    """
    logs = [
        {
            "user_id": "charlie",
            "action": "DOWNLOAD",
            "timestamp": "2026-10-18 22:30:00"
        },
        {
            "user_id": "charlie",
            "action": "RESTORE",
            "timestamp": "2026-10-18 04:15:00"
        }
    ]

    anomalies = check_off_hours_access(logs)
    assert len(anomalies) == 2, "Both off-hours events should trigger alerts"
    for alert in anomalies:
        assert alert["user_id"] == "charlie"
        assert alert["anomaly_type"] == "OFF_HOURS_ACCESS"
        assert alert["severity"] == "MEDIUM"
        assert 60 <= alert["risk_score"] < 80


def test_rule2_business_hours_no_alert():
    """
    Test Rule 2: Access strictly inside business hours (09:00:00, 12:30:00, 18:00:00)
    must NOT trigger any off-hours anomaly alert.
    """
    logs = [
        {"user_id": "admin", "action": "ACCESS", "timestamp": "2026-10-18 09:00:00"},
        {"user_id": "admin", "action": "DOWNLOAD", "timestamp": "2026-10-18 12:30:00"},
        {"user_id": "admin", "action": "RESTORE", "timestamp": "2026-10-18 18:00:00"}
    ]

    anomalies = check_off_hours_access(logs)
    assert len(anomalies) == 0, "Standard business hours access should not trigger alerts"


def test_rule2_boundary_just_after_business_hours():
    """
    Test Rule 2: Boundary test at 08:59:59 (before 9 AM) and 18:00:01 (after 6 PM).
    Both edge cases must be flagged as off-hours access.
    """
    logs = [
        {"user_id": "alice", "action": "ACCESS", "timestamp": "2026-10-18 08:59:59"},
        {"user_id": "alice", "action": "ACCESS", "timestamp": "2026-10-18 18:00:01"}
    ]

    anomalies = check_off_hours_access(logs)
    assert len(anomalies) == 2, "Events just outside 09:00-18:00 boundary must be flagged"
    assert all(a["severity"] == "MEDIUM" for a in anomalies)
    assert all(a["anomaly_type"] == "OFF_HOURS_ACCESS" for a in anomalies)


# ==============================================================================
# RULE 3 TESTS: UNAPPROVED / UNRECOGNIZED IP ADDRESSES (HIGH RISK)
# ==============================================================================

def test_rule3_unapproved_ip_triggers_high_risk():
    """
    Test Rule 3: Access from an unrecognized public IP (e.g. 203.0.113.195)
    must trigger a High Risk alert (score >= 80, severity 'HIGH').
    """
    logs = [
        {
            "user_id": "guest",
            "action": "DOWNLOAD",
            "ip": "203.0.113.195",
            "timestamp": "2026-10-18 14:00:00"
        }
    ]

    anomalies = check_unapproved_ips(logs)
    assert len(anomalies) == 1, "Unapproved IP access must trigger an anomaly alert"
    alert = anomalies[0]
    assert alert["user_id"] == "guest"
    assert alert["anomaly_type"] == "UNAPPROVED_IP_ACCESS"
    assert alert["severity"] == "HIGH"
    assert alert["risk_score"] >= 80
    assert "203.0.113.195" in alert["reason"]


def test_rule3_approved_ip_no_alert():
    """
    Test Rule 3: Access from recognized corporate subnets
    (127.0.0.1, 10.0.0.1, 172.16.5.10, 192.168.1.50, 155.103.1.20)
    must NOT trigger an IP anomaly alert.
    """
    logs = [
        {"user_id": "alice", "action": "ACCESS", "ip": "127.0.0.1", "timestamp": "2026-10-18 11:00:00"},
        {"user_id": "bob", "action": "DOWNLOAD", "ip": "10.0.0.1", "timestamp": "2026-10-18 11:05:00"},
        {"user_id": "charlie", "action": "RESTORE", "ip": "172.16.5.10", "timestamp": "2026-10-18 11:10:00"},
        {"user_id": "admin", "action": "ACCESS", "ip": "192.168.1.50", "timestamp": "2026-10-18 11:15:00"},
        {"user_id": "guest", "action": "DOWNLOAD", "ip": "155.103.1.20", "timestamp": "2026-10-18 11:20:00"},
    ]

    anomalies = check_unapproved_ips(logs)
    assert len(anomalies) == 0, "Approved corporate IP subnets should not trigger alerts"


# ==============================================================================
# DATABASE STORAGE & DEDUPLICATION TEST
# ==============================================================================

def test_db_insertion_and_deduplication(tmp_path):
    """
    Test Database Persistence:
    1. detect_anomalies(save_to_db=True) properly creates and inserts alerts into
       the SQLite 'alerts' table.
    2. Re-running detect_anomalies with identical logs does not insert duplicate rows.
    """
    test_db = tmp_path / "test_backups.db"
    
    # Create test logs containing 1 burst anomaly, 1 off-hours anomaly, 1 unapproved IP anomaly
    base_time = datetime(2026, 10, 18, 10, 0, 0)
    test_logs = [
        # Burst downloads (22 events)
        *[
            {
                "user_id": "alice",
                "action": "DOWNLOAD",
                "ip": "10.0.0.5",
                "timestamp": (base_time + timedelta(seconds=i * 10)).strftime("%Y-%m-%d %H:%M:%S")
            }
            for i in range(22)
        ],
        # Off-hours access (23:45:00)
        {
            "user_id": "bob",
            "action": "ACCESS",
            "ip": "10.0.0.5",
            "timestamp": "2026-10-18 23:45:00"
        },
        # Unapproved IP access (during business hours)
        {
            "user_id": "charlie",
            "action": "DOWNLOAD",
            "ip": "198.51.100.77",
            "timestamp": "2026-10-18 14:30:00"
        }
    ]

    # Run detection with save_to_db=True
    anomalies_first_run = detect_anomalies(
        db_path=str(test_db),
        access_logs=test_logs,
        save_to_db=True
    )
    assert len(anomalies_first_run) == 3, f"Expected 3 detected anomalies, got {len(anomalies_first_run)}"

    # Verify table schema and data in test database
    conn = sqlite3.connect(str(test_db))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    count_first = cur.fetchone()[0]
    assert count_first == 3, f"Expected 3 rows in alerts table, found {count_first}"

    cur.execute("SELECT user_id, anomaly_type, severity, risk_score FROM alerts ORDER BY alert_id ASC")
    rows = cur.fetchall()
    conn.close()

    types = {r[1] for r in rows}
    assert "BURST_DOWNLOAD_RESTORE" in types
    assert "OFF_HOURS_ACCESS" in types
    assert "UNAPPROVED_IP_ACCESS" in types

    # Second Run with identical logs: Deduplication check
    anomalies_second_run = detect_anomalies(
        db_path=str(test_db),
        access_logs=test_logs,
        save_to_db=True
    )
    assert len(anomalies_second_run) == 3

    conn = sqlite3.connect(str(test_db))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    count_second = cur.fetchone()[0]
    conn.close()

    assert count_second == 3, f"Deduplication failed: alerts count changed from 3 to {count_second}"

