"""
Unit tests for the AI Role Suggester module (utils/role_suggester.py).
Covers Scikit-Learn K-Means clustering, feature engineering, Zero-Trust RBAC role
recommendations, explainable AI rationales, and database persistence:

1. Feature extraction accuracy (downloads, restores, deletes, off-hours, denials).
2. K-Means clustering: Restorer archetype recommendation.
3. K-Means clustering: Admin archetype recommendation.
4. K-Means clustering: Owner archetype recommendation.
5. Zero-Trust Least-Privilege: High denial rates recommend Viewer role.
6. Confidence score validity and bounds (50 - 100%).
7. Explainable AI rationale validation.
8. SQLite database persistence with Pending status.
9. Idempotence and non-duplication of pending suggestions.
10. Edge cases: Empty logs and single-user datasets.
"""

import os
import sys
import sqlite3
import pytest
import pandas as pd
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.role_suggester import (
    extract_user_features,
    cluster_users,
    generate_recommendations,
    save_suggestions_to_db,
    suggest_roles,
    is_off_hours,
)


# ==============================================================================
# 1. FEATURE EXTRACTION ACCURACY
# ==============================================================================

def test_feature_extraction_accuracy():
    """
    Verify that user actions from access logs are accurately converted into
    numerical behavioral feature vectors.
    """
    synthetic_logs = [
        {"user_id": "user_dev", "action": "DOWNLOAD", "timestamp": "2026-10-18 10:00:00", "result": "ALLOW"},
        {"user_id": "user_dev", "action": "DOWNLOAD", "timestamp": "2026-10-18 11:30:00", "result": "ALLOW"},
        {"user_id": "user_dev", "action": "RESTORE", "timestamp": "2026-10-18 14:00:00", "result": "ALLOW"},
        {"user_id": "user_dev", "action": "DELETE", "timestamp": "2026-10-18 22:00:00", "result": "DENY"},  # Off-hours & denied
        {"user_id": "user_dev", "action": "DOWNLOAD", "timestamp": "2026-10-18 04:00:00", "result": "ALLOW"},  # Off-hours
    ]

    users_map = {"user_dev": "Viewer"}
    df = extract_user_features(synthetic_logs, users_map=users_map)

    assert not df.empty
    user_row = df[df["user_id"] == "user_dev"].iloc[0]

    assert user_row["total_actions"] == 5
    assert user_row["download_count"] == 3
    assert user_row["restore_count"] == 1
    assert user_row["delete_count"] == 1
    assert user_row["off_hours_count"] == 2  # 22:00 and 04:00
    assert user_row["denied_count"] == 1
    assert pytest.approx(user_row["denied_rate"], 0.01) == 0.20
    assert pytest.approx(user_row["restore_freq"], 0.01) == 0.20


# ==============================================================================
# 2. RESTORER CLUSTERING TEST
# ==============================================================================

def test_kmeans_clustering_restorer_archetype():
    """
    Users with high restore counts and recovery workloads must be clustered
    and recommended the 'Restorer' role.
    """
    synthetic_logs = []
    # User with dominant restore operations
    for i in range(12):
        synthetic_logs.append({
            "user_id": "recovery_lead",
            "action": "RESTORE",
            "timestamp": "2026-10-18 11:00:00",
            "result": "ALLOW"
        })
    # User with standard monitoring
    for i in range(8):
        synthetic_logs.append({
            "user_id": "monitor_analyst",
            "action": "DOWNLOAD",
            "timestamp": "2026-10-18 10:00:00",
            "result": "ALLOW"
        })

    users_map = {"recovery_lead": "Viewer", "monitor_analyst": "Viewer"}
    suggestions = suggest_roles(access_logs=synthetic_logs, save_to_db=False, n_clusters=2)

    recovery_sugg = next(s for s in suggestions if s["user_id"] == "recovery_lead")
    assert recovery_sugg["suggested_role"] == "Restorer"
    assert recovery_sugg["confidence"] >= 80
    assert "restorer" in recovery_sugg["reason"].lower() or "restore" in recovery_sugg["reason"].lower()


# ==============================================================================
# 3. ADMIN CLUSTERING TEST
# ==============================================================================

def test_kmeans_clustering_admin_archetype():
    """
    Users performing administrative deletion/lifecycle tasks and off-hours
    maintenance with authorized access must be assigned the 'Admin' role.
    """
    synthetic_logs = []
    # Admin profile: multiple deletes and off-hours actions
    for i in range(6):
        synthetic_logs.append({
            "user_id": "ops_engineer",
            "action": "DELETE",
            "timestamp": "2026-10-18 23:15:00",  # Off-hours
            "result": "ALLOW"
        })
    for i in range(4):
        synthetic_logs.append({
            "user_id": "ops_engineer",
            "action": "DOWNLOAD",
            "timestamp": "2026-10-18 14:00:00",
            "result": "ALLOW"
        })

    # Read-only user for cluster contrast
    for i in range(5):
        synthetic_logs.append({
            "user_id": "auditor_guest",
            "action": "DOWNLOAD",
            "timestamp": "2026-10-18 10:00:00",
            "result": "ALLOW"
        })

    users_map = {"ops_engineer": "Owner", "auditor_guest": "Viewer"}
    suggestions = suggest_roles(access_logs=synthetic_logs, save_to_db=False, n_clusters=2)

    ops_sugg = next(s for s in suggestions if s["user_id"] == "ops_engineer")
    assert ops_sugg["suggested_role"] == "Admin"
    assert ops_sugg["confidence"] >= 85
    assert "admin" in ops_sugg["reason"].lower() or "deletions" in ops_sugg["reason"].lower()


# ==============================================================================
# 4. OWNER CLUSTERING TEST
# ==============================================================================

def test_kmeans_clustering_owner_archetype():
    """
    Users with active backup management (consistent downloads/creation)
    and zero administrative deletions or heavy restores should be assigned 'Owner'.
    """
    synthetic_logs = [
        {"user_id": "service_owner", "action": "DOWNLOAD", "timestamp": "2026-10-18 10:00:00", "result": "ALLOW"},
        {"user_id": "service_owner", "action": "DOWNLOAD", "timestamp": "2026-10-18 11:00:00", "result": "ALLOW"},
        {"user_id": "service_owner", "action": "DOWNLOAD", "timestamp": "2026-10-18 12:00:00", "result": "ALLOW"},
        {"user_id": "service_owner", "action": "DOWNLOAD", "timestamp": "2026-10-18 14:00:00", "result": "ALLOW"},
        {"user_id": "service_owner", "action": "DOWNLOAD", "timestamp": "2026-10-18 15:00:00", "result": "ALLOW"},
        # Another user with minimal activity
        {"user_id": "casual_user", "action": "DOWNLOAD", "timestamp": "2026-10-18 09:30:00", "result": "ALLOW"},
    ]

    users_map = {"service_owner": "Restorer", "casual_user": "Viewer"}
    suggestions = suggest_roles(access_logs=synthetic_logs, save_to_db=False, n_clusters=2)

    owner_sugg = next(s for s in suggestions if s["user_id"] == "service_owner")
    assert owner_sugg["suggested_role"] == "Owner"
    assert owner_sugg["confidence"] >= 80


# ==============================================================================
# 5. ZERO-TRUST LEAST PRIVILEGE TEST (VIEWER DEMOTION)
# ==============================================================================

def test_least_privilege_viewer_recommendation():
    """
    Users with a high denial rate (>=50%) must be recommended the 'Viewer' role
    under Zero-Trust least-privilege principles to mitigate potential compromise.
    """
    synthetic_logs = [
        {"user_id": "compromised_acc", "action": "DELETE", "timestamp": "2026-10-18 02:00:00", "result": "DENY"},
        {"user_id": "compromised_acc", "action": "DELETE", "timestamp": "2026-10-18 02:05:00", "result": "DENY"},
        {"user_id": "compromised_acc", "action": "RESTORE", "timestamp": "2026-10-18 02:10:00", "result": "DENY"},
        {"user_id": "compromised_acc", "action": "DOWNLOAD", "timestamp": "2026-10-18 02:15:00", "result": "ALLOW"},
    ]

    users_map = {"compromised_acc": "Admin"}
    suggestions = suggest_roles(access_logs=synthetic_logs, save_to_db=False, n_clusters=1)

    sugg = next(s for s in suggestions if s["user_id"] == "compromised_acc")
    assert sugg["suggested_role"] == "Viewer"
    assert sugg["confidence"] >= 80
    assert "least privilege" in sugg["reason"].lower() or "denial rate" in sugg["reason"].lower()


# ==============================================================================
# 6. CONFIDENCE SCORE RANGE TEST
# ==============================================================================

def test_confidence_scores_within_valid_bounds():
    """
    Verify that AI confidence scores for all suggestions are integers strictly
    within [50, 100].
    """
    synthetic_logs = [
        {"user_id": f"user_{i}", "action": "DOWNLOAD", "timestamp": "2026-10-18 10:00:00", "result": "ALLOW"}
        for i in range(8)
    ]
    synthetic_logs.extend([
        {"user_id": "power_user", "action": "RESTORE", "timestamp": "2026-10-18 12:00:00", "result": "ALLOW"}
        for _ in range(5)
    ])

    suggestions = suggest_roles(access_logs=synthetic_logs, save_to_db=False, n_clusters=2)
    assert len(suggestions) >= 2

    for s in suggestions:
        assert isinstance(s["confidence"], int)
        assert 50 <= s["confidence"] <= 100, f"Confidence {s['confidence']} out of valid range"


# ==============================================================================
# 7. EXPLAINABLE AI RATIONALE VALIDATION
# ==============================================================================

def test_explainable_rationale_content():
    """
    Verify that every recommendation provides an explainable AI rationale citing
    the cluster index and behavioral metrics.
    """
    synthetic_logs = [
        {"user_id": "u_admin", "action": "DELETE", "timestamp": "2026-10-18 21:00:00", "result": "ALLOW"},
        {"user_id": "u_admin", "action": "DELETE", "timestamp": "2026-10-18 22:00:00", "result": "ALLOW"},
        {"user_id": "u_admin", "action": "DELETE", "timestamp": "2026-10-18 23:00:00", "result": "ALLOW"},
        {"user_id": "u_restorer", "action": "RESTORE", "timestamp": "2026-10-18 10:00:00", "result": "ALLOW"},
        {"user_id": "u_restorer", "action": "RESTORE", "timestamp": "2026-10-18 11:00:00", "result": "ALLOW"},
        {"user_id": "u_restorer", "action": "RESTORE", "timestamp": "2026-10-18 12:00:00", "result": "ALLOW"},
    ]

    suggestions = suggest_roles(access_logs=synthetic_logs, save_to_db=False, n_clusters=2)

    for s in suggestions:
        assert "reason" in s
        assert isinstance(s["reason"], str)
        assert len(s["reason"]) >= 20, "Rationale should be descriptive"
        assert "Cluster" in s["reason"]


# ==============================================================================
# 8. DATABASE PERSISTENCE TEST
# ==============================================================================

def test_database_persistence_pending_status(tmp_path):
    """
    Verify that suggest_roles correctly saves suggestions into the 'role_suggestions'
    table in an SQLite database with status 'Pending'.
    """
    db_file = tmp_path / "test_backups.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE users (
            user_id TEXT PRIMARY KEY,
            username TEXT,
            role TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE audit_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            action TEXT,
            timestamp TEXT,
            result TEXT,
            decision TEXT,
            reason TEXT
        )
    """)
    cur.execute("INSERT INTO users VALUES ('U10', 'jdoe', 'Viewer')")
    cur.execute("INSERT INTO audit_log (user_id, action, timestamp, result) VALUES ('jdoe', 'RESTORE', '2026-10-18 10:00:00', 'ALLOW')")
    cur.execute("INSERT INTO audit_log (user_id, action, timestamp, result) VALUES ('jdoe', 'RESTORE', '2026-10-18 11:00:00', 'ALLOW')")
    cur.execute("INSERT INTO audit_log (user_id, action, timestamp, result) VALUES ('jdoe', 'RESTORE', '2026-10-18 12:00:00', 'ALLOW')")
    cur.execute("INSERT INTO audit_log (user_id, action, timestamp, result) VALUES ('jdoe', 'RESTORE', '2026-10-18 13:00:00', 'ALLOW')")
    conn.commit()
    conn.close()

    suggestions = suggest_roles(db_path=str(db_file), save_to_db=True)
    assert len(suggestions) == 1
    assert suggestions[0]["suggested_role"] == "Restorer"

    # Verify table in SQLite
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT user_id, current_role, suggested_role, status FROM role_suggestions")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][0] == "jdoe"
    assert rows[0][1] == "Viewer"
    assert rows[0][2] == "Restorer"
    assert rows[0][3] == "Pending"


# ==============================================================================
# 9. IDEMPOTENCE AND NON-DUPLICATION TEST
# ==============================================================================

def test_idempotent_clustering_updates_existing_pending(tmp_path):
    """
    Verify that running suggest_roles multiple times updates existing pending
    suggestions rather than inserting duplicate pending rows for the same user.
    """
    db_file = tmp_path / "test_idempotent.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (user_id TEXT, username TEXT, role TEXT)")
    cur.execute("CREATE TABLE audit_log (log_id INTEGER PRIMARY KEY, user_id TEXT, action TEXT, timestamp TEXT, result TEXT, decision TEXT, reason TEXT)")
    cur.execute("INSERT INTO users VALUES ('U1', 'alice', 'Owner')")
    cur.execute("INSERT INTO audit_log (user_id, action, timestamp, result) VALUES ('alice', 'DOWNLOAD', '2026-10-18 10:00:00', 'ALLOW')")
    conn.commit()
    conn.close()

    # First run
    suggest_roles(db_path=str(db_file), save_to_db=True)
    # Second run
    suggest_roles(db_path=str(db_file), save_to_db=True)

    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM role_suggestions WHERE user_id = 'alice'")
    count = cur.fetchone()[0]
    conn.close()

    assert count == 1, "Pending suggestions should be updated, not duplicated"


# ==============================================================================
# 10. EDGE CASES: EMPTY AND SINGLE-USER LOGS
# ==============================================================================

def test_edge_cases_empty_and_single_user():
    """
    Verify that empty logs return an empty list, and a single-user dataset is handled
    gracefully without crashing Scikit-Learn's K-Means clustering algorithm.
    """
    # Case A: Empty logs
    assert suggest_roles(access_logs=[], save_to_db=False) == []

    # Case B: Single user
    single_user_log = [
        {"user_id": "solo_admin", "action": "DELETE", "timestamp": "2026-10-18 22:00:00", "result": "ALLOW"},
        {"user_id": "solo_admin", "action": "DELETE", "timestamp": "2026-10-18 23:00:00", "result": "ALLOW"},
        {"user_id": "solo_admin", "action": "DELETE", "timestamp": "2026-10-18 23:30:00", "result": "ALLOW"},
    ]
    suggestions = suggest_roles(access_logs=single_user_log, save_to_db=False)
    assert len(suggestions) == 1
    assert suggestions[0]["user_id"] == "solo_admin"
    assert suggestions[0]["suggested_role"] == "Admin"
