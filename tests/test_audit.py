"""
Unit tests for Audit Logging, Tamper Detection, and Backup Creation Edge Cases (tests/test_audit.py).
Covers Zero-Trust immutable audit logging, cryptographic hash verification, and database constraints:

1. test_audit_log_access_recording: Verifies standard audit event logging.
2. test_audit_log_filtering_by_decision_and_user: Tests log filtering by decision, action, and user.
3. test_audit_log_tamper_detection_single_entry: Cryptographic detection of unauthorized log modification.
4. test_audit_log_hash_chain_tamper_detection: Forward hash-chain validation across log sequences.
5. test_audit_log_hash_chain_omission_or_reordering: Detection of deleted or reordered log entries.
6. test_backup_creation_valid_record: Valid backup record insertion and checksum retrieval.
7. test_backup_creation_duplicate_id_raises_integrity_error: Enforcement of PRIMARY KEY uniqueness.
8. test_backup_creation_zero_and_negative_size_edge_cases: Handling zero and negative container sizes.
9. test_backup_creation_special_characters_and_checksum_inconsistencies: Handling special character IDs and malformed checksums.
"""

import os
import sys
import sqlite3
import pytest
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.db_utils import (
    get_connection,
    log_access,
    log_action,
    get_audit_logs,
    insert_backup,
    get_backups,
    get_checksum,
)
from utils.integrity import (
    compute_log_checksum,
    verify_log_entry,
    build_audit_hash_chain,
    verify_audit_hash_chain,
)


@pytest.fixture
def isolated_db(tmp_path):
    """Fixture providing an isolated SQLite database for audit and backup tests."""
    db_file = tmp_path / "audit_test.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE backups (
            backup_id TEXT PRIMARY KEY,
            user_id TEXT,
            version INTEGER,
            size INTEGER,
            checksum TEXT,
            timestamp TEXT,
            status TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE audit_log (
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
    conn.close()
    return str(db_file)


# ==============================================================================
# TEST 1: AUDIT LOG ACCESS RECORDING
# ==============================================================================

def test_audit_log_access_recording(isolated_db, monkeypatch):
    """
    Test standard recording of access events into the audit log table.
    """
    monkeypatch.setattr(db_utils, "get_db_path", lambda: isolated_db)

    log_access(user_id="alice", action="DOWNLOAD", backup_id="BK-001", result="success")
    log_action(action="BACKUP_RESTORED", backup_id="BK-002", user_id="bob", result="success")

    conn = sqlite3.connect(isolated_db)
    cur = conn.cursor()
    cur.execute("SELECT user_id, action, backup_id, result FROM audit_log ORDER BY log_id ASC")
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0] == ("alice", "DOWNLOAD", "BK-001", "success")
    assert rows[1] == ("bob", "BACKUP_RESTORED", "BK-002", "success")


# ==============================================================================
# TEST 2: AUDIT LOG FILTERING BY DECISION AND USER
# ==============================================================================

def test_audit_log_filtering_by_decision_and_user(isolated_db, monkeypatch):
    """
    Test filtering audit logs by user, decision status (Allowed vs Denied), and action.
    """
    monkeypatch.setattr(db_utils, "get_db_path", lambda: isolated_db)
    monkeypatch.setattr(db_utils, "seed_audit_logs", lambda: None)

    conn = sqlite3.connect(isolated_db)
    cur = conn.cursor()
    cur.executemany(
        "INSERT INTO audit_log (user_id, action, backup_id, timestamp, result, decision, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("alice", "DOWNLOAD", "BK-001", "2026-10-18 10:00:00", "Allowed", "Allowed", "Routine read"),
            ("alice", "DELETE", "BK-002", "2026-10-18 10:05:00", "Denied", "Denied", "Unauthorized delete"),
            ("bob", "RESTORE", "BK-001", "2026-10-18 10:10:00", "Allowed", "Allowed", "Disaster recovery dry-run"),
        ]
    )
    conn.commit()
    conn.close()

    # Filter by user
    alice_logs = get_audit_logs(user_filter="alice")
    assert len(alice_logs) == 2
    assert all(l["user"] == "alice" for l in alice_logs)

    # Filter by decision
    denied_logs = get_audit_logs(decision_filter="Denied")
    assert len(denied_logs) == 1
    assert denied_logs[0]["action"] == "DELETE"
    assert denied_logs[0]["decision"] == "Denied"

    # Filter by action
    restore_logs = get_audit_logs(action_filter="RESTORE")
    assert len(restore_logs) == 1
    assert restore_logs[0]["user"] == "bob"


# ==============================================================================
# TEST 3: ACCESS LOG TAMPER-DETECTION (SINGLE RECORD)
# ==============================================================================

def test_audit_log_tamper_detection_single_entry():
    """
    Test cryptographic tamper detection on an individual audit log entry.
    Any post-hoc modification to user, action, decision, or timestamp must be caught.
    """
    original_entry = {
        "log_id": 101,
        "user_id": "malicious_user",
        "action": "DELETE",
        "backup_id": "BK-PRIMARY-DB",
        "timestamp": "2026-10-18 03:15:20",
        "result": "DENIED",
    }

    # Generate reference signature hash
    expected_digest = compute_log_checksum(
        log_id=original_entry["log_id"],
        user_id=original_entry["user_id"],
        action=original_entry["action"],
        backup_id=original_entry["backup_id"],
        timestamp=original_entry["timestamp"],
        result=original_entry["result"]
    )

    # Valid verification
    assert verify_log_entry(original_entry, expected_digest) is True

    # Tampering scenario A: Attacker alters result from DENIED to ALLOWED
    tampered_result = dict(original_entry)
    tampered_result["result"] = "ALLOWED"
    assert verify_log_entry(tampered_result, expected_digest) is False, "Modified result must fail verification"

    # Tampering scenario B: Attacker alters action to disguise DELETE as DOWNLOAD
    tampered_action = dict(original_entry)
    tampered_action["action"] = "DOWNLOAD"
    assert verify_log_entry(tampered_action, expected_digest) is False, "Modified action must fail verification"

    # Tampering scenario C: Attacker modifies timestamp
    tampered_ts = dict(original_entry)
    tampered_ts["timestamp"] = "2026-10-18 12:00:00"
    assert verify_log_entry(tampered_ts, expected_digest) is False, "Modified timestamp must fail verification"


# ==============================================================================
# TEST 4: AUDIT LOG HASH CHAIN TAMPER DETECTION
# ==============================================================================

def test_audit_log_hash_chain_tamper_detection():
    """
    Test blockchain-style forward hash-chaining across an audit log sequence.
    Detects any unauthorized modification to intermediate records.
    """
    log_sequence = [
        {"log_id": 1, "user_id": "admin", "action": "LOGIN", "backup_id": "N/A", "timestamp": "2026-10-18 08:00:00", "result": "Allowed"},
        {"log_id": 2, "user_id": "alice", "action": "DOWNLOAD", "backup_id": "BK-001", "timestamp": "2026-10-18 09:15:00", "result": "Allowed"},
        {"log_id": 3, "user_id": "guest", "action": "DELETE", "backup_id": "BK-002", "timestamp": "2026-10-18 10:20:00", "result": "Denied"},
        {"log_id": 4, "user_id": "bob", "action": "RESTORE", "backup_id": "BK-001", "timestamp": "2026-10-18 11:30:00", "result": "Allowed"},
    ]

    # Generate immutable reference hash chain
    chain = build_audit_hash_chain(log_sequence)
    assert len(chain) == 4

    # Verify pristine sequence
    is_valid, corrupted = verify_audit_hash_chain(log_sequence, chain)
    assert is_valid is True
    assert len(corrupted) == 0

    # Tamper with record at index 2 (change Denied to Allowed)
    tampered_sequence = [dict(entry) for entry in log_sequence]
    tampered_sequence[2]["result"] = "Allowed"

    is_valid_after_tamper, corrupted_indices = verify_audit_hash_chain(tampered_sequence, chain)
    assert is_valid_after_tamper is False
    assert 2 in corrupted_indices, "Tampered entry at index 2 must be flagged as corrupted"


# ==============================================================================
# TEST 5: HASH CHAIN OMISSION OR REORDERING DETECTION
# ==============================================================================

def test_audit_log_hash_chain_omission_or_reordering():
    """
    Test that deleting or reordering an audit log entry breaks the forward hash chain.
    """
    log_sequence = [
        {"log_id": 1, "user_id": "user1", "action": "ACTION1", "backup_id": "B1", "timestamp": "2026-10-18 10:00:00", "result": "Allowed"},
        {"log_id": 2, "user_id": "user2", "action": "ACTION2", "backup_id": "B2", "timestamp": "2026-10-18 10:05:00", "result": "Allowed"},
        {"log_id": 3, "user_id": "user3", "action": "ACTION3", "backup_id": "B3", "timestamp": "2026-10-18 10:10:00", "result": "Allowed"},
    ]
    chain = build_audit_hash_chain(log_sequence)

    # Scenario A: Record omitted (only 2 logs instead of 3)
    omitted_sequence = [log_sequence[0], log_sequence[2]]
    valid_omitted, _ = verify_audit_hash_chain(omitted_sequence, chain)
    assert valid_omitted is False, "Omission of log record must fail chain verification"

    # Scenario B: Logs reordered
    reordered_sequence = [log_sequence[1], log_sequence[0], log_sequence[2]]
    valid_reordered, _ = verify_audit_hash_chain(reordered_sequence, chain)
    assert valid_reordered is False, "Reordering log entries must fail chain verification"


# ==============================================================================
# TEST 6: BACKUP RECORD CREATION (VALID RECORD)
# ==============================================================================

def test_backup_creation_valid_record(isolated_db, monkeypatch):
    """
    Test creating a valid backup record with size, version, and SHA-256 checksum.
    """
    monkeypatch.setattr(db_utils, "get_db_path", lambda: isolated_db)

    b_id = "B2026-TEST-001"
    u_id = "alice"
    checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    size_bytes = 2097152

    insert_backup(
        backup_id=b_id,
        user_id=u_id,
        version=1,
        size=size_bytes,
        checksum=checksum,
        timestamp="2026-10-18 12:00:00",
        status="active"
    )

    stored_checksum = get_checksum(b_id)
    assert stored_checksum == checksum

    backups = get_backups()
    assert len(backups) == 1
    assert backups[0][0] == b_id
    assert backups[0][1] == u_id
    assert backups[0][3] == size_bytes
    assert backups[0][6] == "active"


# ==============================================================================
# TEST 7: BACKUP CREATION DUPLICATE ID (PRIMARY KEY CONSTRAINT)
# ==============================================================================

def test_backup_creation_duplicate_id_raises_integrity_error(isolated_db, monkeypatch):
    """
    Test that creating a backup record with a duplicate backup_id raises sqlite3.IntegrityError.
    """
    monkeypatch.setattr(db_utils, "get_db_path", lambda: isolated_db)

    insert_backup("B_DUP_ID", "user1", 1, 1024, "checksum1", "2026-10-18 10:00:00")

    with pytest.raises(sqlite3.IntegrityError):
        # Attempt duplicate insertion
        insert_backup("B_DUP_ID", "user2", 2, 2048, "checksum2", "2026-10-18 11:00:00")


# ==============================================================================
# TEST 8: BACKUP CREATION ZERO AND NEGATIVE SIZE EDGE CASES
# ==============================================================================

def test_backup_creation_zero_and_negative_size_edge_cases(isolated_db, monkeypatch):
    """
    Test edge cases where backup archive size is 0 bytes (empty container)
    or negative (corrupted size metadata).
    """
    monkeypatch.setattr(db_utils, "get_db_path", lambda: isolated_db)

    # Empty backup (0 bytes)
    insert_backup("B_ZERO_SIZE", "service_acct", 1, 0, "hash_zero", "2026-10-18 10:00:00", status="active")
    # Negative size (corrupted metadata entry)
    insert_backup("B_NEG_SIZE", "service_acct", 1, -512, "hash_neg", "2026-10-18 10:05:00", status="corrupted")

    conn = sqlite3.connect(isolated_db)
    cur = conn.cursor()
    cur.execute("SELECT backup_id, size, status FROM backups ORDER BY timestamp ASC")
    records = cur.fetchall()
    conn.close()

    assert len(records) == 2
    assert records[0] == ("B_ZERO_SIZE", 0, "active")
    assert records[1] == ("B_NEG_SIZE", -512, "corrupted")


# ==============================================================================
# TEST 9: SPECIAL CHARACTERS AND MALFORMED CHECKSUM EDGE CASES
# ==============================================================================

def test_backup_creation_special_characters_and_checksum_inconsistencies(isolated_db, monkeypatch):
    """
    Test backup record creation with special characters in IDs, empty checksums,
    and non-hexadecimal checksum strings.
    """
    monkeypatch.setattr(db_utils, "get_db_path", lambda: isolated_db)

    special_id = "BK-2026.10.18:01_prod#alpha/test"
    special_user = "user.name+tag@corp-domain"
    empty_checksum = ""
    malformed_checksum = "INVALID_NON_HEX_CHECKSUM_XYZ$$$"

    insert_backup(
        backup_id=special_id,
        user_id=special_user,
        version=1,
        size=4096,
        checksum=empty_checksum,
        timestamp="2026-10-18 14:00:00"
    )

    insert_backup(
        backup_id="BK_MALFORMED",
        user_id="bob",
        version=1,
        size=4096,
        checksum=malformed_checksum,
        timestamp="2026-10-18 14:05:00"
    )

    retrieved_checksum1 = get_checksum(special_id)
    retrieved_checksum2 = get_checksum("BK_MALFORMED")

    assert retrieved_checksum1 == ""
    assert retrieved_checksum2 == malformed_checksum
