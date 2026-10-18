"""
Cryptographic Integrity and Tamper Detection Module.
Provides SHA-256 verification for backup containers and audit log immutable trails:
- calculate_checksum(): File-level SHA-256 computation.
- calculate_data_checksum(): In-memory bytes SHA-256.
- compute_log_checksum(): Generates tamper-evident hash for audit log events.
- verify_log_entry(): Verifies an audit log entry against an expected hash digest.
- build_audit_hash_chain(): Computes chained cryptographic hashes across access logs.
- verify_audit_hash_chain(): Detects unauthorized insertions, edits, or omissions in log streams.
"""

import hashlib
import json
from typing import Dict, Any, List, Tuple, Optional


def calculate_checksum(file_path: str) -> str:
    """Calculate SHA-256 checksum for a file on disk."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_data_checksum(data: bytes) -> str:
    """Calculate SHA-256 checksum for arbitrary raw bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_log_checksum(
    log_id: Any,
    user_id: str,
    action: str,
    backup_id: str,
    timestamp: str,
    result: str,
    prev_hash: str = ""
) -> str:
    """
    Generate a cryptographic SHA-256 digest over log fields to detect tampering.
    Can be used standalone or linked forward with prev_hash for blockchain-style immutability.
    """
    payload = f"{log_id}|{str(user_id).strip()}|{str(action).strip()}|{str(backup_id).strip()}|{str(timestamp).strip()}|{str(result).strip()}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_log_entry(log_dict: Dict[str, Any], expected_hash: str, prev_hash: str = "") -> bool:
    """
    Verify whether an audit log entry matches its expected cryptographic digest.
    Returns True if untampered, False if modified.
    """
    actual_hash = compute_log_checksum(
        log_id=log_dict.get("log_id", ""),
        user_id=log_dict.get("user_id", log_dict.get("user", "")),
        action=log_dict.get("action", ""),
        backup_id=log_dict.get("backup_id", ""),
        timestamp=log_dict.get("timestamp", ""),
        result=log_dict.get("result", log_dict.get("decision", "")),
        prev_hash=prev_hash
    )
    return actual_hash.lower() == expected_hash.strip().lower()


def build_audit_hash_chain(logs: List[Dict[str, Any]], genesis_hash: str = "GENESIS_ROOT") -> List[str]:
    """
    Build a sequential hash chain across a list of audit logs.
    Returns a list of cryptographic hashes corresponding to each log entry.
    """
    chain: List[str] = []
    current_prev = genesis_hash

    for log in logs:
        entry_hash = compute_log_checksum(
            log_id=log.get("log_id", ""),
            user_id=log.get("user_id", log.get("user", "")),
            action=log.get("action", ""),
            backup_id=log.get("backup_id", ""),
            timestamp=log.get("timestamp", ""),
            result=log.get("result", log.get("decision", "")),
            prev_hash=current_prev
        )
        chain.append(entry_hash)
        current_prev = entry_hash

    return chain


def verify_audit_hash_chain(
    logs: List[Dict[str, Any]],
    recorded_chain: List[str],
    genesis_hash: str = "GENESIS_ROOT"
) -> Tuple[bool, List[int]]:
    """
    Validate that an audit log sequence has not been modified or reordered.
    Returns (is_valid, list_of_corrupted_indices).
    """
    if len(logs) != len(recorded_chain):
        return False, list(range(max(len(logs), len(recorded_chain))))

    corrupted_indices: List[int] = []
    current_prev = genesis_hash

    for idx, (log, recorded_hash) in enumerate(zip(logs, recorded_chain)):
        expected_hash = compute_log_checksum(
            log_id=log.get("log_id", ""),
            user_id=log.get("user_id", log.get("user", "")),
            action=log.get("action", ""),
            backup_id=log.get("backup_id", ""),
            timestamp=log.get("timestamp", ""),
            result=log.get("result", log.get("decision", "")),
            prev_hash=current_prev
        )
        if expected_hash.lower() != recorded_hash.strip().lower():
            corrupted_indices.append(idx)
        current_prev = recorded_hash

    return len(corrupted_indices) == 0, corrupted_indices
