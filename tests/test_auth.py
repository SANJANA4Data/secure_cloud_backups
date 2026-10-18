"""
Unit tests for the Authentication module (tests/test_auth.py).
Covers Zero-Trust RBAC credential verification, password hashing, and security edge cases:

1. test_login_invalid_password: Rejection of incorrect credentials.
2. test_login_nonexistent_user: Rejection of unknown usernames / IDs.
3. test_login_empty_and_whitespace_inputs: Safe rejection of empty, whitespace, and None values.
4. test_login_case_insensitivity_and_trimming: Normalization of username case and surrounding whitespace.
5. test_login_dual_identifier_support: Verification via both user_id (U000) and username (admin).
6. test_password_hashing_and_tamper_detection: SHA-256 hash generation and tampered hash rejection.
7. test_concurrent_login_attempts: High-concurrency thread safety without database locks.
8. test_sql_injection_mitigation: Rejection of classic SQL injection strings without executing payload.
"""

import os
import sys
import pytest
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils import db_utils
from utils.db_utils import (
    authenticate_user,
    hash_password,
    verify_password,
    get_connection,
)


# Setup fixture to ensure clean test tables
@pytest.fixture(autouse=True)
def setup_auth_db():
    db_utils.init_users_table()
    db_utils.seed_users()


# ==============================================================================
# TEST 1: INVALID LOGIN CREDENTIALS
# ==============================================================================

def test_login_invalid_password():
    """
    Test authenticating with an invalid password for a known valid username.
    Must return None and not create a session.
    """
    result = authenticate_user("admin", "definitely_wrong_password_999")
    assert result is None, "Authentication should fail for invalid password"

    result_user = authenticate_user("alice", "incorrect_pwd")
    assert result_user is None, "Authentication should fail for invalid password"


# ==============================================================================
# TEST 2: NON-EXISTENT USER ID / USERNAME
# ==============================================================================

def test_login_nonexistent_user():
    """
    Test authenticating with a non-existent username and user ID.
    Must return None safely without unhandled database errors.
    """
    result = authenticate_user("phantom_user_xyz_123", "password123")
    assert result is None, "Non-existent user must return None"

    result_id = authenticate_user("U99999", "password123")
    assert result_id is None, "Non-existent user_id must return None"


# ==============================================================================
# TEST 3: EMPTY, WHITESPACE, AND NONE INPUTS
# ==============================================================================

@pytest.mark.parametrize("u_input, p_input", [
    ("", "password123"),
    ("admin", ""),
    ("", ""),
    (None, "password123"),
    ("admin", None),
    (None, None),
    ("    ", "admin123"),
    ("admin", "    "),
    ("   ", "   "),
])
def test_login_empty_and_whitespace_inputs(u_input, p_input):
    """
    Test edge cases where username or password is None, empty string, or whitespace-only.
    Must safely return None without crashing.
    """
    result = authenticate_user(u_input, p_input)
    assert result is None, f"Failed for username='{u_input}', password='{p_input}'"


# ==============================================================================
# TEST 4: CASE INSENSITIVITY AND WHITESPACE TRIMMING
# ==============================================================================

def test_login_case_insensitivity_and_trimming():
    """
    Test that username lookup is case-insensitive and trims leading/trailing whitespace.
    """
    # Mixed case and padding
    user = authenticate_user("  AdMiN  ", "admin123")
    assert user is not None, "Login should succeed for mixed-case, whitespace-padded username"
    assert user["username"] == "admin"
    assert user["role"] == "Admin"

    # All uppercase
    user_upper = authenticate_user("ADMIN", "admin123")
    assert user_upper is not None
    assert user_upper["user_id"] == "U000"


# ==============================================================================
# TEST 5: DUAL IDENTIFIER SUPPORT (USER_ID VS USERNAME)
# ==============================================================================

def test_login_via_user_id_or_username():
    """
    Test that users can authenticate using either their primary user_id (e.g. U000)
    or their friendly username (e.g. admin).
    """
    by_username = authenticate_user("admin", "admin123")
    by_userid = authenticate_user("U000", "admin123")

    assert by_username is not None
    assert by_userid is not None
    assert by_username["user_id"] == by_userid["user_id"] == "U000"
    assert by_username["username"] == by_userid["username"] == "admin"


# ==============================================================================
# TEST 6: PASSWORD HASHING AND TAMPER DETECTION
# ==============================================================================

def test_password_hashing_and_tamper_detection():
    """
    Test SHA-256 password hash computation and verify that any modification/tampering
    with a stored hash fails verification.
    """
    raw_secret = "ZeroTrustPassphrase#2026"
    valid_hash = hash_password(raw_secret)

    # Validate standard SHA-256 format (64 hexadecimal chars)
    assert len(valid_hash) == 64
    assert all(c in "0123456789abcdef" for c in valid_hash)

    # Valid verification
    assert verify_password(raw_secret, valid_hash) is True

    # Tamper with stored hash (flip last character)
    tampered_last_char = "0" if valid_hash[-1] != "0" else "1"
    tampered_hash = valid_hash[:-1] + tampered_last_char
    assert verify_password(raw_secret, tampered_hash) is False

    # Empty and truncated hashes fail
    assert verify_password(raw_secret, "") is False
    assert verify_password(raw_secret, valid_hash[:32]) is False


# ==============================================================================
# TEST 7: CONCURRENT LOGIN ATTEMPTS
# ==============================================================================

def test_concurrent_login_attempts():
    """
    Test high-concurrency authentication across multiple threads.
    Verifies thread safety and ensures SQLite connection handling does not
    throw database locked or concurrency race condition errors.
    """
    total_workers = 8
    requests_per_worker = 5
    credentials_pool = [
        ("admin", "admin123", True),
        ("U000", "admin123", True),
        ("admin", "wrong_password", False),
        ("phantom", "password123", False),
        ("charlie", "charlie123", True),
        ("U003", "password123", True),
    ]

    def perform_login(item):
        user_input, pwd_input, expected_success = item
        auth_res = authenticate_user(user_input, pwd_input)
        if expected_success:
            return auth_res is not None
        else:
            return auth_res is None

    tasks = credentials_pool * (requests_per_worker * 2)

    with ThreadPoolExecutor(max_workers=total_workers) as executor:
        futures = [executor.submit(perform_login, task) for task in tasks]
        results = [f.result() for f in as_completed(futures)]

    assert len(results) == len(tasks)
    assert all(results), "All concurrent authentication attempts should match expected outcomes"


# ==============================================================================
# TEST 8: SQL INJECTION MITIGATION
# ==============================================================================

@pytest.mark.parametrize("malicious_input", [
    "' OR '1'='1",
    "admin' --",
    "admin' OR 1=1 --",
    "' OR 1=1#",
    "'; DROP TABLE users; --",
    "' UNION SELECT 'U999','hacker','hash','Hacker','Admin','IT','Office','Corp' --",
])
def test_sql_injection_defense_in_login(malicious_input):
    """
    Test classic SQL injection payloads in username and password fields.
    Parameterized queries must prevent execution and safely return None.
    """
    # Malicious username with valid password
    res1 = authenticate_user(malicious_input, "admin123")
    assert res1 is None, f"SQL injection bypassed authentication with username: {malicious_input}"

    # Valid username with malicious password
    res2 = authenticate_user("admin", malicious_input)
    assert res2 is None, f"SQL injection bypassed authentication with password: {malicious_input}"

    # Verify table wasn't dropped
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()
    assert count > 0, "Users table must remain intact after SQL injection attempt"
