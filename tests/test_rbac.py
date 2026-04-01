"""Unit tests for RBAC logic in utils/rbac.py (pure check_rbac function)."""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
from utils.rbac import check_rbac


class TestViewerRole:
    def test_viewer_cannot_backup(self):
        allowed, reason = check_rbac("Viewer", "BACKUP", None, "U104")
        assert not allowed
        assert "Viewer" in reason

    def test_viewer_cannot_restore(self):
        allowed, _ = check_rbac("VIEWER", "RESTORE", "U101", "U104")
        assert not allowed

    def test_viewer_cannot_delete(self):
        allowed, _ = check_rbac("VIEWER", "DELETE", "U101", "U104")
        assert not allowed

    def test_viewer_can_download(self):
        allowed, _ = check_rbac("VIEWER", "DOWNLOAD", "U101", "U104")
        assert allowed


class TestOwnerRole:
    def test_owner_can_manage_own_backup(self):
        allowed, _ = check_rbac("OWNER", "RESTORE", "U102", "U102")
        assert allowed

    def test_owner_denied_other_backup(self):
        allowed, reason = check_rbac("OWNER", "RESTORE", "U101", "U102")
        assert not allowed
        assert "Owner" in reason

    def test_owner_creating_new_backup_allowed(self):
        # backup_owner_id is None when no existing backup is involved
        allowed, _ = check_rbac("OWNER", "BACKUP", None, "U102")
        assert allowed


class TestRestorerRole:
    def test_restorer_can_restore(self):
        allowed, _ = check_rbac("RESTORER", "RESTORE", "U101", "U103")
        assert allowed

    def test_restorer_cannot_delete(self):
        allowed, reason = check_rbac("RESTORER", "DELETE", "U101", "U103")
        assert not allowed
        assert "Restorer" in reason

    def test_restorer_can_backup(self):
        allowed, _ = check_rbac("RESTORER", "BACKUP", None, "U103")
        assert allowed


class TestAdminRole:
    def test_admin_can_backup(self):
        allowed, _ = check_rbac("ADMIN", "BACKUP", None, "U101")
        assert allowed

    def test_admin_can_restore_any(self):
        allowed, _ = check_rbac("ADMIN", "RESTORE", "U102", "U101")
        assert allowed

    def test_admin_can_delete_any(self):
        allowed, _ = check_rbac("ADMIN", "DELETE", "U102", "U101")
        assert allowed


class TestCaseInsensitivity:
    def test_lowercase_role_allowed(self):
        allowed, _ = check_rbac("admin", "DELETE", "U102", "U101")
        assert allowed

    def test_mixed_case_action_blocked(self):
        allowed, _ = check_rbac("VIEWER", "restore", "U101", "U104")
        assert not allowed

    def test_mixed_case_role_and_action(self):
        allowed, _ = check_rbac("Restorer", "Delete", "U101", "U103")
        assert not allowed
