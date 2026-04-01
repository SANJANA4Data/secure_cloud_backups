"""Retention-policy enforcement: keep only the N most recent backup versions.

Call :func:`apply_retention` after a successful backup to prune stale versions
for the same ``(user_id, folder_path)`` pair.  The threshold is controlled by
``utils.config.MAX_VERSIONS``.
"""
import os
import logging

from utils.config import CLOUD_DIR, MAX_VERSIONS
from utils import db_utils

logger = logging.getLogger(__name__)


def apply_retention(user_id: str, folder_path: str) -> list:
    """Delete backup versions beyond MAX_VERSIONS for ``(user_id, folder_path)``.

    Versions are sorted oldest-first; the excess leading entries are removed.
    Returns the list of backup IDs that were deleted.
    """
    versions = db_utils.list_versions_for_folder(user_id, folder_path)
    if len(versions) <= MAX_VERSIONS:
        return []

    to_delete = versions[:-MAX_VERSIONS]  # oldest first
    deleted = []
    for backup_id in to_delete:
        enc_path = os.path.join(CLOUD_DIR, f"{backup_id}.zip.enc")
        if os.path.exists(enc_path):
            os.remove(enc_path)
            logger.info("Retention: removed archive %s", enc_path)
        try:
            db_utils.delete_backup(backup_id)
        except ValueError:
            logger.warning("Retention: backup %s not in DB, skipping", backup_id)
            continue
        db_utils.log_action("BACKUP_DELETED_RETENTION", backup_id, user_id)
        logger.info(
            "Retention: pruned backup %s (limit=%d versions)", backup_id, MAX_VERSIONS
        )
        deleted.append(backup_id)
    return deleted
