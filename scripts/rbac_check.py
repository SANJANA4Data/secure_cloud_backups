"""Audit script: replays access_log.csv and verifies each action against RBAC rules."""
import sys
import os
import csv
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils.config import DATA_DIR
from utils.rbac import check_rbac

logger = logging.getLogger(__name__)


def _load_csv(path):
    """Load a CSV file, normalising column names to uppercase stripped strings."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return [
            {k.strip().upper(): v.strip() for k, v in row.items()}
            for row in reader
        ]


def run_audit():
    users   = {r["USER_ID"]: r["ROLE"]      for r in _load_csv(os.path.join(DATA_DIR, "users.csv"))}
    backups = {r["BACKUP_ID"]: r["USER_ID"] for r in _load_csv(os.path.join(DATA_DIR, "backups.csv"))}
    logs    = _load_csv(os.path.join(DATA_DIR, "access_log.csv"))

    for i, entry in enumerate(logs, start=1):
        user_id         = entry["USER_ID"]
        backup_id       = entry["BACKUP_ID"]
        action          = entry["ACTION"]
        user_role       = users.get(user_id)
        backup_owner_id = backups.get(backup_id)

        if user_role is None:
            logger.warning("Log %d: Unknown user %s – skipping", i, user_id)
            continue
        if backup_owner_id is None:
            logger.warning("Log %d: Unknown backup %s – skipping", i, backup_id)
            continue

        result, reason = check_rbac(user_role, action, backup_owner_id, user_id)
        level = logging.INFO if result else logging.WARNING
        logger.log(
            level,
            "Log %d: User %s (%s) tried %s on %s → %s (%s)",
            i, user_id, user_role, action, backup_id, result, reason,
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run_audit()
