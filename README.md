# Secure Cloud Backups

A Python project demonstrating secure, role-based cloud backup and restore operations with full audit logging.

## Features

- **Role-Based Access Control (RBAC)** – enforced *before* every operation (backup, restore, delete)
- **Path-traversal protection** – safe ZIP extraction that rejects entries escaping the restore directory
- **Backup versioning** – auto-increments version number per `(user, folder)` pair
- **Audit logging** – every action is recorded in SQLite
- **CLI interface** – all scripts accept `--user`, `--folder`, `--backup-id` flags
- **Unit & integration tests** – `pytest` test suite with isolated temporary databases

## Project Structure

```
secure_cloud_backups/
├── data/
│   ├── access_log.csv       # Sample access log for RBAC audit
│   ├── backups.csv          # Sample backup metadata (CSV)
│   ├── users.csv            # Users and their roles
│   ├── backups.db           # SQLite database (auto-created)
│   ├── cloud_storage/       # Backup ZIP archives
│   ├── restore_output/      # Extracted restore files
│   └── test_data/           # Sample folder used for testing
├── scripts/
│   ├── backup_script.py     # Create a backup
│   ├── restore_script.py    # Restore a backup
│   ├── delete_backup.py     # Delete a backup
│   ├── list_backups.py      # List backups / audit log
│   └── rbac_check.py        # Replay access_log.csv against RBAC rules
├── utils/
│   ├── config.py            # Centralised paths (BASE_DIR, DB_PATH, …)
│   ├── db_utils.py          # SQLite helpers
│   └── rbac.py              # RBAC logic + enforce_rbac()
├── tests/
│   ├── test_rbac.py         # Unit tests for RBAC rules
│   ├── test_db_utils.py     # Unit tests for database helpers
│   └── test_backup_restore.py # Integration tests
├── __main__.py              # `python -m secure_cloud_backups` entry point
└── requirements.txt
```

## Roles

| Role      | BACKUP | RESTORE | DELETE |
|-----------|--------|---------|--------|
| Admin     | ✅     | ✅      | ✅     |
| Owner     | ✅     | ✅ (own)| ✅ (own)|
| Restorer  | ✅     | ✅      | ❌     |
| Viewer    | ❌     | ❌      | ❌     |

## Setup

```bash
pip install -r requirements.txt
```

## Usage

All commands can be run directly from the `scripts/` directory or via the package entry point.

### Create a backup

```bash
python scripts/backup_script.py --user U101 --folder data/test_data
# or
python -m secure_cloud_backups backup --user U101 --folder data/test_data
```

### Restore a backup

```bash
python scripts/restore_script.py --backup-id B20260214033329 --user U103
# or
python -m secure_cloud_backups restore --backup-id B20260214033329 --user U103
```

### Delete a backup

```bash
python scripts/delete_backup.py --backup-id B20260214033329 --user U101
# or
python -m secure_cloud_backups delete --backup-id B20260214033329 --user U101
```

### List backups and audit log

```bash
python scripts/list_backups.py --table all
# or
python -m secure_cloud_backups list --table backups
```

### Replay RBAC audit

```bash
python scripts/rbac_check.py
# or
python -m secure_cloud_backups audit
```

## Running Tests

```bash
pytest tests/
```
