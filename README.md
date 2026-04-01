# Secure Cloud Backups

A Python project demonstrating secure, role-based cloud backup and restore operations with AES-256-GCM encryption, SHA-256 integrity verification, automatic retention management, and full audit logging.

## Features

- **AES-256-GCM encryption** – every backup archive is encrypted at rest; the plaintext ZIP is never retained on disk
- **SHA-256 integrity verification** – checksum stored at backup time, re-verified before every restore or download
- **Role-Based Access Control (RBAC)** – enforced *before* every operation (backup, restore, delete, download)
- **Backup versioning** – auto-increments version number per `(user, folder)` pair
- **Retention policy** – oldest versions are pruned automatically once `MAX_VERSIONS` is exceeded
- **Path-traversal protection** – safe ZIP extraction that rejects entries escaping the restore directory
- **Audit logging** – every action is recorded in SQLite with timestamp, user, and backup ID
- **CLI interface** – unified `python -m secure_cloud_backups` entry point with 8 subcommands
- **Unit & integration tests** – pytest test suite (57 tests) with isolated temporary databases

## Project Structure

```
secure_cloud_backups/
├── data/
│   ├── users.csv            # 14 users, all roles, EMAIL + ACTIVE columns
│   ├── backups.csv          # 28 backup records, multi-version, 4-week spread
│   ├── access_log.csv       # 50 log entries covering all role × action combos
│   ├── backups.db           # SQLite database (auto-created)
│   ├── cloud_storage/       # Encrypted backup archives (.zip.enc)
│   ├── restore_output/      # Extracted restore files
│   └── test_data/           # Sample folder used for integration tests
│       ├── notes.txt
│       ├── config.json
│       ├── sample.png
│       └── reports/
│           └── q1_summary.txt
├── scripts/
│   ├── backup_script.py     # Create an encrypted, versioned backup
│   ├── restore_script.py    # Decrypt, verify integrity, and extract a backup
│   ├── delete_backup.py     # Delete a backup (DB record + encrypted archive)
│   ├── download_script.py   # Download (decrypt) a backup to a local path
│   ├── list_backups.py      # List backups / audit log
│   ├── cleanup_script.py    # Manually apply retention policy
│   └── rbac_check.py        # Replay access_log.csv against RBAC rules
├── utils/
│   ├── config.py            # Centralised paths + MAX_VERSIONS constant
│   ├── crypto.py            # AES-256-GCM encrypt_file / decrypt_file
│   ├── integrity.py         # SHA-256 sha256_file / verify_integrity
│   ├── retention.py         # apply_retention() – prune oldest versions
│   ├── db_utils.py          # SQLite helpers (backups + audit_log tables)
│   └── rbac.py              # RBAC logic + enforce_rbac()
├── tests/
│   ├── test_rbac.py             # Unit tests for RBAC rules (23 tests)
│   ├── test_db_utils.py         # Unit tests for database helpers (13 tests)
│   ├── test_backup_restore.py   # Integration tests: backup + restore pipeline (5 tests)
│   ├── test_delete_backup.py    # Tests for delete script (4 tests)
│   ├── test_download.py         # Tests for download script (4 tests)
│   ├── test_integrity.py        # Tests for integrity helpers + pipeline (9 tests)
│   └── test_retention.py        # Tests for retention policy (6 tests)
├── __main__.py              # `python -m secure_cloud_backups` entry point
└── requirements.txt
```

## Role × Action Permission Table

| Role      | BACKUP | RESTORE    | DELETE | DOWNLOAD |
|-----------|--------|------------|--------|----------|
| Admin     | ✅     | ✅ (any)   | ✅     | ✅       |
| Owner     | ✅     | ✅ (own)   | ✅ (own) | ✅     |
| Restorer  | ✅     | ✅ (any)   | ❌     | ✅       |
| Viewer    | ❌     | ❌         | ❌     | ✅       |

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set the encryption key

Generate a 32-byte key (once) and export it as a hex string:

```bash
python -c "import os; print(os.urandom(32).hex())"
# example output: 3f8a2b4c...  (64 hex characters)

export BACKUP_ENCRYPTION_KEY=3f8a2b4c...
```

> ⚠️ Keep this key safe. Without it you cannot decrypt any existing backups.

## Usage

All commands are available via the unified entry point:

```
python -m secure_cloud_backups <command> [options]
```

### backup – create an encrypted backup

```bash
python -m secure_cloud_backups backup --user U101 --folder data/test_data
# INFO: Backup created: B20260401120000123456  size=4096 bytes  version=1
```

### restore – decrypt, verify integrity, and extract

```bash
python -m secure_cloud_backups restore --backup-id B20260401120000123456 --user U103
# INFO: Backup B20260401120000123456 restored to data/restore_output
```

### delete – remove record and encrypted archive

```bash
python -m secure_cloud_backups delete --backup-id B20260401120000123456 --user U101
# INFO: Backup B20260401120000123456 deleted by U101
```

### download – decrypt to a local ZIP file

```bash
python -m secure_cloud_backups download \
    --backup-id B20260401120000123456 --user U102 --dest /tmp/my_backup.zip
# INFO: Backup B20260401120000123456 downloaded to /tmp/my_backup.zip by U102
```

### list – display backups and/or audit log

```bash
python -m secure_cloud_backups list --table all
# === Backups ===
# BACKUP_ID              USER_ID  FOLDER   ...
# -----------------------------------------------
# B20260401120000123456  U101     /abs/path ...

# === Audit Log ===
# ID  ACTION               BACKUP_ID              USER_ID  TIMESTAMP
# -------------------------------------------------------------------
#  1  BACKUP_CREATED       B20260401120000123456  U101     2026-04-01T...
```

### audit – replay access_log.csv against RBAC rules

```bash
python -m secure_cloud_backups audit
# INFO: Log 1: User U104 (VIEWER) tried Restore on B20260101090000 → False (Denied: Viewer cannot restore)
# INFO: Log 2: User U102 (OWNER)  tried Download on B20260101090000 → True  (Allowed)
```

### verify – check SHA-256 integrity of a stored backup

```bash
python -m secure_cloud_backups verify --backup-id B20260401120000123456
# Integrity OK: B20260401120000123456
```

### cleanup – manually apply the retention policy

```bash
python -m secure_cloud_backups cleanup --user U101 --folder data/test_data
# INFO: Cleaned up 1 old backup(s): B20260401110000000001
```

## Running Tests

```bash
cd secure_cloud_backups
export BACKUP_ENCRYPTION_KEY=$(python -c "import os; print(os.urandom(32).hex())")
python -m pytest tests/ -v
# 57 passed in ~1s
```

## Environment Variables

| Variable               | Required | Description                                                |
|------------------------|----------|------------------------------------------------------------|
| `BACKUP_ENCRYPTION_KEY`| Yes      | 64-character hex string (32 bytes) used for AES-256-GCM   |

## Configuration (`utils/config.py`)

| Constant      | Default                          | Description                              |
|---------------|----------------------------------|------------------------------------------|
| `BASE_DIR`    | repo root                        | Project root directory                   |
| `DATA_DIR`    | `<BASE_DIR>/data`                | Data directory                           |
| `DB_PATH`     | `<DATA_DIR>/backups.db`          | SQLite database path                     |
| `CLOUD_DIR`   | `<DATA_DIR>/cloud_storage`       | Directory for `.zip.enc` archives        |
| `RESTORE_DIR` | `<DATA_DIR>/restore_output`      | Directory where restores are extracted   |
| `MAX_VERSIONS`| `3`                              | Maximum backup versions retained per (user, folder) |

