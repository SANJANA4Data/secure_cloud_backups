# Secure Cloud Backups

A Python prototype for secure cloud backup workflows with:
- ZIP packaging + encryption
- Backup metadata storage in SQLite
- Restore tracking and audit logging
- RBAC checks and anomaly detection helpers

## Project Structure

- `/scripts/backup_script.py` — creates encrypted backups and stores metadata
- `/scripts/restore_script.py` — decrypts and restores backups, updates audit data
- `/scripts/rbac_check.py` — runs RBAC checks against CSV datasets
- `/scripts/generate_dataset.py` — generates synthetic CSV datasets
- `/scripts/dashboard.py` — local dashboard for progress and activity visualization
- `/utils/crypto.py` — file encryption/decryption helpers
- `/utils/integrity.py` — SHA-256 checksum calculation
- `/utils/db_utils.py` — SQLite schema, data operations, RBAC/anomaly helpers
- `/data/` — database, generated datasets, cloud storage and restore outputs
- `/tests/test_core_flows.py` — basic automated tests for core functionality

## Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start

Run from repository root:

```bash
python scripts/backup_script.py
python scripts/restore_script.py
```

### Generate Synthetic Dataset

```bash
python scripts/generate_dataset.py
```

### Run RBAC Check Script

```bash
python scripts/rbac_check.py
```

### Run Tests

```bash
python -m unittest discover -s tests -v
```

### Run Dashboard

```bash
python scripts/dashboard.py --port 8080
```

Then open: `http://127.0.0.1:8080`

The dashboard provides a full evaluator-facing display with:
- completion status and progress bar
- workflow overview of backup/restore/RBAC/audit pipeline
- key project metrics and distribution charts
- top denied users and data snapshots from users/backups/access logs
- auto-refresh every 20 seconds for live presentation

## Data and Storage

- SQLite DB path: `data/backups.db`
- Encrypted backup output: `data/cloud_storage/*.zip.enc`
- Restore output: `data/restore_output/`
- Encryption key: `data/encryption.key`

## Current Scope

This repository is a prototype focused on demonstrating secure backup and restore flows with access-control and audit support. It is not production-hardened yet (for example, key management and operational hardening would need further work).
