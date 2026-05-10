# Secure Cloud Backups

This repository provides encrypted backup/restore services, RBAC enforcement, audit logging, anomaly detection, a chatbot interface, and a lightweight dashboard.

## Setup

1. Create and activate a Python virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Generate Sample Data

```bash
python scripts/generate_dataset.py
```

This produces `data/users.csv`, `data/backups.csv`, and `data/access_log.csv`.

## Run the Dashboard + API

```bash
python app.py
```

Open `http://localhost:8000` to view the dashboard. Use a valid `User_ID` (for example `U001`) to load data and query the chatbot.

## Core Scripts

- `scripts/backup_script.py`: creates an encrypted backup from `data/test_data`.
- `scripts/restore_script.py`: restores a backup if RBAC permits it.
- `scripts/rbac_check.py`: evaluates access log actions against RBAC rules.

## API Endpoints

All API routes require a `user_id` query parameter or JSON field unless noted.

- `GET /api/health`
- `POST /api/init-data` (reload CSV data into SQLite)
- `GET /api/backups/catalog`
- `GET /api/backups/records`
- `GET /api/access-log`
- `GET /api/audit-log`
- `GET /api/anomalies`
- `POST /api/backup` (`user_id`, `folder_key`, default `test_data`)
- `POST /api/restore` (`user_id`, `backup_id`)
- `POST /api/chat` (`user_id`, `message`)

## Chatbot Intents

The chatbot supports:

- `list backups` or `show backups`
- `show audit log`
- `show anomalies`
- `restore B001`

Each request is RBAC-validated and logged.

## Configuration & Security

- Encryption key: set `SCB_ENCRYPTION_KEY` or allow the app to write `data/secret.key`.
- Storage paths are centralized in `utils/config.py`.
- API endpoints enforce rate limiting (60 requests/minute per user).
- Configure the web host/port via `SCB_HOST` and `SCB_PORT`.

## Testing

```bash
python -m unittest discover -s tests
```
