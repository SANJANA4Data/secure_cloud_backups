import argparse
import csv
import html
import os
import sqlite3
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def _read_csv_rows(file_name, data_dir=DATA_DIR):
    path = os.path.join(data_dir, file_name)
    if not os.path.exists(path):
        return []

    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader)


def _parse_restore_count(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _db_metrics(db_path):
    if not os.path.exists(db_path):
        return {
            "db_backups": 0,
            "db_total_restores": 0,
            "db_checksums": 0,
            "db_audit_events": 0,
        }

    metrics = {
        "db_backups": 0,
        "db_total_restores": 0,
        "db_checksums": 0,
        "db_audit_events": 0,
    }

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}

    if "backups" in tables:
        cursor.execute("PRAGMA table_info(backups)")
        backup_columns = {row[1] for row in cursor.fetchall()}
        checksum_expr = (
            "COALESCE(SUM(CASE WHEN checksum IS NOT NULL AND checksum != '' THEN 1 ELSE 0 END), 0)"
            if "checksum" in backup_columns
            else "0"
        )
        cursor.execute(f"SELECT COUNT(*), COALESCE(SUM(restore_count), 0), {checksum_expr} FROM backups")
        count, restores, checksums = cursor.fetchone()
        metrics["db_backups"] = count
        metrics["db_total_restores"] = restores
        metrics["db_checksums"] = checksums

    if "audit_log" in tables:
        cursor.execute("SELECT COUNT(*) FROM audit_log")
        metrics["db_audit_events"] = cursor.fetchone()[0]

    conn.close()
    return metrics


def collect_dashboard_data(data_dir=DATA_DIR):
    users = _read_csv_rows("users.csv", data_dir=data_dir)
    backups = _read_csv_rows("backups.csv", data_dir=data_dir)
    logs = _read_csv_rows("access_log.csv", data_dir=data_dir)

    role_counter = Counter((row.get("Role") or "Unknown").strip() or "Unknown" for row in users)
    action_counter = Counter((row.get("Action") or "Unknown").strip() or "Unknown" for row in logs)

    denied_counter = Counter()
    allowed = 0
    denied = 0
    for row in logs:
        status = (row.get("Status") or "").strip().lower()
        user_id = (row.get("User_ID") or "Unknown").strip() or "Unknown"
        if status == "allowed":
            allowed += 1
        elif status == "denied":
            denied += 1
            denied_counter[user_id] += 1

    restore_counts = [_parse_restore_count(row.get("Restore_Count")) for row in backups]
    total_restore_count = sum(restore_counts)
    avg_restore_count = round(total_restore_count / len(restore_counts), 2) if restore_counts else 0

    db_path = os.path.join(data_dir, "backups.db")
    db_data = _db_metrics(db_path)

    return {
        "total_users": len(users),
        "total_backups_csv": len(backups),
        "total_logs": len(logs),
        "allowed_count": allowed,
        "denied_count": denied,
        "avg_restore_count": avg_restore_count,
        "unique_backup_owners": len({(row.get("User_ID") or "").strip() for row in backups if row.get("User_ID")}),
        "role_counter": role_counter,
        "action_counter": action_counter,
        "top_denied_users": denied_counter.most_common(5),
        **db_data,
    }


def _render_bar_row(name, count, max_count):
    safe_name = html.escape(str(name))
    width = int((count / max_count) * 100) if max_count else 0
    return (
        "<tr>"
        f"<td>{safe_name}</td>"
        f"<td>{count}</td>"
        f"<td><div class='bar-wrap'><div class='bar' style='width:{width}%'></div></div></td>"
        "</tr>"
    )


def _render_counter_table(title, counter):
    items = counter.most_common()
    if not items:
        return f"<section class='card'><h3>{html.escape(title)}</h3><p>No data available.</p></section>"

    max_count = max(count for _, count in items)
    rows = "".join(_render_bar_row(name, count, max_count) for name, count in items)

    return (
        "<section class='card'>"
        f"<h3>{html.escape(title)}</h3>"
        "<table><thead><tr><th>Label</th><th>Count</th><th>Distribution</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</section>"
    )


def _render_top_denied(users):
    if not users:
        return "<section class='card'><h3>Top denied users</h3><p>No denied actions found.</p></section>"

    rows = "".join(
        f"<tr><td>{html.escape(user_id)}</td><td>{count}</td></tr>" for user_id, count in users
    )
    return (
        "<section class='card'>"
        "<h3>Top denied users</h3>"
        "<table><thead><tr><th>User ID</th><th>Denied attempts</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</section>"
    )


def render_dashboard_html(data):
    cards = [
        ("Users", data["total_users"]),
        ("Backups (CSV)", data["total_backups_csv"]),
        ("Backups (DB)", data["db_backups"]),
        ("Access Logs", data["total_logs"]),
        ("Allowed Actions", data["allowed_count"]),
        ("Denied Actions", data["denied_count"]),
        ("Average Restore Count", data["avg_restore_count"]),
        ("Checksums in DB", data["db_checksums"]),
        ("Audit Events", data["db_audit_events"]),
    ]
    card_html = "".join(
        f"<div class='metric'><span class='label'>{html.escape(label)}</span><span class='value'>{value}</span></div>"
        for label, value in cards
    )

    role_table = _render_counter_table("User role distribution", data["role_counter"])
    action_table = _render_counter_table("Access action distribution", data["action_counter"])
    top_denied = _render_top_denied(data["top_denied_users"])

    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Secure Cloud Backups Dashboard</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 0; background: #f6f8fb; color: #1f2937; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  h1 {{ margin: 0 0 8px; }}
  p.subtitle {{ margin: 0 0 16px; color: #4b5563; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(210px,1fr)); gap: 12px; margin-bottom: 16px; }}
  .metric {{ background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; }}
  .label {{ display: block; font-size: 13px; color: #6b7280; margin-bottom: 6px; }}
  .value {{ font-size: 22px; font-weight: 700; }}
  .layout {{ display: grid; grid-template-columns: 1fr; gap: 12px; }}
  .card {{ background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ border-bottom: 1px solid #f0f2f5; text-align: left; padding: 8px; }}
  .bar-wrap {{ width: 100%; height: 12px; border-radius: 10px; background: #eef2ff; }}
  .bar {{ height: 12px; border-radius: 10px; background: linear-gradient(90deg,#2563eb,#7c3aed); }}
</style>
</head>
<body>
  <div class='container'>
    <h1>Secure Cloud Backups Dashboard</h1>
    <p class='subtitle'>Live summary of backups, access activity, RBAC outcomes, and audit progress from local project data.</p>
    <section class='grid'>{card_html}</section>
    <section class='layout'>
      {role_table}
      {action_table}
      {top_denied}
    </section>
  </div>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        data = collect_dashboard_data()
        output = render_dashboard_html(data).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(output)))
        self.end_headers()
        self.wfile.write(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run local dashboard for secure cloud backups project")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), DashboardHandler)
    print(f"Dashboard running at http://{args.host}:{args.port}")
    server.serve_forever()
