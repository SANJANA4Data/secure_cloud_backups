import sqlite3

conn = sqlite3.connect("data/backups.db")
cursor = conn.cursor()

# Show the schema of the backups table
cursor.execute("PRAGMA table_info(backups)")
print("Backups table columns:")
for row in cursor.fetchall():
    print(row)

# Show the schema of the audit_log table
cursor.execute("PRAGMA table_info(audit_log)")
print("\nAudit log table columns:")
for row in cursor.fetchall():
    print(row)

conn.close()
