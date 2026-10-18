"""
AI Role Suggester Module using Scikit-Learn K-Means Clustering.
Analyzes user activity patterns from access logs in logs/backups.db:
- Download frequency
- Off-hours access (outside 09:00 - 18:00)
- Restore counts & frequencies
- Delete / Administrative actions
- Access denial rates (least privilege enforcement)

Assigns optimal RBAC roles (Admin, Restorer, Owner, Viewer) and persists
recommendations to the 'role_suggestions' SQLite table.
"""

import os
import sys
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# Ensure project root is accessible
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils import db_utils


def parse_timestamp(ts_val: Any) -> Optional[datetime]:
    """Parse string or datetime object into a datetime object."""
    if isinstance(ts_val, datetime):
        return ts_val
    if not ts_val:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(str(ts_val).strip(), fmt)
        except ValueError:
            continue
    return None


def is_off_hours(ts_val: Any) -> bool:
    """Check if action occurred outside business hours (9 AM - 6 PM)."""
    dt = parse_timestamp(ts_val)
    if dt is None:
        return False
    return dt.hour < 9 or dt.hour >= 18


def extract_user_features(
    logs: List[Dict[str, Any]],
    users_map: Optional[Dict[str, str]] = None,
    include_inactive: bool = False
) -> pd.DataFrame:
    """
    Extract quantitative behavioral features per user from access logs.
    Features:
    - total_actions: total log count
    - download_count: count of DOWNLOAD events
    - restore_count: count of RESTORE / BACKUP_RESTORED events
    - delete_count: count of DELETE events
    - off_hours_count: access outside 9 AM - 6 PM
    - denied_count: count of DENY / Denied / failed events
    - download_freq: ratio of downloads to total
    - restore_freq: ratio of restores to total
    - delete_freq: ratio of deletes to total
    - off_hours_ratio: ratio of off-hours to total
    - denied_rate: ratio of denials to total
    """
    if users_map is None:
        users_map = {}

    user_stats: Dict[str, Dict[str, Any]] = {}

    for log in logs:
        uid = str(log.get("user_id") or log.get("user") or "").strip()
        if not uid or uid.lower() in ["unknown", "none"]:
            continue

        if uid not in user_stats:
            user_stats[uid] = {
                "user_id": uid,
                "current_role": users_map.get(uid, users_map.get(uid.lower(), "Viewer")),
                "total_actions": 0,
                "download_count": 0,
                "restore_count": 0,
                "delete_count": 0,
                "off_hours_count": 0,
                "denied_count": 0,
            }

        stats = user_stats[uid]
        stats["total_actions"] += 1

        action = str(log.get("action", "")).strip().upper()
        if "DOWNLOAD" in action or action == "LIST":
            stats["download_count"] += 1
        elif "RESTORE" in action:
            stats["restore_count"] += 1
        elif "DELETE" in action or "DROP" in action:
            stats["delete_count"] += 1

        # Check off-hours
        ts = log.get("timestamp")
        if is_off_hours(ts):
            stats["off_hours_count"] += 1

        # Check denials
        result = str(log.get("result") or log.get("decision") or "").strip().upper()
        if result in ["DENY", "DENIED", "FAILED", "REJECTED"]:
            stats["denied_count"] += 1

    # Optionally include any users in users_map that had no log events
    if include_inactive:
        for uid, role in users_map.items():
            if uid not in user_stats:
                user_stats[uid] = {
                    "user_id": uid,
                    "current_role": role,
                    "total_actions": 0,
                    "download_count": 0,
                    "restore_count": 0,
                    "delete_count": 0,
                    "off_hours_count": 0,
                    "denied_count": 0,
                }

    if not user_stats:
        return pd.DataFrame()

    df = pd.DataFrame(list(user_stats.values()))

    # Calculate frequencies and ratios
    total = np.maximum(df["total_actions"], 1)
    df["download_freq"] = df["download_count"] / total
    df["restore_freq"] = df["restore_count"] / total
    df["delete_freq"] = df["delete_count"] / total
    df["off_hours_ratio"] = df["off_hours_count"] / total
    df["denied_rate"] = df["denied_count"] / total

    return df


def cluster_users(
    features_df: pd.DataFrame,
    n_clusters: Optional[int] = None,
    random_state: int = 42
) -> Tuple[np.ndarray, Optional[KMeans], Optional[StandardScaler]]:
    """
    Apply scikit-learn K-Means clustering algorithm to user features.
    Returns cluster labels, fitted KMeans instance, and fitted StandardScaler.
    """
    n_users = len(features_df)
    if n_users == 0:
        return np.array([]), None, None

    feature_cols = [
        "download_count",
        "restore_count",
        "delete_count",
        "off_hours_count",
        "denied_count",
        "download_freq",
        "restore_freq",
        "delete_freq",
        "off_hours_ratio",
        "denied_rate",
    ]

    X = features_df[feature_cols].values

    if n_users == 1:
        # Edge case: single user
        return np.array([0]), None, None

    # Determine optimal or specified k
    if n_clusters is not None:
        k = max(1, min(n_clusters, n_users))
    else:
        # Default to up to 4 clusters (Admin, Restorer, Owner, Viewer)
        k = min(4, n_users)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    kmeans = KMeans(n_clusters=k, random_state=random_state, n_init=10)
    labels = kmeans.fit_predict(X_scaled)

    return labels, kmeans, scaler


def generate_recommendations(
    features_df: pd.DataFrame,
    cluster_labels: np.ndarray,
    kmeans: Optional[KMeans] = None
) -> List[Dict[str, Any]]:
    """
    Map K-Means cluster profiles and behavioral metrics to intelligent
    role recommendations (Admin, Restorer, Owner, Viewer).
    """
    if features_df.empty:
        return []

    df = features_df.copy()
    df["cluster"] = cluster_labels

    suggestions: List[Dict[str, Any]] = []

    # Compute centroid / mean properties per cluster if kmeans exists
    cluster_profiles: Dict[int, Dict[str, float]] = {}
    for c_id in np.unique(cluster_labels):
        c_subset = df[df["cluster"] == c_id]
        cluster_profiles[c_id] = {
            "avg_restore": float(c_subset["restore_count"].mean()),
            "avg_delete": float(c_subset["delete_count"].mean()),
            "avg_download": float(c_subset["download_count"].mean()),
            "avg_off_hours": float(c_subset["off_hours_count"].mean()),
            "avg_denied_rate": float(c_subset["denied_rate"].mean()),
        }

    for _, row in df.iterrows():
        uid = row["user_id"]
        cur_role = row["current_role"]
        c_id = int(row["cluster"])
        c_prof = cluster_profiles.get(c_id, {})

        restores = int(row["restore_count"])
        deletes = int(row["delete_count"])
        downloads = int(row["download_count"])
        off_hours = int(row["off_hours_count"])
        denials = int(row["denied_count"])
        denied_rate = float(row["denied_rate"])
        total = int(row["total_actions"])

        suggested_role = cur_role
        reason = "Activity profile matches current role assignment."
        confidence = 85

        # Decision Logic based on K-Means cluster alignment + least-privilege principles:
        # 1. High Denial Rate -> Over-privileged, enforce least privilege (Viewer)
        if denied_rate >= 0.5 and total >= 3:
            suggested_role = "Viewer"
            confidence = int(min(98, 75 + denied_rate * 25))
            reason = (
                f"K-Means Cluster {c_id}: High denial rate ({denied_rate:.1%}, {denials}/{total} requests blocked) "
                f"indicates over-privileged identity. Downgrading to Viewer enforces Zero-Trust least privilege."
            )

        # 2. Administrative Role -> High delete actions / retention management & off-hours operations with low denials
        elif (deletes >= 3 or c_prof.get("avg_delete", 0) >= 3.0) and denied_rate < 0.25:
            suggested_role = "Admin"
            confidence = 92 if off_hours >= 2 else 88
            reason = (
                f"K-Means Cluster {c_id} (Admin Archetype): User executes retention lifecycle deletions ({deletes}) "
                f"and off-hours maintenance ({off_hours}) with {100*(1-denied_rate):.0f}% authorization success."
            )

        # 3. Restorer Role -> High restore activity
        elif (restores >= 3 or row["restore_freq"] >= 0.35 or c_prof.get("avg_restore", 0) >= 3.0) and denied_rate < 0.4:
            suggested_role = "Restorer"
            confidence = int(min(96, 80 + restores * 3))
            reason = (
                f"K-Means Cluster {c_id} (Restorer Archetype): High recovery workload ({restores} restores, "
                f"{row['restore_freq']:.1%} of operations) aligns with dedicated Restorer responsibilities."
            )

        # 4. Owner Role -> Regular backups, downloads, and creation with compliant behavior
        elif (downloads >= 3 or total >= 5) and deletes == 0 and denied_rate < 0.3:
            if cur_role in ["Restorer", "Admin"]:
                suggested_role = "Owner"
                confidence = 86
                reason = (
                    f"K-Means Cluster {c_id}: Regular backup downloads ({downloads}) without administrative "
                    f"deletions or heavy restores. Optimized to Owner role."
                )
            else:
                suggested_role = "Owner"
                confidence = 88
                reason = (
                    f"K-Means Cluster {c_id} (Owner Archetype): Consistent active backup management "
                    f"({downloads} downloads) with zero policy violations."
                )

        # 5. Low / Read-Only activity -> Viewer
        elif total <= 2 or (downloads <= 2 and restores == 0 and deletes == 0):
            suggested_role = "Viewer"
            confidence = 82
            reason = (
                f"K-Means Cluster {c_id}: Minimal activity volume ({total} total actions). "
                f"Viewer role fulfills read-only monitoring needs."
            )
        else:
            # Consistent with current role
            suggested_role = cur_role
            confidence = 85
            reason = f"K-Means Cluster {c_id}: User activity is consistent with assigned {cur_role} role."

        suggestions.append({
            "user_id": uid,
            "current_role": cur_role,
            "suggested_role": suggested_role,
            "confidence": int(confidence),
            "reason": reason,
            "status": "Pending",
        })

    return suggestions


def save_suggestions_to_db(
    suggestions: List[Dict[str, Any]],
    db_path: Optional[str] = None
) -> int:
    """
    Save generated role recommendations into the 'role_suggestions' SQLite table.
    Updates or inserts pending suggestions while preserving Approved/Rejected audit trails.
    Returns the number of saved records.
    """
    if db_path is None:
        db_path = db_utils.get_db_path()

    conn = db_utils.get_connection(db_path)
    cursor = conn.cursor()

    # Ensure table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            current_role TEXT,
            suggested_role TEXT,
            confidence INTEGER,
            reason TEXT,
            status TEXT DEFAULT 'Pending'
        )
    """)
    conn.commit()

    saved_count = 0
    for s in suggestions:
        uid = s["user_id"]
        cur_role = s["current_role"]
        sug_role = s["suggested_role"]
        conf = int(s["confidence"])
        reason = s["reason"]
        status = s.get("status", "Pending")

        # Check if a pending suggestion already exists for this user
        cursor.execute("SELECT id FROM role_suggestions WHERE user_id = ? AND status = 'Pending'", (uid,))
        existing = cursor.fetchone()

        if existing:
            # Update existing pending suggestion with fresh cluster results
            cursor.execute("""
                UPDATE role_suggestions
                SET current_role = ?, suggested_role = ?, confidence = ?, reason = ?
                WHERE id = ?
            """, (cur_role, sug_role, conf, reason, existing[0]))
        else:
            cursor.execute("""
                INSERT INTO role_suggestions (user_id, current_role, suggested_role, confidence, reason, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uid, cur_role, sug_role, conf, reason, status))

        saved_count += 1

    conn.commit()
    conn.close()
    return saved_count


def suggest_roles(
    db_path: Optional[str] = None,
    access_logs: Optional[List[Dict[str, Any]]] = None,
    n_clusters: Optional[int] = None,
    save_to_db: bool = True,
    random_state: int = 42
) -> List[Dict[str, Any]]:
    """
    Main AI Role Suggester function.
    Reads access logs, clusters users using Scikit-Learn K-Means, generates role
    recommendations, and saves them to the 'role_suggestions' table.

    Parameters:
        db_path: Path to backups.db (default: logs/backups.db).
        access_logs: Optional list of log dicts (for testing / custom pipelines).
        n_clusters: Optional number of clusters for KMeans.
        save_to_db: If True, persists recommendations into role_suggestions table.
        random_state: Random seed for KMeans reproducibility.

    Returns:
        List of suggestion dictionaries.
    """
    if db_path is None:
        db_path = db_utils.get_db_path()

    users_map: Dict[str, str] = {}

    # Read from database if access_logs not explicitly passed
    if access_logs is None:
        conn = db_utils.get_connection(db_path)
        cur = conn.cursor()

        # Load users map
        try:
            cur.execute("SELECT user_id, username, role FROM users")
            for r in cur.fetchall():
                if r[0]:
                    users_map[str(r[0])] = r[2]
                if r[1]:
                    users_map[str(r[1])] = r[2]
        except Exception:
            pass

        # Load audit logs
        cur.execute("SELECT user_id, action, timestamp, result, decision, reason FROM audit_log")
        rows = cur.fetchall()
        conn.close()

        access_logs = [
            {
                "user_id": r[0],
                "action": r[1],
                "timestamp": r[2],
                "result": r[3] or r[4],
                "reason": r[5]
            }
            for r in rows
        ]

    if not access_logs:
        return []

    # 1. Feature Extraction
    features_df = extract_user_features(access_logs, users_map=users_map)
    if features_df.empty:
        return []

    # 2. K-Means Clustering
    labels, kmeans, scaler = cluster_users(features_df, n_clusters=n_clusters, random_state=random_state)

    # 3. Intelligent Recommendations
    suggestions = generate_recommendations(features_df, labels, kmeans)

    # 4. Save to Database
    if save_to_db and suggestions:
        save_suggestions_to_db(suggestions, db_path=db_path)

    return suggestions


if __name__ == "__main__":
    results = suggest_roles()
    print(f"Generated {len(results)} role recommendations:")
    for res in results:
        print(f" - User {res['user_id']}: {res['current_role']} -> {res['suggested_role']} ({res['confidence']}%) | {res['reason']}")
