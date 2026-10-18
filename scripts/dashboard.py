import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import json
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "backups.db")
ANOMALY_PATH = os.path.join(DATA_DIR, "anomalies.json")

st.set_page_config(
    page_title="Secure Cloud Backup Manager",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

    /* ---------- GLOBAL ---------- */

    .stApp {
        background-color: #f5f7fb;
    }

    .main {
        padding-top: 1rem;
    }

    h1, h2, h3 {
        color: #172033;
    }


    /* ---------- SIDEBAR ---------- */

    section[data-testid="stSidebar"] {
        background: #101827;
    }

    section[data-testid="stSidebar"] * {
        color: white;
    }


    /* ---------- HEADER ---------- */

    .dashboard-header {
        background: linear-gradient(135deg, #172554, #1e40af);
        padding: 28px 32px;
        border-radius: 16px;
        color: white;
        margin-bottom: 25px;
        box-shadow: 0 8px 25px rgba(30, 64, 175, 0.18);
    }

    .dashboard-header h1 {
        color: white;
        font-size: 30px;
        margin-bottom: 5px;
    }

    .dashboard-header p {
        color: #dbeafe;
        margin: 0;
        font-size: 15px;
    }


    /* ---------- KPI CARDS ---------- */

    .kpi-card {
        background: white;
        padding: 20px;
        border-radius: 14px;
        border: 1px solid #e5e7eb;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        min-height: 135px;
    }

    .kpi-title {
        color: #64748b;
        font-size: 14px;
        font-weight: 600;
    }

    .kpi-value {
        color: #172033;
        font-size: 30px;
        font-weight: 700;
        margin-top: 8px;
    }

    .kpi-icon {
        font-size: 26px;
        float: right;
    }


    /* ---------- SECTION ---------- */

    .section-title {
        font-size: 20px;
        font-weight: 700;
        color: #172033;
        margin-top: 15px;
        margin-bottom: 15px;
    }


    /* ---------- STATUS ---------- */

    .status-card {
        background: white;
        padding: 20px;
        border-radius: 14px;
        border: 1px solid #e5e7eb;
        margin-bottom: 12px;
    }

    .status-success {
        color: #15803d;
        font-weight: 700;
    }

    .status-warning {
        color: #ca8a04;
        font-weight: 700;
    }

    .status-danger {
        color: #dc2626;
        font-weight: 700;
    }


    /* ---------- ALERT ---------- */

    .security-alert {
        background: #fff7ed;
        border-left: 5px solid #f97316;
        padding: 14px 16px;
        border-radius: 8px;
        margin-bottom: 10px;
    }

    .security-alert-high {
        background: #fef2f2;
        border-left: 5px solid #dc2626;
    }


    /* ---------- AI CARD ---------- */

    .ai-card {
        background: linear-gradient(135deg, #eef2ff, #f8fafc);
        border: 1px solid #c7d2fe;
        padding: 18px;
        border-radius: 12px;
        margin-bottom: 12px;
    }

    .ai-title {
        font-weight: 700;
        color: #3730a3;
    }


    /* ---------- FOOTER ---------- */

    .footer {
        text-align: center;
        color: #64748b;
        padding: 25px;
        font-size: 13px;
    }

</style>
""", unsafe_allow_html=True)


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def get_connection():
    return sqlite3.connect(DB_PATH)


def get_table_columns(table_name):

    try:
        conn = get_connection()

        columns = pd.read_sql_query(
            f"PRAGMA table_info({table_name})",
            conn
        )

        conn.close()

        return columns["name"].tolist()

    except Exception:
        return []


def load_audit_logs():

    try:
        conn = get_connection()

        df = pd.read_sql_query(
            "SELECT * FROM audit_log ORDER BY timestamp DESC",
            conn
        )

        conn.close()

        return df

    except Exception:
        return pd.DataFrame()


def load_backups():

    try:
        conn = get_connection()

        df = pd.read_sql_query(
            "SELECT * FROM backups",
            conn
        )

        conn.close()

        return df

    except Exception:
        return pd.DataFrame()


# ============================================================
# KPI CALCULATIONS
# ============================================================

def calculate_metrics(audit_df, backup_df):

    total_backups = len(backup_df)

    audit_events = len(audit_df)

    if not audit_df.empty and "action" in audit_df.columns:

        restores = len(
            audit_df[
                audit_df["action"].astype(str).str.upper()
                .str.contains("RESTORE")
            ]
        )

    else:
        restores = 0


    if not audit_df.empty and "result" in audit_df.columns:

        denied = len(
            audit_df[
                audit_df["result"].astype(str).str.upper()
                .str.contains("DENIED|RBAC|ABAC", regex=True)
            ]
        )

    else:
        denied = 0


    anomaly_count = 0

    if os.path.exists(ANOMALY_PATH):

        try:

            with open(
                ANOMALY_PATH,
                encoding="utf-8"
            ) as f:

                data = json.load(f)

                anomaly_count = data.get(
                    "anomaly_count",
                    0
                )

        except Exception:
            anomaly_count = 0


    return {
        "backups": total_backups,
        "audit": audit_events,
        "restores": restores,
        "denied": denied,
        "anomalies": anomaly_count
    }


# ============================================================
# AI ROLE SUGGESTIONS
# ============================================================

def generate_role_suggestions(audit_df):

    suggestions = []

    if audit_df.empty:
        return suggestions

    if "user" not in audit_df.columns:
        return suggestions

    for user in audit_df["user"].dropna().unique():

        user_df = audit_df[
            audit_df["user"] == user
        ]

        actions = []

        if "action" in user_df.columns:

            actions = (
                user_df["action"]
                .astype(str)
                .str.upper()
                .tolist()
            )

        backup_count = sum(
            "BACKUP" in action
            for action in actions
        )

        restore_count = sum(
            "RESTORE" in action
            for action in actions
        )

        download_count = sum(
            "DOWNLOAD" in action
            for action in actions
        )

        delete_count = sum(
            "DELETE" in action
            for action in actions
        )


        if "result" in user_df.columns:

            denied_count = user_df[
                user_df["result"]
                .astype(str)
                .str.upper()
                .str.contains("DENIED|RBAC|ABAC")
            ].shape[0]

        else:
            denied_count = 0


        # Prototype recommendation logic

        if denied_count >= 3:

            role = "Restricted Viewer"
            confidence = min(
                70 + denied_count * 5,
                95
            )

            reason = (
                "Repeated unauthorized access attempts "
                "detected."
            )

        elif backup_count >= 5 and restore_count >= 2:

            role = "Backup Manager"
            confidence = 91

            reason = (
                "Frequent backup and restore operations "
                "indicate elevated backup responsibilities."
            )

        elif download_count >= 5:

            role = "Data Viewer"
            confidence = 84

            reason = (
                "User frequently performs download operations."
            )

        else:

            role = "Standard User"
            confidence = 78

            reason = (
                "Activity pattern matches normal user behavior."
            )


        suggestions.append({
            "user": user,
            "role": role,
            "confidence": confidence,
            "reason": reason
        })


    return suggestions[:5]


# ============================================================
# LOAD DATA
# ============================================================

audit_df = load_audit_logs()
backup_df = load_backups()

metrics = calculate_metrics(
    audit_df,
    backup_df
)

suggestions = generate_role_suggestions(
    audit_df
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div style="
            font-size:25px;
            font-weight:bold;
            margin-bottom:5px;
        ">
        🔐 SecureCloud
        </div>

        <div style="
            color:#94a3b8;
            font-size:13px;
            margin-bottom:30px;
        ">
        Backup & Access Manager
        </div>
        """,
        unsafe_allow_html=True
    )


    page = st.radio(
        "Navigation",
        [
            "📊 Dashboard",
            "📜 Audit Logs",
            "🛡️ Access Control",
            "🚨 Security Alerts",
            "🤖 AI Role Suggestions"
        ]
    )


    st.markdown("---")

    st.markdown(
        """
        **System Status**

        🟢 Database: Online

        🟢 RBAC: Active

        🟢 ABAC: Active

        🟢 Monitoring: Active
        """
    )


    st.markdown("---")

    if st.button("🔄 Refresh Dashboard"):

        st.rerun()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="dashboard-header">

        <h1>🔐 Secure Cloud Backup & Access Manager</h1>

        <p>
        Centralized monitoring for backup operations,
        RBAC/ABAC security, audit activity and
        AI-assisted role management.
        </p>

    </div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# DASHBOARD PAGE
# ============================================================

if page == "📊 Dashboard":

    st.markdown(
        '<div class="section-title">System Overview</div>',
        unsafe_allow_html=True
    )


    # KPI CARDS

    c1, c2, c3, c4, c5 = st.columns(5)


    with c1:

        st.markdown(
            f"""
            <div class="kpi-card">

                <span class="kpi-icon">☁️</span>

                <div class="kpi-title">
                    Total Backups
                </div>

                <div class="kpi-value">
                    {metrics["backups"]}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    with c2:

        st.markdown(
            f"""
            <div class="kpi-card">

                <span class="kpi-icon">📋</span>

                <div class="kpi-title">
                    Audit Events
                </div>

                <div class="kpi-value">
                    {metrics["audit"]}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    with c3:

        st.markdown(
            f"""
            <div class="kpi-card">

                <span class="kpi-icon">♻️</span>

                <div class="kpi-title">
                    Restores
                </div>

                <div class="kpi-value">
                    {metrics["restores"]}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    with c4:

        st.markdown(
            f"""
            <div class="kpi-card">

                <span class="kpi-icon">🚫</span>

                <div class="kpi-title">
                    Denied Events
                </div>

                <div class="kpi-value">
                    {metrics["denied"]}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    with c5:

        st.markdown(
            f"""
            <div class="kpi-card">

                <span class="kpi-icon">🚨</span>

                <div class="kpi-title">
                    Anomalies
                </div>

                <div class="kpi-value">
                    {metrics["anomalies"]}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


    st.write("")


    # ========================================================
    # CHARTS
    # ========================================================

    left, right = st.columns(2)


    # AUDIT TREND

    with left:

        st.markdown(
            '<div class="section-title">📈 Audit Activity</div>',
            unsafe_allow_html=True
        )

        if not audit_df.empty and "timestamp" in audit_df.columns:

            chart_df = audit_df.copy()

            chart_df["timestamp"] = pd.to_datetime(
                chart_df["timestamp"],
                errors="coerce"
            )

            chart_df = chart_df.dropna(
                subset=["timestamp"]
            )

            if not chart_df.empty:

                chart_df["date"] = (
                    chart_df["timestamp"]
                    .dt.date
                )

                daily = (
                    chart_df
                    .groupby("date")
                    .size()
                    .reset_index(name="Events")
                )

                fig = px.line(
                    daily,
                    x="date",
                    y="Events",
                    markers=True,
                    title="Security Events Over Time"
                )

                fig.update_layout(
                    template="plotly_white",
                    margin=dict(
                        l=10,
                        r=10,
                        t=50,
                        b=10
                    ),
                    xaxis_title="Date",
                    yaxis_title="Events"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

            else:

                st.info("No timestamp data available.")

        else:

            st.info("No audit activity available.")


    # ALLOWED VS DENIED

    with right:

        st.markdown(
            '<div class="section-title">🛡️ Access Decisions</div>',
            unsafe_allow_html=True
        )

        if not audit_df.empty and "result" in audit_df.columns:

            result_df = (
                audit_df["result"]
                .astype(str)
                .str.upper()
                .apply(
                    lambda x:
                    "Denied"
                    if "DENIED" in x or
                       "RBAC" in x or
                       "ABAC" in x
                    else "Allowed"
                )
                .value_counts()
                .reset_index()
            )

            result_df.columns = [
                "Decision",
                "Count"
            ]

            fig = px.pie(
                result_df,
                names="Decision",
                values="Count",
                hole=0.55,
                title="Allowed vs Denied Requests"
            )

            fig.update_layout(
                template="plotly_white",
                margin=dict(
                    l=10,
                    r=10,
                    t=50,
                    b=10
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info("No access decision data.")


    # ========================================================
    # SECURITY STATUS
    # ========================================================

    st.markdown(
        '<div class="section-title">🔒 Security Controls</div>',
        unsafe_allow_html=True
    )


    s1, s2, s3, s4 = st.columns(4)


    with s1:

        st.markdown(
            """
            <div class="status-card">

            <h3>RBAC</h3>

            <p class="status-success">
            🟢 Active
            </p>

            <small>
            Role-based permissions are enforced.
            </small>

            </div>
            """,
            unsafe_allow_html=True
        )


    with s2:

        st.markdown(
            """
            <div class="status-card">

            <h3>ABAC</h3>

            <p class="status-success">
            🟢 Active
            </p>

            <small>
            Context-aware access control enabled.
            </small>

            </div>
            """,
            unsafe_allow_html=True
        )


    with s3:

        st.markdown(
            """
            <div class="status-card">

            <h3>Encryption</h3>

            <p class="status-success">
            🟢 AES-256
            </p>

            <small>
            Backup encryption enabled.
            </small>

            </div>
            """,
            unsafe_allow_html=True
        )


    with s4:

        st.markdown(
            """
            <div class="status-card">

            <h3>Monitoring</h3>

            <p class="status-success">
            🟢 Active
            </p>

            <small>
            Anomaly detection is monitoring activity.
            </small>

            </div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # RECENT AUDIT LOGS
    # ========================================================

    st.markdown(
        '<div class="section-title">📜 Recent Security Events</div>',
        unsafe_allow_html=True
    )


    if not audit_df.empty:

        display_df = audit_df.head(8)

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info("No audit events available.")


# ============================================================
# AUDIT LOG PAGE
# ============================================================

elif page == "📜 Audit Logs":

    st.header("📜 Detailed Audit Logs")

    if audit_df.empty:

        st.info("No audit log data available.")

    else:

        filtered_df = audit_df.copy()


        # USER FILTER

        if "user" in filtered_df.columns:

            users = (
                ["All"] +
                sorted(
                    filtered_df["user"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                )
            )

            selected_user = st.selectbox(
                "Filter by User",
                users
            )

            if selected_user != "All":

                filtered_df = filtered_df[
                    filtered_df["user"].astype(str)
                    == selected_user
                ]


        # RESULT FILTER

        if "result" in filtered_df.columns:

            results = (
                ["All"] +
                sorted(
                    filtered_df["result"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                )
            )

            selected_result = st.selectbox(
                "Filter by Decision",
                results
            )

            if selected_result != "All":

                filtered_df = filtered_df[
                    filtered_df["result"].astype(str)
                    == selected_result
                ]


        # SEARCH

        search = st.text_input(
            "🔍 Search audit logs"
        )

        if search:

            mask = (
                filtered_df
                .astype(str)
                .apply(
                    lambda row:
                    row.str.contains(
                        search,
                        case=False,
                        na=False
                    ).any(),
                    axis=1
                )
            )

            filtered_df = filtered_df[mask]


        st.write(
            f"Showing **{len(filtered_df)}** events"
        )


        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# ACCESS CONTROL PAGE
# ============================================================

elif page == "🛡️ Access Control":

    st.header("🛡️ RBAC / ABAC Access Control")

    col1, col2 = st.columns(2)


    with col1:

        st.subheader("RBAC")

        st.info(
            """
            **Role-Based Access Control**

            Determines whether a user's assigned role
            is permitted to perform an action.

            Example:

            Admin → Backup / Restore / Download / Delete

            Developer → Backup / Restore / Download

            Viewer → Download
            """
        )


        if not audit_df.empty and "result" in audit_df.columns:

            denied = audit_df[
                audit_df["result"]
                .astype(str)
                .str.upper()
                .str.contains("RBAC")
            ]

            st.metric(
                "RBAC Denials",
                len(denied)
            )


    with col2:

        st.subheader("ABAC")

        st.info(
            """
            **Attribute-Based Access Control**

            Access decisions can consider:

            • Time

            • Device

            • Location

            • IP Address

            • Backup Age

            • Risk Score
            """
        )


        if not audit_df.empty and "result" in audit_df.columns:

            denied = audit_df[
                audit_df["result"]
                .astype(str)
                .str.upper()
                .str.contains("ABAC")
            ]

            st.metric(
                "ABAC Denials",
                len(denied)
            )


    st.subheader("Security Decision Flow")

    st.code(
        """
        User Request
              │
              ▼
        Authentication
              │
              ▼
        RBAC Check
          │       │
         No      Yes
          │       │
          ▼       ▼
        Deny     ABAC Check
                  │
              ┌───┴───┐
             No      Yes
              │       │
              ▼       ▼
            Deny    Risk Score
                       │
                       ▼
                Allow / Deny
        """,
        language="text"
    )


# ============================================================
# SECURITY ALERTS
# ============================================================

elif page == "🚨 Security Alerts":

    st.header("🚨 Security Alerts")

    if metrics["anomalies"] > 0:

        st.error(
            f"⚠️ {metrics['anomalies']} anomaly/anomalies detected."
        )

    else:

        st.success(
            "🟢 No major anomalies detected."
        )


    # Generate alerts from denied events

    if not audit_df.empty and "result" in audit_df.columns:

        denied_df = audit_df[
            audit_df["result"]
            .astype(str)
            .str.upper()
            .str.contains(
                "DENIED|RBAC|ABAC"
            )
        ]

        if denied_df.empty:

            st.success(
                "No denied access events found."
            )

        else:

            for _, row in denied_df.head(10).iterrows():

                user = (
                    row.get("user", "Unknown")
                )

                action = (
                    row.get("action", "Unknown")
                )

                result = (
                    row.get("result", "Denied")
                )


                st.markdown(
                    f"""
                    <div class="security-alert security-alert-high">

                    <b>🔴 Security Event</b>

                    <br>

                    User: <b>{user}</b>

                    <br>

                    Action: <b>{action}</b>

                    <br>

                    Decision: <b>{result}</b>

                    </div>
                    """,
                    unsafe_allow_html=True
                )


# ============================================================
# AI ROLE SUGGESTIONS
# ============================================================

elif page == "🤖 AI Role Suggestions":

    st.header("🤖 AI-Based Role Suggestions")

    st.info(
        """
        Role recommendations are generated from user activity
        patterns such as backup frequency, restore operations,
        downloads and denied requests.
        """
    )


    if not suggestions:

        st.warning(
            "Not enough user activity data for suggestions."
        )

    else:

        for suggestion in suggestions:

            st.markdown(
                f"""
                <div class="ai-card">

                <div class="ai-title">
                🤖 Role Recommendation
                </div>

                <h3>
                {suggestion["user"]}
                </h3>

                <p>
                Suggested Role:
                <b>{suggestion["role"]}</b>
                </p>

                <p>
                {suggestion["reason"]}
                </p>

                <b>
                AI Confidence: {suggestion["confidence"]}%
                </b>

                </div>
                """,
                unsafe_allow_html=True
            )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">

    🔐 Secure Cloud Backup & Access Manager

    | RBAC | ABAC | Encryption | Audit Logging | Anomaly Detection | AI Suggestions

    <br>

    Academic Project Prototype

    </div>
    """,
    unsafe_allow_html=True
)
