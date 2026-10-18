import sys
import os
import sqlite3
import pandas as pd
import streamlit as st
from datetime import datetime

# ==============================================================================
# 1. APPLICATION SETUP & PATH CONFIGURATION
# ==============================================================================

# Ensure the project root is in sys.path so utils and scripts are accessible
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import importlib
from utils import db_utils, anomaly_detector, role_suggester
importlib.reload(db_utils)
importlib.reload(anomaly_detector)
importlib.reload(role_suggester)

# Streamlit Page Config
st.set_page_config(
    page_title="SecureCloud Backup Manager",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database tables and seeds
db_utils.init_all()

# ==============================================================================
# 2. CUSTOM ENTERPRISE CSS THEME
# ==============================================================================

st.markdown("""
<style>
    /* Font & Global resets */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 2rem;
    }

    /* Header Banner */
    .enterprise-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #1e3a8a 100%);
        padding: 24px 30px;
        border-radius: 14px;
        color: #ffffff;
        margin-bottom: 24px;
        border: 1px solid #334155;
        box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.4);
    }
    .enterprise-header h1 {
        font-size: 26px;
        font-weight: 700;
        margin: 0 0 6px 0;
        color: #f8fafc;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .enterprise-header p {
        font-size: 14px;
        color: #94a3b8;
        margin: 0;
    }

    /* KPI Cards */
    .kpi-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        margin-bottom: 16px;
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .kpi-card:hover {
        border-color: #3b82f6;
        transform: translateY(-2px);
    }
    .kpi-title {
        font-size: 13px;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .kpi-value {
        font-size: 28px;
        font-weight: 700;
        color: #f8fafc;
        margin-top: 6px;
    }
    .kpi-desc {
        font-size: 12px;
        color: #64748b;
        margin-top: 4px;
    }

    /* Badges */
    .badge-allowed, .badge-active, .badge-approved {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .badge-denied, .badge-rejected, .badge-high {
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .badge-restored, .badge-medium {
        background-color: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .badge-pending, .badge-low {
        background-color: rgba(59, 130, 246, 0.15);
        color: #3b82f6;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 12px;
        border: 1px solid rgba(59, 130, 246, 0.3);
    }

    /* Anomaly Alert Card */
    .alert-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-left: 5px solid #ef4444;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 14px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.15);
    }
    .alert-card-medium {
        border-left: 5px solid #f59e0b;
    }
    .alert-card-low {
        border-left: 5px solid #3b82f6;
    }

    /* Role Suggestion Card */
    .role-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 16px;
    }

    /* User Profile in Sidebar */
    .user-profile-box {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 14px;
        margin-bottom: 18px;
    }
    
    /* Login Box Container */
    .login-container {
        max-width: 440px;
        margin: 40px auto;
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 32px 36px;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# 3. AUTHENTICATION & SESSION STATE
# ==============================================================================

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if "user" not in st.session_state:
    st.session_state["user"] = None

def render_login_page():
    """Renders the secure login form against backups.db users table."""
    c1, col, c2 = st.columns([1, 1.8, 1])
    
    with col:
        st.markdown("""
        <div class="login-container">
            <div style="text-align: center; margin-bottom: 24px;">
                <span style="font-size: 42px;">🔐</span>
                <h2 style="color: #f8fafc; margin: 8px 0 4px 0; font-size: 24px;">SecureCloud Backup</h2>
                <p style="color: #94a3b8; font-size: 13px; margin: 0;">Zero-Trust Backup & Audit Management Portal</p>
            </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            username_input = st.text_input("Username or User ID", placeholder="e.g. admin or U003")
            password_input = st.text_input("Password", type="password", placeholder="Enter your password")
            submit_btn = st.form_submit_button("Sign In ➔", use_container_width=True)
            
            if submit_btn:
                if not username_input or not password_input:
                    st.error("Please enter both username/user ID and password.")
                else:
                    try:
                        # Verify credentials against both 'username' OR 'user_id' columns in backups.db
                        user = db_utils.authenticate_user(username_input, password_input)
                        if user:
                            st.session_state["authenticated"] = True
                            st.session_state["user"] = user
                            st.success(f"Welcome back, {user['name']}!")
                            st.rerun()
                        else:
                            st.error("Invalid credentials. Please verify your username or user ID and password.")
                    except Exception as e:
                        st.error(f"Authentication system error: {str(e)}")
                        
        st.markdown("""
            <div style="margin-top: 24px; padding: 14px; background: rgba(15, 23, 42, 0.6); border-radius: 8px; border: 1px dashed #475569; font-size: 12px; color: #94a3b8;">
                <b style="color: #cbd5e1;">🔑 Demo Credentials (Login with Username OR User ID):</b><br>
                • <b>Admin:</b> <code>admin</code> or <code>U000</code> / <code>admin123</code><br>
                • <b>Viewer:</b> <code>charlie</code> or <code>U003</code> / <code>charlie123</code> (or <code>password123</code>)<br>
                • <b>Restorer:</b> <code>bob</code> or <code>U002</code> / <code>bob123</code> (or <code>password123</code>)<br>
                • <b>Owner:</b> <code>alice</code> or <code>U001</code> / <code>alice123</code> (or <code>password123</code>)<br>
                • <b>Guest:</b> <code>guest</code> or <code>U005</code> / <code>guest123</code> (or <code>password123</code>)
            </div>
        </div>
        """, unsafe_allow_html=True)

# If not authenticated, render login page and halt execution
if not st.session_state["authenticated"]:
    render_login_page()
    st.stop()


# ==============================================================================
# 4. SIDEBAR & NAVIGATION
# ==============================================================================

current_user = st.session_state["user"]

with st.sidebar:
    st.markdown("""
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
            <span style="font-size: 26px;">🔐</span>
            <span style="font-size: 18px; font-weight: 700; color: #f8fafc;">SecureCloud</span>
        </div>
        <p style="color: #64748b; font-size: 12px; margin-top: -6px; margin-bottom: 20px;">
            Zero-Trust Encrypted Backup Suite
        </p>
    """, unsafe_allow_html=True)
    
    # User Profile Box
    role_color = "#3b82f6"
    if current_user["role"] == "Admin":
        role_color = "#10b981"
    elif current_user["role"] == "Restorer":
        role_color = "#f59e0b"
        
    st.markdown(f"""
        <div class="user-profile-box">
            <div style="font-size: 14px; font-weight: 600; color: #f8fafc;">{current_user['name']}</div>
            <div style="font-size: 12px; color: #94a3b8;">ID: {current_user['user_id']} | {current_user['department']}</div>
            <div style="margin-top: 8px;">
                <span style="background: rgba(59, 130, 246, 0.15); color: {role_color}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; border: 1px solid {role_color};">
                    {current_user['role'].upper()}
                </span>
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    page = st.radio(
        "Navigation",
        [
            "📦 Backups",
            "📜 Audit Logs",
            "🚨 Alerts",
            "🤖 Role Suggestions"
        ]
    )
    
    st.markdown("---")
    
    # System Status Indicators
    active_db = os.path.relpath(db_utils.get_db_path(), BASE_DIR).replace('\\', '/')
    st.markdown(f"""
        <div style="font-size: 12px; color: #94a3b8; line-height: 1.8;">
            <b>System Status:</b><br>
            🟢 Database: <code>{active_db}</code><br>
            🟢 AES-256 Encryption: Active<br>
            🟢 SHA-256 Integrity: Enforced<br>
            🟢 Audit Logging: Real-time
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    if st.button("🚪 Log Out", use_container_width=True):
        st.session_state["authenticated"] = False
        st.session_state["user"] = None
        st.rerun()


# ==============================================================================
# 5. PAGE: BACKUPS (List + Working Restore Button)
# ==============================================================================

if page == "📦 Backups":
    st.markdown("""
        <div class="enterprise-header">
            <h1><span>📦</span> Cloud Backup Storage</h1>
            <p>Manage AES-256 encrypted backup archives, verify cryptographic integrity, and perform verified restores.</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Fetch backups through db_utils
    try:
        backups = db_utils.get_backups_table_data()
    except Exception as e:
        st.error(f"Failed to load backups from database: {str(e)}")
        backups = []
        
    total_backups = len(backups)
    active_backups = sum(1 for b in backups if b["status"] == "active")
    restored_backups = sum(1 for b in backups if b["status"] == "restored")
    total_bytes = sum(b["raw_size"] for b in backups)
    
    # KPI Row
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Total Archives</div>
                <div class="kpi-value">{total_backups}</div>
                <div class="kpi-desc">Registered encrypted backups</div>
            </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Active Backups</div>
                <div class="kpi-value" style="color: #10b981;">{active_backups}</div>
                <div class="kpi-desc">Ready for restore</div>
            </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Restored Backups</div>
                <div class="kpi-value" style="color: #f59e0b;">{restored_backups}</div>
                <div class="kpi-desc">Previously restored</div>
            </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Total Footprint</div>
                <div class="kpi-value">{total_bytes:,} <span style="font-size: 14px;">B</span></div>
                <div class="kpi-desc">AES-256 cloud container size</div>
            </div>
        """, unsafe_allow_html=True)
        
    st.markdown("### 📋 Encrypted Backups Repository")
    
    # Filter Controls
    search_col, filter_col = st.columns([3, 1])
    with search_col:
        search_query = st.text_input("🔍 Search backups by ID or Owner", placeholder="e.g. B2026 or U101")
    with filter_col:
        status_filter = st.selectbox("Status Filter", ["All", "active", "restored"])
        
    filtered_backups = backups
    if search_query:
        q = search_query.strip().lower()
        filtered_backups = [b for b in filtered_backups if q in b["id"].lower() or q in b["owner"].lower()]
    if status_filter != "All":
        filtered_backups = [b for b in filtered_backups if b["status"] == status_filter]
        
    if not filtered_backups:
        st.info("No backups found matching the specified criteria.")
    else:
        st.markdown(f"Displaying **{len(filtered_backups)}** backups:")
        
        # Table Header
        h1, h2, h3, h4, h5, h6, h7 = st.columns([1.6, 3.2, 1.0, 1.0, 2.0, 1.1, 1.3])
        h1.markdown("**Backup ID**")
        h2.markdown("**Storage Path**")
        h3.markdown("**Size**")
        h4.markdown("**Owner**")
        h5.markdown("**Date Created**")
        h6.markdown("**Status**")
        h7.markdown("**Action**")
        st.markdown("<hr style='margin: 4px 0 12px 0; border-color: #334155;'>", unsafe_allow_html=True)
        
        # Display each row with working Restore button
        for item in filtered_backups:
            c1, c2, c3, c4, c5, c6, c7 = st.columns([1.6, 3.2, 1.0, 1.0, 2.0, 1.1, 1.3])
            
            c1.markdown(f"**`{item['id']}`**")
            c2.markdown(f"<code style='font-size: 11px;'>{item['path']}</code>", unsafe_allow_html=True)
            c3.write(item["size"])
            c4.write(f"👤 {item['owner']}")
            c5.write(item["date"])
            
            # Status Badge
            badge_class = "badge-active" if item["status"] == "active" else "badge-restored"
            c6.markdown(f"<span class='{badge_class}'>{item['status'].upper()}</span>", unsafe_allow_html=True)
            
            # Working Restore Button
            restore_clicked = c7.button("🔄 Restore", key=f"btn_restore_{item['id']}")
            if restore_clicked:
                with st.spinner(f"Verifying checksum & decrypting {item['id']}..."):
                    try:
                        success, message, files = db_utils.restore_backup_file(item["id"], user_id=current_user["user_id"])
                        if success:
                            st.success(f"✅ {message}")
                            st.info(f"📂 Extracted to `data/restore_output/` | Files: {', '.join(files) if files else 'None'}")
                            st.rerun()
                        else:
                            st.error(f"❌ Restore Failed: {message}")
                    except Exception as ex:
                        st.error(f"Execution error during restore: {str(ex)}")
                        
            # Checksum expander per backup
            with st.expander(f"🔍 Technical Details & SHA-256 Checksum for {item['id']}", expanded=False):
                st.code(f"Backup ID: {item['id']}\nEncrypted Path: {item['path']}\nStored SHA-256: {item['checksum']}\nFile Size: {item['raw_size']} bytes\nOwner: {item['owner']}\nStatus: {item['status']}", language="yaml")


# ==============================================================================
# 6. PAGE: AUDIT LOGS (Filterable Data Table)
# ==============================================================================

elif page == "📜 Audit Logs":
    st.markdown("""
        <div class="enterprise-header">
            <h1><span>📜</span> System Audit Logs</h1>
            <p>Immutable forensic audit trail capturing access requests, authorization decisions, and security events.</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Load all distinct users and actions for filters
    all_users = sorted(list({u["user_id"] for u in db_utils.get_all_users()} | {u["username"] for u in db_utils.get_all_users()}))
    user_options = ["All"] + all_users
    action_options = ["All", "DOWNLOAD", "RESTORE", "DELETE", "BACKUP", "LIST", "BACKUP_RESTORED", "ROLE_APPROVED", "ROLE_REJECTED"]
    decision_options = ["All", "ALLOW", "DENY", "Allowed", "Denied", "Rejected"]
    
    # Filter Controls
    f1, f2, f3, f4 = st.columns([1.5, 1.5, 1.5, 2.5])
    with f1:
        sel_user = st.selectbox("Filter by User", user_options)
    with f2:
        sel_action = st.selectbox("Filter by Action", action_options)
    with f3:
        sel_decision = st.selectbox("Filter by Decision", decision_options)
    with f4:
        search_kw = st.text_input("🔍 Search Audit Records", placeholder="Keywords in reason, ID, action...")
        
    try:
        logs = db_utils.get_audit_logs(
            user_filter=sel_user,
            decision_filter=sel_decision,
            action_filter=sel_action,
            search_query=search_kw
        )
    except Exception as e:
        st.error(f"Error querying audit log table: {str(e)}")
        logs = []
        
    # Metrics
    total_logs = len(logs)
    allowed_count = sum(1 for l in logs if str(l["decision"]).strip().upper() in ["ALLOWED", "ALLOW", "SUCCESS"])
    denied_count = sum(1 for l in logs if str(l["decision"]).strip().upper() in ["DENIED", "DENY", "REJECTED", "FAILED"])

    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Filtered Events</div>
                <div class="kpi-value">{total_logs:,}</div>
                <div class="kpi-desc">Matching current filter</div>
            </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Allowed Requests</div>
                <div class="kpi-value" style="color: #10b981;">{allowed_count:,}</div>
                <div class="kpi-desc">Authorized operations</div>
            </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Denied / Flagged</div>
                <div class="kpi-value" style="color: #ef4444;">{denied_count:,}</div>
                <div class="kpi-desc">Policy violations prevented</div>
            </div>
        """, unsafe_allow_html=True)
    with m4:
        compliance_pct = round((allowed_count / total_logs * 100), 1) if total_logs > 0 else 100.0
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Compliance Rate</div>
                <div class="kpi-value" style="color: #3b82f6;">{compliance_pct}%</div>
                <div class="kpi-desc">Policy pass ratio</div>
            </div>
        """, unsafe_allow_html=True)
        
    st.markdown("### 📊 Audit Records Table")
    
    if not logs:
        st.info("No audit logs match your search filters.")
    else:
        df = pd.DataFrame(logs)
        df_display = df[["user", "action", "timestamp", "decision", "reason"]].copy()
        df_display.columns = ["User", "Action", "Timestamp", "Decision", "Reason"]
        
        # Interactive Streamlit Data Table
        st.dataframe(
            df_display,
            use_container_width=True,
            hide_index=True,
            column_config={
                "User": st.column_config.TextColumn("User", width="small"),
                "Action": st.column_config.TextColumn("Action", width="small"),
                "Timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss", width="medium"),
                "Decision": st.column_config.TextColumn("Decision", width="small"),
                "Reason": st.column_config.TextColumn("Reason", width="large")
            }
        )
        
        # CSV Export feature
        csv_data = df_display.to_csv(index=False).encode('utf-8')
        st.download_button(
            "📥 Export Filtered Audit Logs (CSV)",
            data=csv_data,
            file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )


# ==============================================================================
# 7. PAGE: ALERTS (Anomaly Alerts View)
# ==============================================================================

elif page == "🚨 Alerts":
    st.markdown("""
        <div class="enterprise-header">
            <h1><span>🚨</span> Security Anomaly Alerts</h1>
            <p>Real-time threat detection feed flagging privilege misuse, unauthorized delete attempts, and anomalous device access.</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Action panel: Live threat detection trigger
    c_action1, c_action2 = st.columns([2.5, 4.5])
    with c_action1:
        if st.button("⚡ Run Live Threat Detection", use_container_width=True, type="primary"):
            with st.spinner("Analyzing access logs for security anomalies..."):
                try:
                    detected = anomaly_detector.detect_anomalies(save_to_db=True)
                    st.success(f"Detection engine evaluated rules: {len(detected)} live alerts synced.")
                    st.rerun()
                except Exception as scan_err:
                    st.error(f"Detection engine error: {scan_err}")
    with c_action2:
        st.markdown("""
            <div style="font-size: 12px; color: #94a3b8; padding-top: 8px;">
                <b>Active Threat Detection Engine:</b> Continuous heuristic auditing across download bursts (&gt;20/10m), off-hours operations (outside 9am-6pm), and unauthorized IP subnets.
            </div>
        """, unsafe_allow_html=True)
    st.write("")
    
    try:
        alerts = db_utils.get_alerts()
    except Exception as e:
        st.error(f"Error fetching alerts: {str(e)}")
        alerts = []
        
    total_alerts = len(alerts)
    high_risk = sum(1 for a in alerts if a["risk_score"] >= 80)
    med_risk = sum(1 for a in alerts if 60 <= a["risk_score"] < 80)
    low_risk = sum(1 for a in alerts if a["risk_score"] < 60)
    
    # KPI Row
    a1, a2, a3, a4 = st.columns(4)
    with a1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Total Active Alerts</div>
                <div class="kpi-value">{total_alerts}</div>
                <div class="kpi-desc">Engine generated anomalies</div>
            </div>
        """, unsafe_allow_html=True)
    with a2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">High Risk (Score ≥ 80)</div>
                <div class="kpi-value" style="color: #ef4444;">{high_risk}</div>
                <div class="kpi-desc">Requires immediate action</div>
            </div>
        """, unsafe_allow_html=True)
    with a3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Medium Risk (60–79)</div>
                <div class="kpi-value" style="color: #f59e0b;">{med_risk}</div>
                <div class="kpi-desc">Suspicious activity trends</div>
            </div>
        """, unsafe_allow_html=True)
    with a4:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Low Risk (&lt; 60)</div>
                <div class="kpi-value" style="color: #3b82f6;">{low_risk}</div>
                <div class="kpi-desc">Minor policy warnings</div>
            </div>
        """, unsafe_allow_html=True)
        
    st.markdown("### ⚠️ Anomaly Alerts Feed")
    
    # Filters
    col_sev, col_user, col_search = st.columns([1.5, 1.5, 2.5])
    with col_sev:
        sev_filter = st.selectbox("Filter by Severity", ["All", "HIGH", "MEDIUM", "LOW"])
    with col_user:
        alert_users = ["All"] + sorted(list({a["user"] for a in alerts}))
        user_alert_filter = st.selectbox("Filter by User", alert_users)
    with col_search:
        alert_search = st.text_input("🔍 Search Alerts", placeholder="Search in reasons or types...")
        
    filtered_alerts = alerts
    if sev_filter != "All":
        filtered_alerts = [a for a in filtered_alerts if a["severity"].upper() == sev_filter]
    if user_alert_filter != "All":
        filtered_alerts = [a for a in filtered_alerts if a["user"] == user_alert_filter]
    if alert_search:
        qs = alert_search.strip().lower()
        filtered_alerts = [a for a in filtered_alerts if qs in a["reason"].lower() or qs in a["anomaly_type"].lower() or qs in a["user"].lower()]
        
    if not filtered_alerts:
        st.success("🟢 No anomaly alerts match the current filter criteria.")
    else:
        st.markdown(f"Displaying **{len(filtered_alerts)}** security alerts:")
        
        # Render clean, informative Alert Cards
        for alert in filtered_alerts:
            score = alert["risk_score"]
            sev = alert["severity"].upper()
            
            card_class = "alert-card"
            badge_class = "badge-high"
            if sev == "MEDIUM":
                card_class = "alert-card alert-card-medium"
                badge_class = "badge-medium"
            elif sev == "LOW":
                card_class = "alert-card alert-card-low"
                badge_class = "badge-low"
                
            st.markdown(f"""
                <div class="{card_class}">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                        <div>
                            <span style="font-size: 16px; font-weight: 700; color: #f8fafc;">👤 User: {alert['user']}</span>
                            <span style="margin-left: 10px; font-size: 12px; color: #94a3b8;">Type: <code>{alert['anomaly_type']}</code></span>
                        </div>
                        <div>
                            <span class="{badge_class}">RISK SCORE: {score}/100 ({sev})</span>
                        </div>
                    </div>
                    <div style="color: #cbd5e1; font-size: 14px; margin: 6px 0;">
                        <b>Security Reason:</b> {alert['reason']}
                    </div>
                    <div style="font-size: 12px; color: #64748b; margin-top: 6px;">
                        Detected at: {alert['timestamp']}
                    </div>
                </div>
            """, unsafe_allow_html=True)


# ==============================================================================
# 8. PAGE: ROLE SUGGESTIONS (AI Suggestions + Approve / Reject)
# ==============================================================================

elif page == "🤖 Role Suggestions":
    st.markdown("""
        <div class="enterprise-header">
            <h1><span>🤖</span> AI Least-Privilege Role Suggestions</h1>
            <p>Machine learning recommendations to eliminate over-privileged roles and enforce Zero-Trust RBAC policies.</p>
        </div>
    """, unsafe_allow_html=True)
    
    try:
        suggestions = db_utils.get_role_suggestions()
    except Exception as e:
        st.error(f"Error loading role suggestions: {str(e)}")
        suggestions = []
        
    pending_count = sum(1 for s in suggestions if s["status"] == "Pending")
    approved_count = sum(1 for s in suggestions if s["status"] == "Approved")
    rejected_count = sum(1 for s in suggestions if s["status"] == "Rejected")
    
    # KPI Row
    r1, r2, r3, r4 = st.columns(4)
    with r1:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Total Recommendations</div>
                <div class="kpi-value">{len(suggestions)}</div>
                <div class="kpi-desc">AI analyzed identities</div>
            </div>
        """, unsafe_allow_html=True)
    with r2:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Pending Review</div>
                <div class="kpi-value" style="color: #3b82f6;">{pending_count}</div>
                <div class="kpi-desc">Awaiting administrator decision</div>
            </div>
        """, unsafe_allow_html=True)
    with r3:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Approved Roles</div>
                <div class="kpi-value" style="color: #10b981;">{approved_count}</div>
                <div class="kpi-desc">Updated in database</div>
            </div>
        """, unsafe_allow_html=True)
    with r4:
        st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">Rejected Roles</div>
                <div class="kpi-value" style="color: #ef4444;">{rejected_count}</div>
                <div class="kpi-desc">Dismissed suggestions</div>
            </div>
        """, unsafe_allow_html=True)
        
    # Admin Action Controls for AI Suggester
    ctrl_col1, ctrl_col2 = st.columns([2, 1])
    with ctrl_col1:
        if current_user["role"] == "Admin":
            if st.button("⚡ Run AI Role Suggester (K-Means Clustering)", type="primary", use_container_width=True):
                with st.spinner("Analyzing access logs and executing Scikit-Learn K-Means clustering..."):
                    try:
                        new_suggs = role_suggester.suggest_roles()
                        st.success(f"✅ AI Clustering complete! Generated/updated {len(new_suggs)} role suggestions from logs/backups.db.")
                        st.rerun()
                    except Exception as ex:
                        st.error(f"Error executing AI Role Suggester: {str(ex)}")
        else:
            st.info("ℹ️ Administrator privileges required to re-run AI clustering models.")

    with ctrl_col2:
        with st.popover("ℹ️ About Clustering Logic"):
            st.markdown("""
            **Scikit-Learn K-Means Clustering Details:**
            - **Input Data:** `audit_log` from `logs/backups.db`
            - **Feature Vectors:** Download frequency, restore counts, delete counts, off-hours access (outside 9AM-6PM), and denial rates.
            - **Feature Scaling:** `StandardScaler` normalized
            - **Role Mapping:**
              - *Admin Archetype:* Retention deletes & off-hours operations.
              - *Restorer Archetype:* Heavy restore workload & recovery verifications.
              - *Owner Archetype:* Regular backup downloads & zero policy violations.
              - *Viewer Archetype:* Read-only monitoring or high denial rates (Zero-Trust least privilege).
            """)

    st.markdown("### 🛡️ Interactive Role Optimization Queue")
    
    # Filter Controls
    status_filter = st.radio("Filter Status:", ["Pending", "Approved", "Rejected", "All"], horizontal=True)
    
    filtered_suggs = suggestions
    if status_filter != "All":
        filtered_suggs = [s for s in filtered_suggs if s["status"] == status_filter]
        
    if not filtered_suggs:
        st.info(f"No role suggestions with status '{status_filter}'.")
    else:
        st.markdown(f"Displaying **{len(filtered_suggs)}** AI suggestions:")
        
        for item in filtered_suggs:
            s_id = item["id"]
            u_id = item["user_id"]
            cur_role = item["current_role"]
            sug_role = item["suggested_role"]
            conf = item["confidence"]
            reason = item["reason"]
            status = item["status"]
            
            with st.container():
                st.markdown(f"""
                    <div class="role-card">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <div>
                                <span style="font-size: 17px; font-weight: 700; color: #f8fafc;">User: {u_id}</span>
                                <span style="margin-left: 12px; font-size: 13px; color: #94a3b8;">AI Confidence: <b>{conf}%</b></span>
                            </div>
                            <div>
                                <span class="badge-{status.lower()}">{status.upper()}</span>
                            </div>
                        </div>
                        <div style="font-size: 15px; margin: 8px 0; color: #e2e8f0;">
                            Role Transition: <code style="color: #ef4444;">{cur_role}</code> ➔ <code style="color: #10b981; font-weight: 700;">{sug_role}</code>
                        </div>
                        <div style="font-size: 13px; color: #94a3b8; margin-bottom: 12px;">
                            <b>Rationale:</b> {reason}
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                
                # Interactive Action Buttons
                if status == "Pending":
                    btn_col1, btn_col2, _ = st.columns([1.2, 1.2, 5])
                    with btn_col1:
                        if st.button("✅ Approve", key=f"approve_{s_id}", type="primary"):
                            try:
                                ok, msg = db_utils.update_role_suggestion_status(s_id, "Approved", operator_user=current_user["user_id"])
                                if ok:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                            except Exception as ex:
                                st.error(f"Error updating suggestion: {str(ex)}")
                                
                    with btn_col2:
                        if st.button("❌ Reject", key=f"reject_{s_id}"):
                            try:
                                ok, msg = db_utils.update_role_suggestion_status(s_id, "Rejected", operator_user=current_user["user_id"])
                                if ok:
                                    st.warning(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                            except Exception as ex:
                                st.error(f"Error rejecting suggestion: {str(ex)}")
                else:
                    # Provide an option to reset back to Pending if re-evaluating
                    if st.button(f"↺ Re-evaluate {u_id}", key=f"reset_{s_id}"):
                        conn = db_utils.get_connection()
                        conn.execute("UPDATE role_suggestions SET status = 'Pending' WHERE id = ?", (s_id,))
                        conn.commit()
                        conn.close()
                        st.info(f"Suggestion for {u_id} reset to Pending.")
                        st.rerun()
                        
                st.markdown("<hr style='margin: 8px 0 16px 0; border-color: #334155;'>", unsafe_allow_html=True)

# Footer
st.markdown("""
    <div style="text-align: center; color: #64748b; font-size: 12px; margin-top: 40px; padding: 20px 0;">
        🔐 SecureCloud Backup System &bull; Enterprise Zero-Trust Architecture &bull; Standard SQLite3 Direct Integration
    </div>
""", unsafe_allow_html=True)

