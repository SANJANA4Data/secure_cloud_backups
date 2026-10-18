import sys, os
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt


# --- Page Config ---
st.set_page_config(
    page_title="Secure Cloud Backup Dashboard",
    layout="wide",
    page_icon="🔐"
)

# Ensure Python can find scripts and utils
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

from scripts.chatbot_interface import handle_command
from scripts.dashboard import build_dashboard
from utils import db_utils
from scripts import backup_script, restore_script

# --- Branding (optional logo) ---
# st.image("data/logo.png", width=120)

st.title("🔐 Secure Cloud Backup System")

# --- Dashboard Summary ---
st.header("📊 Dashboard")
summary, _ = build_dashboard()
st.write(summary)

# --- Backup & Restore Buttons ---
st.subheader("⚙️ Actions")
if st.button("Backup Now"):
    backup_script.backup_folder("U101", "data/test_data")
    st.success("✅ Backup completed!")

if st.button("Restore Latest"):
    latest = db_utils.get_latest_backup_id()
    if latest:
        restore_script.restore_backup(latest)
        st.success(f"✅ Restored backup {latest}")
    else:
        st.warning("⚠️ No backups found to restore.")

# --- Load Backups Table ---
rows = db_utils.list_backups()
df = pd.DataFrame(rows, columns=["Backup_ID","User_ID","Timestamp","Version","Size","Restore_Count"])

# --- KPIs ---
col1, col2, col3 = st.columns(3)
col1.metric("Total Backups", len(df))
col2.metric("Total Restores", df["Restore_Count"].sum())
col3.metric("Latest Backup", df["Timestamp"].max())

# --- Charts ---
st.subheader("📈 Backup Sizes Over Time")
st.line_chart(df[["Size"]])

st.subheader("📊 Restore Count Distribution")
st.bar_chart(df.set_index("Backup_ID")["Restore_Count"])

# Pie chart of status (Active vs Restored)
st.subheader("🟢 Backup Status Distribution")
status_counts = df["Restore_Count"].apply(lambda x: "Restored" if x > 0 else "Active").value_counts()

fig, ax = plt.subplots()
status_counts.plot.pie(autopct="%1.1f%%", ax=ax, colors=["#00b894","#0984e3"])
st.pyplot(fig)

# --- Chatbot Section ---
st.header("🤖 Chatbot")
user_input = st.text_input("Type a command (help, status <id>, suggest_role <user>, anomalies):")
if user_input:
    response = handle_command(user_input)
    st.write("Bot:", response)

# --- Expanders for Logs ---
with st.expander("🔍 Detailed Backup Logs"):
    st.dataframe(df)
