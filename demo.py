import os
import subprocess
from scripts import ai_role_suggester
from scripts import anomaly_detector
from scripts import dashboard
from scripts import chatbot_interface
from scripts import scalability_test


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

def run_step(description, script, args=""):
    print(f"\n=== {description} ===")
    script_path = os.path.join(SCRIPTS_DIR, script)
    # Wrap in quotes to handle spaces in path
    command = f'"{os.sys.executable}" "{script_path}" {args}'
    result = subprocess.run(command, shell=True)
    if result.returncode == 0:
        print(f"✅ {description} completed successfully")
    else:
        print(f"❌ {description} failed")

def main():
    print("=== Secure Cloud Backup System Demo ===")

    run_step("Run Backup", "backup_script.py", "data/sample_data.txt")
    run_step("Restore Backup", "restore_script.py", "data/sample_data.txt.enc")
    run_step("RBAC Check", "rbac_check.py")
    run_step("Generate Dataset", "generate_dataset.py")

def run_demo():
    print("=== Secure Cloud Backups Demo ===")

    # Step 1: Backup
    print("\n[1] Running Backup...")
    # call backup_script logic here

    # Step 2: Restore
    print("\n[2] Running Restore...")
    # call restore_script logic here

    # Step 3: RBAC + ABAC
    print("\n[3] Checking Access Control...")
    # call rbac_check logic here

    # Step 4: Audit Logging
    print("\n[4] Logging Access...")
    # log event

    # Step 5: AI Role Suggestion
    print("\n[5] Suggesting Roles...")
    ai_role_suggester.run()   # assume you define run() in ai_role_suggester.py

    # Step 6: Anomaly Detection
    print("\n[6] Detecting Anomalies...")
    anomaly_detector.run()    # assume run() in anomaly_detector.py

    # Step 7: Dashboard
    print("\n[7] Launching Dashboard...")
    # dashboard.run() or streamlit entrypoint

    # Step 8: Chatbot Interface
    print("\n[8] Starting Chatbot...")
    chatbot_interface.run()

    # Step 9: Scalability Test
    print("\n[9] Running Scalability Test...")
    scalability_test.run()

    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    main()
