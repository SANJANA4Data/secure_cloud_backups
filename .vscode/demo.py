import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

def run_step(description, script, args=""):
    print(f"\n=== {description} ===")
    script_path = os.path.join(SCRIPTS_DIR, script)
    command = f"python {script_path} {args}"
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

if __name__ == "__main__":
    main()
