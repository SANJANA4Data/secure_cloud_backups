import os
import zipfile
from datetime import datetime

from utils import config, db_utils
from utils.crypto import decrypt_file, encrypt_file
from utils.integrity import calculate_checksum


def backup_folder(user_id: str, folder_path: str) -> dict:
    db_utils.init_all()
    config.ensure_data_dirs()

    if not os.path.isdir(folder_path):
        db_utils.log_action("BACKUP_DENIED", None, user_id, result="INVALID_PATH")
        return {"status": "invalid_path", "message": "Folder path does not exist."}

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_id = f"B{timestamp}"
    zip_path = config.CLOUD_DIR / f"{backup_id}.zip"

    with zipfile.ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

    enc_path = f"{zip_path}.enc"
    encrypt_file(str(zip_path), enc_path)
    os.remove(zip_path)

    checksum = calculate_checksum(enc_path)
    size = os.path.getsize(enc_path)

    db_utils.insert_backup(backup_id, user_id, version=1, size=size, checksum=checksum)
    db_utils.log_action("BACKUP_CREATED", backup_id, user_id)

    return {"backup_id": backup_id, "size": size, "checksum": checksum, "status": "created"}


def restore_backup(backup_id: str, user_id: str) -> dict:
    db_utils.init_all()
    config.ensure_data_dirs()

    enc_path = config.CLOUD_DIR / f"{backup_id}.zip.enc"
    if not enc_path.exists():
        db_utils.log_action("RESTORE_DENIED", backup_id, user_id, result="NOT_FOUND")
        return {"status": "not_found", "message": f"Encrypted backup {backup_id} not found."}

    expected_checksum = db_utils.get_checksum(backup_id)
    current_checksum = calculate_checksum(str(enc_path))
    if expected_checksum and current_checksum != expected_checksum:
        db_utils.log_action("RESTORE_DENIED", backup_id, user_id, result="CHECKSUM_MISMATCH")
        return {"status": "checksum_mismatch", "message": "Checksum mismatch detected."}

    temp_zip = config.RESTORE_DIR / "temp_restore.zip"
    try:
        decrypt_file(str(enc_path), str(temp_zip))
    except ValueError as exc:
        db_utils.log_action("RESTORE_FAILED", backup_id, user_id, result=str(exc))
        return {"status": "decrypt_failed", "message": str(exc)}

    with zipfile.ZipFile(temp_zip, "r") as zipf:
        zipf.extractall(config.RESTORE_DIR)

    os.remove(temp_zip)
    db_utils.increment_restore_count(backup_id)
    db_utils.log_action("BACKUP_RESTORED", backup_id, user_id)

    return {"status": "restored", "restore_dir": str(config.RESTORE_DIR)}


def list_backups() -> list[dict]:
    db_utils.init_all()
    return db_utils.list_backups()
