"""Database and cryptographic utilities package."""
import os
from utils import db_utils
from utils.db_utils import (
    get_db_path,
    get_connection,
    get_all_users,
    get_users,
    get_user,
    get_user_by_id,
    get_user_by_username,
    get_audit_logs,
    get_logs,
    get_access_logs,
    get_backups_table_data,
    get_all_backups,
    get_backups,
    list_backups,
    get_alerts,
    get_all_alerts,
    get_anomaly_alerts,
    get_role_suggestions,
    get_all_role_suggestions,
    get_suggestions,
    restore_backup_file,
    restore_backup,
    authenticate_user,
    update_user_role,
    update_role_suggestion_status,
    approve_role_suggestion,
    reject_role_suggestion,
    init_all,
    init_db,
    init_audit_log,
    init_users_table,
    init_alerts_table,
    init_role_suggestions_table,
    hash_password,
    verify_password,
)
from utils import anomaly_detector
from utils.anomaly_detector import (
    detect_anomalies,
    check_burst_downloads_restores,
    check_off_hours_access,
    check_unapproved_ips,
    is_approved_ip,
    is_outside_business_hours,
)
from utils import role_suggester
from utils.role_suggester import (
    suggest_roles,
    extract_user_features,
    cluster_users,
    generate_recommendations,
    save_suggestions_to_db,
)
from utils import storage
from utils.storage import (
    upload_backup,
    download_backup,
    list_backups as s3_list_backups,
    SecureCloudStorage,
)



