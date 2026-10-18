"""
Unit tests for the Secure Cloud Backup Storage module (utils/storage.py).
Uses unittest.mock to thoroughly mock AWS S3 client interactions, responses, and errors:

1. test_upload_backup_success: Validates file upload with AES256 server-side encryption.
2. test_upload_backup_file_not_found: Validates FileNotFoundError when source does not exist.
3. test_download_backup_success: Validates successful file download to destination path.
4. test_download_backup_client_error: Validates graceful handling of S3 ClientError (e.g. 404 NoSuchKey).
5. test_list_backups_success_and_metadata_parsing: Validates S3 list_objects_v2 response parsing.
"""

import os
import sys
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.storage import (
    upload_backup,
    download_backup,
    list_backups,
    get_aws_config,
    get_s3_client,
    SecureCloudStorage,
)


# ==============================================================================
# TEST 1: UPLOAD BACKUP SUCCESS WITH AES256 ENCRYPTION
# ==============================================================================

def test_upload_backup_success(tmp_path):
    """
    Test successful backup upload to S3.
    Verifies that upload_file is called with the target bucket, object key,
    and AES256 server-side encryption parameters.
    """
    # Create a dummy local backup file
    sample_file = tmp_path / "backup_2026.zip.enc"
    sample_file.write_bytes(b"ENCRYPTED_BACKUP_PAYLOAD_BYTES")

    mock_s3 = MagicMock()

    with patch("utils.storage.get_s3_client", return_value=mock_s3):
        success = upload_backup(
            file_path=str(sample_file),
            object_name="backups/backup_2026.zip.enc",
            bucket_name="my-corporate-backup-bucket",
            s3_client=mock_s3
        )

        assert success is True
        mock_s3.upload_file.assert_called_once_with(
            Filename=str(sample_file),
            Bucket="my-corporate-backup-bucket",
            Key="backups/backup_2026.zip.enc",
            ExtraArgs={"ServerSideEncryption": "AES256"}
        )


# ==============================================================================
# TEST 2: UPLOAD BACKUP LOCAL FILE NOT FOUND
# ==============================================================================

def test_upload_backup_file_not_found():
    """
    Test uploading a non-existent local file.
    Verifies that FileNotFoundError is raised and S3 is not called.
    """
    mock_s3 = MagicMock()
    non_existent_path = "c:/non_existent_directory/missing_backup_archive.zip.enc"

    with pytest.raises(FileNotFoundError) as exc_info:
        upload_backup(
            file_path=non_existent_path,
            bucket_name="my-corporate-backup-bucket",
            s3_client=mock_s3
        )

    assert "not found" in str(exc_info.value).lower()
    mock_s3.upload_file.assert_not_called()


# ==============================================================================
# TEST 3: DOWNLOAD BACKUP SUCCESS
# ==============================================================================

def test_download_backup_success(tmp_path):
    """
    Test successful download of a backup container from S3.
    Verifies that download_file is invoked with the expected bucket, key, and destination path.
    """
    dest_path = tmp_path / "restores" / "downloaded_archive.zip.enc"
    mock_s3 = MagicMock()

    with patch("utils.storage.get_s3_client", return_value=mock_s3):
        success = download_backup(
            object_name="backups/archive_BK001.zip.enc",
            file_path=str(dest_path),
            bucket_name="my-corporate-backup-bucket",
            s3_client=mock_s3
        )

        assert success is True
        mock_s3.download_file.assert_called_once_with(
            Bucket="my-corporate-backup-bucket",
            Key="backups/archive_BK001.zip.enc",
            Filename=str(dest_path)
        )


# ==============================================================================
# TEST 4: DOWNLOAD BACKUP CLIENT ERROR (404 NOSUCHKEY)
# ==============================================================================

def test_download_backup_client_error(tmp_path):
    """
    Test S3 download when an AWS ClientError occurs (e.g. 404 NoSuchKey).
    Verifies that the exception is caught, logged, and False is returned.
    """
    dest_path = tmp_path / "download_failed.zip.enc"
    mock_s3 = MagicMock()

    error_response = {
        "Error": {
            "Code": "NoSuchKey",
            "Message": "The specified key does not exist."
        }
    }
    mock_s3.download_file.side_effect = ClientError(error_response, "GetObject")

    with patch("utils.storage.get_s3_client", return_value=mock_s3):
        success = download_backup(
            object_name="missing_object.zip.enc",
            file_path=str(dest_path),
            bucket_name="my-corporate-backup-bucket",
            s3_client=mock_s3
        )

        assert success is False
        mock_s3.download_file.assert_called_once_with(
            Bucket="my-corporate-backup-bucket",
            Key="missing_object.zip.enc",
            Filename=str(dest_path)
        )


# ==============================================================================
# TEST 5: LIST BACKUPS SUCCESS & METADATA PARSING
# ==============================================================================

def test_list_backups_success_and_metadata_parsing():
    """
    Test enumerating backups with list_backups().
    Verifies that S3 list_objects_v2 is called with the target bucket and prefix,
    and returns parsed metadata dictionaries (key, size, last_modified, etag).
    """
    mock_s3 = MagicMock()
    mock_s3.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": "backups/BK-001.zip.enc",
                "Size": 1485760,
                "LastModified": datetime(2026, 10, 18, 9, 15, 22),
                "ETag": '"45f3abcbce42b272ec800fa8e0dda88d"',
            },
            {
                "Key": "backups/BK-002.zip.enc",
                "Size": 3670016,
                "LastModified": datetime(2026, 10, 18, 11, 30, 45),
                "ETag": '"46b55bdb862a5f1af7b39acb8a600778"',
            },
        ]
    }

    with patch("utils.storage.get_s3_client", return_value=mock_s3):
        backups = list_backups(
            prefix="backups/",
            bucket_name="my-corporate-backup-bucket",
            s3_client=mock_s3
        )

        assert len(backups) == 2

        b1 = backups[0]
        assert b1["key"] == "backups/BK-001.zip.enc"
        assert b1["size"] == 1485760
        assert "2026-10-18" in b1["last_modified"]
        assert b1["etag"] == "45f3abcbce42b272ec800fa8e0dda88d"

        b2 = backups[1]
        assert b2["key"] == "backups/BK-002.zip.enc"
        assert b2["size"] == 3670016
        assert b2["etag"] == "46b55bdb862a5f1af7b39acb8a600778"

        mock_s3.list_objects_v2.assert_called_once_with(
            Bucket="my-corporate-backup-bucket",
            Prefix="backups/"
        )
