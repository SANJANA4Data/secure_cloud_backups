"""
Secure Cloud Backup Storage Module using Boto3 (Amazon S3).
Provides secure cloud operations for backup archives:
- upload_backup(): Upload local backup archives with AES256 server-side encryption.
- download_backup(): Retrieve encrypted backup containers from S3 to local storage.
- list_backups(): Inspect and enumerate available cloud backup objects.

Configured with environment variables for AWS credentials and safe fallbacks.
"""

import os
import sys
import logging
from typing import List, Dict, Optional, Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Configure module logger
logger = logging.getLogger("secure_cloud_storage")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ==============================================================================
# 1. AWS S3 CREDENTIAL CONFIGURATION & SAFE FALLBACKS
# ==============================================================================

def get_aws_config() -> Dict[str, Any]:
    """
    Retrieve AWS configuration from environment variables with safe fallbacks.
    Falls back to mock credentials and default regions if environment is unconfigured.
    """
    return {
        "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID", "mock-access-key"),
        "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key"),
        "aws_session_token": os.getenv("AWS_SESSION_TOKEN", None),
        "region_name": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1")),
        "bucket_name": os.getenv("S3_BUCKET_NAME", os.getenv("AWS_S3_BUCKET", "secure-cloud-backups-default")),
        "endpoint_url": os.getenv("S3_ENDPOINT_URL", os.getenv("AWS_ENDPOINT_URL", None)),
    }


def get_default_bucket() -> str:
    """Return the default S3 bucket name configured for backup storage."""
    return get_aws_config()["bucket_name"]


def get_s3_client(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region_name: Optional[str] = None,
    endpoint_url: Optional[str] = None,
) -> boto3.client:
    """
    Construct a Boto3 S3 client using supplied parameters or environment fallbacks.
    """
    config = get_aws_config()

    client_kwargs: Dict[str, Any] = {
        "service_name": "s3",
        "region_name": region_name or config["region_name"],
        "aws_access_key_id": aws_access_key_id or config["aws_access_key_id"],
        "aws_secret_access_key": aws_secret_access_key or config["aws_secret_access_key"],
    }

    session_token = aws_session_token or config["aws_session_token"]
    if session_token:
        client_kwargs["aws_session_token"] = session_token

    url = endpoint_url or config["endpoint_url"]
    if url:
        client_kwargs["endpoint_url"] = url

    return boto3.client(**client_kwargs)


# ==============================================================================
# 2. CORE S3 STORAGE OPERATIONS
# ==============================================================================

def upload_backup(
    file_path: str,
    object_name: Optional[str] = None,
    bucket_name: Optional[str] = None,
    extra_args: Optional[Dict[str, Any]] = None,
    s3_client: Optional[Any] = None,
) -> bool:
    """
    Upload a local backup file to Amazon S3 with server-side encryption.

    Parameters:
        file_path (str): Path to local file on disk.
        object_name (str, optional): Destination key name in S3. Defaults to file's basename.
        bucket_name (str, optional): Target S3 bucket. Defaults to environment configuration.
        extra_args (dict, optional): Additional S3 parameters. Defaults to AES256 encryption.
        s3_client (optional): Injected Boto3 S3 client (e.g. for testing/mocking).

    Returns:
        bool: True if upload was successful, False otherwise.

    Raises:
        FileNotFoundError: If the specified local file_path does not exist.
    """
    if not os.path.exists(file_path):
        logger.error(f"Upload failed: Local file '{file_path}' not found.")
        raise FileNotFoundError(f"Local backup file not found: {file_path}")

    if object_name is None:
        object_name = os.path.basename(file_path)

    if bucket_name is None:
        bucket_name = get_default_bucket()

    # Enforce Server-Side Encryption (AES256) by default for Zero-Trust compliance
    if extra_args is None:
        extra_args = {"ServerSideEncryption": "AES256"}
    elif "ServerSideEncryption" not in extra_args:
        extra_args["ServerSideEncryption"] = "AES256"

    client = s3_client if s3_client is not None else get_s3_client()

    try:
        logger.info(f"Uploading '{file_path}' to 's3://{bucket_name}/{object_name}'...")
        client.upload_file(
            Filename=file_path,
            Bucket=bucket_name,
            Key=object_name,
            ExtraArgs=extra_args
        )
        logger.info(f"Successfully uploaded '{object_name}' to bucket '{bucket_name}'.")
        return True
    except (ClientError, BotoCoreError) as err:
        logger.error(f"S3 ClientError while uploading '{object_name}' to '{bucket_name}': {err}")
        return False
    except Exception as ex:
        logger.error(f"Unexpected error uploading '{object_name}' to '{bucket_name}': {ex}")
        return False


def download_backup(
    object_name: str,
    file_path: str,
    bucket_name: Optional[str] = None,
    s3_client: Optional[Any] = None,
) -> bool:
    """
    Download a backup archive from Amazon S3 to the local filesystem.

    Parameters:
        object_name (str): The S3 key/object name to download.
        file_path (str): Destination path on the local filesystem.
        bucket_name (str, optional): Source S3 bucket. Defaults to environment configuration.
        s3_client (optional): Injected Boto3 S3 client (e.g. for testing/mocking).

    Returns:
        bool: True if download was successful, False otherwise.
    """
    if not object_name:
        logger.error("Download failed: object_name must be non-empty.")
        return False

    if bucket_name is None:
        bucket_name = get_default_bucket()

    # Ensure parent destination directory exists
    parent_dir = os.path.dirname(os.path.abspath(file_path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    client = s3_client if s3_client is not None else get_s3_client()

    try:
        logger.info(f"Downloading 's3://{bucket_name}/{object_name}' to '{file_path}'...")
        client.download_file(
            Bucket=bucket_name,
            Key=object_name,
            Filename=file_path
        )
        logger.info(f"Successfully downloaded '{object_name}' to '{file_path}'.")
        return True
    except (ClientError, BotoCoreError) as err:
        logger.error(f"S3 ClientError downloading '{object_name}' from '{bucket_name}': {err}")
        return False
    except Exception as ex:
        logger.error(f"Unexpected error downloading '{object_name}' from '{bucket_name}': {ex}")
        return False


def list_backups(
    prefix: str = "",
    bucket_name: Optional[str] = None,
    s3_client: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """
    List backup archives stored in the S3 bucket matching an optional prefix.

    Parameters:
        prefix (str, optional): Key prefix filter (e.g. 'backups/2026/').
        bucket_name (str, optional): Target S3 bucket. Defaults to environment configuration.
        s3_client (optional): Injected Boto3 S3 client (e.g. for testing/mocking).

    Returns:
        List[Dict[str, Any]]: List of metadata dictionaries for each object:
            - key (str): Object key name
            - size (int): Size in bytes
            - last_modified (str): ISO-formatted timestamp or string
            - etag (str): S3 ETag (MD5 hash / multipart checksum)
    """
    if bucket_name is None:
        bucket_name = get_default_bucket()

    client = s3_client if s3_client is not None else get_s3_client()

    backups: List[Dict[str, Any]] = []

    try:
        logger.info(f"Listing backups in 's3://{bucket_name}' with prefix='{prefix}'...")
        response = client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

        for item in response.get("Contents", []):
            backups.append({
                "key": item.get("Key", ""),
                "size": item.get("Size", 0),
                "last_modified": str(item.get("LastModified", "")),
                "etag": str(item.get("ETag", "")).strip('"'),
            })

        logger.info(f"Found {len(backups)} backups in bucket '{bucket_name}'.")
        return backups
    except (ClientError, BotoCoreError) as err:
        logger.error(f"S3 ClientError listing backups in '{bucket_name}': {err}")
        return []
    except Exception as ex:
        logger.error(f"Unexpected error listing backups in '{bucket_name}': {ex}")
        return []


# ==============================================================================
# 3. OBJECT-ORIENTED CLOUD STORAGE CLIENT
# ==============================================================================

class SecureCloudStorage:
    """
    Encapsulated Secure Cloud Storage Manager for S3 backup operations.
    """

    def __init__(
        self,
        bucket_name: Optional[str] = None,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        s3_client: Optional[Any] = None,
    ):
        self.bucket_name = bucket_name or get_default_bucket()
        self.client = s3_client or get_s3_client(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region_name,
            endpoint_url=endpoint_url,
        )

    def upload_backup(
        self,
        file_path: str,
        object_name: Optional[str] = None,
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Upload a backup to the configured bucket."""
        return upload_backup(
            file_path=file_path,
            object_name=object_name,
            bucket_name=self.bucket_name,
            extra_args=extra_args,
            s3_client=self.client,
        )

    def download_backup(
        self,
        object_name: str,
        file_path: str,
    ) -> bool:
        """Download a backup from the configured bucket."""
        return download_backup(
            object_name=object_name,
            file_path=file_path,
            bucket_name=self.bucket_name,
            s3_client=self.client,
        )

    def list_backups(
        self,
        prefix: str = "",
    ) -> List[Dict[str, Any]]:
        """List backups from the configured bucket."""
        return list_backups(
            prefix=prefix,
            bucket_name=self.bucket_name,
            s3_client=self.client,
        )
