import argparse
import base64
from contextlib import closing
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path, PurePosixPath

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError


BASE_DIR = Path(os.environ.get("AI_DFIR_DATA_DIR", Path(__file__).resolve().parent)).resolve()
MANIFEST_NAME = "manifest.json"


class BackupError(Exception):
    pass


def _configuration():
    required = (
        "AI_DFIR_S3_BUCKET",
        "AI_DFIR_S3_ACCESS_KEY",
        "AI_DFIR_S3_SECRET_KEY",
        "AI_DFIR_S3_SSE_KEY",
        "AI_DFIR_BACKUP_SIGNING_KEY",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise BackupError(f"Missing required backup configuration: {', '.join(missing)}")

    try:
        encryption_key = base64.b64decode(
            os.environ["AI_DFIR_S3_SSE_KEY"], validate=True
        )
    except (ValueError, TypeError) as exc:
        raise BackupError("AI_DFIR_S3_SSE_KEY must be base64 encoding of 32 random bytes.") from exc
    if len(encryption_key) != 32:
        raise BackupError("AI_DFIR_S3_SSE_KEY must decode to exactly 32 bytes.")
    signing_key = os.environ["AI_DFIR_BACKUP_SIGNING_KEY"].encode("utf-8")
    if len(signing_key) < 32:
        raise BackupError("AI_DFIR_BACKUP_SIGNING_KEY must contain at least 32 bytes.")
    return encryption_key, signing_key


def _client():
    endpoint = os.environ.get("AI_DFIR_S3_ENDPOINT", "").strip() or None
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=os.environ.get("AI_DFIR_S3_REGION", "us-east-1"),
        aws_access_key_id=os.environ["AI_DFIR_S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["AI_DFIR_S3_SECRET_KEY"],
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 5}),
    )


def _sse_args(encryption_key):
    return {
        "SSECustomerAlgorithm": "AES256",
        "SSECustomerKey": base64.b64encode(encryption_key).decode("ascii"),
    }


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _snapshot_database(source, destination):
    with closing(sqlite3.connect(source)) as source_connection:
        with closing(sqlite3.connect(destination)) as destination_connection:
            source_connection.backup(destination_connection)


def _backup_files(root):
    items = []
    database = root / "ai_dfir.sqlite3"
    if database.is_file():
        items.append((database, "ai_dfir.sqlite3"))
    for dirname in ("uploads", "reports"):
        base = root / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise BackupError(f"Refusing to back up a symbolic link: {path}")
            if path.is_file():
                items.append((path, path.relative_to(root).as_posix()))
    return items


def create_backup(root=BASE_DIR):
    encryption_key, signing_key = _configuration()
    client = _client()
    bucket = os.environ["AI_DFIR_S3_BUCKET"]
    backup_id = uuid.uuid4().hex
    prefix = f"ai-dfir/{backup_id}"
    transfer_config = TransferConfig(
        multipart_threshold=64 * 1024 * 1024,
        multipart_chunksize=64 * 1024 * 1024,
        max_concurrency=2,
        use_threads=True,
    )
    try:
        client.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {"404", "NoSuchBucket", "NotFound"}:
            raise BackupError(f"Cannot access configured object-storage bucket: {code}") from exc
        client.create_bucket(Bucket=bucket)

    with tempfile.TemporaryDirectory(prefix="ai-dfir-backup-") as temporary:
        snapshot_path = Path(temporary) / "ai_dfir.sqlite3"
        original_database = Path(root) / "ai_dfir.sqlite3"
        if original_database.is_file():
            _snapshot_database(original_database, snapshot_path)
        backup_items = _backup_files(Path(root))
        backup_items = [
            (snapshot_path, relative)
            if relative == "ai_dfir.sqlite3"
            else (path, relative)
            for path, relative in backup_items
        ]
        entries = []
        for index, (path, relative) in enumerate(backup_items):
            key = f"{prefix}/data/{index:08d}"
            digest = _sha256(path)
            client.upload_file(
                str(path),
                bucket,
                key,
                ExtraArgs={**_sse_args(encryption_key), "Metadata": {"sha256": digest}},
                Config=transfer_config,
            )
            entries.append({
                "path": relative,
                "key": key,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
            })
        manifest = {
            "format": 1,
            "backup_id": backup_id,
            "files": entries,
        }
        canonical = json.dumps(
            manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signed = {
            **manifest,
            "hmac_sha256": hmac.new(signing_key, canonical, hashlib.sha256).hexdigest(),
        }
        client.put_object(
            Bucket=bucket,
            Key=f"{prefix}/{MANIFEST_NAME}",
            Body=json.dumps(signed, ensure_ascii=True, sort_keys=True).encode("utf-8"),
            ContentType="application/json",
            **_sse_args(encryption_key),
        )
    return backup_id, len(entries)


def _validated_manifest(client, bucket, backup_id, encryption_key, signing_key):
    if not backup_id or any(character not in "0123456789abcdef" for character in backup_id):
        raise BackupError("Backup ID must be a lowercase hexadecimal ID from a backup listing.")
    key = f"ai-dfir/{backup_id}/{MANIFEST_NAME}"
    try:
        response = client.get_object(
            Bucket=bucket, Key=key, **_sse_args(encryption_key)
        )
    except ClientError as exc:
        raise BackupError("The requested backup manifest is unavailable.") from exc
    try:
        manifest = json.loads(response["Body"].read())
        signature = manifest.pop("hmac_sha256")
        canonical = json.dumps(
            manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (ValueError, KeyError, TypeError) as exc:
        raise BackupError("The backup manifest is invalid.") from exc
    expected = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(signature), expected):
        raise BackupError("Backup manifest signature verification failed.")
    if manifest.get("format") != 1 or manifest.get("backup_id") != backup_id:
        raise BackupError("The backup manifest version or identity is invalid.")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BackupError("The backup manifest does not contain a file list.")
    return files


def restore_backup(backup_id, destination):
    encryption_key, signing_key = _configuration()
    client = _client()
    bucket = os.environ["AI_DFIR_S3_BUCKET"]
    destination = Path(destination).resolve()
    if destination.exists():
        raise BackupError("Restore destination must not already exist.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(
        prefix=f".{destination.name}-restore-", dir=destination.parent
    ))
    try:
        files = _validated_manifest(
            client, bucket, backup_id, encryption_key, signing_key
        )
        for entry in files:
            relative = entry.get("path")
            key = entry.get("key")
            if (not isinstance(relative, str) or not isinstance(key, str)
                    or not key.startswith(f"ai-dfir/{backup_id}/data/")):
                raise BackupError("The backup contains an invalid file entry.")
            relative_path = PurePosixPath(relative)
            if relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
                raise BackupError("The backup contains an unsafe destination path.")
            target = staging.joinpath(*relative_path.parts).resolve()
            if not target.is_relative_to(staging):
                raise BackupError("The backup contains an unsafe destination path.")
            target.parent.mkdir(parents=True, exist_ok=True)
            response = client.get_object(
                Bucket=bucket, Key=key, **_sse_args(encryption_key)
            )
            digest = hashlib.sha256()
            size = 0
            with target.open("xb") as output:
                for block in iter(lambda: response["Body"].read(1024 * 1024), b""):
                    output.write(block)
                    digest.update(block)
                    size += len(block)
            if size != entry.get("size_bytes") or not hmac.compare_digest(
                digest.hexdigest(), str(entry.get("sha256", ""))
            ):
                raise BackupError(f"Restored file failed integrity verification: {relative}")
        os.replace(staging, destination)
        return len(files)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def list_backups():
    _configuration()
    client = _client()
    bucket = os.environ["AI_DFIR_S3_BUCKET"]
    response = client.list_objects_v2(Bucket=bucket, Prefix="ai-dfir/", Delimiter="/")
    return [
        prefix["Prefix"].split("/")[1]
        for prefix in response.get("CommonPrefixes", [])
        if prefix["Prefix"].split("/")[-2].isalnum()
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Create and restore client-side-key-encrypted AI-DFIR backups."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create", help="Snapshot the database, evidence, and reports to S3.")
    commands.add_parser("list", help="List backup IDs in the configured bucket.")
    restore = commands.add_parser("restore", help="Restore a backup to a new directory.")
    restore.add_argument("backup_id")
    restore.add_argument("destination")
    args = parser.parse_args()
    try:
        if args.command == "create":
            backup_id, count = create_backup()
            print(f"Backup complete: {backup_id} ({count} files)")
        elif args.command == "list":
            for backup_id in list_backups():
                print(backup_id)
        else:
            count = restore_backup(args.backup_id, args.destination)
            print(f"Restore complete: {count} files written to {args.destination}")
    except (BackupError, ClientError, OSError, sqlite3.Error) as exc:
        print(f"Backup operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
