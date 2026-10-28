import base64
import io
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import backup_evidence


class MemoryS3:
    def __init__(self):
        self.objects = {}
        self.upload_args = []

    def head_bucket(self, **_kwargs):
        return {}

    def create_bucket(self, **_kwargs):
        return {}

    def upload_file(self, filename, bucket, key, ExtraArgs, Config):
        self.upload_args.append(ExtraArgs)
        self.objects[(bucket, key)] = Path(filename).read_bytes()

    def put_object(self, Bucket, Key, Body, **_kwargs):
        self.objects[(Bucket, Key)] = Body
        return {}

    def get_object(self, Bucket, Key, **_kwargs):
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def list_objects_v2(self, Bucket, Prefix, Delimiter):
        prefixes = {
            "/".join(key.split("/")[:2]) + "/"
            for stored_bucket, key in self.objects
            if stored_bucket == Bucket and key.startswith(Prefix)
        }
        return {"CommonPrefixes": [{"Prefix": prefix} for prefix in sorted(prefixes)]}


class EncryptedBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name) / "source"
        self.root.mkdir()
        (self.root / "uploads").mkdir()
        (self.root / "reports").mkdir()
        (self.root / "uploads" / "evidence.csv").write_bytes(b"authorized test evidence\n")
        (self.root / "reports" / "case.pdf").write_bytes(b"report fixture\n")
        with closing(sqlite3.connect(self.root / "ai_dfir.sqlite3")) as conn:
            conn.execute("CREATE TABLE cases(id INTEGER PRIMARY KEY, title TEXT)")
            conn.execute("INSERT INTO cases(title) VALUES('backup test')")
            conn.commit()
        self.s3 = MemoryS3()
        self.environment = patch.dict(
            os.environ,
            {
                "AI_DFIR_S3_BUCKET": "test-bucket",
                "AI_DFIR_S3_ACCESS_KEY": "test-access-key",
                "AI_DFIR_S3_SECRET_KEY": "test-secret-key",
                "AI_DFIR_S3_SSE_KEY": base64.b64encode(b"e" * 32).decode(),
                "AI_DFIR_BACKUP_SIGNING_KEY": "signing-key-with-at-least-32-bytes",
            },
        )
        self.environment.start()
        self.client_patch = patch.object(backup_evidence, "_client", return_value=self.s3)
        self.client_patch.start()

    def tearDown(self):
        self.client_patch.stop()
        self.environment.stop()
        self.temp_dir.cleanup()

    def test_backup_encrypts_objects_and_restores_verified_files(self):
        backup_id, count = backup_evidence.create_backup(self.root)
        self.assertEqual(count, 3)
        self.assertTrue(all(
            args["SSECustomerAlgorithm"] == "AES256"
            and len(base64.b64decode(args["SSECustomerKey"])) == 32
            for args in self.s3.upload_args
        ))
        self.assertIn(backup_id, backup_evidence.list_backups())
        destination = Path(self.temp_dir.name) / "restored"
        restored_count = backup_evidence.restore_backup(backup_id, destination)
        self.assertEqual(restored_count, 3)
        self.assertEqual(
            (destination / "uploads" / "evidence.csv").read_bytes(),
            b"authorized test evidence\n",
        )
        self.assertTrue((destination / "ai_dfir.sqlite3").is_file())

    def test_restore_rejects_tampered_objects_without_leaving_partial_output(self):
        backup_id, _ = backup_evidence.create_backup(self.root)
        data_key = next(
            key for bucket, key in self.s3.objects
            if bucket == "test-bucket" and key.endswith("/data/00000000")
        )
        self.s3.objects[("test-bucket", data_key)] = b"tampered"
        destination = Path(self.temp_dir.name) / "bad-restore"
        with self.assertRaises(backup_evidence.BackupError):
            backup_evidence.restore_backup(backup_id, destination)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
