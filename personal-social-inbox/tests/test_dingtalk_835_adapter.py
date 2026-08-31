from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.dingtalk_835_adapter import (
    DingTalkAdapterError,
    export_dingtalk_snapshot,
)
from personal_social_inbox.dingtalk_generation import (
    CAPTURE_SCHEMA,
    DingTalkGenerationError,
    ingest_generation,
    verify_generation,
)
from personal_social_inbox.importer import import_manifest
from personal_social_inbox.service import InboxService


class DingTalk835AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "decrypted"
        self.root.mkdir()
        self.media_root = Path(self.temporary.name) / "media-root"
        (self.media_root / "ImageFiles").mkdir(parents=True)
        (self.media_root / "Downloads").mkdir()
        self.image_body = self.media_root / "ImageFiles/cache.webp"
        self.image_body.write_bytes(b"RIFF" + (4).to_bytes(4, "little") + b"WEBPtest")
        self.file_body = self.media_root / "Downloads/note.pdf"
        self.file_body.write_bytes(b"%PDF-1.4\nsynthetic\n")
        self.database = self.root / "dingtalk.db"
        self.output = Path(self.temporary.name) / "export"
        self.self_uid = "10001"
        self._make_database()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _make_database(self) -> None:
        message_schema = (
            "(primaryKey TEXT, cid TEXT, localId TEXT, mid TEXT, senderId TEXT, "
            "createdAt INTEGER, contentType INTEGER, content TEXT, messageStatus INTEGER, "
            "recallStatus INTEGER, extension TEXT)"
        )
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "CREATE TABLE tbconversation(cid TEXT, type INTEGER, title TEXT, "
                "memberCount INTEGER, ownerId TEXT, lastModify INTEGER, createAt INTEGER, "
                "unreadCount INTEGER)"
            )
            connection.executemany(
                "INSERT INTO tbconversation VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    ("direct", 1, "Direct chat", 2, "", 1_800_000_000_000, 1_700_000_000_000, 0),
                    ("group", 2, "Group chat", 3, "20002", 1_800_000_000_100, 1_700_000_000_000, 1),
                ],
            )
            connection.execute(
                "CREATE TABLE tbuser_profile_v2(uid TEXT, alias TEXT, nick TEXT, realName TEXT)"
            )
            connection.executemany(
                "INSERT INTO tbuser_profile_v2 VALUES(?, ?, ?, ?)",
                [(self.self_uid, "", "Me", ""), ("20002", "Friend", "", "")],
            )
            connection.execute(f"CREATE TABLE tbmsg_000 {message_schema}")
            connection.execute(f"CREATE TABLE tbmsg_001 {message_schema}")
            connection.executemany(
                "INSERT INTO tbmsg_000 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    ("a", "direct", "1", "m1", "20002", 1_700_000_000_000, 1, json.dumps({"contentType": 1, "text": "hello"}), 1, 0, json.dumps({"sendMsgUUID": "text-token"})),
                    ("b", "direct", "2", "m2", self.self_uid, 1_700_000_001_000, 2, json.dumps({"contentType": 2, "filename": "photo.jpg", "blurredPath": str(self.image_body), "url": "https://example.invalid/original.jpg", "mediaId": "media-token"}), 1, 0, json.dumps({"authMediaId": "auth-token"})),
                ],
            )
            connection.executemany(
                "INSERT INTO tbmsg_001 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    ("c", "group", "3", "m3", "20002", 1_700_000_002_000, 500, json.dumps({"contentType": 500, "attachments": [{"url": "https://example.invalid/file", "extension": json.dumps({"f_name": "note.pdf", "f_size": self.file_body.stat().st_size, "path": str(self.file_body)})}]}), 1, 0, json.dumps({"fileExtension": True})),
                    ("d", "group", "4", "m4", self.self_uid, 1_700_000_003_000, 1200, json.dumps({"contentType": 1200, "attachments": [{"extension": json.dumps({"title": "Card title"})}]}), 1, 0, json.dumps({"cardExtension": True})),
                ],
            )

    def _make_generation(self) -> Path:
        generation = Path(self.temporary.name) / ("20260830T120000Z-" + "a" * 12)
        decrypted = generation / "decrypted"
        encrypted = generation / "encrypted"
        decrypted.mkdir(parents=True)
        encrypted.mkdir()
        shutil.copy2(self.database, decrypted / "dingtalk.db")
        salt = "synthetic-salt"
        salt_md5 = hashlib.md5(salt.encode(), usedforsecurity=False).hexdigest()
        config = base64.b64encode(json.dumps({"salt": salt, "salt_md5": salt_md5}).encode())
        (encrypted / "user_config").write_bytes(config)
        database = decrypted / "dingtalk.db"
        receipt = {
            "schema": CAPTURE_SCHEMA,
            "status": "COMPLETE",
            "captured_at": "2026-08-30T12:00:00Z",
            "generation_id": generation.name,
            "fingerprint_token": "a" * 64,
            "account_binding_sha256": hashlib.sha256((self.self_uid + salt_md5).encode()).hexdigest(),
            "decrypted_database": {
                "relative_path": "decrypted/dingtalk.db",
                "sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
                "quick_check": "ok",
            },
            "source_modified": False,
            "process_attached": False,
            "network_accessed": False,
            "login_bypassed": False,
            "secret_reported": False,
        }
        (generation / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        return generation

    def test_exports_current_shapes_and_imports_without_public_content(self) -> None:
        result = export_dingtalk_snapshot(
            self.root, self.output, account_id="personal", self_uid=self.self_uid,
            max_conversations=2, max_messages_per_conversation=10,
            media_roots=[self.media_root],
        )
        self.assertEqual(result["conversations"], 2)
        self.assertEqual(result["messages"], 4)
        self.assertEqual(result["direction_counts"], {"incoming": 2, "outgoing": 2, "unknown": 0})
        self.assertEqual(result["message_extensions_preserved"], 4)
        self.assertEqual(result["source_urls_preserved"], 2)
        self.assertEqual(result["image_attachments_resolved"], 1)
        self.assertEqual(result["file_attachments_resolved"], 1)
        serialized = json.dumps(result)
        self.assertNotIn("hello", serialized)
        self.assertNotIn(self.self_uid, serialized)
        self.assertNotIn("text-token", serialized)
        self.assertNotIn("example.invalid", serialized)
        manifest_path = self.output / "export.json"
        manifest = json.loads(manifest_path.read_text())
        parts = [part for conversation in manifest["conversations"] for message in conversation["messages"] for part in message["parts"]]
        self.assertEqual({part["type"] for part in parts}, {"text", "image", "file"})
        self.assertIn("Card title", {part.get("text") for part in parts})
        self.assertEqual(sum("dingtalk_source_url" in part for part in parts), 2)
        self.assertEqual(
            sum("source_extension" in message["metadata"] for conversation in manifest["conversations"] for message in conversation["messages"]),
            4,
        )
        imported = import_manifest(manifest_path, Path(self.temporary.name) / "normalized")
        self.assertEqual(imported["inserted_messages"], 4)
        self.assertEqual(imported["present_attachments"], 2)
        self.assertEqual(imported["missing_attachments"], 0)
        with InboxService(Path(self.temporary.name) / "normalized") as service:
            queried = service.search_messages(
                {"query": "", "source_kind": "dingtalk", "limit": 10}
            )
            self.assertEqual(len(queried["items"]), 4)
            self.assertTrue(
                all("source_extension" in item["source_metadata"] for item in queried["items"])
            )
            attachment_item = next(
                item
                for item in queried["items"]
                if any("attachment" in part for part in item["parts"])
            )
            attachment = next(part["attachment"] for part in attachment_item["parts"] if "attachment" in part)
            attachment_evidence = service.get_attachment(
                {"attachment_id": attachment["id"]}
            )
            self.assertIn(
                "dingtalk_source_url", attachment_evidence["source_metadata"]
            )
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((self.output / "attachments").stat().st_mode), 0o700)

    def test_refuses_overwrite_or_unverified_self(self) -> None:
        export_dingtalk_snapshot(self.root, self.output, account_id="personal", self_uid=self.self_uid)
        with self.assertRaises(DingTalkAdapterError):
            export_dingtalk_snapshot(self.root, self.output, account_id="personal", self_uid=self.self_uid)
        with self.assertRaisesRegex(DingTalkAdapterError, "self_uid"):
            export_dingtalk_snapshot(self.root, Path(self.temporary.name) / "other", account_id="personal", self_uid="99999")

    def test_does_not_copy_media_outside_an_allowlisted_root(self) -> None:
        unrelated = Path(self.temporary.name) / "unrelated"
        unrelated.mkdir()
        output = Path(self.temporary.name) / "restricted-export"
        result = export_dingtalk_snapshot(
            self.root,
            output,
            account_id="personal",
            self_uid=self.self_uid,
            media_roots=[unrelated],
        )
        self.assertEqual(result["attachments_resolved"], 0)
        manifest = json.loads((output / "export.json").read_text())
        attachment_parts = [
            part
            for conversation in manifest["conversations"]
            for message in conversation["messages"]
            for part in message["parts"]
            if part["type"] in {"image", "file"}
        ]
        self.assertTrue(attachment_parts)
        self.assertTrue(all("path" not in part for part in attachment_parts))

    def test_output_cannot_be_inside_a_read_only_media_root(self) -> None:
        with self.assertRaisesRegex(DingTalkAdapterError, "media root"):
            export_dingtalk_snapshot(
                self.root,
                self.media_root / "output",
                account_id="personal",
                self_uid=self.self_uid,
                media_roots=[self.media_root],
            )

    def test_generation_import_is_account_bound_and_idempotent(self) -> None:
        generation = self._make_generation()
        verified = verify_generation(generation, self_uid=self.self_uid)
        self.assertEqual(verified["generation_id"], generation.name)
        output = Path(self.temporary.name) / "generation-export"
        home = Path(self.temporary.name) / "generation-normalized"
        first = ingest_generation(generation, output, home, account_id="personal", max_conversations=2, media_roots=[self.media_root])
        second = ingest_generation(generation, output, home, account_id="personal", max_conversations=2, media_roots=[self.media_root])
        self.assertEqual(first["inserted_messages"], 4)
        self.assertEqual(first["present_attachments"], 2)
        self.assertEqual(second["import_status"], "already_imported")
        self.assertFalse(first["message_content_reported"])
        with InboxService(home) as service:
            self.assertEqual(service.stats()["messages"], 4)
        with self.assertRaisesRegex(DingTalkGenerationError, "personal account"):
            verify_generation(generation, self_uid="99999")

    def test_generation_digest_change_is_rejected(self) -> None:
        generation = self._make_generation()
        with (generation / "decrypted/dingtalk.db").open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(DingTalkGenerationError, "digest changed"):
            verify_generation(generation, self_uid=self.self_uid)


if __name__ == "__main__":
    unittest.main()
