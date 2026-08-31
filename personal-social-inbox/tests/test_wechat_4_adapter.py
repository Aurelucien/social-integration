from __future__ import annotations

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

from personal_social_inbox.importer import import_manifest
from personal_social_inbox.service import InboxService
from personal_social_inbox.wechat_4_adapter import (
    WechatAdapterError,
    export_wechat_snapshot,
)
from personal_social_inbox.wechat_generation import (
    CAPTURE_SCHEMA,
    WechatGenerationError,
    ingest_generation,
    verify_generation,
)


def _message_table(username: str) -> str:
    return "Msg_" + hashlib.md5(username.encode(), usedforsecurity=False).hexdigest()


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _protobuf_string(field_number: int, value: str) -> bytes:
    payload = value.encode("utf-8")
    return _varint((field_number << 3) | 2) + _varint(len(payload)) + payload


def _protobuf_int(field_number: int, value: int) -> bytes:
    return _varint(field_number << 3) + _varint(value)


def _group_member(username: str, group_nickname: str, state: int = 1) -> bytes:
    payload = (
        _protobuf_string(1, username)
        + _protobuf_string(2, group_nickname)
        + _protobuf_int(3, state)
    )
    return _varint((1 << 3) | 2) + _varint(len(payload)) + payload


class WeChat4AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "decrypted"
        self.output = Path(self.temporary.name) / "export"
        self._make_snapshot()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _database(self, relative: str) -> sqlite3.Connection:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(path)

    def _make_snapshot(self) -> None:
        with closing(self._database("session/session.db")) as connection, connection:
            connection.execute(
                "CREATE TABLE SessionTable(username TEXT, type INTEGER, "
                "unread_count INTEGER, is_hidden INTEGER, summary TEXT, "
                "status INTEGER, last_timestamp INTEGER, sort_timestamp INTEGER, "
                "last_msg_type INTEGER, last_msg_sub_type INTEGER, "
                "last_msg_sender TEXT, last_sender_display_name TEXT)"
            )
            connection.executemany(
                "INSERT INTO SessionTable VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    ("room@chatroom", 2, 1, 0, "group preview", 0, 202, 202, 1, 0, "me", "My Nick"),
                    ("friend", 1, 0, 0, "voice preview", 0, 102, 102, 34, 0, "friend", "Friend Nick"),
                ],
            )

        with closing(self._database("contact/contact.db")) as connection, connection:
            connection.execute(
                "CREATE TABLE contact(id INTEGER PRIMARY KEY, username TEXT, alias TEXT, "
                "remark TEXT, nick_name TEXT, small_head_url TEXT, big_head_url TEXT)"
            )
            connection.executemany(
                "INSERT INTO contact VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, "friend", "", "Friend Remark", "Friend Nick", "", ""),
                    (2, "room@chatroom", "", "", "Test Room", "", ""),
                    (3, "member", "", "Member Remark", "Member Nick", "small", "large"),
                    (4, "me", "", "", "My Nick", "", ""),
                ],
            )
            connection.execute("CREATE TABLE name2id(username TEXT PRIMARY KEY)")
            connection.executemany(
                "INSERT INTO name2id(rowid, username) VALUES(?, ?)",
                [(1, "friend"), (2, "room@chatroom"), (3, "member"), (4, "me")],
            )
            connection.execute(
                "CREATE TABLE chat_room(id INTEGER PRIMARY KEY, username TEXT, owner TEXT, ext_buffer BLOB)"
            )
            ext_buffer = _group_member("member", "Room Card") + _group_member(
                "me", "My Card", state=17
            )
            connection.execute(
                "INSERT INTO chat_room VALUES(?, ?, ?, ?)",
                (2, "room@chatroom", "member", ext_buffer),
            )
            connection.execute(
                "CREATE TABLE chatroom_member(room_id INTEGER, member_id INTEGER)"
            )
            connection.executemany(
                "INSERT INTO chatroom_member VALUES(2, ?)", [(3,), (4,)]
            )
            connection.execute(
                "CREATE TABLE chat_room_info_detail(room_id_ INTEGER PRIMARY KEY, "
                "announcement_ TEXT, announcement_editor_ TEXT, "
                "announcement_publish_time_ INTEGER, chat_room_status_ INTEGER)"
            )
            connection.execute(
                "INSERT INTO chat_room_info_detail VALUES(2, 'Group notice', 'member', 200, 1)"
            )

        message_schema = (
            "(local_id INTEGER, server_id INTEGER, local_type INTEGER, sort_seq INTEGER, "
            "real_sender_id INTEGER, create_time INTEGER, message_content, "
            "WCDB_CT_message_content INTEGER)"
        )
        with closing(self._database("message/message_0.db")) as connection, connection:
            connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
            connection.executemany(
                "INSERT INTO Name2Id(rowid, user_name) VALUES (?, ?)",
                [(1, "friend"), (2, "member"), (4, "me")],
            )
            direct = _message_table("friend")
            group = _message_table("room@chatroom")
            connection.execute(f'CREATE TABLE "{direct}" {message_schema}')
            connection.execute(f'CREATE TABLE "{group}" {message_schema}')
            from compression import zstd

            connection.executemany(
                f'INSERT INTO "{direct}" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    (1, 1001, 1, 1, 1, 101, zstd.compress(b"compressed text"), 4),
                    (2, 1002, 34, 2, 4, 102, b"", 0),
                ],
            )
            connection.executemany(
                f'INSERT INTO "{group}" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    (3, 2001, 1, 3, 2, 201, "member:\nhello group", 0),
                    (4, 2002, 1, 4, 4, 202, "own group", 0),
                ],
            )

        with closing(self._database("message/message_1.db")) as connection, connection:
            connection.execute("CREATE TABLE Name2Id(user_name TEXT)")

        with closing(self._database("message/media_0.db")) as connection, connection:
            connection.execute("CREATE TABLE Name2Id(user_name TEXT)")
            connection.execute(
                "INSERT INTO Name2Id(rowid, user_name) VALUES (1, 'friend')"
            )
            connection.execute(
                "CREATE TABLE VoiceInfo(chat_name_id INTEGER, create_time INTEGER, "
                "local_id INTEGER, svr_id INTEGER, voice_data BLOB, data_index TEXT)"
            )
            connection.execute(
                "INSERT INTO VoiceInfo VALUES (?, ?, ?, ?, ?, ?)",
                (1, 102, 2, 1002, b"synthetic silk payload", ""),
            )

    def _make_generation(self) -> Path:
        generation = Path(self.temporary.name) / (
            "20260830T120000Z-" + "a" * 12
        )
        decrypted = generation / "decrypted"
        shutil.copytree(self.root, decrypted)
        for relative in (
            "message/message_resource.db",
            "message/media_1.db",
        ):
            path = decrypted / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(path)) as connection, connection:
                pass
        databases = []
        for path in sorted(decrypted.rglob("*.db")):
            relative = path.relative_to(decrypted).as_posix()
            databases.append(
                {
                    "relative_path": relative,
                    "quick_check": "ok",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        receipt = {
            "schema": CAPTURE_SCHEMA,
            "status": "COMPLETE",
            "captured_at": "2026-08-30T12:00:00Z",
            "generation_id": generation.name,
            "fingerprint_token": "a" * 64,
            "decrypted_databases": databases,
        }
        (generation / "receipt.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )
        return generation

    def test_exports_decompressed_text_group_sender_and_voice_then_imports(self) -> None:
        result = export_wechat_snapshot(
            self.root,
            self.output,
            account_id="me",
            max_conversations=2,
            max_messages_per_conversation=10,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["conversations"], 2)
        self.assertEqual(result["messages"], 4)
        self.assertEqual(result["voice_attachments_resolved"], 1)
        self.assertEqual(result["direction"], "verified_mapped_senders_partial")
        self.assertEqual(result["direction_counts"], {"incoming": 2, "outgoing": 2, "unknown": 0})
        self.assertEqual(result["self_identity_status"], "verified_explicit_account_id")
        serialized_result = json.dumps(result)
        self.assertNotIn("compressed text", serialized_result)
        self.assertNotIn("friend", serialized_result)

        manifest_path = self.output / "export.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        messages = [
            message
            for conversation in manifest["conversations"]
            for message in conversation["messages"]
        ]
        self.assertEqual(
            [message["direction"] for message in messages],
            ["incoming", "outgoing", "incoming", "outgoing"],
        )
        text_parts = [part for message in messages for part in message["parts"] if part["type"] == "text"]
        self.assertEqual(
            {part["text"] for part in text_parts},
            {"compressed text", "hello group", "own group"},
        )
        group = next(
            conversation
            for conversation in manifest["conversations"]
            if conversation["type"] == "group"
        )
        self.assertEqual(group["messages"][0]["sender_id"], "member")
        self.assertTrue(group["participants_complete"])
        self.assertEqual(group["group"]["owner_id"], "member")
        self.assertEqual(group["group"]["member_count"], 2)
        self.assertEqual(group["group"]["group_nickname_count"], 2)
        self.assertEqual(
            group["group"]["administrator_status"],
            "unresolved_member_state_semantics",
        )
        self.assertEqual(group["group"]["announcement"], "Group notice")
        owner = next(participant for participant in group["participants"] if participant["role"] == "owner")
        myself = next(participant for participant in group["participants"] if participant["is_self"])
        self.assertEqual(owner["display_name"], "Room Card")
        self.assertEqual(
            owner["membership"]["group_nickname_status"],
            "verified_chat_room_ext_buffer",
        )
        self.assertEqual(myself["display_name"], "My Card")
        self.assertEqual(myself["membership"]["source_member_state"], 17)
        self.assertEqual(group["metadata"]["unread_count"], 1)
        voice = next(
            part for message in messages for part in message["parts"] if part["type"] == "audio"
        )
        self.assertEqual((self.output / voice["path"]).read_bytes(), b"synthetic silk payload")
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((self.output / voice["path"]).stat().st_mode), 0o600)

        data_home = Path(self.temporary.name) / "normalized"
        imported = import_manifest(manifest_path, data_home)
        self.assertEqual(imported["inserted_messages"], 4)
        self.assertEqual(imported["present_attachments"], 1)
        with InboxService(data_home) as service:
            self.assertEqual(service.stats()["messages"], 4)

    def test_refuses_to_overwrite_existing_manifest(self) -> None:
        export_wechat_snapshot(self.root, self.output, "test-account", max_conversations=1)
        with self.assertRaises(WechatAdapterError):
            export_wechat_snapshot(self.root, self.output, "test-account", max_conversations=1)

    def test_verified_generation_exports_imports_and_resumes_idempotently(self) -> None:
        generation = self._make_generation()
        verified = verify_generation(generation)
        self.assertEqual(verified["database_count"], 7)
        output = Path(self.temporary.name) / "generation-export"
        data_home = Path(self.temporary.name) / "generation-normalized"
        first = ingest_generation(
            generation,
            output,
            data_home,
            account_id="me",
            max_conversations=2,
            max_messages_per_conversation=10,
            include_all_groups=True,
        )
        second = ingest_generation(
            generation,
            output,
            data_home,
            account_id="me",
            max_conversations=2,
            max_messages_per_conversation=10,
            include_all_groups=True,
        )
        self.assertEqual(first["inserted_messages"], 4)
        self.assertEqual(first["import_status"], "complete")
        self.assertEqual(second["import_status"], "already_imported")
        self.assertEqual(second["inserted_messages"], 4)
        self.assertFalse(first["message_content_reported"])
        with InboxService(data_home) as service:
            self.assertEqual(service.stats()["messages"], 4)

    def test_generation_digest_change_is_rejected(self) -> None:
        generation = self._make_generation()
        database = generation / "decrypted/session/session.db"
        with database.open("ab") as handle:
            handle.write(b"tamper")
        with self.assertRaisesRegex(WechatGenerationError, "digest changed"):
            verify_generation(generation)


if __name__ == "__main__":
    unittest.main()
