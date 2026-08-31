from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.importer import ImportValidationError, import_manifest
from personal_social_inbox.database import connect, initialize
from personal_social_inbox.service import InboxService, QueryError


class InboxIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.data_home = Path(self.temporary.name) / "data"
        self.fixture = ROOT / "examples" / "sample-export" / "export.json"
        self.first = import_manifest(self.fixture, self.data_home)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_import_is_idempotent_and_reports_missing_attachment(self) -> None:
        second = import_manifest(self.fixture, self.data_home)
        self.assertEqual(self.first["status"], "complete")
        self.assertEqual(self.first["inserted_messages"], 4)
        self.assertEqual(self.first["present_attachments"], 1)
        self.assertEqual(self.first["missing_attachments"], 1)
        self.assertEqual(second["status"], "already_imported")
        with InboxService(self.data_home) as service:
            self.assertEqual(service.stats()["messages"], 4)

    def test_schema_v1_participant_links_migrate_to_relation_metadata(self) -> None:
        legacy_path = Path(self.temporary.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy_path)) as legacy, legacy:
            legacy.execute(
                "CREATE TABLE conversation_participants("
                "conversation_id TEXT NOT NULL, identity_id TEXT NOT NULL, "
                "PRIMARY KEY(conversation_id, identity_id))"
            )
        connection = connect(legacy_path)
        initialize(connection)
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(conversation_participants)"
            )
        }
        versions = {
            int(row[0]) for row in connection.execute("SELECT version FROM schema_info")
        }
        connection.close()
        self.assertIn("raw_json", columns)
        self.assertIn(2, versions)
        self.assertIn(3, versions)

    def test_literal_search_context_and_opaque_cursor(self) -> None:
        with InboxService(self.data_home) as service:
            first_page = service.search_messages({"query": "", "limit": 1})
            self.assertTrue(first_page["has_more"])
            self.assertIsInstance(first_page["next_cursor"], str)
            second_page = service.search_messages(
                {"query": "", "limit": 1, "cursor": first_page["next_cursor"]}
            )
            self.assertNotEqual(
                first_page["items"][0]["message_id"],
                second_page["items"][0]["message_id"],
            )
            with self.assertRaises(QueryError):
                service.search_messages(
                    {"query": "different", "limit": 1, "cursor": first_page["next_cursor"]}
                )

            result = service.search_messages({"query": "shopping list"})
            self.assertEqual(len(result["items"]), 1)
            message_id = result["items"][0]["message_id"]
            context = service.read_context(
                {"message_id": message_id, "before": 1, "after": 1}
            )
            self.assertEqual(len(context["items"]), 3)
            self.assertEqual(context["items"][context["target_index"]]["message_id"], message_id)

    def test_literal_search_scans_the_search_index_once(self) -> None:
        statements: list[str] = []
        with InboxService(self.data_home) as service:
            service.connection.set_trace_callback(statements.append)
            result = service.search_messages({"query": "shopping list"})
        select = next(
            statement
            for statement in statements
            if "ORDER BY m.sent_at DESC" in statement
        )
        self.assertEqual(len(result["items"]), 1)
        self.assertIn("JOIN message_fts search_index", select)
        self.assertNotIn("EXISTS (SELECT 1 FROM message_fts", select)

    def test_source_status_does_not_overclaim_collector_freshness(self) -> None:
        with InboxService(self.data_home) as service:
            status = service.get_source_status({})
        self.assertEqual(len(status["items"]), 1)
        source = status["items"][0]
        self.assertEqual(source["availability_state"], "IMPORTED_EVIDENCE_AVAILABLE")
        self.assertEqual(source["collector_freshness_state"], "NOT_RECORDED")
        self.assertEqual(source["message_count"], 4)
        self.assertIsNotNone(source["last_successful_import_at"])
        self.assertIn("local evidence only", status["freshness_semantics"])

    def test_attachment_hash_and_missing_state_are_preserved(self) -> None:
        with InboxService(self.data_home) as service:
            messages = service.search_messages({"query": "", "media_type": "any"})[
                "items"
            ]
            attachments = [
                part["attachment"]
                for message in messages
                for part in message["parts"]
                if "attachment" in part
            ]
            present = next(item for item in attachments if item["status"] == "present")
            missing = next(item for item in attachments if item["status"] == "missing")
            present_details = service.get_attachment({"attachment_id": present["id"]})
            missing_details = service.get_attachment({"attachment_id": missing["id"]})

        payload = Path(present_details["local_path"]).read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), present_details["blob_sha256"])
        self.assertEqual(missing_details["status"], "missing")
        self.assertNotIn("local_path", missing_details)

    def test_conversation_metadata_and_membership_roles_are_queryable(self) -> None:
        with InboxService(self.data_home) as service:
            group = service.list_conversations(
                {"conversation_type": "group"}
            )["items"][0]
            self.assertEqual(group["participant_count"], 2)
            self.assertEqual(group["unread_count"], 2)
            self.assertTrue(group["has_announcement"])
            details = service.get_conversation(
                {"conversation_id": group["id"], "participant_limit": 10}
            )
        self.assertTrue(details["participants_complete"])
        self.assertEqual(details["group"]["owner_id"], "me")
        self.assertEqual(details["group"]["announcement"], "Dinner schedule")
        self.assertEqual(
            [item["role"] for item in details["participants"]["items"]],
            ["owner", "member"],
        )

    def test_changed_source_message_is_warned_not_overwritten(self) -> None:
        changed_root = Path(self.temporary.name) / "changed-export"
        shutil.copytree(self.fixture.parent, changed_root)
        changed_manifest = changed_root / "export.json"
        payload = json.loads(changed_manifest.read_text(encoding="utf-8"))
        payload["exported_at"] = "2026-08-30T09:00:00Z"
        payload["conversations"][0]["messages"][0]["parts"][0]["text"] = "Changed text"
        changed_manifest.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        result = import_manifest(changed_manifest, self.data_home)
        conflicts = [
            warning
            for warning in result["warnings"]
            if warning["code"] == "SOURCE_MESSAGE_CONFLICT"
        ]
        self.assertEqual(result["inserted_messages"], 0)
        self.assertEqual(result["reused_messages"], 4)
        self.assertEqual(len(conflicts), 1)
        with InboxService(self.data_home) as service:
            self.assertEqual(len(service.search_messages({"query": "Dinner"})["items"]), 1)
            self.assertEqual(len(service.search_messages({"query": "Changed"})["items"]), 0)

    def test_attachment_path_cannot_escape_export(self) -> None:
        malicious_root = Path(self.temporary.name) / "malicious-export"
        malicious_root.mkdir()
        payload = json.loads(self.fixture.read_text(encoding="utf-8"))
        payload["source"]["account_id"] = "malicious-fixture"
        attachment = payload["conversations"][0]["messages"][1]["parts"][1]
        attachment["path"] = "../outside.txt"
        manifest = malicious_root / "export.json"
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        (Path(self.temporary.name) / "outside.txt").write_text("private", encoding="utf-8")
        with self.assertRaises(ImportValidationError):
            import_manifest(manifest, Path(self.temporary.name) / "other-data")

    def test_digest_is_deterministic_and_traceable(self) -> None:
        with InboxService(self.data_home) as service:
            digest = service.build_digest({"limit": 20})
        self.assertEqual(digest["evidence_kind"], "deterministic_digest_packet")
        self.assertEqual(digest["messages_considered"], 4)
        self.assertIn("message_id=msg_", digest["markdown"])
        self.assertIn("This packet is derived", digest["markdown"])


if __name__ == "__main__":
    unittest.main()
