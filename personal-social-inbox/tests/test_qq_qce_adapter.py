from __future__ import annotations

import json
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.importer import import_manifest
from personal_social_inbox.qq_generation import (
    QQGenerationError,
    capture_qce_generation,
    ingest_qce_generation,
    verify_qce_generation,
)
from personal_social_inbox.qq_qce_adapter import QQAdapterError, export_qce_groups
from personal_social_inbox.service import InboxService


class QQQCEAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "qce-source"
        shutil.copytree(ROOT / "examples" / "qce-sample", self.source)
        self.input_json = self.source / "group-export.json"
        self.output = self.root / "normalized-export"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _export(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "account_id": "synthetic-qq-account",
            "allowed_group_ids": {"10001"},
            "since": "2026-08-29T09:00:00+08:00",
            "until": "2026-08-31T00:00:00+08:00",
        }
        arguments.update(overrides)
        return export_qce_groups(
            [self.input_json], self.output, **arguments  # type: ignore[arg-type]
        )

    def test_allowlist_window_directions_attachments_and_idempotent_import(self) -> None:
        result = self._export()

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["selected_json_files"], 1)
        self.assertEqual(result["messages"], 2)
        self.assertEqual(result["direction_counts"]["incoming"], 1)  # type: ignore[index]
        self.assertEqual(result["direction_counts"]["outgoing"], 1)  # type: ignore[index]
        self.assertEqual(result["present_attachment_parts"], 1)
        self.assertEqual(result["missing_attachment_parts"], 1)
        serialized_result = json.dumps(result)
        self.assertNotIn("Synthetic Reading Group", serialized_result)
        self.assertNotIn("10001", serialized_result)
        self.assertFalse(result["message_content_reported"])
        self.assertFalse(result["identifiers_reported"])

        manifest_path = self.output / "export.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        conversation = manifest["conversations"][0]
        self.assertEqual(conversation["source_conversation_id"], "group:group-uid-example")
        self.assertFalse(conversation["participants_complete"])
        self.assertEqual(
            conversation["participant_scope"], "windowed_senders_with_verified_self"
        )
        self.assertEqual(
            [message["direction"] for message in conversation["messages"]],
            ["incoming", "outgoing"],
        )
        parts = [
            part for message in conversation["messages"] for part in message["parts"]
        ]
        present = next(part for part in parts if part.get("source_sha256"))
        missing = next(
            part for part in parts if part.get("file_name") == "missing-image.png"
        )
        self.assertEqual(
            (self.output / present["path"]).read_text(encoding="utf-8"),
            "Synthetic QCE attachment data.\n",
        )
        self.assertFalse((self.output / missing["path"]).exists())
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE((self.output / present["path"]).stat().st_mode), 0o600
            )

        data_home = self.root / "data"
        first = import_manifest(manifest_path, data_home)
        second = import_manifest(manifest_path, data_home)
        self.assertEqual(first["inserted_messages"], 2)
        self.assertEqual(first["present_attachments"], 1)
        self.assertEqual(first["missing_attachments"], 1)
        self.assertEqual(second["status"], "already_imported")
        with InboxService(data_home) as service:
            self.assertEqual(service.stats()["messages"], 2)

    def test_non_allowlisted_group_is_not_exported(self) -> None:
        with self.assertRaisesRegex(QQAdapterError, "matched the explicit allowlist"):
            self._export(allowed_group_ids={"different-group"})
        self.assertFalse((self.output / "export.json").exists())

    def test_private_chat_is_rejected(self) -> None:
        payload = json.loads(self.input_json.read_text(encoding="utf-8"))
        payload["chatInfo"]["type"] = "private"
        self.input_json.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(QQAdapterError, "only group exports are accepted"):
            self._export()

    def test_attachment_path_cannot_escape_qce_export(self) -> None:
        payload = json.loads(self.input_json.read_text(encoding="utf-8"))
        payload["messages"][1]["content"]["resources"][0]["localPath"] = (
            "../outside.txt"
        )
        self.input_json.write_text(json.dumps(payload), encoding="utf-8")
        (self.root / "outside.txt").write_text("outside", encoding="utf-8")
        with self.assertRaisesRegex(QQAdapterError, "escapes the QCE export directory"):
            self._export()
        self.assertFalse((self.output / "export.json").exists())

    def test_refuses_to_overwrite_existing_manifest(self) -> None:
        self._export()
        with self.assertRaisesRegex(QQAdapterError, "refusing to overwrite"):
            self._export()

    def test_output_cannot_modify_selected_source_directory(self) -> None:
        with self.assertRaisesRegex(QQAdapterError, "outside every selected"):
            export_qce_groups(
                [self.input_json],
                self.source / "derived",
                account_id="synthetic-qq-account",
                allowed_group_ids={"10001"},
            )

    def test_generation_capture_verify_ingest_and_resume(self) -> None:
        generation = self.root / "qq-20260830T120000Z-example"
        capture = capture_qce_generation(
            [self.input_json], generation, allowed_group_ids={"10001"}
        )
        self.assertEqual(capture["selected_json_files"], 1)
        self.assertEqual(capture["copied_resources"], 1)
        self.assertEqual(capture["missing_resources"], 1)
        self.assertFalse(capture["message_content_reported"])
        verified = verify_qce_generation(generation)
        self.assertEqual(verified["inventory_files"], 2)

        output = self.root / "generation-export"
        data_home = self.root / "generation-data"
        arguments = {
            "account_id": "synthetic-qq-account",
            "allowed_group_ids": {"10001"},
            "since": "2026-08-29T09:00:00+08:00",
            "until": "2026-08-31T00:00:00+08:00",
        }
        first = ingest_qce_generation(
            generation, output, data_home, **arguments  # type: ignore[arg-type]
        )
        second = ingest_qce_generation(
            generation, output, data_home, **arguments  # type: ignore[arg-type]
        )
        self.assertTrue(first["generation_verified"])
        self.assertEqual(first["inserted_messages"], 2)
        self.assertEqual(first["present_attachments"], 1)
        self.assertEqual(first["missing_attachments"], 1)
        self.assertEqual(second["import_status"], "already_imported")
        self.assertTrue((output / "ingest-receipt.json").is_file())

    def test_generation_capture_supports_official_resources_directory(self) -> None:
        payload = json.loads(self.input_json.read_text(encoding="utf-8"))
        payload["messages"][1]["content"]["resources"][0]["localPath"] = (
            "images/group-note.txt"
        )
        self.input_json.write_text(json.dumps(payload), encoding="utf-8")
        official_resource = self.source / "resources" / "images" / "group-note.txt"
        official_resource.parent.mkdir(parents=True)
        shutil.move(self.source / "resources" / "group-note.txt", official_resource)

        generation = self.root / "qq-20260830T120002Z-official-layout"
        capture = capture_qce_generation(
            [self.input_json], generation, allowed_group_ids={"10001"}
        )

        self.assertEqual(capture["copied_resources"], 1)
        self.assertEqual(capture["missing_resources"], 1)
        self.assertTrue(
            (generation / "raw" / "0000" / "images" / "group-note.txt").is_file()
        )

    def test_generation_tamper_and_scope_change_are_rejected(self) -> None:
        generation = self.root / "qq-20260830T120001Z-example"
        capture_qce_generation(
            [self.input_json], generation, allowed_group_ids={"10001"}
        )
        with self.assertRaisesRegex(QQGenerationError, "differs from capture scope"):
            ingest_qce_generation(
                generation,
                self.root / "scope-export",
                self.root / "scope-data",
                account_id="synthetic-qq-account",
                allowed_group_ids={"different-group"},
            )

        resource = next(
            path
            for path in (generation / "raw").rglob("*")
            if path.is_file() and path.name != "export.json"
        )
        resource.write_bytes(resource.read_bytes() + b"tamper")
        with self.assertRaisesRegex(QQGenerationError, "digest or size changed"):
            verify_qce_generation(generation)


if __name__ == "__main__":
    unittest.main()
