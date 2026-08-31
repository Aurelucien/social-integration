from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.importer import import_manifest
from personal_social_inbox.monitoring import MonitoringError, scan_signup_deadline
from personal_social_inbox.service import InboxService


class MonitoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        fixture_root = self.root / "export"
        shutil.copytree(ROOT / "examples" / "sample-export", fixture_root)
        manifest = fixture_root / "export.json"
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["conversations"][0]["messages"][0]["parts"][0]["text"] = (
            "社团报名将在星期一截止，请按通知登记。"
        )
        manifest.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self.data_home = self.root / "data"
        import_manifest(manifest, self.data_home)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_scan_is_incremental_and_candidates_retain_message_evidence(self) -> None:
        first = scan_signup_deadline(self.data_home)
        second = scan_signup_deadline(self.data_home)
        self.assertEqual(first["status"], "complete")
        self.assertEqual(first["scanned_messages"], 4)
        self.assertEqual(first["candidate_count"], 1)
        self.assertEqual(first["default_review_status"], "REVIEW_REQUIRED")
        self.assertEqual(second["scanned_messages"], 0)
        self.assertEqual(second["candidate_count"], 0)

        with InboxService(self.data_home) as service:
            listing = service.list_event_candidates(
                {"review_status": "REVIEW_REQUIRED"}
            )
            self.assertEqual(len(listing["items"]), 1)
            item = listing["items"][0]
            self.assertEqual(item["event_type"], "registration_deadline")
            self.assertTrue(item["time_uncertain"])
            self.assertEqual(item["evidence_count"], 1)
            candidate = service.get_event_candidate(
                {"candidate_id": item["candidate_id"]}
            )
        self.assertEqual(candidate["review_status"], "REVIEW_REQUIRED")
        self.assertEqual(len(candidate["evidence"]), 1)
        self.assertIn(
            "报名将在星期一截止",
            candidate["evidence"][0]["parts"][0]["text"],
        )
        self.assertEqual(
            candidate["rationale"]["time_extraction"], "NOT_ATTEMPTED_V1"
        )

    def test_rule_version_cannot_silently_change_after_messages_are_scanned(self) -> None:
        scan_signup_deadline(self.data_home)
        with InboxService(self.data_home) as service:
            service.connection.execute(
                "UPDATE monitor_rules SET definition_json = '{}' WHERE id = ?",
                ("signup-deadline-v1",),
            )
            service.connection.commit()
        with self.assertRaises(MonitoringError):
            scan_signup_deadline(self.data_home)


if __name__ == "__main__":
    unittest.main()
