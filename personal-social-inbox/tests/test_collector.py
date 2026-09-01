from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.collector import (
    CONFIG_SCHEMA,
    CollectorConfigError,
    DetectorConfig,
    HeartbeatLedger,
    ProbeResult,
    load_collector_config,
    run_supervisor,
)
from personal_social_inbox.database import connect, initialize
from personal_social_inbox.paths import database_path
from personal_social_inbox.service import InboxService


READY_QQ = {
    "capability": "PARTIAL_EXPORT",
    "reason": "qce_web_ready_login_and_group_scope_not_verified",
}


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data_home = self.root / "data"
        self.wechat_root = self.root / "wechat"
        (self.wechat_root / "session").mkdir(parents=True)
        (self.wechat_root / "contact").mkdir(parents=True)
        (self.wechat_root / "message").mkdir(parents=True)
        (self.wechat_root / "session/session.db").write_bytes(b"wechat")
        (self.wechat_root / "contact/contact.db").write_bytes(b"contact")
        (self.wechat_root / "message/message_0.db").write_bytes(b"message-0")
        (self.wechat_root / "message/message_1.db").write_bytes(b"message-1")
        self.dingtalk_root = self.root / "dingtalk"
        (self.dingtalk_root / "DBFiles").mkdir(parents=True)
        (self.dingtalk_root / "DBFiles/dingtalk.db").write_bytes(b"dingtalk")
        (self.dingtalk_root / "user_config").write_text("{}", encoding="utf-8")
        self.qq_root = self.root / "qq-export"
        self.qq_root.mkdir()
        (self.qq_root / "group.json").write_text("{}", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _config(
        self, detector_id: str, source_kind: str, source_root: Path | None
    ) -> DetectorConfig:
        return DetectorConfig(
            detector_id=detector_id,
            source_kind=source_kind,
            external_account_id=f"personal-{source_kind}",
            interval_seconds=1,
            stale_after_seconds=60,
            source_root=source_root,
            deployment_root=self.root / "deployment",
            docker_app_path=self.root / "Docker.app",
        )

    @patch("personal_social_inbox.collector.diagnose_qq_docker", return_value=READY_QQ)
    def test_once_runs_three_detectors_and_records_only_transitions(self, _doctor) -> None:
        configs = [
            self._config("wechat-main", "wechat", self.wechat_root),
            self._config("dingtalk-main", "dingtalk", self.dingtalk_root),
            self._config("qq-main", "qq", self.qq_root),
        ]
        first = asyncio.run(run_supervisor(configs, self.data_home, once=True))
        second = asyncio.run(run_supervisor(configs, self.data_home, once=True))
        self.assertEqual(first["status"], "COMPLETE")
        self.assertEqual(
            {item["state"] for item in first["items"]}, {"BASELINE_ESTABLISHED"}
        )
        with InboxService(self.data_home) as service:
            source_status = service.get_source_status({})
        self.assertEqual(
            {item["collector_freshness_state"] for item in source_status["items"]},
            {"SOURCE_OBSERVED"},
        )
        self.assertEqual({item["state"] for item in second["items"]}, {"OK_UNCHANGED"})

        connection = connect(database_path(self.data_home))
        initialize(connection)
        event_count = connection.execute(
            "SELECT COUNT(*) FROM collector_events"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(event_count, 6)

        (self.wechat_root / "session/session.db").write_bytes(b"wechat changed")
        third = asyncio.run(run_supervisor(configs, self.data_home, once=True))
        states = {item["source_kind"]: item["state"] for item in third["items"]}
        self.assertEqual(states["wechat"], "CHANGE_OBSERVED")
        self.assertEqual(states["dingtalk"], "OK_UNCHANGED")
        self.assertEqual(states["qq"], "OK_UNCHANGED")

    @patch("personal_social_inbox.collector.diagnose_qq_docker", return_value=READY_QQ)
    def test_readiness_heartbeat_does_not_claim_source_observation(self, _doctor) -> None:
        config = self._config("qq-readiness", "qq", None)
        asyncio.run(run_supervisor([config], self.data_home, once=True))
        with InboxService(self.data_home) as service:
            status = service.get_source_status({})
        self.assertEqual(len(status["items"]), 1)
        source = status["items"][0]
        self.assertEqual(source["availability_state"], "NO_SUCCESSFUL_IMPORT")
        self.assertEqual(
            source["collector_freshness_state"],
            "COLLECTOR_ACTIVE_SOURCE_UNOBSERVED",
        )
        self.assertIsNone(source["collector"]["source_observed_at"])

    def test_retryable_error_preserves_token_and_stale_state_wins(self) -> None:
        config = self._config("wechat-main", "wechat", self.wechat_root)
        ledger = HeartbeatLedger(self.data_home)
        now = datetime.now(timezone.utc)
        ledger.record_probe(
            config,
            ProbeResult("source_profile_metadata", "token-a", True),
            observed_at=now - timedelta(seconds=120),
        )
        ledger.record_error(
            config,
            OSError("private path omitted"),
            observed_at=now - timedelta(seconds=90),
        )
        current = ledger.current(config.detector_id)
        assert current is not None
        self.assertEqual(current["source_token"], "token-a")
        self.assertEqual(current["error_code"], "OSError")
        with InboxService(self.data_home) as service:
            status = service.get_source_status({})
        self.assertEqual(
            status["items"][0]["collector_freshness_state"], "HEARTBEAT_STALE"
        )

    def test_lifecycle_update_is_bound_and_idempotent(self) -> None:
        config = self._config("dingtalk-main", "dingtalk", self.dingtalk_root)
        ledger = HeartbeatLedger(self.data_home)
        ledger.record_probe(
            config,
            ProbeResult("source_profile_metadata", "token-a", True),
        )
        self.assertTrue(
            ledger.record_lifecycle("dingtalk", "personal-dingtalk", "generation-a")
        )
        self.assertFalse(
            ledger.record_lifecycle("dingtalk", "personal-dingtalk", "generation-a")
        )
        current = ledger.current(config.detector_id)
        assert current is not None
        self.assertEqual(current["last_generation_id"], "generation-a")
        self.assertIsNotNone(current["last_import_at"])

    def test_detector_binding_cannot_be_silently_reassigned(self) -> None:
        first = self._config("wechat-main", "wechat", self.wechat_root)
        ledger = HeartbeatLedger(self.data_home)
        ledger.record_probe(
            first,
            ProbeResult("source_profile_metadata", "token-a", True),
        )
        rebound = DetectorConfig(
            detector_id="wechat-main",
            source_kind="wechat",
            external_account_id="another-account",
            interval_seconds=1,
            stale_after_seconds=60,
            source_root=self.wechat_root,
        )
        with self.assertRaisesRegex(ValueError, "binding is immutable"):
            ledger.record_probe(
                rebound,
                ProbeResult("source_profile_metadata", "token-b", True),
            )

    def test_config_requires_explicit_roots_and_unique_bindings(self) -> None:
        config_path = self.root / "collector.json"
        config_path.write_text(
            json.dumps(
                {
                    "schema": CONFIG_SCHEMA,
                    "detectors": [
                        {
                            "id": "wechat-main",
                            "source_kind": "wechat",
                            "account_id": "personal-wechat",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CollectorConfigError, "source_root is required"):
            load_collector_config(config_path)


class CollectorConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_sources_overlap_but_each_detector_never_overlaps_itself(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_home = Path(temporary) / "data"
            active_total = 0
            max_active_total = 0

            class SlowDetector:
                def __init__(self, detector_id: str, source_kind: str):
                    self.config = DetectorConfig(
                        detector_id=detector_id,
                        source_kind=source_kind,
                        external_account_id=detector_id,
                        interval_seconds=0.005,
                        stale_after_seconds=1,
                        source_root=Path(temporary),
                    )
                    self.active = 0
                    self.max_active = 0

                async def probe(self) -> ProbeResult:
                    nonlocal active_total, max_active_total
                    self.active += 1
                    active_total += 1
                    self.max_active = max(self.max_active, self.active)
                    max_active_total = max(max_active_total, active_total)
                    try:
                        await asyncio.sleep(0.02)
                        return ProbeResult(
                            "source_profile_metadata",
                            f"token-{self.config.detector_id}",
                            True,
                        )
                    finally:
                        self.active -= 1
                        active_total -= 1

            first = SlowDetector("wechat-main", "wechat")
            second = SlowDetector("dingtalk-main", "dingtalk")
            configs = [first.config, second.config]
            with patch(
                "personal_social_inbox.collector.build_detector",
                side_effect=[first, second],
            ):
                task = asyncio.create_task(run_supervisor(configs, data_home))
                await asyncio.sleep(0.075)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertEqual(first.max_active, 1)
            self.assertEqual(second.max_active, 1)
            self.assertEqual(max_active_total, 2)


if __name__ == "__main__":
    unittest.main()
