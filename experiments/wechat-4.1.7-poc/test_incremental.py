from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import wechat_incremental


class IncrementalCaptureTests(unittest.TestCase):
    def test_fingerprint_detects_wal_changes_without_opening_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "message/message_0.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"database")
            targets = ("message/message_0.db",)
            before = wechat_incremental.collect_fingerprint(root, targets)
            wal = database.with_name(database.name + "-wal")
            wal.write_bytes(b"wal")
            after = wechat_incremental.collect_fingerprint(root, targets)
        self.assertNotEqual(
            wechat_incremental.fingerprint_token(before),
            wechat_incremental.fingerprint_token(after),
        )

    def test_stable_copy_copies_database_and_wal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            candidate = root / "candidate"
            database = source / "message/message_0.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"database")
            database.with_name(database.name + "-wal").write_bytes(b"wal")
            fingerprint, attempts = wechat_incremental._copy_candidate(
                source, candidate, ("message/message_0.db",), 1
            )
            copied = candidate / "encrypted/message/message_0.db"
            self.assertEqual(attempts, 1)
            self.assertEqual(
                fingerprint["databases"][0]["database"]["size"], 8
            )
            self.assertEqual(copied.read_bytes(), b"database")
            self.assertEqual(
                copied.with_name(copied.name + "-wal").read_bytes(), b"wal"
            )

    def test_message_watermarks_are_opaque_and_report_row_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "message/message_0.db"
            database.parent.mkdir(parents=True)
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE Msg_private_chat(
                    local_id INTEGER,
                    create_time INTEGER,
                    message_content TEXT
                );
                INSERT INTO Msg_private_chat VALUES(1, 100, 'SECRET');
                INSERT INTO Msg_private_chat VALUES(2, 101, 'SECRET TWO');
                """
            )
            connection.commit()
            connection.close()
            current = wechat_incremental.message_watermarks(
                root, ("message/message_0.db",)
            )
        serialized = str(current)
        self.assertNotIn("private_chat", serialized)
        self.assertNotIn("SECRET", serialized)
        self.assertEqual(len(current), 1)
        watermark = next(iter(current.values()))
        self.assertEqual(watermark["rows"], 2)
        self.assertEqual(watermark["max_local_id"], 2)
        change = wechat_incremental.summarize_watermark_change({}, current)
        self.assertTrue(change["baseline"])
        self.assertIsNone(change["row_increase_estimate"])
        self.assertFalse(change["exact_change_detection"])

    def test_watermark_regression_is_not_reported_as_new_rows(self) -> None:
        previous = {
            "stream": {"rows": 4, "max_local_id": 4, "max_create_time": 104}
        }
        current = {
            "stream": {"rows": 3, "max_local_id": 3, "max_create_time": 103}
        }
        change = wechat_incremental.summarize_watermark_change(previous, current)
        self.assertFalse(change["baseline"])
        self.assertEqual(change["row_increase_estimate"], 0)
        self.assertEqual(change["regressions"], 1)

    def test_sync_ingests_last_generation_when_capture_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incremental_root = root / "incremental"
            generation_id = "20260830T120000Z-aaaaaaaaaaaa"
            (incremental_root / "generations" / generation_id).mkdir(parents=True)
            wechat_incremental._write_state(
                incremental_root / "state.json",
                {
                    "schema": wechat_incremental.SCHEMA,
                    "last_generation_id": generation_id,
                },
            )
            options = wechat_incremental.IngestOptions(
                exports_root=root / "exports",
                data_home=root / "normalized",
                account_id="personal-wechat",
            )
            calls = []

            def fake_ingest(*args, **kwargs):
                calls.append((args, kwargs))
                return {"status": "complete", "messages": 3}

            with patch.object(
                wechat_incremental,
                "capture_generation",
                return_value={
                    "status": "UNCHANGED",
                    "source_modified": False,
                    "process_attached": False,
                },
            ):
                result = wechat_incremental.sync_capture_and_ingest(
                    root / "source",
                    incremental_root,
                    root / "keys.json",
                    1,
                    options,
                    ingest=fake_ingest,
                )

        self.assertEqual(result["generation_id"], generation_id)
        self.assertEqual(result["capture"]["status"], "UNCHANGED")
        self.assertEqual(result["ingest"]["messages"], 3)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][0].name, generation_id)
        self.assertEqual(calls[0][0][1], root / "exports" / generation_id)

    def test_ingest_failure_is_retryable_without_recapturing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incremental_root = root / "incremental"
            generation_id = "20260830T120000Z-bbbbbbbbbbbb"
            (incremental_root / "generations" / generation_id).mkdir(parents=True)
            options = wechat_incremental.IngestOptions(
                exports_root=root / "exports",
                data_home=root / "normalized",
                account_id="personal-wechat",
            )

            def failed_ingest(*args, **kwargs):
                raise ValueError("synthetic ingest failure")

            with self.assertRaisesRegex(RuntimeError, "generation ingest failed"):
                wechat_incremental.ingest_generation_id(
                    generation_id,
                    incremental_root,
                    options,
                    ingest=failed_ingest,
                )


if __name__ == "__main__":
    unittest.main()
