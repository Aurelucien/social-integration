from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import wechat_schema_probe
import wechat_snapshot


class SchemaProbeTests(unittest.TestCase):
    def test_message_probe_aggregates_without_reading_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "message/message_0.db"
            path.parent.mkdir(parents=True)
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY);
                CREATE TABLE Msg_00000000000000000000000000000000(
                    local_id INTEGER,
                    local_type INTEGER,
                    create_time INTEGER,
                    real_sender_id INTEGER,
                    message_content TEXT,
                    WCDB_CT_message_content INTEGER
                );
                INSERT INTO Name2Id VALUES('private-id');
                INSERT INTO Msg_00000000000000000000000000000000
                VALUES(1, 1, 1700000000, 2, 'SECRET_MARKER', 0);
                """
            )
            connection.commit()
            connection.close()

            old_targets = wechat_snapshot.TARGETS
            try:
                wechat_snapshot.TARGETS = ("message/message_0.db",)
                report = wechat_schema_probe.build_report(root)
            finally:
                wechat_snapshot.TARGETS = old_targets

        serialized = json.dumps(report)
        self.assertNotIn("SECRET_MARKER", serialized)
        self.assertNotIn("private-id", serialized)
        message = report["databases"]["message/message_0.db"]
        self.assertEqual(message["message_rows"], 1)
        self.assertEqual(message["base_type_counts"], {"1": 1})
        self.assertFalse(message["message_content_read"])


if __name__ == "__main__":
    unittest.main()
