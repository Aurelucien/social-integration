#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import wechat_snapshot


SCHEMA = "wechat-4.1.7-schema-report/v1"
REPORT_FILE = wechat_snapshot.SNAPSHOT_ROOT / "schema-report.json"
MSG_TABLE = re.compile(r"^Msg_[0-9a-f]{32}$")


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _tables(connection: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
    ]


def _columns(connection: sqlite3.Connection, table: str) -> list[dict]:
    return [
        {
            "name": row[1],
            "type": row[2],
            "notnull": bool(row[3]),
            "primary_key": bool(row[5]),
        }
        for row in connection.execute(f"PRAGMA table_info({_quote(table)})")
    ]


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()[0])


def _generic_report(connection: sqlite3.Connection) -> dict:
    tables = _tables(connection)
    return {
        "tables": [
            {"name": table, "rows": _count(connection, table), "columns": _columns(connection, table)}
            for table in tables
        ]
    }


def _message_report(connection: sqlite3.Connection) -> dict:
    tables = _tables(connection)
    message_tables = [table for table in tables if MSG_TABLE.fullmatch(table)]
    type_counts: dict[str, int] = {}
    compression_counts: dict[str, int] = {}
    storage_counts: dict[str, int] = {}
    total_rows = 0
    min_timestamp: int | None = None
    max_timestamp: int | None = None
    representative_columns: list[dict] = []
    for table in message_tables:
        quoted = _quote(table)
        if not representative_columns:
            representative_columns = _columns(connection, table)
        total_rows += _count(connection, table)
        for row in connection.execute(
            f"SELECT (local_type & 4294967295), COUNT(*) FROM {quoted} GROUP BY 1"
        ):
            key = str(int(row[0]))
            type_counts[key] = type_counts.get(key, 0) + int(row[1])
        for row in connection.execute(
            f"SELECT COALESCE(WCDB_CT_message_content, 0), COUNT(*) FROM {quoted} GROUP BY 1"
        ):
            key = str(int(row[0]))
            compression_counts[key] = compression_counts.get(key, 0) + int(row[1])
        for row in connection.execute(
            f"SELECT typeof(message_content), COUNT(*) FROM {quoted} GROUP BY 1"
        ):
            key = str(row[0])
            storage_counts[key] = storage_counts.get(key, 0) + int(row[1])
        bounds = connection.execute(
            f"SELECT MIN(create_time), MAX(create_time) FROM {quoted}"
        ).fetchone()
        if bounds[0] is not None:
            min_timestamp = int(bounds[0]) if min_timestamp is None else min(min_timestamp, int(bounds[0]))
        if bounds[1] is not None:
            max_timestamp = int(bounds[1]) if max_timestamp is None else max(max_timestamp, int(bounds[1]))
    name2id_rows = _count(connection, "Name2Id") if "Name2Id" in tables else 0
    return {
        "message_table_count": len(message_tables),
        "message_rows": total_rows,
        "name2id_rows": name2id_rows,
        "representative_message_columns": representative_columns,
        "base_type_counts": dict(sorted(type_counts.items(), key=lambda item: int(item[0]))),
        "compression_counts": dict(sorted(compression_counts.items())),
        "content_storage_counts": dict(sorted(storage_counts.items())),
        "min_timestamp": min_timestamp,
        "max_timestamp": max_timestamp,
        "message_table_names_reported": False,
        "message_content_read": False,
    }


def build_report(root: Path = wechat_snapshot.DECRYPTED_ROOT) -> dict:
    databases: dict[str, dict] = {}
    for relative in wechat_snapshot.TARGETS:
        path = root / relative
        if not path.is_file():
            continue
        with closing(_connect(path)) as connection:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if relative.startswith("message/message_") and Path(relative).name in {
                "message_0.db",
                "message_1.db",
            }:
                body = _message_report(connection)
            else:
                body = _generic_report(connection)
            databases[relative] = {"quick_check": quick_check, **body}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_kind": "decrypted_staged_copies",
        "message_content_read": False,
        "identifiers_reported": False,
        "databases": databases,
    }


def main() -> int:
    report = build_report()
    wechat_snapshot._write_private_json(REPORT_FILE, report)
    message_rows = sum(
        database.get("message_rows", 0) for database in report["databases"].values()
    )
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "database_count": len(report["databases"]),
                "message_rows_aggregated": message_rows,
                "message_content_read": False,
                "identifiers_reported": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
