from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .database import connect, initialize
from .paths import database_path


PROFILE_ID = "signup-deadline-v1"
PROFILE_NAME = "报名与截止"
PROFILE_VERSION = "1"
PROFILE_DEFINITION = {
    "event_types": {
        "registration": ["报名", "招募", "登记", "申请"],
        "deadline": ["截止", "截至", "逾期"],
    },
    "review_policy": "REVIEW_REQUIRED",
    "time_policy": "unresolved",
}


class MonitoringError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _compact_title(body: str) -> str:
    compact = " ".join(body.split())
    return compact[:160] if compact else "[无可提取文本]"


def _source_status_snapshot(connection: Any) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT s.id AS source_id, s.kind AS source_kind,
               COUNT(DISTINCT m.id) AS message_count,
               MAX(m.sent_at) AS latest_message_at,
               (SELECT MAX(ir.finished_at) FROM import_runs ir
                WHERE ir.source_id = s.id AND ir.status = 'complete')
                   AS last_successful_import_at
        FROM sources s
        LEFT JOIN messages m ON m.source_id = s.id
        GROUP BY s.id
        ORDER BY s.kind, s.id
        """
    ).fetchall()
    return [
        {
            **dict(row),
            "collector_freshness_state": "NOT_RECORDED",
        }
        for row in rows
    ]


def scan_signup_deadline(
    data_home: Path,
    *,
    max_messages: int = 50000,
) -> dict[str, Any]:
    if isinstance(max_messages, bool) or not 1 <= max_messages <= 50000:
        raise MonitoringError("max_messages must be between 1 and 50000")

    connection = connect(database_path(data_home.resolve()))
    initialize(connection)
    now = _utc_now()
    run_id = f"mon_{uuid.uuid4().hex}"
    definition_json = _canonical(PROFILE_DEFINITION)
    try:
        with connection:
            existing_rule = connection.execute(
                """
                SELECT rule_version, enabled, definition_json
                FROM monitor_rules WHERE id = ?
                """,
                (PROFILE_ID,),
            ).fetchone()
            if existing_rule is not None:
                if (
                    existing_rule["rule_version"] != PROFILE_VERSION
                    or existing_rule["definition_json"] != definition_json
                ):
                    raise MonitoringError(
                        "stored rule definition differs; use a new profile version"
                    )
                if not existing_rule["enabled"]:
                    raise MonitoringError("monitor profile is disabled")
            else:
                connection.execute(
                    """
                    INSERT INTO monitor_rules(
                        id, name, rule_version, enabled, definition_json,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, 1, ?, ?, ?)
                    """,
                    (
                        PROFILE_ID,
                        PROFILE_NAME,
                        PROFILE_VERSION,
                        definition_json,
                        now,
                        now,
                    ),
                )
            outstanding = connection.execute(
                """
                SELECT COUNT(*)
                FROM messages m
                WHERE NOT EXISTS (
                    SELECT 1 FROM monitor_message_state state
                    WHERE state.rule_id = ? AND state.message_id = m.id
                )
                """,
                (PROFILE_ID,),
            ).fetchone()[0]
            rows = connection.execute(
                """
                SELECT m.id AS message_id, m.sent_at, m.sender_display_name,
                       c.title AS conversation_title,
                       s.kind AS source_kind,
                       COALESCE(GROUP_CONCAT(p.text_content, char(10)), '') AS body
                FROM messages m
                JOIN conversations c ON c.id = m.conversation_id
                JOIN sources s ON s.id = m.source_id
                LEFT JOIN message_parts p ON p.message_id = m.id
                WHERE NOT EXISTS (
                    SELECT 1 FROM monitor_message_state state
                    WHERE state.rule_id = ? AND state.message_id = m.id
                )
                GROUP BY m.id
                ORDER BY m.sent_at, m.id
                LIMIT ?
                """,
                (PROFILE_ID, max_messages),
            ).fetchall()
            remaining = outstanding - len(rows)
            status = "partial" if remaining else "complete"
            connection.execute(
                """
                INSERT INTO monitor_runs(
                    id, rule_id, started_at, finished_at, status,
                    scanned_messages, candidate_count, remaining_messages,
                    source_status_json, warnings_json
                ) VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?, '[]')
                """,
                (
                    run_id,
                    PROFILE_ID,
                    now,
                    now,
                    status,
                    len(rows),
                    remaining,
                    _canonical(_source_status_snapshot(connection)),
                ),
            )

            candidate_count = 0
            for row in rows:
                body = str(row["body"])
                matches = {
                    event_type: [keyword for keyword in keywords if keyword in body]
                    for event_type, keywords in PROFILE_DEFINITION["event_types"].items()
                }
                matches = {
                    event_type: keywords
                    for event_type, keywords in matches.items()
                    if keywords
                }
                matched = bool(matches)
                if matched:
                    if {"registration", "deadline"}.issubset(matches):
                        event_type = "registration_deadline"
                    elif "registration" in matches:
                        event_type = "registration"
                    else:
                        event_type = "deadline"
                    dedup_key = hashlib.sha256(
                        f"{row['message_id']}\0{event_type}".encode()
                    ).hexdigest()
                    candidate_id = f"evt_{dedup_key[:32]}"
                    rationale = {
                        "profile_id": PROFILE_ID,
                        "matched_keywords": matches,
                        "source_kind": row["source_kind"],
                        "message_timestamp": row["sent_at"],
                        "time_extraction": "NOT_ATTEMPTED_V1",
                    }
                    connection.execute(
                        """
                        INSERT INTO event_candidates(
                            id, rule_id, event_type, title, review_status,
                            first_seen_at, last_seen_at, event_at, deadline_at,
                            time_uncertain, importance, dedup_key, rationale_json
                        ) VALUES(?, ?, ?, ?, 'REVIEW_REQUIRED', ?, ?, NULL, NULL,
                                 1, 'normal', ?, ?)
                        ON CONFLICT(rule_id, dedup_key) DO UPDATE SET
                            last_seen_at = excluded.last_seen_at,
                            title = excluded.title,
                            rationale_json = excluded.rationale_json
                        """,
                        (
                            candidate_id,
                            PROFILE_ID,
                            event_type,
                            _compact_title(body),
                            now,
                            now,
                            dedup_key,
                            _canonical(rationale),
                        ),
                    )
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO event_evidence(
                            candidate_id, message_id, evidence_role, evidence_order
                        ) VALUES(?, ?, 'trigger', 0)
                        """,
                        (candidate_id, row["message_id"]),
                    )
                    candidate_count += 1
                connection.execute(
                    """
                    INSERT INTO monitor_message_state(
                        rule_id, message_id, scanned_at, matched, monitor_run_id
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (PROFILE_ID, row["message_id"], now, int(matched), run_id),
                )

            connection.execute(
                "UPDATE monitor_runs SET candidate_count = ? WHERE id = ?",
                (candidate_count, run_id),
            )
    finally:
        connection.close()

    return {
        "status": status,
        "profile_id": PROFILE_ID,
        "monitor_run_id": run_id,
        "scanned_messages": len(rows),
        "candidate_count": candidate_count,
        "remaining_messages": remaining,
        "default_review_status": "REVIEW_REQUIRED",
        "collector_freshness_state": "NOT_RECORDED",
    }
