from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .database import connect, initialize
from .paths import database_path, default_data_home


class QueryError(ValueError):
    pass


def _bounded_limit(value: Any, default: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise QueryError("limit must be an integer")
    if value < 1 or value > maximum:
        raise QueryError(f"limit must be between 1 and {maximum}")
    return value


def _bounded_offset(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QueryError("participant_offset must be a non-negative integer")
    return value


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _collector_status(row: sqlite3.Row | dict[str, Any]) -> tuple[str, dict[str, Any]]:
    heartbeat = dict(row)
    now = datetime.now(timezone.utc)
    try:
        observed = datetime.fromisoformat(
            str(heartbeat["worker_heartbeat_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        stale = (now - observed).total_seconds() > float(
            heartbeat["stale_after_seconds"]
        )
    except (TypeError, ValueError):
        stale = True
    if stale:
        freshness = "HEARTBEAT_STALE"
    elif heartbeat["state"] == "RETRYABLE_ERROR":
        freshness = "COLLECTOR_ERROR"
    elif heartbeat["state"] == "REQUIRES_USER_ACTION":
        freshness = "REQUIRES_USER_ACTION"
    elif heartbeat["observation_scope"] == "acquisition_readiness":
        freshness = "COLLECTOR_ACTIVE_SOURCE_UNOBSERVED"
    else:
        freshness = "SOURCE_OBSERVED"
    public = {
        key: heartbeat[key]
        for key in (
            "detector_id",
            "observation_scope",
            "state",
            "worker_heartbeat_at",
            "source_observed_at",
            "last_change_at",
            "last_generation_id",
            "generation_complete_at",
            "last_import_at",
            "consecutive_failures",
            "next_retry_at",
            "error_code",
            "stale_after_seconds",
        )
    }
    return freshness, public


def _query_signature(namespace: str, values: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"namespace": namespace, "values": values},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()[:16]


def _encode_cursor(timestamp: str, item_id: str, signature: str) -> str:
    raw = json.dumps(
        {"t": timestamp, "i": item_id, "q": signature}, separators=(",", ":")
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(value: str, expected_signature: str) -> tuple[str, str]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(value + padding))
        timestamp = decoded["t"]
        item_id = decoded["i"]
        signature = decoded["q"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise QueryError("cursor is invalid or from another query") from exc
    if (
        not isinstance(timestamp, str)
        or not isinstance(item_id, str)
        or signature != expected_signature
    ):
        raise QueryError("cursor is invalid or from another query")
    return timestamp, item_id


class InboxService:
    def __init__(self, data_home: Path | None = None):
        self.data_home = (data_home or default_data_home()).resolve()
        self.connection = connect(database_path(self.data_home))
        initialize(self.connection)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "InboxService":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def stats(self) -> dict[str, Any]:
        tables = {
            "sources": "sources",
            "conversations": "conversations",
            "messages": "messages",
            "attachments": "attachments",
            "import_runs": "import_runs",
        }
        counts = {
            key: self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for key, table in tables.items()
        }
        attachment_rows = self.connection.execute(
            "SELECT status, COUNT(*) AS count FROM attachments GROUP BY status"
        ).fetchall()
        counts["attachment_status"] = {
            row["status"]: row["count"] for row in attachment_rows
        }
        return counts

    def get_source_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        source_kind = arguments.get("source_kind")
        if source_kind is not None and (
            not isinstance(source_kind, str) or not source_kind
        ):
            raise QueryError("source_kind must be a non-empty string")

        conditions = ["s.kind = ?"] if source_kind is not None else []
        params: list[Any] = [source_kind] if source_kind is not None else []
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self.connection.execute(
            f"""
            SELECT s.id AS source_id, s.kind AS source_kind,
                   s.external_account_id, s.display_name,
                   s.created_at, s.updated_at,
                   COUNT(DISTINCT c.id) AS conversation_count,
                   COUNT(DISTINCT m.id) AS message_count,
                   MAX(m.sent_at) AS latest_message_at,
                   (SELECT COUNT(*) FROM import_runs ir
                    WHERE ir.source_id = s.id AND ir.status = 'complete')
                       AS successful_import_count,
                   (SELECT MAX(ir.finished_at) FROM import_runs ir
                    WHERE ir.source_id = s.id AND ir.status = 'complete')
                       AS last_successful_import_at,
                   (SELECT MAX(ir.exported_at) FROM import_runs ir
                    WHERE ir.source_id = s.id AND ir.status = 'complete')
                       AS latest_exported_at,
                   (SELECT COUNT(*) FROM import_runs ir
                    WHERE ir.source_id = s.id AND ir.status != 'complete')
                       AS incomplete_import_count
            FROM sources s
            LEFT JOIN conversations c ON c.source_id = s.id
            LEFT JOIN messages m ON m.source_id = s.id
            {where}
            GROUP BY s.id
            ORDER BY s.kind, s.id
            """,
            params,
        ).fetchall()

        heartbeat_conditions = ["source_kind = ?"] if source_kind is not None else []
        heartbeat_where = (
            f"WHERE {' AND '.join(heartbeat_conditions)}"
            if heartbeat_conditions
            else ""
        )
        heartbeat_rows = self.connection.execute(
            f"""
            SELECT * FROM collector_heartbeats
            {heartbeat_where}
            ORDER BY source_kind, detector_id
            """,
            params,
        ).fetchall()
        heartbeats = {
            (row["source_kind"], row["external_account_id"]): row
            for row in heartbeat_rows
        }

        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if item["incomplete_import_count"]:
                item["availability_state"] = "IMPORT_INCOMPLETE"
            elif item["successful_import_count"]:
                item["availability_state"] = "IMPORTED_EVIDENCE_AVAILABLE"
            else:
                item["availability_state"] = "NO_SUCCESSFUL_IMPORT"
            heartbeat = heartbeats.pop(
                (item["source_kind"], item["external_account_id"]), None
            )
            if heartbeat is None:
                # Import receipts establish what is locally available. Do not
                # infer live-source freshness from message timestamps.
                item["collector_freshness_state"] = "NOT_RECORDED"
            else:
                freshness, collector = _collector_status(heartbeat)
                item["collector_freshness_state"] = freshness
                item["collector"] = collector
            items.append(item)

        for (heartbeat_kind, account_id), heartbeat in heartbeats.items():
            freshness, collector = _collector_status(heartbeat)
            items.append(
                {
                    "source_id": None,
                    "source_kind": heartbeat_kind,
                    "external_account_id": account_id,
                    "display_name": None,
                    "created_at": None,
                    "updated_at": None,
                    "conversation_count": 0,
                    "message_count": 0,
                    "latest_message_at": None,
                    "successful_import_count": 0,
                    "last_successful_import_at": None,
                    "latest_exported_at": None,
                    "incomplete_import_count": 0,
                    "availability_state": "NO_SUCCESSFUL_IMPORT",
                    "collector_freshness_state": freshness,
                    "collector": collector,
                }
            )
        items.sort(key=lambda item: (item["source_kind"], item["source_id"] or ""))

        return {
            "observed_at": datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "freshness_semantics": (
                "Import timestamps describe local evidence only. Collector heartbeat "
                "reports worker/source observation separately and never infers live "
                "source freshness from message timestamps."
            ),
            "items": items,
        }

    def list_conversations(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = _bounded_limit(arguments.get("limit"), 50, 200)
        signature = _query_signature(
            "list_conversations",
            {
                key: arguments.get(key)
                for key in ("source_kind", "conversation_type", "query")
                if arguments.get(key) is not None
            },
        )
        conditions: list[str] = []
        params: list[Any] = []
        source_kind = arguments.get("source_kind")
        if source_kind is not None:
            if not isinstance(source_kind, str):
                raise QueryError("source_kind must be a string")
            conditions.append("s.kind = ?")
            params.append(source_kind)
        conversation_type = arguments.get("conversation_type")
        if conversation_type is not None:
            if conversation_type not in {"single", "group"}:
                raise QueryError("conversation_type must be single or group")
            conditions.append("c.conversation_type = ?")
            params.append(conversation_type)
        query = arguments.get("query")
        if query is not None:
            if not isinstance(query, str):
                raise QueryError("query must be a string")
            conditions.append("lower(c.title) LIKE ?")
            params.append(f"%{query.lower()}%")
        cursor = arguments.get("cursor")
        if cursor is not None:
            if not isinstance(cursor, str):
                raise QueryError("cursor must be a string")
            timestamp, item_id = _decode_cursor(cursor, signature)
            conditions.append(
                "(COALESCE(c.last_activity, '') < ? OR "
                "(COALESCE(c.last_activity, '') = ? AND c.id < ?))"
            )
            params.extend((timestamp, timestamp, item_id))
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self.connection.execute(
            f"""
            SELECT c.id, c.external_conversation_id, c.title,
                   c.conversation_type, c.last_activity,
                   c.raw_json,
                   s.id AS source_id, s.kind AS source_kind,
                   s.external_account_id, s.display_name AS source_display_name,
                   (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id)
                       AS message_count,
                   (SELECT COUNT(*) FROM conversation_participants cp
                    WHERE cp.conversation_id = c.id) AS participant_count
            FROM conversations c
            JOIN sources s ON s.id = c.source_id
            {where}
            ORDER BY COALESCE(c.last_activity, '') DESC, c.id DESC
            LIMIT ?
            """,
            (*params, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw = _json_object(str(item.pop("raw_json")))
            metadata = raw.get("metadata")
            if isinstance(metadata, dict):
                item["unread_count"] = metadata.get("unread_count", 0)
                item["is_hidden"] = metadata.get("is_hidden")
                item["last_message_type"] = metadata.get("last_message_type")
            group = raw.get("group")
            if isinstance(group, dict):
                item["current_member_count"] = group.get("member_count")
                item["has_announcement"] = bool(group.get("announcement"))
            item["participants_complete"] = bool(
                raw.get("participants_complete", False)
            )
            items.append(item)
        next_cursor = None
        if has_more and rows:
            next_cursor = _encode_cursor(
                rows[-1]["last_activity"] or "", rows[-1]["id"], signature
            )
        return {"items": items, "has_more": has_more, "next_cursor": next_cursor}

    def get_conversation(self, arguments: dict[str, Any]) -> dict[str, Any]:
        conversation_id = arguments.get("conversation_id")
        if not isinstance(conversation_id, str) or not conversation_id:
            raise QueryError("conversation_id is required")
        participant_limit = _bounded_limit(
            arguments.get("participant_limit"), 200, 500
        )
        participant_offset = _bounded_offset(arguments.get("participant_offset"))
        row = self.connection.execute(
            """
            SELECT c.id, c.external_conversation_id, c.title,
                   c.conversation_type, c.last_activity, c.raw_json,
                   s.id AS source_id, s.kind AS source_kind,
                   s.external_account_id, s.display_name AS source_display_name,
                   (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id)
                       AS message_count,
                   (SELECT COUNT(*) FROM conversation_participants cp
                    WHERE cp.conversation_id = c.id) AS participant_count
            FROM conversations c
            JOIN sources s ON s.id = c.source_id
            WHERE c.id = ?
            """,
            (conversation_id,),
        ).fetchone()
        if row is None:
            raise QueryError("conversation_id was not found")
        raw = _json_object(str(row["raw_json"]))
        participant_rows = self.connection.execute(
            """
            SELECT i.id AS identity_id, i.external_identity_id,
                   i.display_name, i.is_self, i.raw_json AS identity_raw,
                   cp.raw_json AS membership_raw
            FROM conversation_participants cp
            JOIN identities i ON i.id = cp.identity_id
            WHERE cp.conversation_id = ?
            ORDER BY CASE json_extract(cp.raw_json, '$.role')
                         WHEN 'owner' THEN 0 WHEN 'member' THEN 1 ELSE 2 END,
                     lower(i.display_name), i.id
            LIMIT ? OFFSET ?
            """,
            (conversation_id, participant_limit, participant_offset),
        ).fetchall()
        participants: list[dict[str, Any]] = []
        for participant_row in participant_rows:
            membership = _json_object(str(participant_row["membership_raw"]))
            identity_raw = _json_object(str(participant_row["identity_raw"]))
            participant = {
                "identity_id": participant_row["identity_id"],
                "source_identity_id": participant_row["external_identity_id"],
                "display_name": participant_row["display_name"],
                "is_self": bool(participant_row["is_self"]),
                "role": membership.get("role"),
                "membership": membership.get("membership"),
                "metadata": identity_raw.get("metadata", membership.get("metadata")),
            }
            participants.append(participant)
        result = {
            key: row[key]
            for key in (
                "id",
                "external_conversation_id",
                "title",
                "conversation_type",
                "last_activity",
                "source_id",
                "source_kind",
                "external_account_id",
                "source_display_name",
                "message_count",
                "participant_count",
            )
        }
        result.update(
            {
                "metadata": raw.get("metadata", {}),
                "group": raw.get("group"),
                "participant_scope": raw.get("participant_scope"),
                "participants_complete": bool(
                    raw.get("participants_complete", False)
                ),
                "participants": {
                    "items": participants,
                    "offset": participant_offset,
                    "limit": participant_limit,
                    "has_more": participant_offset + len(participants)
                    < int(row["participant_count"]),
                },
            }
        )
        return result

    def _message(self, row: sqlite3.Row) -> dict[str, Any]:
        raw_message = _json_object(str(row["raw_json"]))
        raw_parts = raw_message.get("parts")
        if not isinstance(raw_parts, list):
            raw_parts = []
        part_rows = self.connection.execute(
            """
            SELECT p.part_index, p.part_type, p.text_content,
                   a.id AS attachment_id, a.file_name, a.mime_type,
                   a.status AS attachment_status, a.size_bytes,
                   a.blob_sha256
            FROM message_parts p
            LEFT JOIN attachments a ON a.id = p.attachment_id
            WHERE p.message_id = ?
            ORDER BY p.part_index
            """,
            (row["id"],),
        ).fetchall()
        parts: list[dict[str, Any]] = []
        for part in part_rows:
            item = {
                "index": part["part_index"],
                "type": part["part_type"],
                "text": part["text_content"],
            }
            if part["attachment_id"]:
                item["attachment"] = {
                    "id": part["attachment_id"],
                    "file_name": part["file_name"],
                    "mime_type": part["mime_type"],
                    "status": part["attachment_status"],
                    "size_bytes": part["size_bytes"],
                    "sha256": part["blob_sha256"],
                }
            part_index = int(part["part_index"])
            if part_index < len(raw_parts) and isinstance(raw_parts[part_index], dict):
                source_metadata = {
                    key: value
                    for key, value in raw_parts[part_index].items()
                    if key
                    not in {
                        "type",
                        "text",
                        "url",
                        "path",
                        "file_name",
                        "mime_type",
                        "transcription",
                    }
                }
                if source_metadata:
                    item["source_metadata"] = source_metadata
            parts.append(item)
        result = {
            "message_id": row["id"],
            "source_message_id": row["external_message_id"],
            "source_kind": row["source_kind"],
            "source_account_id": row["external_account_id"],
            "conversation_id": row["conversation_id"],
            "conversation_title": row["conversation_title"],
            "sender": row["sender_display_name"],
            "timestamp": row["sent_at"],
            "direction": row["direction"],
            "parts": parts,
        }
        message_metadata = raw_message.get("metadata")
        if isinstance(message_metadata, dict) and message_metadata:
            result["source_metadata"] = message_metadata
        return result

    def _message_select(self, *, join_search_index: bool = False) -> str:
        search_join = (
            "JOIN message_fts search_index ON search_index.message_id = m.id"
            if join_search_index
            else ""
        )
        return f"""
            SELECT m.id, m.external_message_id, m.conversation_id,
                   m.sender_display_name, m.sent_at, m.direction, m.raw_json,
                   c.title AS conversation_title,
                   s.kind AS source_kind,
                   s.external_account_id
            FROM messages m
            JOIN conversations c ON c.id = m.conversation_id
            JOIN sources s ON s.id = m.source_id
            {search_join}
        """

    def search_messages(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = _bounded_limit(arguments.get("limit"), 20, 500)
        query = arguments.get("query", "")
        signature = _query_signature(
            "search_messages",
            {
                **{"query": query},
                **{
                    key: arguments.get(key)
                    for key in (
                    "source_kind",
                    "conversation_id",
                    "sender",
                    "date_after",
                    "date_before",
                    "media_type",
                    )
                    if arguments.get(key) is not None
                },
            },
        )
        conditions: list[str] = []
        params: list[Any] = []
        if not isinstance(query, str):
            raise QueryError("query must be a string")
        words = [word for word in query.split() if word]
        if query and not words:
            words = [query]
        for word in words:
            conditions.append("lower(search_index.body) LIKE ?")
            params.append(f"%{word.lower()}%")

        filters = {
            "source_kind": ("s.kind = ?", str),
            "conversation_id": ("m.conversation_id = ?", str),
            "sender": ("lower(m.sender_display_name) = ?", str),
            "date_after": ("m.sent_at > ?", str),
            "date_before": ("m.sent_at < ?", str),
        }
        for key, (clause, expected_type) in filters.items():
            value = arguments.get(key)
            if value is None:
                continue
            if not isinstance(value, expected_type):
                raise QueryError(f"{key} must be a string")
            conditions.append(clause)
            params.append(value.lower() if key == "sender" else value)

        media_type = arguments.get("media_type")
        if media_type is not None:
            if media_type == "any":
                conditions.append(
                    "EXISTS (SELECT 1 FROM attachments a WHERE a.message_id = m.id)"
                )
            elif media_type in {"image", "audio", "video", "file"}:
                conditions.append(
                    "EXISTS (SELECT 1 FROM message_parts p "
                    "WHERE p.message_id = m.id AND p.part_type = ?)"
                )
                params.append(media_type)
            else:
                raise QueryError("media_type must be any, image, audio, video, or file")

        cursor = arguments.get("cursor")
        if cursor is not None:
            if not isinstance(cursor, str):
                raise QueryError("cursor must be a string")
            timestamp, item_id = _decode_cursor(cursor, signature)
            conditions.append(
                "(m.sent_at < ? OR (m.sent_at = ? AND m.id < ?))"
            )
            params.extend((timestamp, timestamp, item_id))

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self.connection.execute(
            self._message_select(join_search_index=bool(words))
            + f" {where} ORDER BY m.sent_at DESC, m.id DESC LIMIT ?",
            (*params, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [self._message(row) for row in rows]
        next_cursor = None
        if has_more and rows:
            next_cursor = _encode_cursor(rows[-1]["sent_at"], rows[-1]["id"], signature)
        return {
            "query_mode": "literal",
            "items": items,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }

    def read_context(self, arguments: dict[str, Any]) -> dict[str, Any]:
        message_id = arguments.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            raise QueryError("message_id is required")
        before = _bounded_limit(arguments.get("before"), 5, 50)
        after = _bounded_limit(arguments.get("after"), 5, 50)
        target = self.connection.execute(
            self._message_select() + " WHERE m.id = ?", (message_id,)
        ).fetchone()
        if not target:
            raise QueryError("message_id was not found")

        earlier = self.connection.execute(
            self._message_select()
            + """
              WHERE m.conversation_id = ?
                AND (m.sent_at < ? OR (m.sent_at = ? AND m.id < ?))
              ORDER BY m.sent_at DESC, m.id DESC LIMIT ?
              """,
            (
                target["conversation_id"],
                target["sent_at"],
                target["sent_at"],
                target["id"],
                before,
            ),
        ).fetchall()
        later = self.connection.execute(
            self._message_select()
            + """
              WHERE m.conversation_id = ?
                AND (m.sent_at > ? OR (m.sent_at = ? AND m.id > ?))
              ORDER BY m.sent_at ASC, m.id ASC LIMIT ?
              """,
            (
                target["conversation_id"],
                target["sent_at"],
                target["sent_at"],
                target["id"],
                after,
            ),
        ).fetchall()
        ordered = list(reversed(earlier)) + [target] + list(later)
        return {
            "conversation_id": target["conversation_id"],
            "target_index": len(earlier),
            "items": [self._message(row) for row in ordered],
        }

    def list_event_candidates(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = _bounded_limit(arguments.get("limit"), 50, 200)
        signature = _query_signature(
            "list_event_candidates",
            {
                key: arguments.get(key)
                for key in ("review_status", "event_type", "source_kind")
                if arguments.get(key) is not None
            },
        )
        conditions: list[str] = []
        params: list[Any] = []
        review_status = arguments.get("review_status")
        if review_status is not None:
            if review_status not in {"REVIEW_REQUIRED", "APPROVED", "DISMISSED"}:
                raise QueryError(
                    "review_status must be REVIEW_REQUIRED, APPROVED, or DISMISSED"
                )
            conditions.append("e.review_status = ?")
            params.append(review_status)
        event_type = arguments.get("event_type")
        if event_type is not None:
            if not isinstance(event_type, str) or not event_type:
                raise QueryError("event_type must be a non-empty string")
            conditions.append("e.event_type = ?")
            params.append(event_type)
        source_kind = arguments.get("source_kind")
        if source_kind is not None:
            if not isinstance(source_kind, str) or not source_kind:
                raise QueryError("source_kind must be a non-empty string")
            conditions.append(
                "EXISTS (SELECT 1 FROM event_evidence ee "
                "JOIN messages em ON em.id = ee.message_id "
                "JOIN sources es ON es.id = em.source_id "
                "WHERE ee.candidate_id = e.id AND es.kind = ?)"
            )
            params.append(source_kind)
        cursor = arguments.get("cursor")
        if cursor is not None:
            if not isinstance(cursor, str):
                raise QueryError("cursor must be a string")
            timestamp, item_id = _decode_cursor(cursor, signature)
            conditions.append(
                "(e.last_seen_at < ? OR (e.last_seen_at = ? AND e.id < ?))"
            )
            params.extend((timestamp, timestamp, item_id))
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self.connection.execute(
            f"""
            SELECT e.id AS candidate_id, e.event_type, e.title,
                   e.review_status, e.first_seen_at, e.last_seen_at,
                   e.event_at, e.deadline_at, e.time_uncertain,
                   e.importance, e.rationale_json,
                   r.id AS rule_id, r.name AS rule_name,
                   (SELECT COUNT(*) FROM event_evidence ee
                    WHERE ee.candidate_id = e.id) AS evidence_count
            FROM event_candidates e
            JOIN monitor_rules r ON r.id = e.rule_id
            {where}
            ORDER BY e.last_seen_at DESC, e.id DESC
            LIMIT ?
            """,
            (*params, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["time_uncertain"] = bool(item["time_uncertain"])
            item["rationale"] = _json_object(str(item.pop("rationale_json")))
            items.append(item)
        next_cursor = None
        if has_more and rows:
            next_cursor = _encode_cursor(
                rows[-1]["last_seen_at"], rows[-1]["candidate_id"], signature
            )
        return {"items": items, "has_more": has_more, "next_cursor": next_cursor}

    def get_event_candidate(self, arguments: dict[str, Any]) -> dict[str, Any]:
        candidate_id = arguments.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            raise QueryError("candidate_id is required")
        row = self.connection.execute(
            """
            SELECT e.id AS candidate_id, e.event_type, e.title,
                   e.review_status, e.first_seen_at, e.last_seen_at,
                   e.event_at, e.deadline_at, e.time_uncertain,
                   e.importance, e.dedup_key, e.rationale_json,
                   r.id AS rule_id, r.name AS rule_name,
                   r.rule_version, r.definition_json
            FROM event_candidates e
            JOIN monitor_rules r ON r.id = e.rule_id
            WHERE e.id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise QueryError("candidate_id was not found")
        evidence_rows = self.connection.execute(
            self._message_select()
            + """
              JOIN event_evidence ee ON ee.message_id = m.id
              WHERE ee.candidate_id = ?
              ORDER BY ee.evidence_order, m.sent_at, m.id
              """,
            (candidate_id,),
        ).fetchall()
        result = dict(row)
        result["time_uncertain"] = bool(result["time_uncertain"])
        result["rationale"] = _json_object(str(result.pop("rationale_json")))
        result["rule_definition"] = _json_object(
            str(result.pop("definition_json"))
        )
        result["evidence"] = [self._message(item) for item in evidence_rows]
        return result

    def get_attachment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        attachment_id = arguments.get("attachment_id")
        if not isinstance(attachment_id, str) or not attachment_id:
            raise QueryError("attachment_id is required")
        row = self.connection.execute(
            """
            SELECT a.id, a.message_id, a.part_index, a.file_name, a.mime_type,
                   a.source_relative_path, a.status, a.size_bytes,
                   a.blob_sha256, a.raw_json, b.stored_path,
                   m.conversation_id, m.sent_at,
                   s.kind AS source_kind, s.external_account_id
            FROM attachments a
            JOIN messages m ON m.id = a.message_id
            JOIN sources s ON s.id = m.source_id
            LEFT JOIN blobs b ON b.sha256 = a.blob_sha256
            WHERE a.id = ?
            """,
            (attachment_id,),
        ).fetchone()
        if not row:
            raise QueryError("attachment_id was not found")
        result = dict(row)
        raw_attachment = _json_object(str(result.pop("raw_json")))
        source_metadata = {
            key: value
            for key, value in raw_attachment.items()
            if key not in {"type", "path", "file_name", "mime_type", "transcription"}
        }
        if source_metadata:
            result["source_metadata"] = source_metadata
        if result["stored_path"]:
            stored = Path(result["stored_path"]).resolve()
            try:
                stored.relative_to((self.data_home / "blobs").resolve())
            except ValueError as exc:
                raise QueryError("attachment storage path failed validation") from exc
            result["local_path"] = str(stored)
        result.pop("stored_path", None)
        return result

    def build_digest(self, arguments: dict[str, Any]) -> dict[str, Any]:
        query_args = {
            key: arguments[key]
            for key in ("source_kind", "date_after", "date_before")
            if key in arguments
        }
        query_args["query"] = ""
        query_args["limit"] = _bounded_limit(arguments.get("limit"), 100, 500)
        result = self.search_messages(query_args)
        messages = result["items"]
        by_conversation: dict[str, list[dict[str, Any]]] = defaultdict(list)
        source_counts: Counter[str] = Counter()
        sender_counts: Counter[str] = Counter()
        attachment_counts: Counter[str] = Counter()
        for message in messages:
            by_conversation[message["conversation_title"]].append(message)
            source_counts[message["source_kind"]] += 1
            sender_counts[message["sender"]] += 1
            for part in message["parts"]:
                if "attachment" in part:
                    attachment_counts[part["attachment"]["status"]] += 1

        lines = [
            "# Deterministic inbox digest packet",
            "",
            "This packet is derived from normalized evidence; it is not an AI summary.",
            f"Messages considered: {len(messages)}",
            f"Additional messages omitted by limit: {'yes' if result['has_more'] else 'no'}",
            "",
            "## Source counts",
        ]
        lines.extend(f"- {name}: {count}" for name, count in source_counts.most_common())
        lines.extend(["", "## Conversation excerpts"])
        for title, conversation_messages in sorted(
            by_conversation.items(), key=lambda pair: pair[1][0]["timestamp"], reverse=True
        ):
            lines.append(f"### {title}")
            for message in conversation_messages[:10]:
                text = next(
                    (
                        part["text"]
                        for part in message["parts"]
                        if isinstance(part.get("text"), str) and part["text"]
                    ),
                    "[attachment-only message]",
                )
                compact = " ".join(text.split())[:240]
                lines.append(
                    f"- {message['timestamp']} {message['sender']}: {compact} "
                    f"(message_id={message['message_id']})"
                )
            if len(conversation_messages) > 10:
                lines.append(f"- … {len(conversation_messages) - 10} more in selected window")
            lines.append("")

        return {
            "evidence_kind": "deterministic_digest_packet",
            "messages_considered": len(messages),
            "truncated": result["has_more"],
            "source_counts": dict(source_counts),
            "top_senders": dict(sender_counts.most_common(10)),
            "attachment_status": dict(attachment_counts),
            "markdown": "\n".join(lines).rstrip() + "\n",
        }
