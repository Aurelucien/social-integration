from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .database import connect, initialize
from .paths import blob_root, database_path, default_data_home


SCHEMA_VERSION = "social-inbox-import/v1"
PART_TYPES = {"text", "image", "audio", "video", "file", "link", "system"}
DIRECTIONS = {"incoming", "outgoing", "system", "unknown"}


class ImportValidationError(ValueError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\0".join(parts).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(payload).hexdigest()[:24]}"


def _required_string(container: dict[str, Any], key: str, where: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ImportValidationError(f"{where}.{key} must be a non-empty string")
    return value


def _normalized_timestamp(value: str, where: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ImportValidationError(f"{where} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ImportValidationError(f"{where} must include a timezone")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat().replace("+00:00", "Z")


def _safe_attachment_path(export_root: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute():
        raise ImportValidationError("attachment paths must be relative")
    candidate = (export_root / relative_path).resolve()
    try:
        candidate.relative_to(export_root)
    except ValueError as exc:
        raise ImportValidationError("attachment path escapes the export directory") from exc
    return candidate


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _store_blob(source: Path, digest: str, destination_root: Path) -> Path:
    destination = destination_root / digest[:2] / digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        destination_root.chmod(0o700)
        destination.parent.chmod(0o700)
    if destination.exists():
        if os.name == "posix":
            destination.chmod(0o600)
        return destination

    temporary_name: str | None = None
    try:
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{digest}.", delete=False
        ) as temporary:
            shutil.copyfileobj(source_handle, temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, destination)
        if os.name == "posix":
            destination.chmod(0o600)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()
    return destination


def _previous_run(row: Any) -> dict[str, Any]:
    return {
        "import_run_id": row["id"],
        "status": "already_imported",
        "manifest_sha256": row["manifest_sha256"],
        "inserted_messages": row["inserted_messages"],
        "reused_messages": row["reused_messages"],
        "present_attachments": row["present_attachments"],
        "missing_attachments": row["missing_attachments"],
        "warnings": json.loads(row["warnings_json"]),
    }


def import_manifest(manifest_path: Path, data_home: Path | None = None) -> dict[str, Any]:
    home = (data_home or default_data_home()).resolve()
    manifest_path = manifest_path.expanduser().resolve()
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise ImportValidationError(f"invalid JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ImportValidationError("manifest root must be an object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ImportValidationError(f"schema_version must be {SCHEMA_VERSION}")

    source = manifest.get("source")
    if not isinstance(source, dict):
        raise ImportValidationError("source must be an object")
    source_kind = _required_string(source, "kind", "source")
    account_id = _required_string(source, "account_id", "source")
    source_name = _required_string(source, "display_name", "source")
    source_id = _stable_id("src", source_kind, account_id)

    conversations = manifest.get("conversations")
    if not isinstance(conversations, list):
        raise ImportValidationError("conversations must be an array")

    exported_at = manifest.get("exported_at")
    if exported_at is not None:
        if not isinstance(exported_at, str):
            raise ImportValidationError("exported_at must be a string")
        exported_at = _normalized_timestamp(exported_at, "exported_at")

    connection = connect(database_path(home))
    initialize(connection)
    previous = connection.execute(
        "SELECT * FROM import_runs WHERE manifest_sha256 = ? AND status = 'complete'",
        (manifest_sha,),
    ).fetchone()
    if previous:
        connection.close()
        return _previous_run(previous)

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    run_id = _stable_id("imp", manifest_sha)
    export_root = manifest_path.parent.resolve()
    warnings: list[dict[str, Any]] = []
    inserted_messages = 0
    reused_messages = 0
    present_attachments = 0
    missing_attachments = 0

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO sources(id, kind, external_account_id, display_name, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(kind, external_account_id) DO UPDATE SET
                    display_name = excluded.display_name,
                    updated_at = excluded.updated_at
                """,
                (source_id, source_kind, account_id, source_name, now, now),
            )
            connection.execute(
                """
                INSERT INTO import_runs(
                    id, manifest_sha256, source_id, source_manifest_path,
                    exported_at, started_at, status
                ) VALUES(?, ?, ?, ?, ?, ?, 'running')
                """,
                (run_id, manifest_sha, source_id, str(manifest_path), exported_at, now),
            )

            for conversation_index, conversation in enumerate(conversations):
                where = f"conversations[{conversation_index}]"
                if not isinstance(conversation, dict):
                    raise ImportValidationError(f"{where} must be an object")
                external_conversation_id = _required_string(
                    conversation, "source_conversation_id", where
                )
                title = _required_string(conversation, "title", where)
                conversation_type = conversation.get("type", "single")
                if conversation_type not in {"single", "group"}:
                    raise ImportValidationError(f"{where}.type must be single or group")
                conversation_id = _stable_id(
                    "con", source_id, external_conversation_id
                )
                explicit_last_activity = conversation.get("last_activity")
                if explicit_last_activity is not None:
                    if not isinstance(explicit_last_activity, str):
                        raise ImportValidationError(
                            f"{where}.last_activity must be a string"
                        )
                    explicit_last_activity = _normalized_timestamp(
                        explicit_last_activity, f"{where}.last_activity"
                    )
                conversation_raw = _canonical(
                    {key: value for key, value in conversation.items() if key != "messages"}
                )
                connection.execute(
                    """
                    INSERT INTO conversations(
                        id, source_id, external_conversation_id, title,
                        conversation_type, last_activity, raw_json
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(source_id, external_conversation_id) DO UPDATE SET
                        title = excluded.title,
                        conversation_type = excluded.conversation_type,
                        last_activity = CASE
                            WHEN excluded.last_activity IS NULL THEN conversations.last_activity
                            WHEN conversations.last_activity IS NULL THEN excluded.last_activity
                            WHEN excluded.last_activity > conversations.last_activity THEN excluded.last_activity
                            ELSE conversations.last_activity
                        END,
                        raw_json = excluded.raw_json
                    """,
                    (
                        conversation_id,
                        source_id,
                        external_conversation_id,
                        title,
                        conversation_type,
                        explicit_last_activity,
                        conversation_raw,
                    ),
                )

                participants = conversation.get("participants", [])
                if not isinstance(participants, list):
                    raise ImportValidationError(f"{where}.participants must be an array")
                participants_complete = conversation.get("participants_complete", False)
                if not isinstance(participants_complete, bool):
                    raise ImportValidationError(
                        f"{where}.participants_complete must be a boolean"
                    )
                if participants_complete:
                    connection.execute(
                        "DELETE FROM conversation_participants WHERE conversation_id = ?",
                        (conversation_id,),
                    )
                identity_ids: dict[str, str] = {}
                for participant_index, participant in enumerate(participants):
                    participant_where = f"{where}.participants[{participant_index}]"
                    if not isinstance(participant, dict):
                        raise ImportValidationError(
                            f"{participant_where} must be an object"
                        )
                    external_identity_id = _required_string(
                        participant, "source_identity_id", participant_where
                    )
                    display_name = _required_string(
                        participant, "display_name", participant_where
                    )
                    identity_id = _stable_id(
                        "idn", source_id, external_identity_id
                    )
                    identity_ids[external_identity_id] = identity_id
                    identity_raw = {
                        key: value
                        for key, value in participant.items()
                        if key not in {"role", "group_nickname", "membership"}
                    }
                    connection.execute(
                        """
                        INSERT INTO identities(
                            id, source_id, external_identity_id, display_name,
                            is_self, raw_json
                        ) VALUES(?, ?, ?, ?, ?, ?)
                        ON CONFLICT(source_id, external_identity_id) DO UPDATE SET
                            display_name = excluded.display_name,
                            is_self = excluded.is_self,
                            raw_json = excluded.raw_json
                        """,
                        (
                            identity_id,
                            source_id,
                            external_identity_id,
                            display_name,
                            int(bool(participant.get("is_self", False))),
                            _canonical(identity_raw),
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO conversation_participants(
                            conversation_id, identity_id, raw_json
                        ) VALUES(?, ?, ?)
                        ON CONFLICT(conversation_id, identity_id) DO UPDATE SET
                            raw_json = excluded.raw_json
                        """,
                        (conversation_id, identity_id, _canonical(participant)),
                    )

                messages = conversation.get("messages")
                if not isinstance(messages, list):
                    raise ImportValidationError(f"{where}.messages must be an array")
                conversation_last_activity: str | None = explicit_last_activity
                for message_index, message in enumerate(messages):
                    message_where = f"{where}.messages[{message_index}]"
                    if not isinstance(message, dict):
                        raise ImportValidationError(f"{message_where} must be an object")
                    external_message_id = _required_string(
                        message, "source_message_id", message_where
                    )
                    sent_at = _normalized_timestamp(
                        _required_string(message, "timestamp", message_where),
                        f"{message_where}.timestamp",
                    )
                    conversation_last_activity = max(
                        conversation_last_activity or sent_at, sent_at
                    )
                    sender_external_id = message.get("sender_id")
                    sender_name = message.get("sender_name", sender_external_id or "Unknown")
                    if not isinstance(sender_name, str):
                        raise ImportValidationError(
                            f"{message_where}.sender_name must be a string"
                        )
                    sender_identity_id = (
                        identity_ids.get(sender_external_id)
                        if isinstance(sender_external_id, str)
                        else None
                    )
                    direction = message.get("direction", "unknown")
                    if direction not in DIRECTIONS:
                        raise ImportValidationError(
                            f"{message_where}.direction is unsupported"
                        )
                    message_id = _stable_id("msg", source_id, external_message_id)
                    raw_message = _canonical(message)
                    existing = connection.execute(
                        "SELECT raw_json FROM messages WHERE id = ?", (message_id,)
                    ).fetchone()
                    if existing:
                        reused_messages += 1
                        if existing["raw_json"] != raw_message:
                            warnings.append(
                                {
                                    "code": "SOURCE_MESSAGE_CONFLICT",
                                    "message_id": message_id,
                                    "source_message_id": external_message_id,
                                }
                            )
                        continue

                    connection.execute(
                        """
                        INSERT INTO messages(
                            id, source_id, conversation_id, external_message_id,
                            sender_identity_id, sender_display_name, sent_at,
                            direction, raw_json, import_run_id
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            message_id,
                            source_id,
                            conversation_id,
                            external_message_id,
                            sender_identity_id,
                            sender_name,
                            sent_at,
                            direction,
                            raw_message,
                            run_id,
                        ),
                    )
                    inserted_messages += 1

                    parts = message.get("parts")
                    if not isinstance(parts, list) or not parts:
                        raise ImportValidationError(
                            f"{message_where}.parts must be a non-empty array"
                        )
                    searchable: list[str] = [sender_name]
                    for part_index, part in enumerate(parts):
                        part_where = f"{message_where}.parts[{part_index}]"
                        if not isinstance(part, dict):
                            raise ImportValidationError(f"{part_where} must be an object")
                        part_type = _required_string(part, "type", part_where)
                        if part_type not in PART_TYPES:
                            raise ImportValidationError(
                                f"{part_where}.type is unsupported"
                            )
                        part_id = _stable_id("prt", message_id, str(part_index))
                        text_content: str | None = None
                        attachment_id: str | None = None

                        if part_type in {"text", "system", "link"}:
                            candidate_text = part.get("text", part.get("url"))
                            if not isinstance(candidate_text, str):
                                raise ImportValidationError(
                                    f"{part_where} requires text or url"
                                )
                            text_content = candidate_text
                            searchable.append(candidate_text)
                        else:
                            attachment_id = _stable_id(
                                "att", message_id, str(part_index)
                            )
                            relative_path = part.get("path")
                            if relative_path is not None and not isinstance(relative_path, str):
                                raise ImportValidationError(
                                    f"{part_where}.path must be a string"
                                )
                            file_name = part.get("file_name")
                            if not isinstance(file_name, str) or not file_name:
                                file_name = Path(relative_path).name if relative_path else "unknown"
                            mime_type = part.get("mime_type")
                            if mime_type is not None and not isinstance(mime_type, str):
                                raise ImportValidationError(
                                    f"{part_where}.mime_type must be a string"
                                )
                            transcription = part.get("transcription")
                            if transcription is not None:
                                if not isinstance(transcription, str):
                                    raise ImportValidationError(
                                        f"{part_where}.transcription must be a string"
                                    )
                                text_content = transcription
                                searchable.append(transcription)
                            searchable.append(file_name)

                            status = "missing"
                            blob_sha: str | None = None
                            size_bytes: int | None = None
                            if relative_path:
                                source_attachment = _safe_attachment_path(
                                    export_root, relative_path
                                )
                                if source_attachment.is_file():
                                    blob_sha, size_bytes = _hash_file(source_attachment)
                                    stored = _store_blob(
                                        source_attachment, blob_sha, blob_root(home)
                                    )
                                    connection.execute(
                                        """
                                        INSERT OR IGNORE INTO blobs(
                                            sha256, size_bytes, stored_path, created_at
                                        ) VALUES(?, ?, ?, ?)
                                        """,
                                        (blob_sha, size_bytes, str(stored), now),
                                    )
                                    status = "present"
                                    present_attachments += 1
                            if status == "missing":
                                missing_attachments += 1
                                warnings.append(
                                    {
                                        "code": "ATTACHMENT_MISSING",
                                        "message_id": message_id,
                                        "part_index": part_index,
                                        "path": relative_path,
                                    }
                                )
                            connection.execute(
                                """
                                INSERT INTO attachments(
                                    id, message_id, part_index, blob_sha256,
                                    file_name, mime_type, source_relative_path,
                                    status, size_bytes, raw_json
                                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    attachment_id,
                                    message_id,
                                    part_index,
                                    blob_sha,
                                    file_name,
                                    mime_type,
                                    relative_path,
                                    status,
                                    size_bytes,
                                    _canonical(part),
                                ),
                            )

                        connection.execute(
                            """
                            INSERT INTO message_parts(
                                id, message_id, part_index, part_type,
                                text_content, attachment_id, raw_json
                            ) VALUES(?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                part_id,
                                message_id,
                                part_index,
                                part_type,
                                text_content,
                                attachment_id,
                                _canonical(part),
                            ),
                        )
                    connection.execute(
                        "INSERT INTO message_fts(message_id, body) VALUES(?, ?)",
                        (message_id, "\n".join(searchable)),
                    )

                if conversation_last_activity:
                    current = connection.execute(
                        "SELECT last_activity FROM conversations WHERE id = ?",
                        (conversation_id,),
                    ).fetchone()
                    previous_activity = current["last_activity"] if current else None
                    last_activity = max(
                        previous_activity or conversation_last_activity,
                        conversation_last_activity,
                    )
                    connection.execute(
                        "UPDATE conversations SET last_activity = ? WHERE id = ?",
                        (last_activity, conversation_id),
                    )

            finished = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            connection.execute(
                """
                UPDATE import_runs SET
                    finished_at = ?, status = 'complete', inserted_messages = ?,
                    reused_messages = ?, present_attachments = ?,
                    missing_attachments = ?, warnings_json = ?
                WHERE id = ?
                """,
                (
                    finished,
                    inserted_messages,
                    reused_messages,
                    present_attachments,
                    missing_attachments,
                    _canonical(warnings),
                    run_id,
                ),
            )
    finally:
        connection.close()

    return {
        "import_run_id": run_id,
        "status": "complete",
        "manifest_sha256": manifest_sha,
        "inserted_messages": inserted_messages,
        "reused_messages": reused_messages,
        "present_attachments": present_attachments,
        "missing_attachments": missing_attachments,
        "warnings": warnings,
    }
