from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit


ADAPTER_SCHEMA = "personal-social-inbox/dingtalk-macos-8.3.5/v2"
IMPORT_SCHEMA = "social-inbox-import/v1"
MESSAGE_TABLE = re.compile(r"^tbmsg_[0-9]{3}$")


class DingTalkAdapterError(RuntimeError):
    pass


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.chmod(0o700)


def _write_private_json(path: Path, payload: dict[str, Any]) -> str:
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    _private_directory(path.parent)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        if os.name == "posix":
            os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()
    return hashlib.sha256(encoded).hexdigest()


def _json_object(value: object) -> dict[str, Any]:
    if not isinstance(value, (str, bytes)):
        return {}
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _timestamp(value: object) -> str:
    try:
        numeric = int(value)
    except (TypeError, ValueError) as exc:
        raise DingTalkAdapterError("DingTalk row has an invalid timestamp") from exc
    seconds = numeric / 1000 if numeric >= 100_000_000_000 else numeric
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def _profile_name(row: sqlite3.Row | None, fallback: str) -> str:
    if row is not None:
        for key in ("alias", "nick", "realName"):
            value = row[key] if key in row.keys() else None
            if result := _text(value):
                return result
    return fallback


def _extension(attachment: object) -> dict[str, Any]:
    if not isinstance(attachment, dict):
        return {}
    value = attachment.get("extension")
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return _json_object(value)
    return {}


def _source_url(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = urlsplit(value)
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else None


def _image_mime(path: Path) -> str | None:
    with path.open("rb") as handle:
        header = handle.read(16)
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    return None


class _LocalMediaResolver:
    def __init__(self, roots: Sequence[Path], output: Path):
        self._roots = [root.expanduser().resolve(strict=True) for root in roots]
        self._output = output
        self.image_files = 0
        self.file_files = 0
        self.bytes_copied = 0

    def _candidate(self, raw_path: object) -> Path | None:
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None
        source = Path(raw_path)
        for root in self._roots:
            candidate = source.resolve() if source.is_absolute() else (root / source).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            if candidate.is_file():
                return candidate
        return None

    def resolve(
        self,
        candidates: Sequence[tuple[str, object]],
        *,
        category: str,
        expected_size: int | None = None,
    ) -> dict[str, Any] | None:
        for variant, raw_path in candidates:
            source = self._candidate(raw_path)
            if source is None:
                continue
            before = source.stat()
            if expected_size is not None and expected_size >= 0 and before.st_size != expected_size:
                continue
            mime_type = _image_mime(source) if category == "image" else mimetypes.guess_type(source.name)[0]
            if category == "image" and mime_type is None:
                continue
            attachment_root = self._output / "attachments"
            _private_directory(attachment_root)
            destination_root = attachment_root / category
            _private_directory(destination_root)
            temporary_name: str | None = None
            digest = hashlib.sha256()
            try:
                with source.open("rb") as input_file, tempfile.NamedTemporaryFile(
                    dir=destination_root, prefix=".copy-", delete=False
                ) as temporary:
                    temporary_name = temporary.name
                    while chunk := input_file.read(1024 * 1024):
                        digest.update(chunk)
                        temporary.write(chunk)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                after = source.stat()
                if (
                    before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ino != after.st_ino
                ):
                    raise DingTalkAdapterError("DingTalk media changed during read-only copy")
                suffix = source.suffix.lower()
                if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
                    suffix = ""
                relative = Path("attachments") / category / f"{digest.hexdigest()}{suffix}"
                destination = self._output / relative
                if destination.exists():
                    Path(temporary_name).unlink()
                    temporary_name = None
                else:
                    if os.name == "posix":
                        os.chmod(temporary_name, 0o600)
                    os.replace(temporary_name, destination)
                    temporary_name = None
                self.bytes_copied += before.st_size
                if category == "image":
                    self.image_files += 1
                else:
                    self.file_files += 1
                return {
                    "path": relative.as_posix(),
                    "file_name": source.name,
                    "mime_type": mime_type or "application/octet-stream",
                    "dingtalk_media_variant": variant,
                    "dingtalk_source_sha256": digest.hexdigest(),
                    "dingtalk_source_size": before.st_size,
                }
            finally:
                if temporary_name and Path(temporary_name).exists():
                    Path(temporary_name).unlink()
        return None


def _card_text(content: dict[str, Any]) -> str | None:
    attachments = content.get("attachments")
    if not isinstance(attachments, list):
        return None
    for attachment in attachments:
        ext = _extension(attachment)
        for key in ("title", "single_title", "desc", "markdown"):
            if result := _text(ext.get(key)):
                return result
    return None


def _parts(
    content_type: int,
    raw_content: object,
    local_id: object,
    resolver: _LocalMediaResolver,
) -> list[dict[str, Any]]:
    content = _json_object(raw_content)
    if content_type == 1:
        text = _text(content.get("text"))
        return [{"type": "text", "text": text or "[Empty DingTalk text]", "dingtalk_content_type": 1}]
    if content_type == 2:
        name = _text(content.get("filename")) or f"dingtalk-image-{local_id}.dat"
        resolved = resolver.resolve(
            [
                ("original_cache", content.get("filepath")),
                ("thumbnail_cache", content.get("thumbpath")),
                ("blurred_cache", content.get("blurredPath")),
            ],
            category="image",
        )
        part: dict[str, Any] = {
            "type": "image",
            "file_name": name,
            "mime_type": "application/octet-stream",
            "dingtalk_content_type": 2,
        }
        if url := _source_url(content.get("url")):
            part["dingtalk_source_url"] = url
        if media_id := _source_url(content.get("mediaId")):
            part["dingtalk_media_id"] = media_id
        if resolved is not None:
            part.update(resolved)
            part["dingtalk_attachment_status"] = "copied_from_allowlisted_local_path"
        else:
            part["dingtalk_attachment_status"] = "local_resource_not_resolved"
        return [part]
    if content_type == 500:
        attachments = content.get("attachments")
        attachment = attachments[0] if isinstance(attachments, list) and attachments else {}
        ext = _extension(attachment)
        name = _text(ext.get("f_name")) or f"dingtalk-file-{local_id}"
        size_value = ext.get("f_size")
        try:
            expected_size = int(size_value) if size_value is not None else None
        except (TypeError, ValueError):
            expected_size = None
        resolved = resolver.resolve(
            [
                ("recorded_file_path", ext.get("path")),
                ("attachment_file_path", attachment.get("filepath") if isinstance(attachment, dict) else None),
                ("content_file_path", content.get("filepath")),
            ],
            category="file",
            expected_size=expected_size,
        )
        part = {
            "type": "file",
            "file_name": name,
            "mime_type": mimetypes.guess_type(name)[0] or "application/octet-stream",
            "dingtalk_content_type": content_type,
        }
        if isinstance(attachment, dict) and (url := _source_url(attachment.get("url"))):
            part["dingtalk_source_url"] = url
        if media_id := _source_url(ext.get("mediaId")):
            part["dingtalk_media_id"] = media_id
        if expected_size is not None:
            part["dingtalk_source_size"] = expected_size
        if resolved is not None:
            part.update(resolved)
            part["file_name"] = name
            part["dingtalk_attachment_status"] = "copied_from_allowlisted_local_path"
        else:
            part["dingtalk_attachment_status"] = "local_resource_not_resolved"
        return [part]
    if text := _card_text(content):
        return [{"type": "text", "text": text, "dingtalk_content_type": content_type, "dingtalk_subtype": "card"}]
    return [{"type": "system", "text": f"[DingTalk content type {content_type}]", "dingtalk_content_type": content_type}]


def _message_tables(connection: sqlite3.Connection) -> list[str]:
    return sorted(
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        if MESSAGE_TABLE.fullmatch(str(row[0]))
    )


def _rows_for_conversation(
    connection: sqlite3.Connection, tables: list[str], cid: str, limit: int
) -> list[tuple[str, sqlite3.Row]]:
    collected: list[tuple[str, sqlite3.Row]] = []
    for table in tables:
        rows = connection.execute(
            f'SELECT primaryKey, localId, mid, senderId, createdAt, contentType, content, '
            f'messageStatus, recallStatus, extension FROM "{table}" WHERE cid = ? '
            "ORDER BY createdAt DESC, primaryKey DESC LIMIT ?",
            (cid, limit),
        ).fetchall()
        collected.extend((table, row) for row in rows)
    collected.sort(
        key=lambda item: (int(item[1]["createdAt"] or 0), str(item[1]["primaryKey"] or "")),
        reverse=True,
    )
    selected = collected[:limit]
    selected.reverse()
    return selected


def export_dingtalk_snapshot(
    snapshot_root: Path,
    output_directory: Path,
    *,
    account_id: str,
    self_uid: str,
    display_name: str = "Personal DingTalk",
    max_conversations: int = 20,
    max_messages_per_conversation: int = 200,
    media_roots: Sequence[Path] = (),
) -> dict[str, Any]:
    root = snapshot_root.expanduser().resolve()
    database = root if root.is_file() else root / "dingtalk.db"
    output = output_directory.expanduser().resolve()
    if not account_id.strip() or not self_uid.isdecimal():
        raise DingTalkAdapterError("account_id must be non-empty and self_uid must be decimal")
    if max_conversations <= 0 or max_messages_per_conversation <= 0:
        raise DingTalkAdapterError("export limits must be positive")
    if not database.is_file():
        raise DingTalkAdapterError("required decrypted database missing: dingtalk.db")
    source_boundary = database.parent if root.is_file() else root
    try:
        output.relative_to(source_boundary)
    except ValueError:
        pass
    else:
        raise DingTalkAdapterError("output cannot be inside the decrypted snapshot")
    normalized_media_roots: list[Path] = []
    for media_root in media_roots:
        normalized = media_root.expanduser().resolve(strict=True)
        if not normalized.is_dir():
            raise DingTalkAdapterError("media_root must be a directory")
        try:
            output.relative_to(normalized)
        except ValueError:
            pass
        else:
            raise DingTalkAdapterError("output cannot be inside a read-only media root")
        if normalized not in normalized_media_roots:
            normalized_media_roots.append(normalized)
    normalized_media_roots.sort(key=str)
    manifest_path = output / "export.json"
    if manifest_path.exists():
        raise DingTalkAdapterError("output export.json already exists; choose a new directory")
    _private_directory(output)

    resolver = _LocalMediaResolver(normalized_media_roots, output)
    with closing(_connect(database)) as connection:
        tables = _message_tables(connection)
        available = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables or not {"tbconversation", "tbuser_profile_v2"}.issubset(available):
            raise DingTalkAdapterError("DingTalk 8.3.5 schema is incomplete")
        profiles = {
            str(row["uid"]): row
            for row in connection.execute("SELECT uid, alias, nick, realName FROM tbuser_profile_v2 WHERE uid IS NOT NULL")
        }
        if self_uid not in profiles:
            raise DingTalkAdapterError("self_uid is not present in the captured profile table")
        conversations_rows = connection.execute(
            "SELECT cid, type, title, memberCount, ownerId, lastModify, createAt, unreadCount "
            "FROM tbconversation WHERE cid IS NOT NULL AND cid != '' "
            "ORDER BY COALESCE(lastModify, createAt, 0) DESC LIMIT ?",
            (max_conversations,),
        ).fetchall()

        conversations: list[dict[str, Any]] = []
        direction_counts = {"incoming": 0, "outgoing": 0, "unknown": 0}
        content_type_counts: dict[str, int] = {}
        for conversation_row in conversations_rows:
            cid = str(conversation_row["cid"])
            rows = _rows_for_conversation(connection, tables, cid, max_messages_per_conversation)
            participant_ids: set[str] = {self_uid}
            messages: list[dict[str, Any]] = []
            for table, row in rows:
                sender_id = str(row["senderId"] or "")
                if sender_id:
                    participant_ids.add(sender_id)
                direction = "outgoing" if sender_id == self_uid else "incoming" if sender_id else "unknown"
                direction_counts[direction] += 1
                content_type = int(row["contentType"] or 0)
                content_type_counts[str(content_type)] = content_type_counts.get(str(content_type), 0) + 1
                mid = _text(str(row["mid"])) if row["mid"] is not None else None
                fallback = f'{table}:{row["primaryKey"]}:{row["localId"]}'
                source_extension = _json_object(row["extension"])
                message_metadata: dict[str, Any] = {
                    "adapter_schema": ADAPTER_SCHEMA,
                    "message_status": row["messageStatus"],
                    "recall_status": row["recallStatus"],
                    "source_table": table,
                }
                if source_extension:
                    message_metadata["source_extension"] = source_extension
                messages.append({
                    "source_message_id": f"{cid}:{mid or fallback}",
                    "timestamp": _timestamp(row["createdAt"]),
                    "sender_id": sender_id or None,
                    "sender_name": _profile_name(profiles.get(sender_id), "Unknown DingTalk sender"),
                    "direction": direction,
                    "parts": _parts(content_type, row["content"], row["localId"], resolver),
                    "metadata": message_metadata,
                })
            participants = [{
                "source_identity_id": uid,
                "display_name": _profile_name(profiles.get(uid), "Unknown DingTalk user"),
                "is_self": uid == self_uid,
                "dingtalk_identity_status": "verified_self" if uid == self_uid else "observed_sender",
            } for uid in sorted(participant_ids)]
            source_type = int(conversation_row["type"] or 0)
            last_value = conversation_row["lastModify"] or conversation_row["createAt"]
            conversation: dict[str, Any] = {
                "source_conversation_id": cid,
                "title": _text(conversation_row["title"]) or "DingTalk conversation",
                "type": "single" if source_type == 1 else "group",
                "participants_complete": False,
                "participant_scope": "bounded_message_senders_plus_verified_self",
                "participants": participants,
                "messages": messages,
                "metadata": {
                    "adapter_schema": ADAPTER_SCHEMA,
                    "source_type": source_type,
                    "source_member_count": conversation_row["memberCount"],
                    "unread_count": conversation_row["unreadCount"],
                },
            }
            if last_value:
                conversation["last_activity"] = _timestamp(last_value)
            conversations.append(conversation)

    manifest = {
        "schema_version": IMPORT_SCHEMA,
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {"kind": "dingtalk", "account_id": account_id, "display_name": display_name},
        "conversations": conversations,
    }
    manifest_sha = _write_private_json(manifest_path, manifest)
    message_count = sum(len(item["messages"]) for item in conversations)
    return {
        "status": "complete",
        "adapter_schema": ADAPTER_SCHEMA,
        "manifest_sha256": manifest_sha,
        "conversations": len(conversations),
        "messages": message_count,
        "message_shards_scanned": len(tables),
        "direction_counts": direction_counts,
        "content_type_counts": dict(sorted(content_type_counts.items())),
        "self_identity_status": "verified_profile_uid",
        "attachments_resolved": resolver.image_files + resolver.file_files,
        "message_extensions_preserved": sum(
            "source_extension" in message["metadata"]
            for conversation in conversations
            for message in conversation["messages"]
        ),
        "source_urls_preserved": sum(
            "dingtalk_source_url" in part
            for conversation in conversations
            for message in conversation["messages"]
            for part in message["parts"]
        ),
        "image_attachments_resolved": resolver.image_files,
        "file_attachments_resolved": resolver.file_files,
        "attachment_bytes_copied": resolver.bytes_copied,
        "message_content_reported": False,
        "identifiers_reported": False,
    }
