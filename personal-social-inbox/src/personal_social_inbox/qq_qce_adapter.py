from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ADAPTER_SCHEMA = "personal-social-inbox/qq-qce-single-json/v1"
IMPORT_SCHEMA = "social-inbox-import/v1"
RESOURCE_TYPES = {"image", "audio", "video", "file"}


class QQAdapterError(RuntimeError):
    pass


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.chmod(0o700)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    _private_directory(path.parent)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        if os.name == "posix":
            os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _write_private_json(path: Path, payload: dict[str, Any]) -> str:
    encoded = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    _write_private_bytes(path, encoded)
    return hashlib.sha256(encoded).hexdigest()


def _required_string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise QQAdapterError(f"{where} must be a non-empty string")
    return value.strip()


def _optional_identifier(value: object, where: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise QQAdapterError(f"{where} must be a string or integer")
    text = str(value).strip()
    return text or None


def _parse_window(value: str | None, where: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QQAdapterError(f"{where} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise QQAdapterError(f"{where} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _message_timestamp(value: object, where: str) -> tuple[datetime, str]:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise QQAdapterError(f"{where} must be a millisecond timestamp")
    try:
        milliseconds = int(value)
    except ValueError as exc:
        raise QQAdapterError(f"{where} must be a millisecond timestamp") from exc
    try:
        parsed = datetime.fromtimestamp(milliseconds / 1000, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise QQAdapterError(f"{where} is outside the supported timestamp range") from exc
    return parsed, parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_source_path(root: Path, relative_path: str, where: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise QQAdapterError(f"{where} must be relative to the QCE export directory")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise QQAdapterError(f"{where} escapes the QCE export directory") from exc
    return resolved


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _safe_file_name(value: object, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        name = Path(value.strip()).name
    else:
        name = Path(fallback).name
    name = re.sub(r"[^\w.()\[\] -]+", "_", name, flags=re.UNICODE).strip(" .")
    return name or "attachment"


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _copy_private(source: Path, destination: Path, expected_sha256: str) -> None:
    _private_directory(destination.parent)
    temporary_name: str | None = None
    try:
        copied_digest = hashlib.sha256()
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as temporary:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                temporary.write(chunk)
                copied_digest.update(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        if copied_digest.hexdigest() != expected_sha256:
            raise QQAdapterError("a QCE attachment changed while it was being copied")
        if os.name == "posix":
            os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _sender_identity(sender: dict[str, Any], where: str) -> tuple[str | None, set[str]]:
    uid = _optional_identifier(sender.get("uid"), f"{where}.uid")
    uin = _optional_identifier(sender.get("uin"), f"{where}.uin")
    aliases = {value for value in (uid, uin) if value is not None}
    return uid or uin, aliases


def _resource_part(
    resource: dict[str, Any],
    *,
    source_root: Path,
    where: str,
    copies: dict[str, Path],
) -> tuple[dict[str, Any], bool]:
    resource_type = _required_string(resource.get("type"), f"{where}.type")
    if resource_type not in RESOURCE_TYPES:
        raise QQAdapterError(f"{where}.type is unsupported")
    local_path_value = resource.get("localPath")
    if local_path_value is not None and not isinstance(local_path_value, str):
        raise QQAdapterError(f"{where}.localPath must be a string")
    local_path = local_path_value.strip() if isinstance(local_path_value, str) else ""
    file_name = _safe_file_name(resource.get("filename"), local_path)
    mime_type = mimetypes.guess_type(file_name)[0]
    part: dict[str, Any] = {
        "type": resource_type,
        "file_name": file_name,
        "qq_resource": resource,
    }
    if mime_type:
        part["mime_type"] = mime_type

    if local_path:
        source = _safe_source_path(source_root, local_path, f"{where}.localPath")
        if source.is_file():
            sha256, size = _hash_file(source)
            suffix = Path(file_name).suffix.lower()
            relative_destination = Path("attachments") / sha256[:2] / f"{sha256}{suffix}"
            part["path"] = relative_destination.as_posix()
            part["source_size_bytes"] = size
            part["source_sha256"] = sha256
            copies.setdefault(relative_destination.as_posix(), source)
            return part, True

    missing_fingerprint = hashlib.sha256(
        json.dumps(resource, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:20]
    part["path"] = (
        Path("attachments") / "missing" / f"{missing_fingerprint}-{file_name}"
    ).as_posix()
    return part, False


def export_qce_groups(
    qce_json_files: list[Path],
    output_directory: Path,
    *,
    account_id: str,
    allowed_group_ids: set[str],
    display_name: str = "Personal QQ",
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """Convert explicitly selected QCE single-chat JSON files into one v1 manifest."""

    account_id = _required_string(account_id, "account_id")
    display_name = _required_string(display_name, "display_name")
    allowed = {
        _required_string(value, "allowed_group_ids item") for value in allowed_group_ids
    }
    if not allowed:
        raise QQAdapterError("at least one allowed QQ group ID is required")
    if not qce_json_files:
        raise QQAdapterError("at least one QCE JSON file is required")

    since_value = _parse_window(since, "since")
    until_value = _parse_window(until, "until")
    if since_value is not None and until_value is not None and since_value >= until_value:
        raise QQAdapterError("since must be earlier than until")

    output = output_directory.expanduser().resolve()
    manifest_path = output / "export.json"
    if manifest_path.exists():
        raise QQAdapterError("output export.json already exists; refusing to overwrite it")

    input_files = [path.expanduser().resolve() for path in qce_json_files]
    for index, input_file in enumerate(input_files):
        if not input_file.is_file():
            raise QQAdapterError(f"qce_json_files[{index}] is not a file")
        if _is_within(output, input_file.parent):
            raise QQAdapterError(
                "output_directory must be outside every selected QCE export directory"
            )

    conversations: dict[str, dict[str, Any]] = {}
    message_fingerprints: dict[str, str] = {}
    copies: dict[str, Path] = {}
    selected_files = 0
    skipped_files = 0
    present_attachment_parts = 0
    missing_attachment_parts = 0
    direction_counts = {"incoming": 0, "outgoing": 0, "system": 0, "unknown": 0}

    for file_index, input_file in enumerate(input_files):
        try:
            root = json.loads(input_file.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QQAdapterError(f"qce_json_files[{file_index}] is not valid UTF-8 JSON") from exc
        if not isinstance(root, dict):
            raise QQAdapterError(f"qce_json_files[{file_index}] root must be an object")
        chat_info = root.get("chatInfo")
        if not isinstance(chat_info, dict):
            raise QQAdapterError(f"qce_json_files[{file_index}].chatInfo must be an object")
        chat_type = _required_string(
            chat_info.get("type"), f"qce_json_files[{file_index}].chatInfo.type"
        )
        if chat_type != "group":
            raise QQAdapterError(
                f"qce_json_files[{file_index}] is a {chat_type!r} chat; only group exports are accepted"
            )
        peer_uid = _optional_identifier(
            chat_info.get("peerUid"), f"qce_json_files[{file_index}].chatInfo.peerUid"
        )
        peer_uin = _optional_identifier(
            chat_info.get("peerUin"), f"qce_json_files[{file_index}].chatInfo.peerUin"
        )
        peer_ids = {value for value in (peer_uid, peer_uin) if value is not None}
        if not peer_ids:
            raise QQAdapterError(f"qce_json_files[{file_index}] has no stable group ID")
        if peer_ids.isdisjoint(allowed):
            skipped_files += 1
            continue
        selected_files += 1

        canonical_group_id = peer_uid or peer_uin
        assert canonical_group_id is not None
        conversation_id = f"group:{canonical_group_id}"
        title = _required_string(
            chat_info.get("name"), f"qce_json_files[{file_index}].chatInfo.name"
        )
        self_uid = _optional_identifier(
            chat_info.get("selfUid"), f"qce_json_files[{file_index}].chatInfo.selfUid"
        )
        self_uin = _optional_identifier(
            chat_info.get("selfUin"), f"qce_json_files[{file_index}].chatInfo.selfUin"
        )
        self_name_value = chat_info.get("selfName")
        if self_name_value is not None and not isinstance(self_name_value, str):
            raise QQAdapterError(
                f"qce_json_files[{file_index}].chatInfo.selfName must be a string"
            )
        self_name = (
            self_name_value.strip()
            if isinstance(self_name_value, str) and self_name_value.strip()
            else display_name
        )
        self_ids = {value for value in (self_uid, self_uin) if value is not None}
        self_primary = self_uid or self_uin

        conversation = conversations.setdefault(
            conversation_id,
            {
                "source_conversation_id": conversation_id,
                "title": title,
                "type": "group",
                "participants_complete": False,
                "participant_scope": (
                    "windowed_senders_with_verified_self"
                    if self_ids
                    else "windowed_senders_self_unresolved"
                ),
                "metadata": {
                    "adapter_schema": ADAPTER_SCHEMA,
                    "source_format": "QCE single-file JSON",
                    "participant_count_reported": chat_info.get("participantCount"),
                },
                "group": {
                    "qq_peer_uid": peer_uid,
                    "qq_peer_uin": peer_uin,
                    "roster_status": "not_exported_by_qce_single_json",
                },
                "participants": [],
                "messages": [],
                "qq_chat_info": chat_info,
                "_participant_map": {},
                "_self_ids": self_ids,
                "_self_primary": self_primary,
            },
        )
        if conversation["title"] != title:
            raise QQAdapterError("selected QCE files disagree on a group title")
        if conversation["_self_ids"] != self_ids:
            raise QQAdapterError("selected QCE files disagree on the QQ self identity")

        participants: dict[str, dict[str, Any]] = conversation["_participant_map"]
        if self_primary is not None:
            participants.setdefault(
                self_primary,
                {
                    "source_identity_id": self_primary,
                    "display_name": self_name,
                    "is_self": True,
                    "qq_identifiers": sorted(self_ids),
                },
            )

        messages = root.get("messages")
        if not isinstance(messages, list):
            raise QQAdapterError(f"qce_json_files[{file_index}].messages must be an array")
        for message_index, source_message in enumerate(messages):
            where = f"qce_json_files[{file_index}].messages[{message_index}]"
            if not isinstance(source_message, dict):
                raise QQAdapterError(f"{where} must be an object")
            message_id = _required_string(source_message.get("id"), f"{where}.id")
            instant, normalized_timestamp = _message_timestamp(
                source_message.get("timestamp"), f"{where}.timestamp"
            )
            if since_value is not None and instant < since_value:
                continue
            if until_value is not None and instant >= until_value:
                continue
            sender = source_message.get("sender")
            if not isinstance(sender, dict):
                raise QQAdapterError(f"{where}.sender must be an object")
            sender_name = _required_string(sender.get("name"), f"{where}.sender.name")
            sender_id, sender_aliases = _sender_identity(sender, f"{where}.sender")
            is_system = bool(source_message.get("system", False))
            if is_system:
                direction = "system"
            elif self_ids and not sender_aliases.isdisjoint(self_ids):
                direction = "outgoing"
            elif self_ids and sender_id is not None:
                direction = "incoming"
            else:
                direction = "unknown"

            if sender_id is not None:
                participant = participants.setdefault(
                    sender_id,
                    {
                        "source_identity_id": sender_id,
                        "display_name": sender_name,
                        "is_self": direction == "outgoing",
                        "qq_sender": sender,
                    },
                )
                if participant["display_name"] != sender_name:
                    participant["display_name_variants"] = sorted(
                        {participant["display_name"], sender_name}
                    )

            content = source_message.get("content")
            if not isinstance(content, dict):
                raise QQAdapterError(f"{where}.content must be an object")
            parts: list[dict[str, Any]] = []
            text = content.get("text")
            if text is not None and not isinstance(text, str):
                raise QQAdapterError(f"{where}.content.text must be a string")
            if isinstance(text, str) and text:
                parts.append({"type": "system" if is_system else "text", "text": text})
            resources = content.get("resources", [])
            if not isinstance(resources, list):
                raise QQAdapterError(f"{where}.content.resources must be an array")
            for resource_index, resource in enumerate(resources):
                if not isinstance(resource, dict):
                    raise QQAdapterError(
                        f"{where}.content.resources[{resource_index}] must be an object"
                    )
                resource_type = resource.get("type")
                if resource_type not in RESOURCE_TYPES:
                    continue
                part, present = _resource_part(
                    resource,
                    source_root=input_file.parent,
                    where=f"{where}.content.resources[{resource_index}]",
                    copies=copies,
                )
                parts.append(part)
                if present:
                    present_attachment_parts += 1
                else:
                    missing_attachment_parts += 1
            if not parts:
                parts.append(
                    {
                        "type": "system",
                        "text": "[No textual or supported attachment content in QCE export]",
                        "derived_placeholder": True,
                    }
                )

            external_message_id = f"{conversation_id}:{message_id}"
            normalized_message: dict[str, Any] = {
                "source_message_id": external_message_id,
                "timestamp": normalized_timestamp,
                "sender_name": sender_name,
                "direction": direction,
                "parts": parts,
                "qq_message": source_message,
            }
            if sender_id is not None:
                normalized_message["sender_id"] = sender_id
            fingerprint = json.dumps(normalized_message, ensure_ascii=False, sort_keys=True)
            previous = message_fingerprints.get(external_message_id)
            if previous is not None:
                if previous != fingerprint:
                    raise QQAdapterError("duplicate QCE message ID has conflicting content")
                continue
            message_fingerprints[external_message_id] = fingerprint
            conversation["messages"].append(normalized_message)
            direction_counts[direction] += 1

    if selected_files == 0:
        raise QQAdapterError("none of the QCE group exports matched the explicit allowlist")

    exported_conversations: list[dict[str, Any]] = []
    total_messages = 0
    for conversation in conversations.values():
        conversation["messages"].sort(key=lambda item: (item["timestamp"], item["source_message_id"]))
        conversation["participants"] = sorted(
            conversation.pop("_participant_map").values(),
            key=lambda item: item["source_identity_id"],
        )
        conversation.pop("_self_ids")
        conversation.pop("_self_primary")
        if conversation["messages"]:
            conversation["last_activity"] = conversation["messages"][-1]["timestamp"]
        total_messages += len(conversation["messages"])
        exported_conversations.append(conversation)
    exported_conversations.sort(key=lambda item: item["source_conversation_id"])

    manifest = {
        "schema_version": IMPORT_SCHEMA,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "source": {
            "kind": "qq",
            "account_id": account_id,
            "display_name": display_name,
            "adapter_schema": ADAPTER_SCHEMA,
        },
        "conversations": exported_conversations,
    }

    _private_directory(output)
    for relative_destination, source in sorted(copies.items()):
        expected_sha256 = Path(relative_destination).stem
        _copy_private(source, output / relative_destination, expected_sha256)
    manifest_sha256 = _write_private_json(manifest_path, manifest)
    return {
        "status": "complete",
        "capability_state": "SUPPORTED_EXPORT",
        "adapter_schema": ADAPTER_SCHEMA,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "selected_json_files": selected_files,
        "skipped_json_files": skipped_files,
        "conversations": len(exported_conversations),
        "messages": total_messages,
        "present_attachment_parts": present_attachment_parts,
        "missing_attachment_parts": missing_attachment_parts,
        "unique_files_copied": len(copies),
        "direction_counts": direction_counts,
        "window": {"since": since, "until": until},
        "message_content_reported": False,
        "identifiers_reported": False,
    }
