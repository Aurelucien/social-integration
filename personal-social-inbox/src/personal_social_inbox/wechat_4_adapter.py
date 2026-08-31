from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ADAPTER_SCHEMA = "personal-social-inbox/wechat-macos-4/v1"
IMPORT_SCHEMA = "social-inbox-import/v1"
MSG_TABLE = re.compile(r"^Msg_[0-9a-f]{32}$")
GROUP_SUFFIX = "@chatroom"
REQUIRED_DATABASES = (
    "session/session.db",
    "contact/contact.db",
    "message/message_0.db",
    "message/message_1.db",
)


class WechatAdapterError(RuntimeError):
    pass


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }


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


def _read_content(value: object, compression_type: int) -> str:
    if isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    elif value is None:
        data = b""
    else:
        data = str(value).encode("utf-8")

    if compression_type == 4 and data:
        try:
            from compression import zstd
        except ImportError as exc:  # pragma: no cover - depends on Python runtime
            raise WechatAdapterError(
                "compressed WeChat rows require Python 3.14+ compression.zstd"
            ) from exc
        try:
            data = zstd.decompress(data)
        except Exception as exc:
            raise WechatAdapterError("could not decompress a WeChat message row") from exc
    return data.decode("utf-8", errors="replace").rstrip("\x00")


def _strip_group_prefix(content: str, is_group: bool) -> tuple[str, str | None]:
    if is_group and ":\n" in content:
        candidate, remainder = content.split(":\n", 1)
        if candidate and not any(character.isspace() for character in candidate):
            return remainder, candidate
    return content, None


def _timestamp(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def _display_name(contact: sqlite3.Row | None, fallback: str) -> str:
    if contact is None:
        return fallback
    for key in ("remark", "nick_name", "alias", "username"):
        value = contact[key]
        if isinstance(value, str) and value.strip():
            return value
    return fallback


def _row_value(row: sqlite3.Row | None, key: str, default: Any = None) -> Any:
    if row is None or key not in row.keys():
        return default
    value = row[key]
    return default if value is None else value


def _decode_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    position = offset
    while position < len(data) and shift <= 63:
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, position
        shift += 7
    return None


def _protobuf_fields(data: bytes) -> list[tuple[int, int, int | bytes]]:
    fields: list[tuple[int, int, int | bytes]] = []
    position = 0
    while position < len(data):
        decoded = _decode_varint(data, position)
        if decoded is None:
            break
        tag, position = decoded
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            break
        if wire_type == 0:
            decoded = _decode_varint(data, position)
            if decoded is None:
                break
            value, position = decoded
            fields.append((field_number, wire_type, value))
        elif wire_type == 1:
            end = position + 8
            if end > len(data):
                break
            fields.append(
                (field_number, wire_type, int.from_bytes(data[position:end], "little"))
            )
            position = end
        elif wire_type == 2:
            decoded = _decode_varint(data, position)
            if decoded is None:
                break
            size, position = decoded
            end = position + size
            if end > len(data):
                break
            fields.append((field_number, wire_type, data[position:end]))
            position = end
        elif wire_type == 5:
            end = position + 4
            if end > len(data):
                break
            fields.append(
                (field_number, wire_type, int.from_bytes(data[position:end], "little"))
            )
            position = end
        else:
            break
    return fields


def _protobuf_text(value: int | bytes) -> str | None:
    if not isinstance(value, bytes) or not value or len(value) > 512:
        return None
    try:
        text = value.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if not text or any(ord(character) < 32 or ord(character) == 127 for character in text):
        return None
    return text


def _group_member_metadata(
    ext_buffer: bytes | None, member_usernames: set[str]
) -> dict[str, dict[str, Any]]:
    """Decode only the verified member fields in chat_room.ext_buffer.

    WeChat 4.x stores repeated member messages in top-level field 1. Within a
    member message, field 1 is the stable username, field 2 is the optional
    group-specific display name, and field 3 is an opaque member state. The
    state is retained as provenance but is not interpreted as an admin role.
    """

    result: dict[str, dict[str, Any]] = {}
    if not ext_buffer or not member_usernames:
        return result
    for field_number, wire_type, value in _protobuf_fields(ext_buffer):
        if field_number != 1 or wire_type != 2 or not isinstance(value, bytes):
            continue
        strings: dict[int, str] = {}
        integers: dict[int, int] = {}
        for nested_number, nested_wire_type, nested_value in _protobuf_fields(value):
            if nested_wire_type == 2:
                text = _protobuf_text(nested_value)
                if text is not None:
                    strings.setdefault(nested_number, text)
            elif nested_wire_type == 0 and isinstance(nested_value, int):
                integers.setdefault(nested_number, nested_value)
        username = next(
            (
                strings.get(candidate_field)
                for candidate_field in (1, 4)
                if strings.get(candidate_field) in member_usernames
            ),
            None,
        )
        if username is None or username in result:
            continue
        metadata: dict[str, Any] = {}
        group_nickname = strings.get(2)
        if group_nickname and group_nickname != username:
            metadata["group_nickname"] = group_nickname
        if 3 in integers:
            metadata["source_member_state"] = integers[3]
        result[username] = metadata
    return result


def _resolve_self_identity(
    account_id: str,
    contacts: dict[str, sqlite3.Row],
    wechat_profile_root: Path | None,
) -> tuple[str | None, str]:
    if account_id in contacts:
        return account_id, "verified_explicit_account_id"
    if wechat_profile_root is None:
        return None, "unresolved"
    profile_name = wechat_profile_root.expanduser().resolve().name
    matches = [
        username
        for username in contacts
        if profile_name == username or profile_name.startswith(f"{username}_")
    ]
    if not matches:
        return None, "unresolved"
    longest = max(len(username) for username in matches)
    longest_matches = [username for username in matches if len(username) == longest]
    if len(longest_matches) != 1:
        return None, "unresolved"
    return longest_matches[0], "verified_profile_directory"


def _contact_metadata(contact: sqlite3.Row | None) -> dict[str, Any]:
    if contact is None:
        return {"contact_status": "unresolved"}
    fields = {
        "alias": "alias",
        "remark": "remark",
        "nickname": "nick_name",
        "avatar_small_url": "small_head_url",
        "avatar_large_url": "big_head_url",
        "description": "description",
        "verify_flag": "verify_flag",
        "contact_type": "local_type",
    }
    result: dict[str, Any] = {"contact_status": "resolved"}
    for target, source in fields.items():
        value = _row_value(contact, source)
        if value not in (None, ""):
            result[target] = value
    return result


def _session_metadata(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {"session_status": "not_present"}
    result: dict[str, Any] = {"session_status": "present"}
    integers = {
        "type": "session_type",
        "unread_count": "unread_count",
        "status": "source_status",
        "last_msg_type": "last_message_type",
        "last_msg_sub_type": "last_message_subtype",
        "last_msg_ext_type": "last_message_extension_type",
    }
    for source, target in integers.items():
        if source in row.keys():
            value = int(_row_value(row, source, 0))
            result[target] = value & 0xFFFF_FFFF if source == "last_msg_type" else value
    if "is_hidden" in row.keys():
        result["is_hidden"] = bool(_row_value(row, "is_hidden", 0))
    timestamps = {
        "last_timestamp": "last_message_at",
        "sort_timestamp": "sort_at",
        "last_clear_unread_timestamp": "last_clear_unread_at",
    }
    for source, target in timestamps.items():
        value = int(_row_value(row, source, 0))
        if value > 0:
            result[target] = _timestamp(value)
    texts = {
        "summary": "last_message_preview",
        "last_msg_sender": "last_message_sender_id",
        "last_sender_display_name": "last_sender_display_name",
    }
    for source, target in texts.items():
        value = _row_value(row, source)
        if isinstance(value, str) and value:
            result[target] = value
    return result


def _session_titles(path: Path) -> dict[str, str]:
    with closing(_connect(path)) as connection:
        if "SessionNoContactInfoTable" not in _tables(connection):
            return {}
        return {
            str(row["username"]): str(row["session_title"])
            for row in connection.execute(
                "SELECT username, session_title FROM SessionNoContactInfoTable "
                "WHERE username IS NOT NULL AND session_title IS NOT NULL "
                "AND session_title != ''"
            )
        }


def _conversation_title(
    chat: str, contacts: dict[str, sqlite3.Row], session_titles: dict[str, str]
) -> str:
    contact_title = _display_name(contacts.get(chat), chat)
    return session_titles.get(chat, contact_title) if contact_title == chat else contact_title


def _contact_map(path: Path) -> dict[str, sqlite3.Row]:
    with closing(_connect(path)) as connection:
        if "contact" not in _tables(connection):
            raise WechatAdapterError("contact/contact.db has no contact table")
        return {
            str(row["username"]): row
            for row in connection.execute(
                "SELECT * FROM contact "
                "WHERE username IS NOT NULL AND username != ''"
            )
        }


def _group_metadata(
    path: Path,
    contacts: dict[str, sqlite3.Row],
    self_identity: str | None,
) -> dict[str, dict[str, Any]]:
    with closing(_connect(path)) as connection:
        tables = _tables(connection)
        required = {"chat_room", "chatroom_member"}
        if not required.issubset(tables):
            return {}
        id_to_username: dict[int, str] = {}
        for contact in contacts.values():
            contact_id = _row_value(contact, "id")
            if isinstance(contact_id, int):
                id_to_username[contact_id] = str(contact["username"])
        if "name2id" in tables:
            for row in connection.execute(
                "SELECT rowid, username FROM name2id WHERE username IS NOT NULL"
            ):
                id_to_username.setdefault(int(row[0]), str(row[1]))

        details: dict[int, sqlite3.Row] = {}
        if "chat_room_info_detail" in tables:
            details = {
                int(row["room_id_"]): row
                for row in connection.execute("SELECT * FROM chat_room_info_detail")
            }
        groups: dict[str, dict[str, Any]] = {}
        room_ids: dict[int, str] = {}
        for room in connection.execute("SELECT * FROM chat_room"):
            chat = str(room["username"])
            room_id = int(room["id"])
            room_ids[room_id] = chat
            detail = details.get(room_id)
            group: dict[str, Any] = {
                "owner_id": str(_row_value(room, "owner", "")),
                "participants": [],
                "unresolved_member_ids": 0,
                "ext_buffer": _row_value(room, "ext_buffer", b""),
                "administrator_status": "unresolved_member_state_semantics",
            }
            source_status = _row_value(detail, "chat_room_status_")
            if source_status is not None:
                group["source_status"] = int(source_status)
            announcement = _row_value(detail, "announcement_")
            if isinstance(announcement, str) and announcement:
                group["announcement"] = announcement
                editor = _row_value(detail, "announcement_editor_")
                if isinstance(editor, str) and editor:
                    group["announcement_editor_id"] = editor
                published = int(_row_value(detail, "announcement_publish_time_", 0))
                if published > 0:
                    group["announcement_published_at"] = _timestamp(published)
            groups[chat] = group

        for member in connection.execute(
            "SELECT room_id, member_id FROM chatroom_member ORDER BY room_id, member_id"
        ):
            chat = room_ids.get(int(member["room_id"]))
            if chat is None:
                continue
            identity = id_to_username.get(int(member["member_id"]))
            if identity is None:
                groups[chat]["unresolved_member_ids"] += 1
                continue
            contact = contacts.get(identity)
            owner_id = groups[chat]["owner_id"]
            groups[chat]["participants"].append(
                {
                    "source_identity_id": identity,
                    "display_name": _display_name(contact, identity),
                    "is_self": False,
                    "role": "owner" if identity == owner_id else "member",
                    "membership": {
                        "current": True,
                        "group_nickname_status": "not_decoded",
                    },
                    "metadata": _contact_metadata(contact),
                    "wechat_identity_status": "self_unresolved",
                }
            )
        for group in groups.values():
            participant_ids = {
                str(participant["source_identity_id"])
                for participant in group["participants"]
            }
            member_metadata = _group_member_metadata(
                group.get("ext_buffer"), participant_ids
            )
            group_nickname_count = 0
            for participant in group["participants"]:
                identity = str(participant["source_identity_id"])
                is_self = self_identity is not None and identity == self_identity
                participant["is_self"] = is_self
                participant["wechat_identity_status"] = (
                    "verified_self" if is_self else "verified_not_self"
                    if self_identity is not None
                    else "self_unresolved"
                )
                decoded = member_metadata.get(identity, {})
                membership = participant["membership"]
                if "source_member_state" in decoded:
                    membership["source_member_state"] = decoded["source_member_state"]
                group_nickname = decoded.get("group_nickname")
                if isinstance(group_nickname, str) and group_nickname:
                    membership["group_nickname"] = group_nickname
                    membership["group_nickname_status"] = (
                        "verified_chat_room_ext_buffer"
                    )
                    participant["display_name"] = group_nickname
                    group_nickname_count += 1
                else:
                    membership["group_nickname_status"] = "not_present"
                membership["administrator_status"] = (
                    "not_applicable_owner"
                    if participant["role"] == "owner"
                    else "unresolved_member_state_semantics"
                )
            group["member_count"] = len(group["participants"])
            group["group_nickname_count"] = group_nickname_count
            group["membership_status"] = (
                "complete" if group["unresolved_member_ids"] == 0 else "partial"
            )
        return groups


def _group_export_metadata(group: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in group.items()
        if key not in {"participants", "unresolved_member_ids", "ext_buffer"}
    }


def _observed_participant(
    identity: str,
    name: str,
    contacts: dict[str, sqlite3.Row],
    *,
    current_member: bool | None,
    self_identity: str | None,
) -> dict[str, Any]:
    is_self = self_identity is not None and identity == self_identity
    participant: dict[str, Any] = {
        "source_identity_id": identity,
        "display_name": name,
        "is_self": is_self,
        "wechat_identity_status": (
            "verified_self" if is_self else "verified_not_self"
            if self_identity is not None
            else "self_unresolved"
        ),
        "metadata": _contact_metadata(contacts.get(identity)),
    }
    if current_member is not None:
        participant["role"] = "observed_sender" if not current_member else "member"
        participant["membership"] = {
            "current": current_member,
            "group_nickname_status": (
                "not_available_not_current" if not current_member else "not_decoded"
            ),
            "administrator_status": (
                "not_applicable_not_current"
                if not current_member
                else "unresolved_member_state_semantics"
            ),
        }
    return participant


def _id_to_username(connection: sqlite3.Connection) -> dict[int, str]:
    if "Name2Id" not in _tables(connection):
        return {}
    return {
        int(row[0]): str(row[1])
        for row in connection.execute(
            "SELECT rowid, user_name FROM Name2Id WHERE user_name IS NOT NULL"
        )
    }


def _xml_root(content: str) -> ET.Element | None:
    positions = [position for marker in ("<msg", "<appmsg", "<location") if (position := content.find(marker)) >= 0]
    if not positions:
        return None
    try:
        return ET.fromstring(content[min(positions) :])
    except ET.ParseError:
        return None


def _xml_text(root: ET.Element, path: str) -> str:
    element = root.find(path)
    return (element.text or "").strip() if element is not None else ""


def _parts_for_message(
    base_type: int,
    content: str,
    local_id: int,
    voice_path: str | None,
    image_part: dict[str, Any] | None = None,
    video_part: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if base_type == 1:
        return [{"type": "text", "text": content}]
    if base_type == 3:
        if image_part is not None:
            return [image_part]
        return [
            {
                "type": "image",
                "file_name": f"wechat-image-{local_id}.dat",
                "mime_type": "application/octet-stream",
                "wechat_attachment_status": "resource_not_exported",
            }
        ]
    if base_type == 34:
        part: dict[str, Any] = {
            "type": "audio",
            "file_name": f"wechat-voice-{local_id}.silk",
            "mime_type": "audio/silk",
        }
        if voice_path:
            part["path"] = voice_path
            part["file_name"] = Path(voice_path).name
        else:
            part["wechat_attachment_status"] = "voice_row_not_resolved"
        return [part]
    if base_type == 43:
        if video_part is not None:
            return [video_part]
        return [
            {
                "type": "video",
                "file_name": f"wechat-video-{local_id}.dat",
                "mime_type": "application/octet-stream",
                "wechat_attachment_status": "resource_not_exported",
            }
        ]
    if base_type == 47:
        return [
            {
                "type": "image",
                "file_name": f"wechat-sticker-{local_id}.dat",
                "mime_type": "application/octet-stream",
                "wechat_subtype": "sticker",
                "wechat_attachment_status": "resource_not_exported",
            }
        ]
    if base_type == 48:
        root = _xml_root(content)
        if root is not None:
            location = root if root.tag == "location" else root.find(".//location")
            if location is not None:
                label = location.attrib.get("poiname") or location.attrib.get("label")
                if label:
                    return [{"type": "text", "text": label, "wechat_subtype": "location"}]
        return [{"type": "system", "text": "[WeChat location]"}]
    if base_type == 49:
        root = _xml_root(content)
        appmsg = None
        if root is not None:
            appmsg = root if root.tag == "appmsg" else root.find(".//appmsg")
        if appmsg is not None:
            subtype = _xml_text(appmsg, "type")
            title = _xml_text(appmsg, "title") or "WeChat app message"
            url = _xml_text(appmsg, "url")
            if subtype == "6":
                return [
                    {
                        "type": "file",
                        "file_name": title,
                        "mime_type": "application/octet-stream",
                        "wechat_subtype": "appmsg_file",
                        "wechat_attachment_status": "resource_not_exported",
                    }
                ]
            if url:
                return [{"type": "link", "text": title, "url": url, "wechat_appmsg_type": subtype}]
            return [{"type": "text", "text": title, "wechat_appmsg_type": subtype}]
        return [{"type": "system", "text": "[WeChat app message]"}]
    if base_type in {50, 10000}:
        return [{"type": "system", "text": content or f"[WeChat message type {base_type}]"}]
    return [{"type": "system", "text": f"[WeChat message type {base_type}]"}]


class _VoiceResolver:
    def __init__(self, paths: list[Path], export_root: Path):
        self._connections: list[tuple[sqlite3.Connection, dict[str, int]]] = []
        self._export_root = export_root
        self.rows_considered = 0
        self.rows_resolved = 0
        for path in paths:
            if not path.is_file():
                continue
            connection = _connect(path)
            tables = _tables(connection)
            if not {"Name2Id", "VoiceInfo"}.issubset(tables):
                connection.close()
                continue
            mapping = {
                str(row[1]): int(row[0])
                for row in connection.execute(
                    "SELECT rowid, user_name FROM Name2Id WHERE user_name IS NOT NULL"
                )
            }
            self._connections.append((connection, mapping))

    def close(self) -> None:
        for connection, _mapping in self._connections:
            connection.close()
        self._connections.clear()

    def resolve(self, chat: str, local_id: int, create_time: int) -> str | None:
        self.rows_considered += 1
        for connection, mapping in self._connections:
            chat_id = mapping.get(chat)
            if chat_id is None:
                continue
            row = connection.execute(
                "SELECT voice_data FROM VoiceInfo "
                "WHERE chat_name_id = ? AND local_id = ? AND create_time = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (chat_id, local_id, create_time),
            ).fetchone()
            if row is None:
                row = connection.execute(
                    "SELECT voice_data FROM VoiceInfo "
                    "WHERE chat_name_id = ? AND local_id = ? "
                    "ORDER BY create_time DESC, rowid DESC LIMIT 1",
                    (chat_id, local_id),
                ).fetchone()
            if row is None or not isinstance(row[0], bytes) or not row[0]:
                continue
            digest = hashlib.sha256(row[0]).hexdigest()
            relative = Path("attachments") / "voice" / f"{digest}.silk"
            destination = self._export_root / relative
            if not destination.exists():
                _write_private_bytes(destination, row[0])
            self.rows_resolved += 1
            return relative.as_posix()
        return None


def _message_databases(root: Path) -> list[tuple[str, Path]]:
    paths: list[tuple[str, Path]] = []
    message_root = root / "message"
    for path in sorted(message_root.glob("message_[0-9]*.db")):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        paths.append((relative, path))
    return paths


def _message_tables(path: Path) -> set[str]:
    with closing(_connect(path)) as connection:
        return {table for table in _tables(connection) if MSG_TABLE.fullmatch(table)}


def export_wechat_snapshot(
    snapshot_root: Path,
    output_directory: Path,
    account_id: str,
    display_name: str = "Personal WeChat",
    max_conversations: int = 20,
    max_messages_per_conversation: int = 200,
    wechat_profile_root: Path | None = None,
    include_all_groups: bool = False,
) -> dict[str, Any]:
    root = snapshot_root.expanduser().resolve()
    output = output_directory.expanduser().resolve()
    if not account_id.strip():
        raise WechatAdapterError("account_id must be non-empty")
    if max_conversations <= 0 or max_messages_per_conversation <= 0:
        raise WechatAdapterError("export limits must be positive")
    for relative in REQUIRED_DATABASES:
        if not (root / relative).is_file():
            raise WechatAdapterError(f"required decrypted database missing: {relative}")
    manifest_path = output / "export.json"
    if manifest_path.exists():
        raise WechatAdapterError("output export.json already exists; choose a new directory")
    _private_directory(output)

    profile_root = (
        wechat_profile_root.expanduser().resolve()
        if wechat_profile_root is not None
        else None
    )
    contacts = _contact_map(root / "contact/contact.db")
    session_titles = _session_titles(root / "session/session.db")
    self_identity, self_identity_status = _resolve_self_identity(
        account_id, contacts, profile_root
    )
    groups = _group_metadata(
        root / "contact/contact.db", contacts, self_identity
    )
    message_databases = _message_databases(root)
    if not message_databases:
        raise WechatAdapterError("no decrypted message shard found")
    table_locations: dict[str, list[tuple[str, Path]]] = {}
    for relative, path in message_databases:
        for table in _message_tables(path):
            table_locations.setdefault(table, []).append((relative, path))

    voice_resolver = _VoiceResolver(
        [root / "message/media_0.db", root / "message/media_1.db"], output
    )
    image_resolver = None
    video_resolver = None
    file_resolver = None
    exported_messages = 0
    skipped_sessions = 0
    compression_counts: dict[str, int] = {}
    base_type_counts: dict[str, int] = {}
    conversations: list[dict[str, Any]] = []
    exported_chats: set[str] = set()
    current_members_exported = 0
    metadata_only_groups = 0
    direction_counts = {"incoming": 0, "outgoing": 0, "unknown": 0}
    try:
        if profile_root is not None:
            resource_database = root / "message/message_resource.db"
            if not resource_database.is_file():
                raise WechatAdapterError(
                    "message/message_resource.db is required for image attachments"
                )
            from .wechat_4_attachments import (
                ImageAttachmentResolver,
                LocalFileResolver,
                VideoAttachmentResolver,
            )

            image_resolver = ImageAttachmentResolver(
                resource_database, profile_root, output
            )
            video_resolver = VideoAttachmentResolver(
                resource_database, profile_root, output
            )
            file_resolver = LocalFileResolver(profile_root, output)

        with closing(_connect(root / "session/session.db")) as session:
            all_session_rows = session.execute("SELECT * FROM SessionTable").fetchall()
        session_by_chat = {
            str(row["username"]): row for row in all_session_rows
        }
        sessions = sorted(
            (
                row
                for row in all_session_rows
                if int(_row_value(row, "last_timestamp", 0)) > 0
            ),
            key=lambda row: int(_row_value(row, "last_timestamp", 0)),
            reverse=True,
        )[:max_conversations]

        for session_row in sessions:
            chat = str(session_row["username"])
            table = "Msg_" + hashlib.md5(chat.encode("utf-8"), usedforsecurity=False).hexdigest()
            locations = table_locations.get(table, [])
            if not locations:
                skipped_sessions += 1
                continue
            is_group = chat.endswith(GROUP_SUFFIX)
            group = groups.get(chat) if is_group else None
            group_display_names = (
                {
                    str(participant["source_identity_id"]): str(
                        participant["display_name"]
                    )
                    for participant in group["participants"]
                }
                if group is not None
                else {}
            )
            collected: list[tuple[str, sqlite3.Row, dict[int, str]]] = []
            for relative, database_path in locations:
                with closing(_connect(database_path)) as connection:
                    id2u = _id_to_username(connection)
                    rows = connection.execute(
                        f"SELECT local_id, server_id, local_type, sort_seq, "
                        f"real_sender_id, create_time, message_content, "
                        f"COALESCE(WCDB_CT_message_content, 0) AS content_type "
                        f"FROM {_quote(table)} ORDER BY create_time DESC, local_id DESC LIMIT ?",
                        (max_messages_per_conversation,),
                    ).fetchall()
                    collected.extend((relative, row, id2u) for row in rows)
            collected.sort(
                key=lambda item: (int(item[1]["create_time"]), int(item[1]["local_id"])),
                reverse=True,
            )
            collected = collected[:max_messages_per_conversation]
            collected.reverse()

            participant_names: dict[str, str] = {
                chat: _conversation_title(chat, contacts, session_titles)
            } if not is_group else {}
            if self_identity is not None and not is_group:
                participant_names.setdefault(
                    self_identity,
                    _display_name(contacts.get(self_identity), self_identity),
                )
            messages: list[dict[str, Any]] = []
            for relative, row, id2u in collected:
                local_id = int(row["local_id"])
                local_type = int(row["local_type"])
                base_type = local_type & 0xFFFF_FFFF
                create_time = int(row["create_time"])
                compression_type = int(row["content_type"])
                content = _read_content(row["message_content"], compression_type)
                content, prefixed_sender = _strip_group_prefix(content, is_group)
                mapped_sender = id2u.get(int(row["real_sender_id"]))
                sender_id = mapped_sender or prefixed_sender or f"unknown:{chat}"
                sender_name = group_display_names.get(
                    sender_id, _display_name(contacts.get(sender_id), sender_id)
                )
                participant_names[sender_id] = sender_name
                if self_identity is None or sender_id.startswith("unknown:"):
                    direction = "unknown"
                    direction_status = "unresolved_sender_or_self"
                elif sender_id == self_identity:
                    direction = "outgoing"
                    direction_status = "verified_self_sender"
                else:
                    direction = "incoming"
                    direction_status = "verified_nonself_sender"
                direction_counts[direction] += 1

                voice_path = None
                if base_type == 34:
                    voice_path = voice_resolver.resolve(chat, local_id, create_time)
                image_part = None
                if base_type == 3 and image_resolver is not None:
                    image_part = image_resolver.resolve(
                        chat, local_id, create_time, base_type
                    )
                video_part = None
                if base_type == 43 and video_resolver is not None:
                    video_part = video_resolver.resolve(
                        chat, local_id, create_time, base_type
                    )
                parts = _parts_for_message(
                    base_type, content, local_id, voice_path, image_part, video_part
                )
                if (
                    base_type == 49
                    and file_resolver is not None
                    and len(parts) == 1
                    and parts[0].get("type") == "file"
                ):
                    resolved_file = file_resolver.resolve(
                        str(parts[0].get("file_name", "")), create_time
                    )
                    if resolved_file is not None:
                        parts = [resolved_file]
                server_id = int(row["server_id"] or 0)
                message_id = f"{relative}:{table}:{local_id}:{server_id}:{create_time}"
                messages.append(
                    {
                        "source_message_id": message_id,
                        "timestamp": _timestamp(create_time),
                        "sender_id": sender_id,
                        "sender_name": sender_name,
                        "direction": direction,
                        "parts": parts,
                        "wechat": {
                            "adapter_schema": ADAPTER_SCHEMA,
                            "database": relative,
                            "local_id": local_id,
                            "server_id": server_id,
                            "local_type": local_type,
                            "base_type": base_type,
                            "sort_seq": int(row["sort_seq"] or 0),
                            "real_sender_id": int(row["real_sender_id"] or 0),
                            "content_storage": compression_type,
                            "direction_status": direction_status,
                        },
                    }
                )
                exported_messages += 1
                compression_key = str(compression_type)
                compression_counts[compression_key] = compression_counts.get(compression_key, 0) + 1
                type_key = str(base_type)
                base_type_counts[type_key] = base_type_counts.get(type_key, 0) + 1

            if group is not None:
                participants = [dict(participant) for participant in group["participants"]]
                known_identities = {
                    str(participant["source_identity_id"]) for participant in participants
                }
                for identity, name in sorted(participant_names.items()):
                    if identity not in known_identities:
                        participants.append(
                            _observed_participant(
                                identity,
                                name,
                                contacts,
                                current_member=False,
                                self_identity=self_identity,
                            )
                        )
                current_members_exported += len(group["participants"])
            else:
                participants = [
                    _observed_participant(
                        identity,
                        name,
                        contacts,
                        current_member=False if is_group else None,
                        self_identity=self_identity,
                    )
                    for identity, name in sorted(participant_names.items())
                ]

            session_metadata = _session_metadata(session_row)
            last_timestamp = int(_row_value(session_row, "last_timestamp", 0))
            conversation: dict[str, Any] = {
                "source_conversation_id": chat,
                "title": _conversation_title(chat, contacts, session_titles),
                "type": "group" if is_group else "single",
                "participants": participants,
                "participants_complete": bool(
                    group is not None and group["membership_status"] == "complete"
                ),
                "participant_scope": (
                    "current_roster_plus_windowed_senders"
                    if is_group
                    else "windowed_senders_with_verified_self"
                    if self_identity is not None
                    else "windowed_senders_self_unresolved"
                ),
                "metadata": session_metadata,
                "messages": messages,
                "wechat": {
                    "adapter_schema": ADAPTER_SCHEMA,
                    "message_table_mapping": "md5_username",
                    "metadata_status": "verified_session_fields",
                },
            }
            if last_timestamp > 0:
                conversation["last_activity"] = _timestamp(last_timestamp)
            if group is not None:
                conversation["group"] = _group_export_metadata(group)
            conversations.append(conversation)
            exported_chats.add(chat)

        if include_all_groups:
            for chat, group in sorted(groups.items()):
                if chat in exported_chats:
                    continue
                session_row = session_by_chat.get(chat)
                last_timestamp = int(_row_value(session_row, "last_timestamp", 0))
                conversation = {
                    "source_conversation_id": chat,
                    "title": _conversation_title(chat, contacts, session_titles),
                    "type": "group",
                    "participants": [
                        dict(participant) for participant in group["participants"]
                    ],
                    "participants_complete": group["membership_status"] == "complete",
                    "participant_scope": "current_roster",
                    "metadata": _session_metadata(session_row),
                    "group": _group_export_metadata(group),
                    "messages": [],
                    "wechat": {
                        "adapter_schema": ADAPTER_SCHEMA,
                        "message_table_mapping": "md5_username",
                        "metadata_status": "verified_group_metadata_only",
                    },
                }
                if last_timestamp > 0:
                    conversation["last_activity"] = _timestamp(last_timestamp)
                conversations.append(conversation)
                exported_chats.add(chat)
                current_members_exported += len(group["participants"])
                metadata_only_groups += 1
    finally:
        voice_resolver.close()
        if image_resolver is not None:
            image_resolver.close()
        if video_resolver is not None:
            video_resolver.close()

    manifest = {
        "schema_version": IMPORT_SCHEMA,
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "kind": "wechat",
            "account_id": account_id,
            "display_name": display_name,
            "adapter_schema": ADAPTER_SCHEMA,
            "direction_status": (
                "verified_sender_identity_with_unknown_system_rows"
                if self_identity is not None
                else "unresolved"
            ),
            "self_identity_status": self_identity_status,
        },
        "conversations": conversations,
    }
    manifest_sha256 = _write_private_json(manifest_path, manifest)
    result = {
        "status": "complete",
        "adapter_schema": ADAPTER_SCHEMA,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "conversations": len(conversations),
        "messages": exported_messages,
        "skipped_sessions_without_message_table": skipped_sessions,
        "group_metadata_records_available": len(groups),
        "groups_exported": sum(
            1 for conversation in conversations if conversation["type"] == "group"
        ),
        "metadata_only_groups_exported": metadata_only_groups,
        "current_group_memberships_exported": current_members_exported,
        "voice_rows_considered": voice_resolver.rows_considered,
        "voice_attachments_resolved": voice_resolver.rows_resolved,
        "base_type_counts": dict(sorted(base_type_counts.items(), key=lambda item: int(item[0]))),
        "compression_counts": dict(sorted(compression_counts.items())),
        "direction": (
            "verified_mapped_senders_partial"
            if self_identity is not None
            else "unknown"
        ),
        "direction_counts": direction_counts,
        "self_identity_status": self_identity_status,
        "message_content_reported": False,
        "identifiers_reported": False,
    }
    if image_resolver is not None:
        result.update(image_resolver.stats)
        result["image_key_status"] = image_resolver.key_status
    if video_resolver is not None:
        result.update(video_resolver.stats)
    if file_resolver is not None:
        result.update(file_resolver.stats)
    return result
