from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from .dingtalk_835_adapter import export_dingtalk_snapshot
from .importer import import_manifest


CAPTURE_SCHEMA = "dingtalk-8.3.5-personal-snapshot/v1"
INGEST_SCHEMA = "personal-social-inbox/dingtalk-generation-ingest/v2"
RECEIPT_NAME = "ingest-receipt.json"


class DingTalkGenerationError(ValueError):
    pass


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DingTalkGenerationError(f"{label} is unavailable") from exc
    except json.JSONDecodeError as exc:
        raise DingTalkGenerationError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise DingTalkGenerationError(f"{label} must be an object")
    return value


def _private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.parent.chmod(0o700)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False) as temporary:
            json.dump(payload, temporary, ensure_ascii=False, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        if os.name == "posix":
            os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _safe_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise DingTalkGenerationError("capture receipt contains an unsafe database path")
    candidate = (root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise DingTalkGenerationError("capture database escapes the generation") from exc
    return candidate


def _quick_check(database: Path) -> str:
    connection = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        row = connection.execute("PRAGMA quick_check").fetchone()
    finally:
        connection.close()
    return str(row[0]) if row else "missing_result"


def _salt_md5(config_path: Path) -> str:
    try:
        value = json.loads(base64.b64decode(config_path.read_bytes(), validate=True))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        raise DingTalkGenerationError("captured user_config is invalid") from exc
    salt = value.get("salt") if isinstance(value, dict) else None
    salt_md5 = value.get("salt_md5") if isinstance(value, dict) else None
    if not isinstance(salt, str) or not isinstance(salt_md5, str):
        raise DingTalkGenerationError("captured user_config has no salt metadata")
    if hashlib.md5(salt.encode("ascii"), usedforsecurity=False).hexdigest() != salt_md5:
        raise DingTalkGenerationError("captured user_config salt metadata changed")
    return salt_md5


def verify_generation(generation_root: Path, *, self_uid: str | None = None) -> dict[str, Any]:
    root = generation_root.expanduser().resolve()
    receipt = _read_object(root / "receipt.json", "capture receipt")
    if receipt.get("schema") != CAPTURE_SCHEMA or receipt.get("status") != "COMPLETE":
        raise DingTalkGenerationError("capture generation is not a supported complete generation")
    if receipt.get("generation_id") != root.name:
        raise DingTalkGenerationError("capture generation identity does not match its directory")
    token = receipt.get("fingerprint_token")
    binding = receipt.get("account_binding_sha256")
    for label, value in (("fingerprint", token), ("account binding", binding)):
        if not isinstance(value, str) or len(value) != 64:
            raise DingTalkGenerationError(f"capture {label} is invalid")
        try:
            int(value, 16)
        except ValueError as exc:
            raise DingTalkGenerationError(f"capture {label} is invalid") from exc
    for key in ("source_modified", "process_attached", "network_accessed", "login_bypassed", "secret_reported"):
        if receipt.get(key) is not False:
            raise DingTalkGenerationError(f"capture boundary is not accepted: {key}")
    entry = receipt.get("decrypted_database")
    if not isinstance(entry, dict) or entry.get("quick_check") != "ok":
        raise DingTalkGenerationError("capture database receipt is invalid")
    relative = entry.get("relative_path")
    expected_sha = entry.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected_sha, str) or len(expected_sha) != 64:
        raise DingTalkGenerationError("capture database inventory is invalid")
    database = _safe_path(root, relative)
    if not database.is_file() or _hash_file(database) != expected_sha:
        raise DingTalkGenerationError("captured database digest changed")
    if _quick_check(database) != "ok":
        raise DingTalkGenerationError("captured database quick_check changed")
    salt_md5 = _salt_md5(root / "encrypted/user_config")
    if self_uid is not None and not self_uid.isdecimal():
        raise DingTalkGenerationError("self_uid must be decimal")
    candidates: list[str]
    if self_uid is not None:
        candidates = [self_uid]
    else:
        connection = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            candidates = [
                str(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT uid FROM tbuser_profile_v2 WHERE uid IS NOT NULL"
                )
                if str(row[0]).isdecimal()
            ]
        except sqlite3.Error as exc:
            raise DingTalkGenerationError("could not resolve the captured personal account") from exc
        finally:
            connection.close()
    matches = [
        candidate
        for candidate in candidates
        if hashlib.sha256((candidate + salt_md5).encode("ascii")).hexdigest() == binding
    ]
    if len(matches) != 1:
        raise DingTalkGenerationError("self_uid does not match the captured personal account")
    resolved_self_uid = matches[0]
    return {
        "generation_id": root.name,
        "fingerprint_token": token,
        "account_binding_sha256": binding,
        "captured_at": receipt.get("captured_at"),
        "database": database,
        "database_sha256": expected_sha,
        "self_uid": resolved_self_uid,
    }


def _warning_counts(warnings: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    if isinstance(warnings, list):
        for warning in warnings:
            code = warning.get("code") if isinstance(warning, dict) else None
            label = code if isinstance(code, str) else "UNKNOWN"
            counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def ingest_generation(
    generation_root: Path,
    output_directory: Path,
    data_home: Path,
    *,
    account_id: str,
    self_uid: str | None = None,
    display_name: str = "Personal DingTalk",
    max_conversations: int = 20,
    max_messages_per_conversation: int = 200,
    media_roots: Sequence[Path] = (),
) -> dict[str, Any]:
    verified = verify_generation(generation_root, self_uid=self_uid)
    generation = generation_root.expanduser().resolve()
    output = output_directory.expanduser().resolve()
    home = data_home.expanduser().resolve()
    for label, candidate in (("ingest output", output), ("data home", home)):
        try:
            candidate.relative_to(generation)
        except ValueError:
            pass
        else:
            raise DingTalkGenerationError(f"{label} cannot be inside the capture generation")
    resolved_self_uid = verified["self_uid"]
    configuration = {
        "account_identity_sha256": hashlib.sha256(account_id.encode()).hexdigest(),
        "self_identity_sha256": hashlib.sha256(resolved_self_uid.encode()).hexdigest(),
        "display_name_sha256": hashlib.sha256(display_name.encode()).hexdigest(),
        "max_conversations": max_conversations,
        "max_messages_per_conversation": max_messages_per_conversation,
        "media_roots_sha256": sorted({
            hashlib.sha256(str(root.expanduser().resolve()).encode()).hexdigest()
            for root in media_roots
        }),
    }
    configuration_sha = hashlib.sha256(json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        output.chmod(0o700)
    manifest_path = output / "export.json"
    receipt_path = output / RECEIPT_NAME
    if receipt_path.exists():
        lifecycle = _read_object(receipt_path, "ingest receipt")
        if lifecycle.get("schema") != INGEST_SCHEMA:
            raise DingTalkGenerationError("ingest receipt schema is unsupported")
        checks = {
            "generation_id": verified["generation_id"],
            "fingerprint_token": verified["fingerprint_token"],
            "account_binding_sha256": verified["account_binding_sha256"],
            "configuration_sha256": configuration_sha,
        }
        if any(lifecycle.get(key) != value for key, value in checks.items()):
            raise DingTalkGenerationError("ingest receipt does not match this generation or configuration")
        expected_manifest = lifecycle.get("manifest_sha256")
        if not isinstance(expected_manifest, str) or not manifest_path.is_file() or _hash_file(manifest_path) != expected_manifest:
            raise DingTalkGenerationError("export manifest changed after generation ingest")
        export_result = lifecycle.get("export")
        if not isinstance(export_result, dict):
            raise DingTalkGenerationError("ingest receipt has no export result")
    else:
        if manifest_path.exists():
            raise DingTalkGenerationError("existing export has no trusted generation receipt")
        export_result = export_dingtalk_snapshot(
            verified["database"], output, account_id=account_id, self_uid=resolved_self_uid,
            display_name=display_name, max_conversations=max_conversations,
            max_messages_per_conversation=max_messages_per_conversation,
            media_roots=media_roots,
        )
        lifecycle = {
            "schema": INGEST_SCHEMA,
            "status": "EXPORTED",
            "generation_id": verified["generation_id"],
            "fingerprint_token": verified["fingerprint_token"],
            "account_binding_sha256": verified["account_binding_sha256"],
            "configuration_sha256": configuration_sha,
            "configuration": configuration,
            "captured_at": verified["captured_at"],
            "database_sha256": verified["database_sha256"],
            "manifest_sha256": export_result["manifest_sha256"],
            "export": export_result,
        }
        _private_json(receipt_path, lifecycle)
    imported = import_manifest(manifest_path, home)
    lifecycle["status"] = "COMPLETE"
    lifecycle["import"] = {
        "status": imported["status"],
        "import_run_id": imported["import_run_id"],
        "inserted_messages": imported["inserted_messages"],
        "reused_messages": imported["reused_messages"],
        "present_attachments": imported["present_attachments"],
        "missing_attachments": imported["missing_attachments"],
        "warning_counts": _warning_counts(imported.get("warnings")),
    }
    _private_json(receipt_path, lifecycle)
    return {
        "status": "complete",
        "generation_id": verified["generation_id"],
        "generation_verified": True,
        "manifest_sha256": export_result["manifest_sha256"],
        "conversations": export_result["conversations"],
        "messages": export_result["messages"],
        "direction_counts": export_result["direction_counts"],
        "content_type_counts": export_result["content_type_counts"],
        "message_extensions_preserved": export_result["message_extensions_preserved"],
        "source_urls_preserved": export_result["source_urls_preserved"],
        "image_attachments_resolved": export_result["image_attachments_resolved"],
        "file_attachments_resolved": export_result["file_attachments_resolved"],
        "attachment_bytes_copied": export_result["attachment_bytes_copied"],
        "import_status": imported["status"],
        "inserted_messages": imported["inserted_messages"],
        "reused_messages": imported["reused_messages"],
        "present_attachments": imported["present_attachments"],
        "missing_attachments": imported["missing_attachments"],
        "warning_counts": _warning_counts(imported.get("warnings")),
        "message_content_reported": False,
        "identifiers_reported": False,
    }
