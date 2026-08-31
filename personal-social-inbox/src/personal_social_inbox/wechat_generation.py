from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .importer import import_manifest
from .wechat_4_adapter import export_wechat_snapshot


CAPTURE_SCHEMA = "wechat-4.1.7-incremental-capture/v1"
INGEST_SCHEMA = "personal-social-inbox/wechat-generation-ingest/v1"
RECEIPT_NAME = "ingest-receipt.json"
REQUIRED_DATABASES = {
    "session/session.db",
    "contact/contact.db",
    "message/message_0.db",
    "message/message_1.db",
    "message/message_resource.db",
    "message/media_0.db",
    "message/media_1.db",
}


class WechatGenerationError(ValueError):
    pass


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WechatGenerationError(f"{label} is unavailable") from exc
    except json.JSONDecodeError as exc:
        raise WechatGenerationError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise WechatGenerationError(f"{label} must be an object")
    return payload


def _private_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.parent.chmod(0o700)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            json.dump(payload, temporary, ensure_ascii=False, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
        if os.name == "posix":
            path.chmod(0o600)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _safe_database_path(decrypted_root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise WechatGenerationError("capture receipt contains an unsafe database path")
    database = (decrypted_root / Path(*pure.parts)).resolve()
    try:
        database.relative_to(decrypted_root)
    except ValueError as exc:
        raise WechatGenerationError("capture database escapes the generation") from exc
    return database


def _quick_check(database: Path) -> str:
    uri = database.as_uri() + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        row = connection.execute("PRAGMA quick_check").fetchone()
    finally:
        connection.close()
    return str(row[0]) if row else "missing_result"


def verify_generation(generation_root: Path) -> dict[str, Any]:
    root = generation_root.expanduser().resolve()
    receipt = _read_object(root / "receipt.json", "capture receipt")
    if receipt.get("schema") != CAPTURE_SCHEMA:
        raise WechatGenerationError("capture receipt schema is unsupported")
    if receipt.get("status") != "COMPLETE":
        raise WechatGenerationError("capture generation is not complete")
    generation_id = receipt.get("generation_id")
    if not isinstance(generation_id, str) or generation_id != root.name:
        raise WechatGenerationError("capture generation identity does not match its directory")
    token = receipt.get("fingerprint_token")
    if not isinstance(token, str) or len(token) != 64:
        raise WechatGenerationError("capture fingerprint token is invalid")
    try:
        int(token, 16)
    except ValueError as exc:
        raise WechatGenerationError("capture fingerprint token is invalid") from exc

    entries = receipt.get("decrypted_databases")
    if not isinstance(entries, list):
        raise WechatGenerationError("capture receipt has no decrypted database inventory")
    decrypted_root = (root / "decrypted").resolve()
    observed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise WechatGenerationError("capture database inventory is invalid")
        relative = entry.get("relative_path")
        expected_sha = entry.get("sha256")
        if not isinstance(relative, str) or relative in observed:
            raise WechatGenerationError("capture database inventory has an invalid path")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            raise WechatGenerationError(f"capture digest is invalid: {relative}")
        if entry.get("quick_check") != "ok":
            raise WechatGenerationError(f"capture did not pass quick_check: {relative}")
        database = _safe_database_path(decrypted_root, relative)
        if not database.is_file():
            raise WechatGenerationError(f"captured database is unavailable: {relative}")
        if _hash_file(database) != expected_sha:
            raise WechatGenerationError(f"captured database digest changed: {relative}")
        if _quick_check(database) != "ok":
            raise WechatGenerationError(f"captured database quick_check changed: {relative}")
        observed.add(relative)

    if REQUIRED_DATABASES - observed:
        raise WechatGenerationError("capture generation is missing required databases")
    return {
        "generation_id": generation_id,
        "fingerprint_token": token,
        "captured_at": receipt.get("captured_at"),
        "database_count": len(observed),
        "decrypted_root": decrypted_root,
    }


def _warning_counts(warnings: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(warnings, list):
        return counts
    for warning in warnings:
        code = warning.get("code") if isinstance(warning, dict) else None
        label = code if isinstance(code, str) else "UNKNOWN"
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _public_result(
    verified: dict[str, Any], export_result: dict[str, Any], import_result: dict[str, Any]
) -> dict[str, Any]:
    return {
        "status": "complete",
        "generation_id": verified["generation_id"],
        "generation_verified": True,
        "database_count": verified["database_count"],
        "manifest_sha256": export_result["manifest_sha256"],
        "conversations": export_result["conversations"],
        "messages": export_result["messages"],
        "groups_exported": export_result["groups_exported"],
        "voice_attachments_resolved": export_result["voice_attachments_resolved"],
        "image_attachments_resolved": export_result.get("image_attachments_decoded", 0),
        "video_attachments_resolved": export_result.get("video_attachments_copied", 0),
        "file_attachments_resolved": export_result.get("file_attachments_copied", 0),
        "import_status": import_result["status"],
        "inserted_messages": import_result["inserted_messages"],
        "reused_messages": import_result["reused_messages"],
        "present_attachments": import_result["present_attachments"],
        "missing_attachments": import_result["missing_attachments"],
        "warning_counts": _warning_counts(import_result.get("warnings")),
        "message_content_reported": False,
        "identifiers_reported": False,
    }


def ingest_generation(
    generation_root: Path,
    output_directory: Path,
    data_home: Path,
    *,
    account_id: str,
    display_name: str = "Personal WeChat",
    max_conversations: int = 20,
    max_messages_per_conversation: int = 200,
    wechat_profile_root: Path | None = None,
    include_all_groups: bool = False,
) -> dict[str, Any]:
    verified = verify_generation(generation_root)
    generation = generation_root.expanduser().resolve()
    output = output_directory.expanduser().resolve()
    normalized_home = data_home.expanduser().resolve()
    for label, candidate in (("ingest output", output), ("data home", normalized_home)):
        try:
            candidate.relative_to(generation)
        except ValueError:
            pass
        else:
            raise WechatGenerationError(f"{label} cannot be inside the capture generation")
    account_identity_sha256 = hashlib.sha256(account_id.encode("utf-8")).hexdigest()

    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        output.chmod(0o700)
    manifest_path = output / "export.json"
    receipt_path = output / RECEIPT_NAME

    if receipt_path.exists():
        lifecycle = _read_object(receipt_path, "ingest receipt")
        if lifecycle.get("schema") != INGEST_SCHEMA:
            raise WechatGenerationError("ingest receipt schema is unsupported")
        if lifecycle.get("generation_id") != verified["generation_id"]:
            raise WechatGenerationError("ingest receipt belongs to another generation")
        if lifecycle.get("fingerprint_token") != verified["fingerprint_token"]:
            raise WechatGenerationError("ingest receipt fingerprint does not match capture")
        if lifecycle.get("account_identity_sha256") != account_identity_sha256:
            raise WechatGenerationError("ingest receipt belongs to another account identity")
        expected_manifest_sha = lifecycle.get("manifest_sha256")
        if not isinstance(expected_manifest_sha, str) or not manifest_path.is_file():
            raise WechatGenerationError("ingest receipt has no usable export manifest")
        if _hash_file(manifest_path) != expected_manifest_sha:
            raise WechatGenerationError("export manifest changed after generation ingest")
        export_result = lifecycle.get("export")
        if not isinstance(export_result, dict):
            raise WechatGenerationError("ingest receipt has no export result")
    else:
        if manifest_path.exists():
            raise WechatGenerationError("existing export has no trusted generation receipt")
        export_result = export_wechat_snapshot(
            verified["decrypted_root"],
            output,
            account_id=account_id,
            display_name=display_name,
            max_conversations=max_conversations,
            max_messages_per_conversation=max_messages_per_conversation,
            wechat_profile_root=wechat_profile_root,
            include_all_groups=include_all_groups,
        )
        lifecycle = {
            "schema": INGEST_SCHEMA,
            "status": "EXPORTED",
            "generation_id": verified["generation_id"],
            "fingerprint_token": verified["fingerprint_token"],
            "account_identity_sha256": account_identity_sha256,
            "captured_at": verified["captured_at"],
            "database_count": verified["database_count"],
            "manifest_sha256": export_result["manifest_sha256"],
            "export": export_result,
        }
        _private_json(receipt_path, lifecycle)

    import_result = import_manifest(manifest_path, normalized_home)
    result = _public_result(verified, export_result, import_result)
    lifecycle["status"] = "COMPLETE"
    lifecycle["import"] = {
        "status": import_result["status"],
        "import_run_id": import_result["import_run_id"],
        "inserted_messages": import_result["inserted_messages"],
        "reused_messages": import_result["reused_messages"],
        "present_attachments": import_result["present_attachments"],
        "missing_attachments": import_result["missing_attachments"],
        "warning_counts": result["warning_counts"],
    }
    _private_json(receipt_path, lifecycle)
    return result
