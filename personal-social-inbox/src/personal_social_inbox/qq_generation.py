from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .importer import import_manifest
from .qq_qce_adapter import export_qce_groups


CAPTURE_SCHEMA = "qq-qce-docker-capture/v1"
INGEST_SCHEMA = "personal-social-inbox/qq-generation-ingest/v1"
RECEIPT_NAME = "ingest-receipt.json"
QCE_VERSION = "v6.2.8"
QCE_SOURCE_COMMIT = "aa85135d8e94654970051c359735e2dbd9535fa2"
QCE_IMAGE_DIGEST = "sha256:b5d4be820d2d097475981c3b1f3870e699ebfc73439d928ff174d24ea2780753"


class QQGenerationError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.chmod(0o700)


def _private_bytes(path: Path, payload: bytes) -> tuple[str, int]:
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
    return _sha256_bytes(payload), len(payload)


def _private_json(path: Path, payload: dict[str, Any]) -> None:
    _private_bytes(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )


def _copy_private(source: Path, destination: Path) -> tuple[str, int]:
    try:
        before = source.stat()
    except OSError as exc:
        raise QQGenerationError("a referenced QCE resource is unavailable") from exc
    if not source.is_file() or source.is_symlink():
        raise QQGenerationError("a referenced QCE resource is not a regular file")
    _private_directory(destination.parent)
    digest = hashlib.sha256()
    size = 0
    temporary_name: str | None = None
    try:
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as temporary:
            while chunk := source_handle.read(1024 * 1024):
                temporary.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        after = source.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise QQGenerationError("a QCE resource changed while it was being captured")
        if os.name == "posix":
            os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, destination)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()
    return digest.hexdigest(), size


def _read_object_bytes(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except FileNotFoundError as exc:
        raise QQGenerationError(f"{label} is unavailable") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QQGenerationError(f"{label} is invalid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise QQGenerationError(f"{label} must be an object")
    return payload, raw


def _read_object(path: Path, label: str) -> dict[str, Any]:
    return _read_object_bytes(path, label)[0]


def _scope_sha256(group_ids: set[str]) -> str:
    cleaned = sorted(
        value.strip() for value in group_ids if isinstance(value, str) and value.strip()
    )
    if not cleaned:
        raise QQGenerationError("at least one allowed QQ group ID is required")
    return _sha256_bytes(_canonical(cleaned))


def _safe_relative(value: str, label: str) -> PurePosixPath:
    if "\\" in value:
        raise QQGenerationError(f"{label} uses an unsupported path separator")
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise QQGenerationError(f"{label} contains an unsafe path")
    return relative


def _contained_source(root: Path, relative: PurePosixPath) -> Path:
    resolved_root = root.resolve()
    resolved = (resolved_root / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise QQGenerationError("a QCE resource escapes its export directory") from exc
    return resolved


def _qce_resource_source(root: Path, relative: PurePosixPath) -> Path:
    """Resolve both JSON-relative and official QCE resources/ layouts."""
    primary = _contained_source(root, relative)
    if primary.exists() or relative.parts[0] == "resources":
        return primary
    official = _contained_source(root, PurePosixPath("resources") / relative)
    return official if official.exists() else primary


def _chat_ids(chat_info: dict[str, Any], file_index: int) -> set[str]:
    if chat_info.get("type") != "group":
        raise QQGenerationError(
            f"qce_json_files[{file_index}] is not a group export"
        )
    identifiers: set[str] = set()
    for key in ("peerUid", "peerUin"):
        value = chat_info.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise QQGenerationError(
                f"qce_json_files[{file_index}].chatInfo.{key} is invalid"
            )
        text = str(value).strip()
        if text:
            identifiers.add(text)
    if not identifiers:
        raise QQGenerationError(f"qce_json_files[{file_index}] has no stable group ID")
    return identifiers


def _resource_paths(payload: dict[str, Any], file_index: int) -> set[PurePosixPath]:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise QQGenerationError(f"qce_json_files[{file_index}].messages must be an array")
    result: set[PurePosixPath] = set()
    for message_index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise QQGenerationError(
                f"qce_json_files[{file_index}].messages[{message_index}] must be an object"
            )
        content = message.get("content")
        if not isinstance(content, dict):
            raise QQGenerationError(
                f"qce_json_files[{file_index}].messages[{message_index}].content must be an object"
            )
        resources = content.get("resources", [])
        if not isinstance(resources, list):
            raise QQGenerationError(
                f"qce_json_files[{file_index}].messages[{message_index}].content.resources must be an array"
            )
        for resource_index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                raise QQGenerationError(
                    f"qce_json_files[{file_index}].messages[{message_index}].content.resources[{resource_index}] must be an object"
                )
            local_path = resource.get("localPath")
            if local_path is None or local_path == "":
                continue
            if not isinstance(local_path, str):
                raise QQGenerationError("a QCE resource localPath is not a string")
            result.add(_safe_relative(local_path, "QCE resource localPath"))
    return result


def _fingerprint(
    *,
    generation_id: str,
    scope_sha256: str,
    files: list[dict[str, Any]],
) -> str:
    return _sha256_bytes(
        _canonical(
            {
                "generation_id": generation_id,
                "qce_version": QCE_VERSION,
                "qce_source_commit": QCE_SOURCE_COMMIT,
                "qce_image_digest": QCE_IMAGE_DIGEST,
                "allowed_group_scope_sha256": scope_sha256,
                "files": files,
            }
        )
    )


def capture_qce_generation(
    qce_json_files: list[Path],
    generation_root: Path,
    *,
    allowed_group_ids: set[str],
) -> dict[str, Any]:
    if not qce_json_files:
        raise QQGenerationError("at least one QCE JSON file is required")
    allowed = {value.strip() for value in allowed_group_ids if value.strip()}
    scope_sha256 = _scope_sha256(allowed)
    generation = generation_root.expanduser().resolve()
    if generation.exists() and any(generation.iterdir()):
        raise QQGenerationError("generation directory is not empty")
    for source in qce_json_files:
        resolved = source.expanduser().resolve()
        try:
            resolved.relative_to(generation)
        except ValueError:
            pass
        else:
            raise QQGenerationError("a source export cannot be inside its generation")

    _private_directory(generation)
    inventory: list[dict[str, Any]] = []
    json_relative_paths: list[str] = []
    selected_files = 0
    skipped_files = 0
    missing_resources = 0
    copied_resources = 0

    for file_index, source_input in enumerate(qce_json_files):
        source = source_input.expanduser().resolve()
        payload, raw = _read_object_bytes(source, f"qce_json_files[{file_index}]")
        chat_info = payload.get("chatInfo")
        if not isinstance(chat_info, dict):
            raise QQGenerationError(
                f"qce_json_files[{file_index}].chatInfo must be an object"
            )
        if _chat_ids(chat_info, file_index).isdisjoint(allowed):
            skipped_files += 1
            continue

        capture_index = selected_files
        selected_files += 1
        raw_root = generation / "raw" / f"{capture_index:04d}"
        json_relative = Path("raw") / f"{capture_index:04d}" / "export.json"
        json_sha, json_size = _private_bytes(generation / json_relative, raw)
        json_relative_paths.append(json_relative.as_posix())
        inventory.append(
            {
                "relative_path": json_relative.as_posix(),
                "sha256": json_sha,
                "size_bytes": json_size,
                "kind": "qce_json",
            }
        )

        for relative in sorted(_resource_paths(payload, file_index), key=str):
            resource_source = _qce_resource_source(source.parent, relative)
            if not resource_source.exists():
                missing_resources += 1
                continue
            destination = raw_root / Path(*relative.parts)
            sha256, size = _copy_private(resource_source, destination)
            inventory.append(
                {
                    "relative_path": destination.relative_to(generation).as_posix(),
                    "sha256": sha256,
                    "size_bytes": size,
                    "kind": "resource",
                }
            )
            copied_resources += 1

    if selected_files == 0:
        raise QQGenerationError("none of the QCE exports matched the explicit allowlist")
    inventory.sort(key=lambda item: item["relative_path"])
    generation_id = generation.name
    fingerprint = _fingerprint(
        generation_id=generation_id, scope_sha256=scope_sha256, files=inventory
    )
    receipt = {
        "schema": CAPTURE_SCHEMA,
        "status": "COMPLETE",
        "generation_id": generation_id,
        "captured_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "qce_version": QCE_VERSION,
        "qce_source_commit": QCE_SOURCE_COMMIT,
        "qce_image_digest": QCE_IMAGE_DIGEST,
        "allowed_group_scope_sha256": scope_sha256,
        "fingerprint_token": fingerprint,
        "qce_json_files": json_relative_paths,
        "files": inventory,
        "missing_resources": missing_resources,
    }
    _private_json(generation / "receipt.json", receipt)
    return {
        "status": "complete",
        "generation_id": generation_id,
        "qce_version": QCE_VERSION,
        "qce_image_digest": QCE_IMAGE_DIGEST,
        "selected_json_files": selected_files,
        "skipped_json_files": skipped_files,
        "copied_resources": copied_resources,
        "missing_resources": missing_resources,
        "inventory_files": len(inventory),
        "message_content_reported": False,
        "identifiers_reported": False,
    }


def verify_qce_generation(generation_root: Path) -> dict[str, Any]:
    generation = generation_root.expanduser().resolve()
    receipt = _read_object(generation / "receipt.json", "capture receipt")
    if receipt.get("schema") != CAPTURE_SCHEMA:
        raise QQGenerationError("capture receipt schema is unsupported")
    if receipt.get("status") != "COMPLETE":
        raise QQGenerationError("capture generation is not complete")
    if receipt.get("generation_id") != generation.name:
        raise QQGenerationError("capture generation identity does not match its directory")
    expected_runtime = {
        "qce_version": QCE_VERSION,
        "qce_source_commit": QCE_SOURCE_COMMIT,
        "qce_image_digest": QCE_IMAGE_DIGEST,
    }
    for key, expected in expected_runtime.items():
        if receipt.get(key) != expected:
            raise QQGenerationError(f"capture {key} is not the accepted pinned runtime")
    scope_sha256 = receipt.get("allowed_group_scope_sha256")
    if not isinstance(scope_sha256, str) or len(scope_sha256) != 64:
        raise QQGenerationError("capture group scope fingerprint is invalid")
    files = receipt.get("files")
    if not isinstance(files, list) or not files:
        raise QQGenerationError("capture receipt has no file inventory")

    observed: set[str] = set()
    normalized_files: list[dict[str, Any]] = []
    for entry in files:
        if not isinstance(entry, dict):
            raise QQGenerationError("capture file inventory is invalid")
        relative_value = entry.get("relative_path")
        expected_sha = entry.get("sha256")
        expected_size = entry.get("size_bytes")
        kind = entry.get("kind")
        if not isinstance(relative_value, str):
            raise QQGenerationError("capture file inventory path is invalid")
        relative = _safe_relative(relative_value, "capture inventory path")
        normalized_relative = relative.as_posix()
        if normalized_relative in observed:
            raise QQGenerationError("capture file inventory contains a duplicate path")
        if (
            not isinstance(expected_sha, str)
            or len(expected_sha) != 64
            or not isinstance(expected_size, int)
            or expected_size < 0
            or kind not in {"qce_json", "resource"}
        ):
            raise QQGenerationError("capture file inventory entry is invalid")
        path = _contained_source(generation, relative)
        if not path.is_file() or path.is_symlink():
            raise QQGenerationError("a captured file is unavailable or not regular")
        actual_sha, actual_size = _hash_file(path)
        if actual_sha != expected_sha or actual_size != expected_size:
            raise QQGenerationError("a captured file digest or size changed")
        observed.add(normalized_relative)
        normalized_files.append(
            {
                "relative_path": normalized_relative,
                "sha256": expected_sha,
                "size_bytes": expected_size,
                "kind": kind,
            }
        )

    actual_files = {
        path.relative_to(generation).as_posix()
        for path in (generation / "raw").rglob("*")
        if path.is_file()
    }
    if actual_files != observed:
        raise QQGenerationError("capture generation has uninventoried or missing raw files")
    qce_json_values = receipt.get("qce_json_files")
    if not isinstance(qce_json_values, list) or not qce_json_values:
        raise QQGenerationError("capture receipt has no QCE JSON inputs")
    qce_json_paths: list[Path] = []
    for value in qce_json_values:
        if not isinstance(value, str) or value not in observed:
            raise QQGenerationError("capture QCE JSON inventory is invalid")
        path = generation / Path(*_safe_relative(value, "QCE JSON path").parts)
        matching = next(
            entry for entry in normalized_files if entry["relative_path"] == value
        )
        if matching["kind"] != "qce_json":
            raise QQGenerationError("capture QCE JSON is not typed as JSON")
        qce_json_paths.append(path)

    expected_fingerprint = _fingerprint(
        generation_id=generation.name,
        scope_sha256=scope_sha256,
        files=sorted(normalized_files, key=lambda item: item["relative_path"]),
    )
    if receipt.get("fingerprint_token") != expected_fingerprint:
        raise QQGenerationError("capture fingerprint does not match its inventory")
    return {
        "generation_id": generation.name,
        "captured_at": receipt.get("captured_at"),
        "qce_version": QCE_VERSION,
        "qce_image_digest": QCE_IMAGE_DIGEST,
        "allowed_group_scope_sha256": scope_sha256,
        "fingerprint_token": expected_fingerprint,
        "qce_json_paths": qce_json_paths,
        "inventory_files": len(observed),
        "missing_resources": receipt.get("missing_resources", 0),
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


def ingest_qce_generation(
    generation_root: Path,
    output_directory: Path,
    data_home: Path,
    *,
    account_id: str,
    allowed_group_ids: set[str],
    display_name: str = "Personal QQ",
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    verified = verify_qce_generation(generation_root)
    scope_sha256 = _scope_sha256(allowed_group_ids)
    if scope_sha256 != verified["allowed_group_scope_sha256"]:
        raise QQGenerationError("ingest group allowlist differs from capture scope")
    generation = generation_root.expanduser().resolve()
    output = output_directory.expanduser().resolve()
    normalized_home = data_home.expanduser().resolve()
    for label, candidate in (("ingest output", output), ("data home", normalized_home)):
        try:
            candidate.relative_to(generation)
        except ValueError:
            pass
        else:
            raise QQGenerationError(f"{label} cannot be inside the capture generation")

    configuration_sha256 = _sha256_bytes(
        _canonical(
            {
                "account_identity_sha256": _sha256_bytes(account_id.encode("utf-8")),
                "display_identity_sha256": _sha256_bytes(display_name.encode("utf-8")),
                "allowed_group_scope_sha256": scope_sha256,
                "since": since,
                "until": until,
            }
        )
    )
    _private_directory(output)
    manifest_path = output / "export.json"
    receipt_path = output / RECEIPT_NAME

    if receipt_path.exists():
        lifecycle = _read_object(receipt_path, "ingest receipt")
        if lifecycle.get("schema") != INGEST_SCHEMA:
            raise QQGenerationError("ingest receipt schema is unsupported")
        if lifecycle.get("generation_id") != verified["generation_id"]:
            raise QQGenerationError("ingest receipt belongs to another generation")
        if lifecycle.get("fingerprint_token") != verified["fingerprint_token"]:
            raise QQGenerationError("ingest receipt fingerprint does not match capture")
        if lifecycle.get("configuration_sha256") != configuration_sha256:
            raise QQGenerationError("ingest receipt belongs to another configuration")
        expected_manifest_sha = lifecycle.get("manifest_sha256")
        if not isinstance(expected_manifest_sha, str) or not manifest_path.is_file():
            raise QQGenerationError("ingest receipt has no usable export manifest")
        manifest_sha, _ = _hash_file(manifest_path)
        if manifest_sha != expected_manifest_sha:
            raise QQGenerationError("export manifest changed after generation ingest")
        export_result = lifecycle.get("export")
        if not isinstance(export_result, dict):
            raise QQGenerationError("ingest receipt has no export result")
    else:
        if manifest_path.exists():
            raise QQGenerationError("existing export has no trusted generation receipt")
        export_result = export_qce_groups(
            verified["qce_json_paths"],
            output,
            account_id=account_id,
            allowed_group_ids=allowed_group_ids,
            display_name=display_name,
            since=since,
            until=until,
        )
        lifecycle = {
            "schema": INGEST_SCHEMA,
            "status": "EXPORTED",
            "generation_id": verified["generation_id"],
            "fingerprint_token": verified["fingerprint_token"],
            "configuration_sha256": configuration_sha256,
            "captured_at": verified["captured_at"],
            "qce_version": verified["qce_version"],
            "qce_image_digest": verified["qce_image_digest"],
            "manifest_sha256": export_result["manifest_sha256"],
            "export": export_result,
        }
        _private_json(receipt_path, lifecycle)

    import_result = import_manifest(manifest_path, normalized_home)
    warning_counts = _warning_counts(import_result.get("warnings"))
    lifecycle["status"] = "COMPLETE"
    lifecycle["import"] = {
        "status": import_result["status"],
        "import_run_id": import_result["import_run_id"],
        "inserted_messages": import_result["inserted_messages"],
        "reused_messages": import_result["reused_messages"],
        "present_attachments": import_result["present_attachments"],
        "missing_attachments": import_result["missing_attachments"],
        "warning_counts": warning_counts,
    }
    _private_json(receipt_path, lifecycle)
    return {
        "status": "complete",
        "generation_id": verified["generation_id"],
        "generation_verified": True,
        "qce_version": verified["qce_version"],
        "inventory_files": verified["inventory_files"],
        "manifest_sha256": export_result["manifest_sha256"],
        "conversations": export_result["conversations"],
        "messages": export_result["messages"],
        "import_status": import_result["status"],
        "inserted_messages": import_result["inserted_messages"],
        "reused_messages": import_result["reused_messages"],
        "present_attachments": import_result["present_attachments"],
        "missing_attachments": import_result["missing_attachments"],
        "warning_counts": warning_counts,
        "message_content_reported": False,
        "identifiers_reported": False,
    }
