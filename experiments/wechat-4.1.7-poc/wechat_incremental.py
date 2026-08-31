#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import poc
import wechat_snapshot


SCHEMA = "wechat-4.1.7-incremental-capture/v1"
INCREMENTAL_ROOT = poc.PRIVATE / "incremental"
GENERATIONS_ROOT = INCREMENTAL_ROOT / "generations"
STATE_FILE = INCREMENTAL_ROOT / "state.json"
DEFAULT_KEYS_FILE = wechat_snapshot.KEYS_FILE


@dataclass(frozen=True)
class IngestOptions:
    exports_root: Path
    data_home: Path
    account_id: str
    display_name: str = "Personal WeChat"
    max_conversations: int = 100
    max_messages_per_conversation: int = 200
    wechat_profile_root: Path | None = None
    include_all_groups: bool = True


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _source_root(explicit: Path | None = None) -> Path:
    if explicit is not None:
        root = explicit.expanduser().resolve()
        if root.is_dir():
            return root
        raise RuntimeError("source database root is unavailable")
    profiles = poc._profile_roots()
    if len(profiles) != 1:
        raise RuntimeError("expected exactly one local WeChat profile")
    return profiles[0] / "db_storage"


def _file_fingerprint(path: Path) -> dict[str, int] | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    if not path.is_file():
        return None
    return {
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "inode": stat.st_ino,
    }


def collect_fingerprint(
    source_root: Path, targets: tuple[str, ...] = wechat_snapshot.TARGETS
) -> dict:
    databases: list[dict] = []
    for relative in targets:
        database = source_root / relative
        database_fingerprint = _file_fingerprint(database)
        if database_fingerprint is None:
            raise RuntimeError(f"required database is unavailable: {relative}")
        wal = database.with_name(database.name + "-wal")
        databases.append(
            {
                "relative_path": relative,
                "database": database_fingerprint,
                "wal": _file_fingerprint(wal),
            }
        )
    return {"databases": databases}


def fingerprint_token(fingerprint: dict) -> str:
    encoded = json.dumps(
        fingerprint, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_state(path: Path = STATE_FILE) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"schema": SCHEMA}
    return payload if payload.get("schema") == SCHEMA else {"schema": SCHEMA}


def _write_state(path: Path, payload: dict) -> None:
    wechat_snapshot._write_private_json(path, payload)


def _copy_candidate(
    source_root: Path,
    candidate_root: Path,
    targets: tuple[str, ...],
    attempts: int,
) -> tuple[dict, int]:
    encrypted_root = candidate_root / "encrypted"
    last_reason = "source_changed_during_copy"
    for attempt in range(1, attempts + 1):
        shutil.rmtree(encrypted_root, ignore_errors=True)
        before = collect_fingerprint(source_root, targets)
        try:
            for relative in targets:
                source = source_root / relative
                destination = encrypted_root / relative
                wechat_snapshot._copy_private(source, destination)
                wal = source.with_name(source.name + "-wal")
                if wal.is_file() and wal.stat().st_size:
                    wechat_snapshot._copy_private(
                        wal, destination.with_name(destination.name + "-wal")
                    )
        except (FileNotFoundError, RuntimeError):
            last_reason = "source_changed_during_copy"
            continue
        after = collect_fingerprint(source_root, targets)
        if before == after:
            return after, attempt
    raise RuntimeError(last_reason)


def _load_keys(path: Path) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise RuntimeError("verified key file is unavailable") from exc
    keys = payload.get("keys")
    if not isinstance(keys, dict):
        raise RuntimeError("verified key file has an invalid schema")
    return {str(key): str(value) for key, value in keys.items()}


def _decrypt_candidate(
    candidate_root: Path,
    targets: tuple[str, ...],
    keys_file: Path,
) -> list[dict]:
    encrypted_root = candidate_root / "encrypted"
    decrypted_root = candidate_root / "decrypted"
    keys = _load_keys(keys_file)
    results: list[dict] = []
    for relative in targets:
        key_hex = keys.get(relative)
        if not key_hex:
            raise RuntimeError(f"verified key is unavailable: {relative}")
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise RuntimeError(f"verified key is malformed: {relative}") from exc
        database = encrypted_root / relative
        with database.open("rb") as source:
            page1 = source.read(poc.PAGE_SIZE)
        if not poc.verify_key(key, page1):
            raise RuntimeError(f"key re-verification failed: {relative}")
        output = decrypted_root / relative
        page_count, mac_key = wechat_snapshot._decrypt_main(database, output, key)
        wal = database.with_name(database.name + "-wal")
        wal_result = (
            wechat_snapshot._apply_wal(wal, output, key, mac_key)
            if wal.is_file() and wal.stat().st_size
            else {"applied_frames": 0, "commit_pages": None}
        )
        quick_check = wechat_snapshot._quick_check(output)
        if quick_check != "ok":
            raise RuntimeError(f"quick_check failed: {relative}")
        results.append(
            {
                "relative_path": relative,
                "page_count": page_count,
                "wal": wal_result,
                "quick_check": quick_check,
                "sha256": wechat_snapshot._sha256(output),
            }
        )
    return results


def message_watermarks(
    decrypted_root: Path,
    targets: tuple[str, ...] = wechat_snapshot.TARGETS,
) -> dict[str, dict[str, int]]:
    watermarks: dict[str, dict[str, int]] = {}
    for relative in targets:
        if not relative.startswith("message/message_") or relative.endswith(
            "message_resource.db"
        ):
            continue
        database = decrypted_root / relative
        if not database.is_file():
            continue
        connection = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (table,) in tables:
                escaped = str(table).replace('"', '""')
                columns = {
                    row[1]
                    for row in connection.execute(
                        f'PRAGMA table_info("{escaped}")'
                    )
                }
                if not {"local_id", "create_time"}.issubset(columns):
                    continue
                row = connection.execute(
                    f'SELECT COUNT(*), COALESCE(MAX(local_id), 0), '
                    f'COALESCE(MAX(create_time), 0) FROM "{escaped}"'
                ).fetchone()
                stream_id = hashlib.sha256(
                    f"{relative}\0{table}".encode("utf-8")
                ).hexdigest()[:24]
                watermarks[stream_id] = {
                    "rows": int(row[0]),
                    "max_local_id": int(row[1]),
                    "max_create_time": int(row[2]),
                }
        finally:
            connection.close()
    return watermarks


def summarize_watermark_change(previous: dict, current: dict) -> dict:
    if not previous:
        return {
            "baseline": True,
            "new_streams": len(current),
            "removed_streams": 0,
            "changed_streams": len(current),
            "row_increase_estimate": None,
            "regressions": 0,
            "exact_change_detection": False,
        }
    new_streams = set(current) - set(previous)
    removed_streams = set(previous) - set(current)
    changed_streams = 0
    row_increase = 0
    regressions = 0
    for stream_id in set(previous) & set(current):
        before = previous[stream_id]
        after = current[stream_id]
        if before != after:
            changed_streams += 1
        difference = int(after.get("rows", 0)) - int(before.get("rows", 0))
        if difference >= 0:
            row_increase += difference
        else:
            regressions += 1
    row_increase += sum(int(current[item].get("rows", 0)) for item in new_streams)
    return {
        "baseline": False,
        "new_streams": len(new_streams),
        "removed_streams": len(removed_streams),
        "changed_streams": changed_streams + len(new_streams),
        "row_increase_estimate": row_increase,
        "regressions": regressions + len(removed_streams),
        "exact_change_detection": False,
    }


def _changed_files(previous: dict | None, current: dict) -> list[str]:
    if not previous:
        return [item["relative_path"] for item in current["databases"]]
    old = {item["relative_path"]: item for item in previous.get("databases", [])}
    return [
        item["relative_path"]
        for item in current["databases"]
        if old.get(item["relative_path"]) != item
    ]


def capture_generation(
    source_root: Path,
    incremental_root: Path = INCREMENTAL_ROOT,
    keys_file: Path = DEFAULT_KEYS_FILE,
    targets: tuple[str, ...] = wechat_snapshot.TARGETS,
    attempts: int = 3,
) -> dict:
    incremental_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(incremental_root, 0o700)
    state_file = incremental_root / "state.json"
    generations_root = incremental_root / "generations"
    generations_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(generations_root, 0o700)
    state = _read_state(state_file)
    initial_fingerprint = collect_fingerprint(source_root, targets)
    if fingerprint_token(initial_fingerprint) == state.get("last_captured_token"):
        return {
            "status": "UNCHANGED",
            "source_modified": False,
            "process_attached": False,
        }
    candidate = Path(tempfile.mkdtemp(prefix=".candidate-", dir=generations_root))
    try:
        fingerprint, copy_attempts = _copy_candidate(
            source_root, candidate, targets, attempts
        )
        token = fingerprint_token(fingerprint)
        results = _decrypt_candidate(candidate, targets, keys_file)
        watermarks = message_watermarks(candidate / "decrypted", targets)
        change = summarize_watermark_change(state.get("watermarks", {}), watermarks)
        generation_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + token[:12]
        )
        destination = generations_root / generation_id
        if destination.exists():
            raise RuntimeError("generation destination already exists")
        receipt = {
            "schema": SCHEMA,
            "status": "COMPLETE",
            "captured_at": _utc_now(),
            "generation_id": generation_id,
            "fingerprint_token": token,
            "copy_attempts": copy_attempts,
            "source_modified": False,
            "process_attached": False,
            "network_accessed": False,
            "source_closed_required": False,
            "changed_databases": _changed_files(
                state.get("last_captured_fingerprint"), fingerprint
            ),
            "incremental_estimate": change,
            "decrypted_databases": results,
        }
        wechat_snapshot._write_private_json(candidate / "receipt.json", receipt)
        os.replace(candidate, destination)
        _write_state(
            state_file,
            {
                "schema": SCHEMA,
                "last_captured_at": receipt["captured_at"],
                "last_generation_id": generation_id,
                "last_captured_token": token,
                "last_captured_fingerprint": fingerprint,
                "watermarks": watermarks,
            },
        )
        return {
            "status": "COMPLETE",
            "generation_id": generation_id,
            "changed_database_count": len(receipt["changed_databases"]),
            "incremental_estimate": change,
            "quick_check_ok": sum(
                item["quick_check"] == "ok" for item in results
            ),
            "source_modified": False,
            "process_attached": False,
            "network_accessed": False,
        }
    except Exception:
        shutil.rmtree(candidate, ignore_errors=True)
        raise
    finally:
        if candidate.exists():
            shutil.rmtree(candidate, ignore_errors=True)


def _load_ingest_generation() -> Callable[..., dict]:
    project_src = (
        Path(__file__).resolve().parents[2]
        / "personal-social-inbox"
        / "src"
    )
    if not project_src.is_dir():
        raise RuntimeError("Personal Social Inbox source is unavailable")
    if str(project_src) not in sys.path:
        sys.path.insert(0, str(project_src))
    try:
        from personal_social_inbox.wechat_generation import ingest_generation
    except ImportError as exc:
        raise RuntimeError("generation ingest bridge is unavailable") from exc
    return ingest_generation


def _latest_generation_id(incremental_root: Path) -> str:
    state = _read_state(incremental_root / "state.json")
    generation_id = state.get("last_generation_id")
    if not isinstance(generation_id, str) or not generation_id:
        raise RuntimeError("no completed capture generation is available for ingest")
    generation_root = incremental_root / "generations" / generation_id
    if not generation_root.is_dir():
        raise RuntimeError("latest capture generation is unavailable")
    return generation_id


def ingest_generation_id(
    generation_id: str,
    incremental_root: Path,
    options: IngestOptions,
    ingest: Callable[..., dict] | None = None,
) -> dict:
    generation_root = incremental_root / "generations" / generation_id
    if not generation_root.is_dir():
        raise RuntimeError("capture generation is unavailable for ingest")
    output_directory = options.exports_root / generation_id
    ingest_function = ingest or _load_ingest_generation()
    try:
        return ingest_function(
            generation_root,
            output_directory,
            options.data_home,
            account_id=options.account_id,
            display_name=options.display_name,
            max_conversations=options.max_conversations,
            max_messages_per_conversation=options.max_messages_per_conversation,
            wechat_profile_root=options.wechat_profile_root,
            include_all_groups=options.include_all_groups,
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        raise RuntimeError(f"generation ingest failed: {exc}") from exc


def sync_capture_and_ingest(
    source_root: Path,
    incremental_root: Path,
    keys_file: Path,
    attempts: int,
    options: IngestOptions,
    ingest: Callable[..., dict] | None = None,
) -> dict:
    capture = capture_generation(
        source_root,
        incremental_root=incremental_root,
        keys_file=keys_file,
        attempts=attempts,
    )
    generation_id = (
        capture.get("generation_id")
        if capture.get("status") == "COMPLETE"
        else _latest_generation_id(incremental_root)
    )
    if not isinstance(generation_id, str):
        raise RuntimeError("capture did not produce a usable generation")
    imported = ingest_generation_id(
        generation_id,
        incremental_root,
        options,
        ingest=ingest,
    )
    return {
        "status": "COMPLETE",
        "generation_id": generation_id,
        "capture": capture,
        "ingest": imported,
        "source_modified": False,
        "process_attached": False,
        "network_accessed": False,
    }


def watch(
    source_root: Path,
    incremental_root: Path,
    keys_file: Path,
    poll_seconds: float,
    quiet_seconds: float,
    attempts: int,
    ingest_options: IngestOptions | None = None,
) -> int:
    last_token = fingerprint_token(collect_fingerprint(source_root))
    changed_at = time.monotonic()
    last_ingested_generation: str | None = None
    while True:
        try:
            if ingest_options is not None:
                state = _read_state(incremental_root / "state.json")
                pending = state.get("last_generation_id")
                if (
                    isinstance(pending, str)
                    and pending
                    and pending != last_ingested_generation
                ):
                    imported = ingest_generation_id(
                        pending, incremental_root, ingest_options
                    )
                    print(
                        json.dumps(
                            {
                                "status": "COMPLETE",
                                "generation_id": pending,
                                "capture": {"status": "RECOVERED_EXISTING"},
                                "ingest": imported,
                                "source_modified": False,
                                "process_attached": False,
                                "network_accessed": False,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    last_ingested_generation = pending
            time.sleep(poll_seconds)
            current = collect_fingerprint(source_root)
            token = fingerprint_token(current)
            if token != last_token:
                last_token = token
                changed_at = time.monotonic()
                continue
            if time.monotonic() - changed_at < quiet_seconds:
                continue
            state = _read_state(incremental_root / "state.json")
            if last_token == state.get("last_captured_token"):
                changed_at = time.monotonic()
                continue
            result = capture_generation(
                source_root,
                incremental_root=incremental_root,
                keys_file=keys_file,
                attempts=attempts,
            )
            if result["status"] == "COMPLETE":
                if ingest_options is None:
                    event = result
                else:
                    generation_id = result["generation_id"]
                    event = {
                        "status": "COMPLETE",
                        "generation_id": generation_id,
                        "capture": result,
                        "ingest": ingest_generation_id(
                            generation_id, incremental_root, ingest_options
                        ),
                        "source_modified": False,
                        "process_attached": False,
                        "network_accessed": False,
                    }
                    last_ingested_generation = generation_id
                print(json.dumps(event, sort_keys=True), flush=True)
            changed_at = time.monotonic()
        except KeyboardInterrupt:
            print(json.dumps({"status": "STOPPED", "reason": "user_interrupt"}))
            return 0
        except RuntimeError as exc:
            print(
                json.dumps(
                    {
                        "status": "RETRYABLE",
                        "reason": str(exc),
                        "source_modified": False,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            changed_at = time.monotonic()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only, copy-on-change WeChat database capture."
    )
    parser.add_argument(
        "command", choices=("probe", "capture", "watch", "sync", "watch-ingest")
    )
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--output-root", type=Path, default=INCREMENTAL_ROOT)
    parser.add_argument("--keys-file", type=Path, default=DEFAULT_KEYS_FILE)
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--quiet-seconds", type=float, default=5.0)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--ingest-exports-root", type=Path)
    parser.add_argument("--data-home", type=Path)
    parser.add_argument("--account-id")
    parser.add_argument("--display-name", default="Personal WeChat")
    parser.add_argument("--wechat-profile-root", type=Path)
    parser.add_argument("--max-conversations", type=int, default=100)
    parser.add_argument("--max-messages", type=int, default=200)
    parser.add_argument("--no-include-all-groups", action="store_true")
    args = parser.parse_args()
    if args.poll_seconds <= 0 or args.quiet_seconds < 0 or args.attempts < 1:
        parser.error("poll/quiet/attempt values are outside their valid range")
    if args.max_conversations < 1 or args.max_messages < 1:
        parser.error("ingest limits must be positive")
    ingest_options = None
    if args.command in {"sync", "watch-ingest"}:
        account_id = args.account_id or os.environ.get(
            "PERSONAL_SOCIAL_INBOX_ACCOUNT_ID"
        )
        if not account_id or args.ingest_exports_root is None or args.data_home is None:
            parser.error(
                "sync/watch-ingest require account identity, --ingest-exports-root, "
                "and --data-home"
            )
        ingest_options = IngestOptions(
            exports_root=args.ingest_exports_root.expanduser().resolve(),
            data_home=args.data_home.expanduser().resolve(),
            account_id=account_id,
            display_name=args.display_name,
            max_conversations=args.max_conversations,
            max_messages_per_conversation=args.max_messages,
            wechat_profile_root=(
                args.wechat_profile_root.expanduser().resolve()
                if args.wechat_profile_root is not None
                else None
            ),
            include_all_groups=not args.no_include_all_groups,
        )
    try:
        source_root = _source_root(args.source_root)
        if args.command == "probe":
            current = collect_fingerprint(source_root)
            state = _read_state(args.output_root / "state.json")
            print(
                json.dumps(
                    {
                        "status": (
                            "UNCHANGED"
                            if fingerprint_token(current)
                            == state.get("last_captured_token")
                            else "CHANGED"
                        ),
                        "database_count": len(current["databases"]),
                        "source_modified": False,
                        "process_attached": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "capture":
            print(
                json.dumps(
                    capture_generation(
                        source_root,
                        incremental_root=args.output_root,
                        keys_file=args.keys_file,
                        attempts=args.attempts,
                    ),
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "sync":
            assert ingest_options is not None
            print(
                json.dumps(
                    sync_capture_and_ingest(
                        source_root,
                        args.output_root,
                        args.keys_file,
                        args.attempts,
                        ingest_options,
                    ),
                    sort_keys=True,
                )
            )
            return 0
        return watch(
            source_root,
            args.output_root,
            args.keys_file,
            args.poll_seconds,
            args.quiet_seconds,
            args.attempts,
            ingest_options=ingest_options,
        )
    except RuntimeError as exc:
        print(
            json.dumps(
                {
                    "status": "STOPPED",
                    "reason": str(exc),
                    "source_modified": False,
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
