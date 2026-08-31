#!/usr/bin/env python3
"""Create one stable, account-bound DingTalk 8.3.5 database generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import decrypt_db_copy as decryptor


SCHEMA = "dingtalk-8.3.5-personal-snapshot/v1"
DATABASE_RELATIVE = Path("DBFiles/dingtalk.db")
CONFIG_RELATIVE = Path("user_config")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fingerprint_file(path: Path) -> dict[str, int] | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    if not path.is_file():
        return None
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}


def collect_fingerprint(profile: Path) -> dict[str, object]:
    database = profile / DATABASE_RELATIVE
    config = profile / CONFIG_RELATIVE
    db_fingerprint = _fingerprint_file(database)
    config_fingerprint = _fingerprint_file(config)
    if db_fingerprint is None or config_fingerprint is None:
        raise RuntimeError("required DingTalk profile files are unavailable")
    wal = database.with_name(database.name + "-wal")
    return {
        "database": db_fingerprint,
        "wal": _fingerprint_file(wal),
        "user_config": config_fingerprint,
    }


def fingerprint_token(fingerprint: dict[str, object]) -> str:
    encoded = json.dumps(
        fingerprint, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _copy_private(source: Path, destination: Path) -> dict[str, object]:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    temporary = destination.with_name(destination.name + ".partial")
    if destination.exists() or temporary.exists():
        raise FileExistsError("refusing to overwrite a staged file")
    source_hash = decryptor._sha256(source)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
            descriptor = -1
            shutil.copyfileobj(input_file, output_file, 1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    copied_hash = decryptor._sha256(temporary)
    if copied_hash != source_hash:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("staged copy hash mismatch")
    os.replace(temporary, destination)
    os.chmod(destination, 0o600)
    return {"size": destination.stat().st_size, "sha256": copied_hash}


def _copy_candidate(
    profile: Path, candidate: Path, attempts: int
) -> tuple[dict[str, object], int, dict[str, object]]:
    last_reason = "source_changed_during_copy"
    for attempt in range(1, attempts + 1):
        encrypted = candidate / "encrypted"
        if encrypted.exists():
            shutil.rmtree(encrypted)
        before = collect_fingerprint(profile)
        try:
            inventory: dict[str, object] = {
                "database": _copy_private(
                    profile / DATABASE_RELATIVE, encrypted / DATABASE_RELATIVE
                ),
                "user_config": _copy_private(
                    profile / CONFIG_RELATIVE, encrypted / CONFIG_RELATIVE
                ),
            }
            source_wal = (profile / DATABASE_RELATIVE).with_name("dingtalk.db-wal")
            if before["wal"] is not None:
                inventory["wal"] = _copy_private(
                    source_wal,
                    (encrypted / DATABASE_RELATIVE).with_name("dingtalk.db-wal"),
                )
        except (FileNotFoundError, RuntimeError):
            last_reason = "source_changed_during_copy"
            continue
        after = collect_fingerprint(profile)
        if before == after:
            return after, attempt, inventory
    raise RuntimeError(last_reason)


def _write_private_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + ".partial")
    if temporary.exists():
        raise FileExistsError("refusing to overwrite a partial receipt")
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def capture_generation(
    profile: Path, output_root: Path, uid: str, attempts: int = 3
) -> dict[str, object]:
    profile = profile.resolve(strict=True)
    output_root = output_root.resolve()
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output_root, 0o700)
    generations = output_root / "generations"
    generations.mkdir(mode=0o700, exist_ok=True)
    os.chmod(generations, 0o700)
    state_file = output_root / "state.json"
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        state = {"schema": SCHEMA}

    initial = collect_fingerprint(profile)
    initial_token = fingerprint_token(initial)
    if state.get("schema") == SCHEMA and state.get("last_captured_token") == initial_token:
        return {
            "status": "UNCHANGED",
            "source_modified": False,
            "process_attached": False,
            "network_accessed": False,
        }

    candidate = Path(tempfile.mkdtemp(prefix=".candidate-", dir=generations))
    try:
        fingerprint, copy_attempts, inventory = _copy_candidate(
            profile, candidate, attempts
        )
        token = fingerprint_token(fingerprint)
        encrypted = candidate / "encrypted"
        database = encrypted / DATABASE_RELATIVE
        wal_candidate = database.with_name("dingtalk.db-wal")
        wal = wal_candidate if wal_candidate.is_file() else None
        config_path = encrypted / CONFIG_RELATIVE
        config = decryptor._load_config(config_path)
        key = decryptor._derive_codec_key(uid, config["salt"])
        decrypted = candidate / "decrypted" / "dingtalk.db"
        decryptor._decrypt_ecb_copy(database, decrypted, key)
        wal_result = decryptor._apply_wal(wal, decrypted, key)
        validation = decryptor._validate_sqlite(decrypted)
        generation_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + token[:12]
        )
        destination = generations / generation_id
        if destination.exists():
            raise RuntimeError("generation destination already exists")
        account_binding = hashlib.sha256(
            (uid + config["salt_md5"]).encode("ascii")
        ).hexdigest()
        receipt: dict[str, object] = {
            "schema": SCHEMA,
            "status": "COMPLETE",
            "captured_at": _utc_now(),
            "generation_id": generation_id,
            "fingerprint_token": token,
            "copy_attempts": copy_attempts,
            "account_binding_sha256": account_binding,
            "inventory": inventory,
            "decrypted_database": {
                "relative_path": "decrypted/dingtalk.db",
                "sha256": decryptor._sha256(decrypted),
                "wal": wal_result,
                **validation,
            },
            "source_modified": False,
            "process_attached": False,
            "network_accessed": False,
            "login_bypassed": False,
            "secret_reported": False,
        }
        _write_private_json(candidate / "receipt.json", receipt)
        os.replace(candidate, destination)
        _write_private_json(
            state_file,
            {
                "schema": SCHEMA,
                "last_captured_at": receipt["captured_at"],
                "last_generation_id": generation_id,
                "last_captured_token": token,
                "last_captured_fingerprint": fingerprint,
                "account_binding_sha256": account_binding,
            },
        )
        return {
            "status": "COMPLETE",
            "generation_id": generation_id,
            "quick_check": validation["quick_check"],
            "wal_applied_frames": wal_result["applied_frames"],
            "source_modified": False,
            "process_attached": False,
            "network_accessed": False,
            "login_bypassed": False,
            "message_bodies_read": False,
        }
    except Exception:
        shutil.rmtree(candidate, ignore_errors=True)
        raise
    finally:
        if candidate.exists():
            shutil.rmtree(candidate, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--uid", required=True)
    parser.add_argument("--attempts", type=int, default=3)
    args = parser.parse_args()
    if not args.uid.isdecimal():
        parser.error("--uid must be decimal")
    if args.attempts < 1 or args.attempts > 10:
        parser.error("--attempts must be between 1 and 10")
    result = capture_generation(
        args.profile, args.output_root, args.uid, args.attempts
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"capture_error={type(exc).__name__}: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
