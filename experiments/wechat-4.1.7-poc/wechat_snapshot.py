#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import poc


SCHEMA = "wechat-4.1.7-multi-db-snapshot/v1"
SNAPSHOT_ROOT = poc.PRIVATE / "snapshot"
ENCRYPTED_ROOT = SNAPSHOT_ROOT / "encrypted"
DECRYPTED_ROOT = SNAPSHOT_ROOT / "decrypted"
MANIFEST_FILE = SNAPSHOT_ROOT / "manifest.json"
KEYS_FILE = SNAPSHOT_ROOT / "keys.json"
RECEIPT_FILE = SNAPSHOT_ROOT / "receipt.json"

TARGETS = (
    "session/session.db",
    "contact/contact.db",
    "message/message_0.db",
    "message/message_1.db",
    "message/message_resource.db",
    "message/media_0.db",
    "message/media_1.db",
)
PRIMARY_TARGETS = {
    "session/session.db",
    "contact/contact.db",
    "message/message_0.db",
    "message/message_1.db",
}

WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def _write_private_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as destination:
        json.dump(payload, destination, ensure_ascii=False, indent=2, sort_keys=True)
        destination.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_private(source: Path, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    shutil.copyfile(source, temporary)
    os.chmod(temporary, 0o600)
    source_sha = _sha256(source)
    copied_sha = _sha256(temporary)
    if source_sha != copied_sha:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("snapshot hash mismatch")
    os.replace(temporary, destination)
    return {"size": destination.stat().st_size, "sha256": copied_sha}


def _wechat_running() -> bool:
    result = subprocess.run(
        ["pgrep", "-x", "WeChat"], capture_output=True, text=True, check=False
    )
    return bool(result.stdout.strip())


def stage() -> int:
    if _wechat_running():
        print(json.dumps({"status": "STOPPED", "reason": "wechat_must_be_closed"}))
        return 2
    profiles = poc._profile_roots()
    if len(profiles) != 1:
        print(json.dumps({"status": "STOPPED", "reason": "expected_one_profile"}))
        return 2
    source_root = profiles[0] / "db_storage"
    databases: list[dict] = []
    for relative in TARGETS:
        source = source_root / relative
        if not source.is_file():
            print(
                json.dumps(
                    {"status": "STOPPED", "reason": "required_database_missing", "database": relative}
                )
            )
            return 2
        destination = ENCRYPTED_ROOT / relative
        database = {"relative_path": relative, **_copy_private(source, destination)}
        wal_source = source.with_name(source.name + "-wal")
        if wal_source.is_file() and wal_source.stat().st_size:
            wal_destination = destination.with_name(destination.name + "-wal")
            database["wal"] = _copy_private(wal_source, wal_destination)
        databases.append(database)

    manifest = {
        "schema": SCHEMA,
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_closed": True,
        "account_reported": False,
        "databases": databases,
    }
    _write_private_json(MANIFEST_FILE, manifest)
    _write_private_json(
        RECEIPT_FILE,
        {
            "schema": SCHEMA,
            "stage": "COMPLETE",
            "database_count": len(databases),
            "source_closed": True,
            "keys": "NOT_RUN",
            "decryption": "NOT_RUN",
            "message_rows_queried": False,
        },
    )
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "database_count": len(databases),
                "wal_count": sum("wal" in item for item in databases),
                "account_reported": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _manifest() -> dict:
    return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))


def staged_databases() -> list[tuple[str, Path]]:
    manifest = _manifest()
    return [
        (item["relative_path"], ENCRYPTED_ROOT / item["relative_path"])
        for item in manifest["databases"]
    ]


def derive_verified_keys(passphrase: bytes) -> dict[str, str]:
    if len(passphrase) != 32 or not MANIFEST_FILE.is_file():
        return {}
    verified: dict[str, str] = {}
    for relative, database in staged_databases():
        with database.open("rb") as source:
            page1 = source.read(poc.PAGE_SIZE)
        if len(page1) != poc.PAGE_SIZE:
            continue
        key = hashlib.pbkdf2_hmac(
            "sha512", passphrase, page1[: poc.SALT_SIZE], 256_000, dklen=poc.KEY_SIZE
        )
        if poc.verify_key(key, page1):
            verified[relative] = key.hex()
    return verified


def save_verified_keys(keys: dict[str, str]) -> None:
    _write_private_json(
        KEYS_FILE,
        {
            "schema": "wechat-4.1.7-verified-keys/v1",
            "verification": "per_database_page1_hmac_sha512",
            "passphrase_saved": False,
            "keys": keys,
        },
    )
    receipt = json.loads(RECEIPT_FILE.read_text(encoding="utf-8"))
    receipt.update(
        {
            "keys": "COMPLETE" if PRIMARY_TARGETS.issubset(keys) else "PARTIAL",
            "verified_key_count": len(keys),
            "passphrase_saved": False,
        }
    )
    _write_private_json(RECEIPT_FILE, receipt)


def _mac_key(key: bytes, salt: bytes) -> bytes:
    mac_salt = bytes(value ^ 0x3A for value in salt)
    return hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=poc.KEY_SIZE)


def verify_page(key: bytes, mac_key: bytes, page: bytes, number: int, main_page1: bool) -> bool:
    if len(page) != poc.PAGE_SIZE:
        return False
    start = poc.SALT_SIZE if main_page1 else 0
    authenticated = page[start : poc.PAGE_SIZE - poc.RESERVE_SIZE + 16]
    stored = page[poc.PAGE_SIZE - poc.HMAC_SIZE :]
    calculated = hmac.new(mac_key, authenticated, hashlib.sha512)
    calculated.update(struct.pack("<I", number))
    return hmac.compare_digest(calculated.digest(), stored)


def _decrypt_main(database: Path, output: Path, key: bytes) -> tuple[int, bytes]:
    size = database.stat().st_size
    if size % poc.PAGE_SIZE:
        raise RuntimeError("unaligned database size")
    with database.open("rb") as source:
        first_page = source.read(poc.PAGE_SIZE)
    salt = first_page[: poc.SALT_SIZE]
    mac_key = _mac_key(key, salt)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output.parent, 0o700)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with database.open("rb") as source, temporary.open("wb") as destination:
        for number in range(1, size // poc.PAGE_SIZE + 1):
            page = source.read(poc.PAGE_SIZE)
            if not verify_page(key, mac_key, page, number, number == 1):
                temporary.unlink(missing_ok=True)
                raise RuntimeError(f"page HMAC failed at page {number}")
            destination.write(poc._decrypt_page(key, page, number))
    os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    return size // poc.PAGE_SIZE, mac_key


def _current_wal_frames(wal: Path) -> tuple[list[tuple[int, int, bytes]], int | None]:
    data = wal.read_bytes()
    if len(data) <= WAL_HEADER_SIZE:
        return [], None
    page_size = int.from_bytes(data[8:12], "big")
    if page_size != poc.PAGE_SIZE:
        raise RuntimeError("unexpected WAL page size")
    salt1 = data[16:20]
    salt2 = data[20:24]
    frame_size = WAL_FRAME_HEADER_SIZE + poc.PAGE_SIZE
    frames: list[tuple[int, int, bytes]] = []
    offset = WAL_HEADER_SIZE
    while offset + frame_size <= len(data):
        header = data[offset : offset + WAL_FRAME_HEADER_SIZE]
        page = data[offset + WAL_FRAME_HEADER_SIZE : offset + frame_size]
        offset += frame_size
        page_number = int.from_bytes(header[0:4], "big")
        commit_pages = int.from_bytes(header[4:8], "big")
        if page_number == 0 or page_number > 1_000_000:
            continue
        if header[8:12] != salt1 or header[12:16] != salt2:
            continue
        frames.append((page_number, commit_pages, page))
    last_commit = next(
        (index for index in range(len(frames) - 1, -1, -1) if frames[index][1] > 0),
        None,
    )
    if last_commit is None:
        return [], None
    committed = frames[: last_commit + 1]
    return committed, committed[-1][1]


def _apply_wal(wal: Path, output: Path, key: bytes, mac_key: bytes) -> dict:
    frames, commit_pages = _current_wal_frames(wal)
    if not frames or commit_pages is None:
        return {"applied_frames": 0, "commit_pages": None}
    with output.open("r+b") as destination:
        for page_number, _commit, page in frames:
            if not verify_page(key, mac_key, page, page_number, False):
                raise RuntimeError(f"WAL page HMAC failed at page {page_number}")
            plaintext = poc._decrypt_page(key, page, 2)
            destination.seek((page_number - 1) * poc.PAGE_SIZE)
            destination.write(plaintext)
        destination.truncate(commit_pages * poc.PAGE_SIZE)
    return {"applied_frames": len(frames), "commit_pages": commit_pages}


def _quick_check(path: Path) -> str:
    uri = f"file:{path}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        row = connection.execute("PRAGMA quick_check").fetchone()
        return str(row[0]) if row else "no_result"
    finally:
        connection.close()


def decrypt() -> int:
    if not MANIFEST_FILE.is_file() or not KEYS_FILE.is_file():
        print(json.dumps({"status": "STOPPED", "reason": "stage_or_keys_missing"}))
        return 2
    key_payload = json.loads(KEYS_FILE.read_text(encoding="utf-8"))["keys"]
    results: list[dict] = []
    for relative, database in staged_databases():
        key_hex = key_payload.get(relative)
        if not key_hex:
            continue
        key = bytes.fromhex(key_hex)
        output = DECRYPTED_ROOT / relative
        page_count, mac_key = _decrypt_main(database, output, key)
        wal = database.with_name(database.name + "-wal")
        wal_result = (
            _apply_wal(wal, output, key, mac_key)
            if wal.is_file() and wal.stat().st_size
            else {"applied_frames": 0, "commit_pages": None}
        )
        quick_check = _quick_check(output)
        if quick_check != "ok":
            raise RuntimeError(f"quick_check failed for {relative}: {quick_check}")
        results.append(
            {
                "relative_path": relative,
                "page_count": page_count,
                "wal": wal_result,
                "quick_check": quick_check,
                "sha256": _sha256(output),
            }
        )
    receipt = json.loads(RECEIPT_FILE.read_text(encoding="utf-8"))
    receipt.update(
        {
            "decryption": "COMPLETE" if PRIMARY_TARGETS.issubset(
                item["relative_path"] for item in results
            ) else "PARTIAL",
            "decrypted_database_count": len(results),
            "databases": results,
            "message_rows_queried": False,
        }
    )
    _write_private_json(RECEIPT_FILE, receipt)
    print(
        json.dumps(
            {
                "status": receipt["decryption"],
                "decrypted_database_count": len(results),
                "quick_check_ok": sum(item["quick_check"] == "ok" for item in results),
                "message_rows_queried": False,
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["decryption"] == "COMPLETE" else 3


def status() -> int:
    try:
        receipt = json.loads(RECEIPT_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        receipt = {"schema": SCHEMA}
    print(
        json.dumps(
            {
                "schema": receipt.get("schema", SCHEMA),
                "stage": receipt.get("stage", "NOT_RUN"),
                "keys": receipt.get("keys", "NOT_RUN"),
                "decryption": receipt.get("decryption", "NOT_RUN"),
                "database_count": receipt.get("database_count", 0),
                "verified_key_count": receipt.get("verified_key_count", 0),
                "decrypted_database_count": receipt.get("decrypted_database_count", 0),
                "passphrase_saved": receipt.get("passphrase_saved", False),
                "message_rows_queried": receipt.get("message_rows_queried", False),
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("stage", "decrypt", "status"))
    args = parser.parse_args()
    return {"stage": stage, "decrypt": decrypt, "status": status}[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
