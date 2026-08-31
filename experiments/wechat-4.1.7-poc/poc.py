#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
HMAC_SIZE = 64
RESERVE_SIZE = 80
SQLITE_HEADER = b"SQLite format 3\x00"
KEY_PATTERN = re.compile(rb"x'([0-9a-f]{96})'")
CHUNK_SIZE = 4 * 1024 * 1024

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
ENCRYPTED_DB = PRIVATE / "encrypted/session.db"
DECRYPTED_DB = PRIVATE / "decrypted/session.db"
KEY_FILE = PRIVATE / "key.json"
RECEIPT_FILE = PRIVATE / "receipt.json"
XWECHAT_ROOT = (
    Path.home()
    / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)

KERN_SUCCESS = 0
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 9
VM_PROT_READ = 0x01


class VmRegionBasicInfo64(ctypes.Structure):
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("shared", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("behavior", ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]


LIBSYSTEM = ctypes.CDLL(ctypes.util.find_library("System"))
LIBSYSTEM.task_for_pid.argtypes = [
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint32),
]
LIBSYSTEM.task_for_pid.restype = ctypes.c_int
LIBSYSTEM.mach_vm_region.argtypes = [
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
]
LIBSYSTEM.mach_vm_region.restype = ctypes.c_int
LIBSYSTEM.mach_vm_read_overwrite.argtypes = [
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint64),
]
LIBSYSTEM.mach_vm_read_overwrite.restype = ctypes.c_int
LIBSYSTEM.mach_port_deallocate.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
LIBSYSTEM.mach_port_deallocate.restype = ctypes.c_int
LIBSYSTEM.CCCrypt.argtypes = [
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
LIBSYSTEM.CCCrypt.restype = ctypes.c_int32


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_private() -> None:
    PRIVATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(PRIVATE, 0o700)


def _write_private_json(path: Path, payload: dict) -> None:
    _prepare_private()
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as destination:
        json.dump(payload, destination, ensure_ascii=False, indent=2, sort_keys=True)
        destination.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_receipt() -> dict:
    try:
        return json.loads(RECEIPT_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"schema": "wechat-4.1.7-single-db-poc/v1"}


def _update_receipt(**updates: object) -> None:
    receipt = _read_receipt()
    receipt.update(updates)
    _write_private_json(RECEIPT_FILE, receipt)


def _profile_roots() -> list[Path]:
    if not XWECHAT_ROOT.is_dir():
        return []
    return sorted(
        path
        for path in XWECHAT_ROOT.iterdir()
        if path.is_dir()
        and path.name not in {"all_users", "Backup"}
        and (path / "db_storage").is_dir()
    )


def stage() -> int:
    profiles = _profile_roots()
    candidates = [
        profile / "db_storage/session/session.db"
        for profile in profiles
        if (profile / "db_storage/session/session.db").is_file()
    ]
    if len(candidates) != 1:
        print(json.dumps({"status": "STOPPED", "reason": "expected_one_session_db"}))
        return 2
    source = candidates[0]
    if source.stat().st_size < PAGE_SIZE:
        print(json.dumps({"status": "STOPPED", "reason": "database_too_small"}))
        return 2
    _prepare_private()
    ENCRYPTED_DB.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = ENCRYPTED_DB.with_suffix(".db.tmp")
    shutil.copyfile(source, temporary)
    os.chmod(temporary, 0o600)
    os.replace(temporary, ENCRYPTED_DB)
    source_hash = _sha256(source)
    staged_hash = _sha256(ENCRYPTED_DB)
    if source_hash != staged_hash:
        print(json.dumps({"status": "STOPPED", "reason": "snapshot_hash_mismatch"}))
        return 2
    _update_receipt(
        stage={
            "status": "COMPLETE",
            "source_kind": "live_read_only_session_db",
            "source_account_reported": False,
            "source_sha256": source_hash,
            "staged_sha256": staged_hash,
            "size": ENCRYPTED_DB.stat().st_size,
        }
    )
    print(json.dumps({"status": "COMPLETE", "artifact": "encrypted/session.db"}))
    return 0


def _page1() -> bytes:
    with ENCRYPTED_DB.open("rb") as source:
        page = source.read(PAGE_SIZE)
    if len(page) != PAGE_SIZE:
        raise RuntimeError("staged database does not contain a complete first page")
    return page


def verify_key(key: bytes, page1: bytes) -> bool:
    if len(key) != KEY_SIZE:
        return False
    salt = page1[:SALT_SIZE]
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=KEY_SIZE)
    authenticated = page1[SALT_SIZE : PAGE_SIZE - RESERVE_SIZE + 16]
    stored = page1[PAGE_SIZE - HMAC_SIZE : PAGE_SIZE]
    calculated = hmac.new(mac_key, authenticated, hashlib.sha512)
    calculated.update(struct.pack("<I", 1))
    return hmac.compare_digest(calculated.digest(), stored)


def _wechat_pids() -> list[int]:
    result = subprocess.run(
        ["pgrep", "-x", "WeChat"], capture_output=True, text=True, check=False
    )
    return [int(value) for value in result.stdout.split() if value.isdigit()]


def _task_for_pid(pid: int) -> int | None:
    task = ctypes.c_uint32(0)
    status = LIBSYSTEM.task_for_pid(
        LIBSYSTEM.mach_task_self(), ctypes.c_int(pid), ctypes.byref(task)
    )
    return task.value if status == KERN_SUCCESS else None


def _readable_regions(task: int):
    address = ctypes.c_uint64(0)
    while True:
        size = ctypes.c_uint64(0)
        info = VmRegionBasicInfo64()
        count = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
        object_name = ctypes.c_uint32(0)
        status = LIBSYSTEM.mach_vm_region(
            ctypes.c_uint32(task),
            ctypes.byref(address),
            ctypes.byref(size),
            ctypes.c_int(VM_REGION_BASIC_INFO_64),
            ctypes.byref(info),
            ctypes.byref(count),
            ctypes.byref(object_name),
        )
        if status != KERN_SUCCESS:
            return
        start = address.value
        length = size.value
        if info.protection & VM_PROT_READ and length:
            yield start, length
        next_address = start + length
        if next_address <= start:
            return
        address.value = next_address


def _read_chunk(task: int, address: int, size: int) -> bytes | None:
    buffer = ctypes.create_string_buffer(size)
    copied = ctypes.c_uint64(0)
    status = LIBSYSTEM.mach_vm_read_overwrite(
        ctypes.c_uint32(task),
        ctypes.c_uint64(address),
        ctypes.c_uint64(size),
        ctypes.c_uint64(ctypes.addressof(buffer)),
        ctypes.byref(copied),
    )
    if status != KERN_SUCCESS or not copied.value:
        return None
    return buffer.raw[: copied.value]


def scan_raw() -> int:
    if not ENCRYPTED_DB.is_file():
        print(json.dumps({"status": "STOPPED", "reason": "run_stage_first"}))
        return 2
    pids = _wechat_pids()
    if not pids:
        print(json.dumps({"status": "STOPPED", "reason": "wechat_not_running"}))
        return 2
    page1 = _page1()
    target_salt = page1[:SALT_SIZE].hex()
    readable_processes = 0
    for pid in pids:
        task = _task_for_pid(pid)
        if task is None:
            continue
        readable_processes += 1
        try:
            for base, region_size in _readable_regions(task):
                offset = 0
                carry = b""
                while offset < region_size:
                    amount = min(CHUNK_SIZE, region_size - offset)
                    data = _read_chunk(task, base + offset, amount)
                    if data:
                        combined = carry + data
                        for match in KEY_PATTERN.finditer(combined):
                            candidate = match.group(1).decode("ascii")
                            if candidate[64:] != target_salt:
                                continue
                            key = bytes.fromhex(candidate[:64])
                            if verify_key(key, page1):
                                _write_private_json(
                                    KEY_FILE,
                                    {
                                        "schema": "wechat-4.1.7-verified-key/v1",
                                        "enc_key": key.hex(),
                                        "verification": "page1_hmac_sha512",
                                    },
                                )
                                _update_receipt(
                                    acquisition={
                                        "status": "COMPLETE",
                                        "method": "raw_memory_pattern",
                                        "page1_hmac_verified": True,
                                        "secret_reported": False,
                                    }
                                )
                                print(
                                    json.dumps(
                                        {
                                            "status": "COMPLETE",
                                            "method": "raw_memory_pattern",
                                            "page1_hmac_verified": True,
                                        }
                                    )
                                )
                                return 0
                        carry = combined[-128:]
                    offset += amount
        finally:
            LIBSYSTEM.mach_port_deallocate(LIBSYSTEM.mach_task_self(), task)
    if not readable_processes:
        status = "TASK_FOR_PID_DENIED"
        code = 2
    else:
        status = "RAW_KEY_NOT_FOUND"
        code = 3
    _update_receipt(
        acquisition={"status": status, "page1_hmac_verified": False}
    )
    print(json.dumps({"status": status, "page1_hmac_verified": False}))
    return code


def _decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    output = ctypes.create_string_buffer(len(ciphertext) + 32)
    output_size = ctypes.c_size_t(0)
    status = LIBSYSTEM.CCCrypt(
        1,
        0,
        0,
        key,
        len(key),
        iv,
        ciphertext,
        len(ciphertext),
        output,
        len(output),
        ctypes.byref(output_size),
    )
    if status != 0:
        raise RuntimeError(f"CommonCrypto status {status}")
    return output.raw[: output_size.value]


def _decrypt_page(key: bytes, page: bytes, number: int) -> bytes:
    iv_offset = PAGE_SIZE - RESERVE_SIZE
    iv = page[iv_offset : iv_offset + 16]
    if number == 1:
        ciphertext = page[SALT_SIZE:iv_offset]
        plaintext = _decrypt_aes_cbc(key, iv, ciphertext)
        return SQLITE_HEADER + plaintext + (b"\x00" * RESERVE_SIZE)
    ciphertext = page[:iv_offset]
    plaintext = _decrypt_aes_cbc(key, iv, ciphertext)
    return plaintext + (b"\x00" * RESERVE_SIZE)


def decrypt() -> int:
    if not ENCRYPTED_DB.is_file() or not KEY_FILE.is_file():
        print(json.dumps({"status": "STOPPED", "reason": "stage_or_key_missing"}))
        return 2
    key_payload = json.loads(KEY_FILE.read_text(encoding="utf-8"))
    key = bytes.fromhex(key_payload["enc_key"])
    first_page = _page1()
    if not verify_key(key, first_page):
        print(json.dumps({"status": "STOPPED", "reason": "hmac_reverification_failed"}))
        return 2
    size = ENCRYPTED_DB.stat().st_size
    if size % PAGE_SIZE:
        print(json.dumps({"status": "STOPPED", "reason": "unaligned_database_size"}))
        return 2
    DECRYPTED_DB.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = DECRYPTED_DB.with_suffix(".db.tmp")
    with ENCRYPTED_DB.open("rb") as source, temporary.open("wb") as destination:
        for number in range(1, size // PAGE_SIZE + 1):
            page = source.read(PAGE_SIZE)
            destination.write(_decrypt_page(key, page, number))
    os.chmod(temporary, 0o600)
    with temporary.open("rb") as candidate:
        header_ok = candidate.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    if not header_ok:
        temporary.unlink(missing_ok=True)
        print(json.dumps({"status": "STOPPED", "reason": "sqlite_header_missing"}))
        return 2
    os.replace(temporary, DECRYPTED_DB)
    _update_receipt(
        decryption={
            "status": "COMPLETE",
            "input_kind": "staged_copy",
            "page1_hmac_reverified": True,
            "sqlite_header_verified": True,
            "rows_queried": False,
            "page_count": size // PAGE_SIZE,
            "output_sha256": _sha256(DECRYPTED_DB),
        }
    )
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "sqlite_header_verified": True,
                "rows_queried": False,
            }
        )
    )
    return 0


def status() -> int:
    receipt = _read_receipt()
    result = {
        "schema": receipt.get("schema"),
        "stage": receipt.get("stage", {}).get("status", "NOT_RUN"),
        "acquisition": receipt.get("acquisition", {}).get("status", "NOT_RUN"),
        "decryption": receipt.get("decryption", {}).get("status", "NOT_RUN"),
        "secret_files_present": KEY_FILE.is_file(),
        "decrypted_copy_present": DECRYPTED_DB.is_file(),
        "message_rows_queried": receipt.get("decryption", {}).get(
            "rows_queried", False
        ),
    }
    print(json.dumps(result, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("stage", "scan-raw", "decrypt", "status"))
    args = parser.parse_args()
    return {
        "stage": stage,
        "scan-raw": scan_raw,
        "decrypt": decrypt,
        "status": status,
    }[args.command]()


if __name__ == "__main__":
    sys.exit(main())
