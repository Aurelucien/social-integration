#!/usr/bin/env python3
"""Decrypt one copied DingTalk 8.3.5 ArkSQLite database, read-only.

The source is never opened by SQLite and never modified.  The produced copy is
accepted only after SQLite's own quick_check succeeds.  Validation records
schema counts only; it does not read table rows or message bodies.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import sqlite3
from pathlib import Path


LIBCRYPTO_CANDIDATES = (
    Path("/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib"),
    Path("/opt/homebrew/lib/libcrypto.dylib"),
)
SQLITE_HEADER = b"SQLite format 3\x00"
PAGE_SIZE = 4096
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def _load_config(path: Path) -> dict[str, str]:
    value = json.loads(base64.b64decode(path.read_bytes(), validate=True))
    if not isinstance(value, dict):
        raise ValueError("user_config is not an object")
    salt = value.get("salt")
    salt_md5 = value.get("salt_md5")
    if not isinstance(salt, str) or not isinstance(salt_md5, str):
        raise ValueError("user_config is missing salt metadata")
    if hashlib.md5(salt.encode("ascii")).hexdigest() != salt_md5:
        raise ValueError("user_config salt metadata is invalid")
    return {"salt": salt, "salt_md5": salt_md5}


def _derive_codec_key(uid: str, salt: str) -> bytes:
    outer = hashlib.pbkdf2_hmac(
        "sha1",
        (uid + salt).encode("ascii"),
        b"666DingTalk888"[:8],
        1_000,
        dklen=32,
    )
    passphrase = hashlib.md5(outer).hexdigest().encode("ascii")
    # ArkSQLite pads this passphrase to 44 bytes with 0x7b and expands only
    # the first 16 bytes as an AES-128 key.
    return passphrase[:16]


def _load_crypto():
    for candidate in LIBCRYPTO_CANDIDATES:
        if candidate.exists():
            library = ctypes.CDLL(str(candidate))
            break
    else:
        raise RuntimeError("OpenSSL libcrypto was not found")

    library.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    library.EVP_CIPHER_CTX_free.argtypes = (ctypes.c_void_p,)
    library.EVP_aes_128_ecb.restype = ctypes.c_void_p
    library.EVP_DecryptInit_ex.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    library.EVP_DecryptInit_ex.restype = ctypes.c_int
    library.EVP_CIPHER_CTX_set_padding.argtypes = (ctypes.c_void_p, ctypes.c_int)
    library.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int
    library.EVP_DecryptUpdate.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_void_p,
        ctypes.c_int,
    )
    library.EVP_DecryptUpdate.restype = ctypes.c_int
    library.EVP_DecryptFinal_ex.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    )
    library.EVP_DecryptFinal_ex.restype = ctypes.c_int
    return library


def _decrypt_bytes(library, payload: bytes, key: bytes) -> bytes:
    if len(payload) % 16:
        raise ValueError("encrypted payload is not AES-block aligned")
    context = library.EVP_CIPHER_CTX_new()
    if not context:
        raise RuntimeError("EVP context allocation failed")
    key_buffer = ctypes.create_string_buffer(key, len(key))
    try:
        cipher = library.EVP_aes_128_ecb()
        if library.EVP_DecryptInit_ex(context, cipher, None, key_buffer, None) != 1:
            raise RuntimeError("EVP decrypt initialization failed")
        if library.EVP_CIPHER_CTX_set_padding(context, 0) != 1:
            raise RuntimeError("EVP padding configuration failed")
        input_buffer = ctypes.create_string_buffer(payload, len(payload))
        output_buffer = ctypes.create_string_buffer(len(payload) + 16)
        output_length = ctypes.c_int()
        if library.EVP_DecryptUpdate(
            context,
            output_buffer,
            ctypes.byref(output_length),
            input_buffer,
            len(payload),
        ) != 1:
            raise RuntimeError("EVP decrypt update failed")
        final_buffer = ctypes.create_string_buffer(16)
        final_length = ctypes.c_int()
        if library.EVP_DecryptFinal_ex(
            context, final_buffer, ctypes.byref(final_length)
        ) != 1:
            raise RuntimeError("EVP decrypt finalization failed")
        return (
            output_buffer.raw[: output_length.value]
            + final_buffer.raw[: final_length.value]
        )
    finally:
        library.EVP_CIPHER_CTX_free(context)


def _decrypt_ecb_copy(source: Path, destination: Path, key: bytes) -> None:
    if source.stat().st_size % 16:
        raise ValueError("encrypted database size is not AES-block aligned")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination.parent, 0o700)
    partial = destination.with_name(destination.name + ".partial")
    if destination.exists() or partial.exists():
        raise FileExistsError("refusing to overwrite an existing output")

    library = _load_crypto()
    context = library.EVP_CIPHER_CTX_new()
    if not context:
        raise RuntimeError("EVP context allocation failed")
    key_buffer = ctypes.create_string_buffer(key, len(key))
    try:
        cipher = library.EVP_aes_128_ecb()
        if library.EVP_DecryptInit_ex(context, cipher, None, key_buffer, None) != 1:
            raise RuntimeError("EVP decrypt initialization failed")
        if library.EVP_CIPHER_CTX_set_padding(context, 0) != 1:
            raise RuntimeError("EVP padding configuration failed")

        descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
                descriptor = -1
                while chunk := input_file.read(1024 * 1024):
                    input_buffer = ctypes.create_string_buffer(chunk, len(chunk))
                    output_buffer = ctypes.create_string_buffer(len(chunk) + 16)
                    output_length = ctypes.c_int()
                    if library.EVP_DecryptUpdate(
                        context,
                        output_buffer,
                        ctypes.byref(output_length),
                        input_buffer,
                        len(chunk),
                    ) != 1:
                        raise RuntimeError("EVP decrypt update failed")
                    output_file.write(output_buffer.raw[: output_length.value])

                final_buffer = ctypes.create_string_buffer(16)
                final_length = ctypes.c_int()
                if library.EVP_DecryptFinal_ex(
                    context, final_buffer, ctypes.byref(final_length)
                ) != 1:
                    raise RuntimeError("EVP decrypt finalization failed")
                output_file.write(final_buffer.raw[: final_length.value])
                output_file.flush()
                os.fsync(output_file.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    finally:
        library.EVP_CIPHER_CTX_free(context)

    os.replace(partial, destination)
    os.chmod(destination, 0o600)


def _current_wal_frames(wal: Path) -> tuple[list[tuple[int, bytes]], int | None]:
    data = wal.read_bytes()
    if len(data) <= WAL_HEADER_SIZE:
        return [], None
    magic = int.from_bytes(data[0:4], "big")
    if magic not in (0x377F0682, 0x377F0683):
        raise ValueError("unexpected WAL magic")
    if int.from_bytes(data[8:12], "big") != PAGE_SIZE:
        raise ValueError("unexpected WAL page size")
    salt = data[16:24]
    frame_size = WAL_FRAME_HEADER_SIZE + PAGE_SIZE
    frames: list[tuple[int, int, bytes]] = []
    offset = WAL_HEADER_SIZE
    while offset + frame_size <= len(data):
        header = data[offset : offset + WAL_FRAME_HEADER_SIZE]
        page = data[offset + WAL_FRAME_HEADER_SIZE : offset + frame_size]
        offset += frame_size
        page_number = int.from_bytes(header[0:4], "big")
        commit_pages = int.from_bytes(header[4:8], "big")
        if page_number == 0 or page_number > 1_000_000 or header[8:16] != salt:
            continue
        frames.append((page_number, commit_pages, page))
    last_commit = next(
        (index for index in range(len(frames) - 1, -1, -1) if frames[index][1]),
        None,
    )
    if last_commit is None:
        return [], None
    committed = frames[: last_commit + 1]
    return [(page_number, page) for page_number, _commit, page in committed], committed[-1][1]


def _apply_wal(wal: Path | None, output: Path, key: bytes) -> dict[str, object]:
    if wal is None:
        return {"present": False, "applied_frames": 0, "commit_pages": None}
    frames, commit_pages = _current_wal_frames(wal)
    if not frames or commit_pages is None:
        return {
            "present": True,
            "sha256": _sha256(wal),
            "applied_frames": 0,
            "commit_pages": None,
        }
    library = _load_crypto()
    with output.open("r+b") as destination:
        for page_number, encrypted_page in frames:
            plaintext = _decrypt_bytes(library, encrypted_page, key)
            destination.seek((page_number - 1) * PAGE_SIZE)
            destination.write(plaintext)
        destination.truncate(commit_pages * PAGE_SIZE)
        destination.flush()
        os.fsync(destination.fileno())
    return {
        "present": True,
        "sha256": _sha256(wal),
        "applied_frames": len(frames),
        "commit_pages": commit_pages,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_sqlite(path: Path) -> dict[str, object]:
    if path.read_bytes()[:16] != SQLITE_HEADER:
        raise ValueError("decrypted output is missing the SQLite header")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        quick_check = [row[0] for row in connection.execute("PRAGMA quick_check")]
        if quick_check != ["ok"]:
            raise ValueError("SQLite quick_check failed")
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        schema_counts = {
            kind: count
            for kind, count in connection.execute(
                "SELECT type, count(*) FROM sqlite_master GROUP BY type ORDER BY type"
            )
        }
    finally:
        connection.close()
    return {
        "quick_check": "ok",
        "page_size": page_size,
        "page_count": page_count,
        "schema_counts": schema_counts,
        "rows_queried": False,
        "message_bodies_read": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--wal", type=Path)
    parser.add_argument("--user-config", required=True, type=Path)
    parser.add_argument("--uid", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if not args.uid.isdecimal():
        parser.error("--uid must be decimal")
    if args.receipt.exists():
        raise FileExistsError("refusing to overwrite an existing receipt")

    source = args.db.resolve(strict=True)
    wal = args.wal.resolve(strict=True) if args.wal is not None else None
    config = _load_config(args.user_config.resolve(strict=True))
    output = args.output.resolve()
    receipt_path = args.receipt.resolve()
    key = _derive_codec_key(args.uid, config["salt"])
    _decrypt_ecb_copy(source, output, key)
    try:
        wal_result = _apply_wal(wal, output, key)
        validation = _validate_sqlite(output)
    except Exception:
        output.unlink(missing_ok=True)
        raise

    receipt_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(receipt_path.parent, 0o700)
    receipt = {
        "schema": "dingtalk-8.3.5-personal-db-decrypt/v1",
        "status": "COMPLETE",
        "source_name": source.name,
        "source_sha256": _sha256(source),
        "output_name": output.name,
        "output_sha256": _sha256(output),
        "account_binding_sha256": hashlib.sha256(
            (args.uid + config["salt_md5"]).encode("ascii")
        ).hexdigest(),
        "codec": "ArkSQLite AES-128-ECB, account-derived key",
        "wal": wal_result,
        "secret_reported": False,
        "validation": validation,
    }
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "quick_check": "ok",
                "schema_counts": validation["schema_counts"],
                "rows_queried": False,
                "message_bodies_read": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"decrypt_error={type(exc).__name__}: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
