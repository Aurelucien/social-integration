#!/usr/bin/env python3
"""Probe DingTalk 8.3.5 database-key and page-codec candidates offline.

This script deliberately validates only SQLite page-header structure. It does
not issue SQL, enumerate tables, or print the derived database key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


SQLITE_HEADER = b"SQLite format 3\x00"
VALID_PAGE_SIZES = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}


@dataclass(frozen=True)
class CodecProfile:
    name: str
    page_size: int
    reserve: int
    kdf_hash: str | None
    kdf_iterations: int


PROFILES = (
    CodecProfile("sqlcipher-v4", 4096, 80, "sha512", 256_000),
    CodecProfile("sqlcipher-v3-4096", 4096, 48, "sha1", 64_000),
    CodecProfile("sqlcipher-v3-1024", 1024, 48, "sha1", 64_000),
    CodecProfile("direct-aes-4096-r48", 4096, 48, None, 0),
    CodecProfile("direct-aes-4096-r80", 4096, 80, None, 0),
    CodecProfile("direct-aes-1024-r48", 1024, 48, None, 0),
)


def decode_user_config(path: Path) -> dict[str, str]:
    encoded = path.read_bytes()
    decoded = base64.b64decode(encoded, validate=True)
    value = json.loads(decoded)
    if not isinstance(value, dict):
        raise ValueError("user_config does not decode to an object")
    salt = value.get("salt")
    salt_md5 = value.get("salt_md5")
    if not isinstance(salt, str) or not isinstance(salt_md5, str):
        raise ValueError("user_config is missing salt metadata")
    if hashlib.md5(salt.encode("ascii")).hexdigest() != salt_md5:
        raise ValueError("user_config salt_md5 check failed")
    return {"salt": salt, "salt_md5": salt_md5}


def derive_db_key(uid: str, salt: str) -> tuple[bytes, bytes, bytes]:
    # The local 8.3.5 binary embeds 666DingTalk888 and passes an 8-byte salt.
    pbkdf2 = hashlib.pbkdf2_hmac(
        "sha1",
        (uid + salt).encode("ascii"),
        b"666DingTalk888"[:8],
        1_000,
        dklen=32,
    )
    md5_raw = hashlib.md5(pbkdf2).digest()
    md5_ascii = hashlib.md5(pbkdf2).hexdigest().encode("ascii")
    return pbkdf2, md5_raw, md5_ascii


def openssl_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes | None:
    if len(key) not in (16, 24, 32) or len(iv) != 16 or len(ciphertext) % 16:
        return None
    cipher = {16: "aes-128-cbc", 24: "aes-192-cbc", 32: "aes-256-cbc"}[len(key)]
    result = subprocess.run(
        [
            "/opt/homebrew/bin/openssl",
            "enc",
            "-d",
            f"-{cipher}",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
            "-nopad",
        ],
        input=ciphertext,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def openssl_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes | None:
    if len(key) not in (16, 24, 32) or len(ciphertext) % 16:
        return None
    cipher = {16: "aes-128-ecb", 24: "aes-192-ecb", 32: "aes-256-ecb"}[len(key)]
    result = subprocess.run(
        [
            "/opt/homebrew/bin/openssl",
            "enc",
            "-d",
            f"-{cipher}",
            "-K",
            key.hex(),
            "-nopad",
        ],
        input=ciphertext,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor operands must have equal length")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def validate_sqlite_page1_content(content: bytes) -> tuple[bool, str]:
    """Validate decrypted page-1 bytes that start at SQLite offset 16."""
    if len(content) < 84:
        return False, "short"
    raw_page_size = int.from_bytes(content[0:2], "big")
    page_size = 65536 if raw_page_size == 1 else raw_page_size
    write_version, read_version, reserve = content[2], content[3], content[4]
    payload = tuple(content[5:8])
    schema_format = int.from_bytes(content[28:32], "big")
    text_encoding = int.from_bytes(content[40:44], "big")
    ok = (
        page_size in VALID_PAGE_SIZES
        and write_version in (1, 2)
        and read_version in (1, 2)
        and payload == (64, 32, 32)
        and schema_format in (1, 2, 3, 4)
        and text_encoding in (1, 2, 3)
    )
    detail = (
        f"page_size={page_size}, write={write_version}, read={read_version}, "
        f"reserve={reserve}, schema={schema_format}, encoding={text_encoding}"
    )
    return ok, detail


def key_material_candidates(file_salt: bytes, pbkdf2: bytes, md5_raw: bytes, md5_ascii: bytes):
    passphrases = {
        "md5-ascii": md5_ascii,
        "md5-raw": md5_raw,
        "outer-pbkdf2": pbkdf2,
        "engine-md5-ascii": hashlib.md5(md5_ascii).hexdigest().encode("ascii"),
        "engine-md5-raw": hashlib.md5(md5_ascii).digest(),
        "engine-sha256": hashlib.sha256(md5_ascii).digest(),
    }
    for profile in PROFILES:
        for key_name, material in passphrases.items():
            if profile.kdf_hash:
                key = hashlib.pbkdf2_hmac(
                    profile.kdf_hash,
                    material,
                    file_salt,
                    profile.kdf_iterations,
                    dklen=32,
                )
            else:
                key = material
            yield profile, key_name, key


def probe(db_path: Path, uid: str, config_path: Path) -> int:
    config = decode_user_config(config_path)
    pbkdf2, md5_raw, md5_ascii = derive_db_key(uid, config["salt"])
    data = db_path.read_bytes()
    if len(data) < 4096:
        raise ValueError("database is too small for the probe")
    file_salt = data[:16]
    matches: list[str] = []

    # SQLCipher-style page layouts: file salt replaces SQLite bytes 0..15,
    # encrypted page content begins at byte 16, and the IV sits in reserve.
    for profile, key_name, key in key_material_candidates(
        file_salt, pbkdf2, md5_raw, md5_ascii
    ):
        page = data[: profile.page_size]
        encrypted_end = profile.page_size - profile.reserve
        ciphertext = page[16:encrypted_end]
        iv = page[encrypted_end : encrypted_end + 16]
        plain = openssl_decrypt(ciphertext, key, iv)
        if plain is None:
            continue
        ok, detail = validate_sqlite_page1_content(plain)
        if ok:
            matches.append(f"{profile.name}/{key_name}: {detail}")

    # Simple container layouts occasionally use the leading 16 bytes as an IV.
    for key_name, key in {
        # DingTalk's embedded ArkSQLite codec copies the passphrase into a
        # 44-byte, 0x7b-padded buffer and expands only its first 16 bytes as
        # an AES-128 key.  The pager transform applies AES independently to
        # each 16-byte block.
        "ark-aes128-first16": md5_ascii[:16],
        "md5-ascii": md5_ascii,
        "md5-raw": md5_raw,
        "outer-pbkdf2": pbkdf2,
        "engine-md5-ascii": hashlib.md5(md5_ascii).hexdigest().encode("ascii"),
        "engine-md5-raw": hashlib.md5(md5_ascii).digest(),
        "engine-sha256": hashlib.sha256(md5_ascii).digest(),
    }.items():
        plain = openssl_decrypt(data[16:16 + 4096], key, data[:16])
        if plain and plain.startswith(SQLITE_HEADER):
            matches.append(f"whole-file-cbc/{key_name}: SQLite header")

        plain = openssl_decrypt(data[:4096], key, bytes(16))
        if plain and plain.startswith(SQLITE_HEADER):
            ok, detail = validate_sqlite_page1_content(plain[16:100])
            if ok:
                matches.append(f"zero-iv-cbc/{key_name}: {detail}")

        plain = openssl_decrypt_ecb(data[:4096], key)
        if plain and plain.startswith(SQLITE_HEADER):
            ok, detail = validate_sqlite_page1_content(plain[16:100])
            if ok:
                matches.append(f"ecb/{key_name}: {detail}")

        # A deterministic page codec can keep its IV outside the database.
        # SQLite's first 16 plaintext bytes are fixed, so derive that IV from
        # AES-ECB(C1) and then validate the independent bytes at offsets 16..99.
        first_block = openssl_decrypt_ecb(data[:16], key)
        if first_block is not None:
            derived_iv = xor_bytes(first_block, SQLITE_HEADER)
            page_plain = openssl_decrypt(data[:4096], key, derived_iv)
            if page_plain is not None and page_plain.startswith(SQLITE_HEADER):
                ok, detail = validate_sqlite_page1_content(page_plain[16:100])
                if ok:
                    iv_fingerprint = hashlib.sha256(derived_iv).hexdigest()[:16]
                    matches.append(
                        f"derived-iv-cbc/{key_name}: {detail}, "
                        f"iv_sha256_16={iv_fingerprint}"
                    )

    print(f"salt_metadata=valid; db_bytes={len(data)}; structural_matches={len(matches)}")
    for match in matches:
        print(match)
    return 0 if matches else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--user-config", required=True, type=Path)
    parser.add_argument("--uid", required=True)
    args = parser.parse_args()
    if not args.uid.isdecimal():
        parser.error("--uid must be decimal")
    return probe(args.db, args.uid, args.user_config)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"probe_error={type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
