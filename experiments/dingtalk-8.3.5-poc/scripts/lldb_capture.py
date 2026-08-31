"""LLDB callback for a verified DingTalk 8.3.5 database AES key.

The callback observes only AES key-setup calls in the disposable PoC process.
A candidate is persisted only when it decrypts the staged database page-1
header into independently valid SQLite header fields.  No SQL is executed and
no candidate key is printed.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path


SQLITE_HEADER = b"SQLite format 3\x00"
VALID_PAGE_SIZES = {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
OPENSSL_LIBCRYPTO = Path(
    "/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.dylib"
)

_crypto = None
_seen: set[str] = set()
_schedule_keys: dict[int, bytes] = {}
_complete = False
_db_cache: tuple[Path, bytes] | None = None


def _load_crypto():
    global _crypto
    if _crypto is not None:
        return _crypto
    library = ctypes.CDLL(str(OPENSSL_LIBCRYPTO))
    library.AES_set_decrypt_key.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
    )
    library.AES_set_decrypt_key.restype = ctypes.c_int
    library.AES_decrypt.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    library.AES_decrypt.restype = None
    _crypto = library
    return library


def _aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(key) not in (16, 24, 32) or len(block) != 16:
        raise ValueError("invalid AES input")
    library = _load_crypto()
    schedule = ctypes.create_string_buffer(244)
    key_buffer = ctypes.create_string_buffer(key, len(key))
    if library.AES_set_decrypt_key(key_buffer, len(key) * 8, schedule) != 0:
        raise RuntimeError("AES key setup failed")
    input_buffer = ctypes.create_string_buffer(block, len(block))
    output_buffer = ctypes.create_string_buffer(16)
    library.AES_decrypt(input_buffer, output_buffer, schedule)
    return output_buffer.raw


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _decrypt_page_prefix(key: bytes, encrypted: bytes) -> tuple[bytes, bytes]:
    if len(encrypted) < 112:
        raise ValueError("database page is too short")
    blocks = [encrypted[offset : offset + 16] for offset in range(0, 112, 16)]
    first_pre_xor = _aes_decrypt_block(key, blocks[0])
    iv = _xor(first_pre_xor, SQLITE_HEADER)
    plaintext = bytearray()
    previous = iv
    for block in blocks:
        plaintext.extend(_xor(_aes_decrypt_block(key, block), previous))
        previous = block
    return bytes(plaintext), iv


def _valid_sqlite_header(header: bytes) -> tuple[bool, dict[str, int]]:
    if len(header) < 100 or not header.startswith(SQLITE_HEADER):
        return False, {}
    raw_page_size = int.from_bytes(header[16:18], "big")
    page_size = 65536 if raw_page_size == 1 else raw_page_size
    detail = {
        "page_size": page_size,
        "write_version": header[18],
        "read_version": header[19],
        "reserve": header[20],
        "schema_format": int.from_bytes(header[44:48], "big"),
        "text_encoding": int.from_bytes(header[56:60], "big"),
    }
    valid = (
        page_size in VALID_PAGE_SIZES
        and detail["write_version"] in (1, 2)
        and detail["read_version"] in (1, 2)
        and tuple(header[21:24]) == (64, 32, 32)
        and detail["schema_format"] in (1, 2, 3, 4)
        and detail["text_encoding"] in (1, 2, 3)
    )
    return valid, detail


def _write_private(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if path.read_bytes() != payload:
            raise RuntimeError(f"refusing to overwrite changed capture: {path.name}")
        return
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def _persist_verified(
    key: bytes,
    iv: bytes,
    detail: dict[str, int],
    db: Path,
    method: str,
) -> None:
    capture_dir = Path(os.environ["DINGTALK_POC_CAPTURE_DIR"]).resolve()
    capture_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(capture_dir, 0o700)
    _write_private(capture_dir / "aes-key.bin", key)
    _write_private(capture_dir / "page1-iv.bin", iv)
    receipt = {
        "schema": "dingtalk-8.3.5-verified-aes-key/v1",
        "status": "COMPLETE",
        "method": method,
        "database": db.name,
        "database_sha256": hashlib.sha256(db.read_bytes()).hexdigest(),
        "key_bits": len(key) * 8,
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "page1_iv_sha256": hashlib.sha256(iv).hexdigest(),
        "verification": "sqlite_page1_header_structure",
        "header": detail,
        "secret_reported": False,
        "rows_queried": False,
    }
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    _write_private(capture_dir / "capture.json", payload)


def _read_memory(frame, address: int, size: int) -> bytes | None:
    import lldb

    error = lldb.SBError()
    payload = frame.GetThread().GetProcess().ReadMemory(address, size, error)
    return payload if error.Success() and len(payload) == size else None


def _database_prefix() -> tuple[Path, bytes]:
    global _db_cache
    if _db_cache is not None:
        return _db_cache
    db = Path(os.environ["DINGTALK_POC_DB"]).resolve()
    _db_cache = (db, db.read_bytes()[:112])
    return _db_cache


def _complete_capture(key: bytes, observed_iv: bytes | None, method: str) -> bool:
    global _complete
    db, encrypted = _database_prefix()
    header, derived_iv = _decrypt_page_prefix(key, encrypted)
    valid, detail = _valid_sqlite_header(header)
    if not valid or (observed_iv is not None and observed_iv != derived_iv):
        return False
    _persist_verified(key, derived_iv, detail, db, method)
    _complete = True
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "method": method,
                "page1_header_verified": True,
                "secret_reported": False,
                "rows_queried": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return True


def observe_key_setup(frame, breakpoint_location, internal_dict) -> bool:
    """Associate an observed raw key with its target AES schedule in memory."""
    del breakpoint_location, internal_dict
    if _complete:
        return True

    bits = frame.FindRegister("x1").GetValueAsUnsigned()
    if bits not in (128, 192, 256):
        return False
    key_address = frame.FindRegister("x0").GetValueAsUnsigned()
    schedule_address = frame.FindRegister("x2").GetValueAsUnsigned()
    key = _read_memory(frame, key_address, bits // 8)
    if key is None or schedule_address == 0:
        return False
    fingerprint = hashlib.sha256(key).hexdigest()
    _seen.add(fingerprint)
    _schedule_keys[schedule_address] = key
    return False


def capture_aes_cbc(frame, breakpoint_location, internal_dict) -> bool:
    """Accept only CBC decrypt calls over this account database's first block."""
    del breakpoint_location, internal_dict
    if _complete:
        return True
    input_address = frame.FindRegister("x0").GetValueAsUnsigned()
    length = frame.FindRegister("x2").GetValueAsUnsigned()
    schedule_address = frame.FindRegister("x3").GetValueAsUnsigned()
    iv_address = frame.FindRegister("x4").GetValueAsUnsigned()
    encrypt = frame.FindRegister("x5").GetValueAsUnsigned()
    if encrypt != 0 or length < 112:
        return False
    db, encrypted = _database_prefix()
    del db
    prefix = _read_memory(frame, input_address, 16)
    key = _schedule_keys.get(schedule_address)
    iv = _read_memory(frame, iv_address, 16)
    if prefix != encrypted[:16] or key is None or iv is None:
        return False
    try:
        return _complete_capture(key, iv, "lldb_aes_cbc_first_block")
    except Exception:
        return False


def capture_aes_block(frame, breakpoint_location, internal_dict) -> bool:
    """Recognize a manual AES mode by its database first ciphertext block."""
    del breakpoint_location, internal_dict
    if _complete:
        return True
    input_address = frame.FindRegister("x0").GetValueAsUnsigned()
    schedule_address = frame.FindRegister("x2").GetValueAsUnsigned()
    db, encrypted = _database_prefix()
    del db
    prefix = _read_memory(frame, input_address, 16)
    key = _schedule_keys.get(schedule_address)
    if prefix != encrypted[:16] or key is None:
        return False
    try:
        return _complete_capture(key, None, "lldb_aes_block_first_block")
    except Exception:
        return False


def capture_cccrypt(frame, breakpoint_location, internal_dict) -> bool:
    """Recognize CommonCrypto AES decrypt over the database first block."""
    del breakpoint_location, internal_dict
    if _complete:
        return True
    operation = frame.FindRegister("x0").GetValueAsUnsigned()
    algorithm = frame.FindRegister("x1").GetValueAsUnsigned()
    key_address = frame.FindRegister("x3").GetValueAsUnsigned()
    key_length = frame.FindRegister("x4").GetValueAsUnsigned()
    iv_address = frame.FindRegister("x5").GetValueAsUnsigned()
    input_address = frame.FindRegister("x6").GetValueAsUnsigned()
    input_length = frame.FindRegister("x7").GetValueAsUnsigned()
    if operation != 1 or algorithm != 0 or key_length not in (16, 24, 32):
        return False
    if input_length < 112:
        return False
    db, encrypted = _database_prefix()
    del db
    prefix = _read_memory(frame, input_address, 16)
    key = _read_memory(frame, key_address, key_length)
    iv = bytes(16) if iv_address == 0 else _read_memory(frame, iv_address, 16)
    if prefix != encrypted[:16] or key is None or iv is None:
        return False
    try:
        return _complete_capture(key, iv, "lldb_cccrypt_first_block")
    except Exception:
        return False


# Backward-compatible callback name for any retained local command files.
capture_key = observe_key_setup
