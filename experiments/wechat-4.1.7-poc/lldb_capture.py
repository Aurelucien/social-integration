from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import poc

try:
    import wechat_snapshot
except ImportError:
    wechat_snapshot = None


PASSPHRASE_SIZE = 32
PBKDF2_ROUNDS = 256_000


def derive_verified_key(passphrase: bytes, page1: bytes) -> bytes | None:
    if len(passphrase) != PASSPHRASE_SIZE:
        return None
    salt = page1[: poc.SALT_SIZE]
    key = hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, PBKDF2_ROUNDS, dklen=poc.KEY_SIZE
    )
    return key if poc.verify_key(key, page1) else None


def _save_verified_key(key: bytes) -> None:
    poc._write_private_json(
        poc.KEY_FILE,
        {
            "schema": "wechat-4.1.7-verified-key/v1",
            "enc_key": key.hex(),
            "verification": "page1_hmac_sha512",
        },
    )
    poc._update_receipt(
        acquisition={
            "status": "COMPLETE",
            "method": "lldb_pbkdf2_breakpoint",
            "page1_hmac_verified": True,
            "passphrase_saved": False,
            "secret_reported": False,
        }
    )


def capture_passphrase(frame, breakpoint_location, internal_dict) -> bool:
    process = frame.GetThread().GetProcess()
    password_length = frame.FindRegister("x2").GetValueAsUnsigned()
    salt_length = frame.FindRegister("x4").GetValueAsUnsigned()
    rounds = frame.FindRegister("x6").GetValueAsUnsigned()
    if (
        password_length != PASSPHRASE_SIZE
        or salt_length != poc.SALT_SIZE
        or rounds != PBKDF2_ROUNDS
    ):
        return False

    password_address = frame.FindRegister("x1").GetValueAsUnsigned()
    import lldb

    read_error = lldb.SBError()
    passphrase = process.ReadMemory(
        password_address, PASSPHRASE_SIZE, read_error
    )
    if not read_error.Success() or len(passphrase) != PASSPHRASE_SIZE:
        return False

    if wechat_snapshot is not None and wechat_snapshot.MANIFEST_FILE.is_file():
        keys = wechat_snapshot.derive_verified_keys(passphrase)
        if wechat_snapshot.PRIMARY_TARGETS.issubset(keys):
            wechat_snapshot.save_verified_keys(keys)
            session_key = keys.get("session/session.db")
            if session_key:
                _save_verified_key(bytes.fromhex(session_key))
            print(
                json.dumps(
                    {
                        "status": "COMPLETE",
                        "method": "lldb_pbkdf2_breakpoint_multi_db",
                        "verified_key_count": len(keys),
                        "passphrase_saved": False,
                        "secret_reported": False,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return True

    key = derive_verified_key(passphrase, poc._page1())
    if key is None:
        return False

    _save_verified_key(key)
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "method": "lldb_pbkdf2_breakpoint",
                "page1_hmac_verified": True,
                "passphrase_saved": False,
                "secret_reported": False,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return True
