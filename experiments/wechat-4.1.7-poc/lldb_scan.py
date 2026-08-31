from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import poc


KEY_PATTERN = re.compile(rb"x'([0-9a-fA-F]{96})'")
CHUNK_SIZE = 4 * 1024 * 1024
OVERLAP_SIZE = 128


def verified_key_in_bytes(
    data: bytes, target_salt: str, page1: bytes
) -> bytes | None:
    for match in KEY_PATTERN.finditer(data):
        candidate = match.group(1).decode("ascii").lower()
        if candidate[64:] != target_salt:
            continue
        key = bytes.fromhex(candidate[:64])
        if poc.verify_key(key, page1):
            return key
    return None


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
            "method": "lldb_memory_pattern",
            "page1_hmac_verified": True,
            "secret_reported": False,
        }
    )


def scan_wechat_key(debugger, command, result, internal_dict) -> None:
    # Imported lazily so the matching and verification logic remains unit-testable
    # with the system Python outside LLDB.
    import lldb

    if not poc.ENCRYPTED_DB.is_file():
        result.SetError("STAGED_DATABASE_MISSING")
        return

    page1 = poc._page1()
    target_salt = page1[: poc.SALT_SIZE].hex()
    process = debugger.GetSelectedTarget().GetProcess()
    if not process.IsValid():
        result.SetError("LLDB_PROCESS_INVALID")
        return

    regions = process.GetMemoryRegions()
    scanned_regions = 0
    readable_bytes = 0
    read_error = lldb.SBError()

    for index in range(regions.GetSize()):
        region = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(index, region):
            continue
        if not region.IsReadable():
            continue
        start = region.GetRegionBase()
        end = region.GetRegionEnd()
        if end <= start:
            continue

        scanned_regions += 1
        address = start
        carry = b""
        while address < end:
            amount = min(CHUNK_SIZE, end - address)
            read_error.Clear()
            data = process.ReadMemory(address, amount, read_error)
            if data:
                readable_bytes += len(data)
                combined = carry + data
                key = verified_key_in_bytes(combined, target_salt, page1)
                if key is not None:
                    _save_verified_key(key)
                    result.AppendMessage(
                        json.dumps(
                            {
                                "status": "COMPLETE",
                                "method": "lldb_memory_pattern",
                                "page1_hmac_verified": True,
                                "secret_reported": False,
                            },
                            sort_keys=True,
                        )
                    )
                    return
                carry = combined[-OVERLAP_SIZE:]
            else:
                carry = b""
            address += amount

    poc._update_receipt(
        acquisition={
            "status": "RAW_KEY_NOT_FOUND",
            "method": "lldb_memory_pattern",
            "page1_hmac_verified": False,
            "scanned_regions": scanned_regions,
            "readable_bytes": readable_bytes,
        }
    )
    result.AppendMessage(
        json.dumps(
            {
                "status": "RAW_KEY_NOT_FOUND",
                "method": "lldb_memory_pattern",
                "page1_hmac_verified": False,
                "scanned_regions": scanned_regions,
                "readable_bytes": readable_bytes,
            },
            sort_keys=True,
        )
    )


def __lldb_init_module(debugger, internal_dict) -> None:
    debugger.HandleCommand(
        "command script add -f lldb_scan.scan_wechat_key scan-wechat-key"
    )
