#!/usr/bin/env python3
"""Replace one verified arm64 instruction with NOP in a disposable thin Mach-O."""

from __future__ import annotations

import argparse
from pathlib import Path


ARM64_NOP = bytes.fromhex("1f2003d5")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--offset", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--expect", required=True, help="expected 4 bytes as hex")
    args = parser.parse_args()

    expected = bytes.fromhex(args.expect)
    if len(expected) != 4:
        parser.error("--expect must encode exactly four bytes")

    with args.binary.open("r+b") as handle:
        handle.seek(args.offset)
        actual = handle.read(4)
        if actual != expected:
            raise SystemExit(
                f"refusing patch: expected={expected.hex()} actual={actual.hex()}"
            )
        handle.seek(args.offset)
        handle.write(ARM64_NOP)
        handle.flush()

    print(
        f"patched_offset=0x{args.offset:x} old={expected.hex()} new={ARM64_NOP.hex()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
