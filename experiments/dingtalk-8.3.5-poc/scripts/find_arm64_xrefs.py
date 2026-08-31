#!/usr/bin/env python3
"""Find simple ADRP+ADD references in a thin arm64 Mach-O __text section."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_adrp(instruction: int, pc: int) -> tuple[int, int] | None:
    if instruction & 0x9F000000 != 0x90000000:
        return None
    immlo = (instruction >> 29) & 0x3
    immhi = (instruction >> 5) & 0x7FFFF
    displacement = sign_extend((immhi << 2) | immlo, 21) << 12
    return instruction & 0x1F, (pc & ~0xFFF) + displacement


def decode_add_immediate(instruction: int) -> tuple[int, int, int] | None:
    if instruction & 0xFF000000 != 0x91000000:
        return None
    destination = instruction & 0x1F
    source = (instruction >> 5) & 0x1F
    immediate = (instruction >> 10) & 0xFFF
    if (instruction >> 22) & 1:
        immediate <<= 12
    return destination, source, immediate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("target", type=lambda value: int(value, 0))
    parser.add_argument("--text-address", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--text-offset", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--text-size", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--window", type=int, default=12)
    args = parser.parse_args()

    with args.binary.open("rb") as handle:
        handle.seek(args.text_offset)
        text = handle.read(args.text_size)

    instructions = struct.unpack(f"<{len(text) // 4}I", text[: len(text) // 4 * 4])
    matches: list[tuple[int, int]] = []
    for index, instruction in enumerate(instructions):
        pc = args.text_address + index * 4
        decoded = decode_adrp(instruction, pc)
        if decoded is None:
            continue
        register, page = decoded
        for lookahead in range(1, min(args.window + 1, len(instructions) - index)):
            add = decode_add_immediate(instructions[index + lookahead])
            if add is None:
                continue
            _destination, source, immediate = add
            if source == register and page + immediate == args.target:
                matches.append((pc, args.text_address + (index + lookahead) * 4))
                break

    for adrp, add in matches:
        print(f"adrp=0x{adrp:x} add=0x{add:x}")
    print(f"matches={len(matches)}")
    return 0 if matches else 2


if __name__ == "__main__":
    raise SystemExit(main())
