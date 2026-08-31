#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
DIRECTORIES = (
    PRIVATE,
    PRIVATE / "exports",
)


def main() -> int:
    for directory in DIRECTORIES:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            directory.chmod(0o700)

    print(
        json.dumps(
            {
                "status": "ready",
                "private_root": str(PRIVATE),
                "directories": len(DIRECTORIES),
                "docker_persistence": "named_volumes",
                "secrets_read": False,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
