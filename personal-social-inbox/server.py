#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from personal_social_inbox.mcp_server import serve


if __name__ == "__main__":
    serve()
