from __future__ import annotations

import os
import sys
from pathlib import Path


def default_data_home() -> Path:
    override = os.environ.get("PERSONAL_SOCIAL_INBOX_HOME")
    if override:
        return Path(override).expanduser().resolve()

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "PersonalSocialInbox"

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "personal-social-inbox"
    return Path.home() / ".local" / "share" / "personal-social-inbox"


def database_path(data_home: Path | None = None) -> Path:
    root = data_home or default_data_home()
    return root / "inbox.sqlite3"


def blob_root(data_home: Path | None = None) -> Path:
    root = data_home or default_data_home()
    return root / "blobs"
