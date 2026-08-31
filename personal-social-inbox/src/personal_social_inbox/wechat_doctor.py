from __future__ import annotations

import hashlib
import os
import plistlib
from pathlib import Path
from typing import Any


SQLITE_HEADER = b"SQLite format 3\x00"
DEFAULT_APP_PATH = Path("/Applications/WeChat.app")
DEFAULT_CONTAINER_PATH = (
    Path.home() / "Library/Containers/com.tencent.xinWeChat"
)
IGNORED_PROFILE_NAMES = {"all_users", "Backup"}


def _file_summary(root: Path) -> dict[str, int | bool]:
    file_count = 0
    total_bytes = 0
    if root.is_dir():
        for directory, _, filenames in os.walk(root, followlinks=False):
            base = Path(directory)
            for filename in filenames:
                path = base / filename
                try:
                    if path.is_symlink():
                        continue
                    total_bytes += path.stat().st_size
                    file_count += 1
                except OSError:
                    continue
    return {
        "exists": root.is_dir(),
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def _header_kind(path: Path) -> str:
    try:
        with path.open("rb") as source:
            return (
                "sqlite_plain"
                if source.read(len(SQLITE_HEADER)) == SQLITE_HEADER
                else "encrypted_or_custom"
            )
    except OSError:
        return "unreadable"


def _database_summary(root: Path) -> dict[str, Any]:
    counts = {
        "sqlite_plain": 0,
        "encrypted_or_custom": 0,
        "unreadable": 0,
    }
    total_bytes = 0
    files = []
    if root.is_dir():
        files = sorted(path for path in root.rglob("*.db") if path.is_file())
    for path in files:
        counts[_header_kind(path)] += 1
        try:
            total_bytes += path.stat().st_size
        except OSError:
            pass
    return {
        "exists": root.is_dir(),
        "database_count": len(files),
        "total_bytes": total_bytes,
        "format_counts": counts,
    }


def _profile_id(raw_name: str) -> str:
    digest = hashlib.sha256(raw_name.encode("utf-8")).hexdigest()[:12]
    return f"profile_{digest}"


def _app_summary(app_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"exists": app_path.is_dir(), "path": str(app_path)}
    plist_path = app_path / "Contents/Info.plist"
    if not plist_path.is_file():
        return result
    try:
        with plist_path.open("rb") as source:
            info = plistlib.load(source)
    except (OSError, plistlib.InvalidFileException):
        result["metadata_status"] = "unreadable"
        return result
    result.update(
        {
            "bundle_id": info.get("CFBundleIdentifier"),
            "version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
        }
    )
    return result


def _key_metadata_summary(xwechat_root: Path) -> dict[str, Any]:
    login_root = xwechat_root / "all_users/login"
    candidates = (
        sorted(login_root.glob("*/key_info.db")) if login_root.is_dir() else []
    )
    formats = {
        "sqlite_plain": 0,
        "encrypted_or_custom": 0,
        "unreadable": 0,
    }
    for candidate in candidates:
        formats[_header_kind(candidate)] += 1
    return {
        "present": bool(candidates),
        "database_count": len(candidates),
        "format_counts": formats,
        "values_read": False,
        "note": "Metadata presence does not establish access to a plaintext business-database key.",
    }


def diagnose_wechat(
    app_path: Path = DEFAULT_APP_PATH,
    container_path: Path = DEFAULT_CONTAINER_PATH,
) -> dict[str, Any]:
    """Inspect only paths, file metadata, plist fields, and database headers."""

    app_path = app_path.expanduser().resolve()
    container_path = container_path.expanduser().resolve()
    xwechat_root = container_path / "Data/Documents/xwechat_files"
    profiles = []
    if xwechat_root.is_dir():
        candidates = sorted(
            path
            for path in xwechat_root.iterdir()
            if path.is_dir()
            and path.name not in IGNORED_PROFILE_NAMES
            and (path / "db_storage").is_dir()
        )
        for path in candidates:
            profiles.append(
                {
                    "profile_id": _profile_id(path.name),
                    "databases": _database_summary(path / "db_storage"),
                    "media": {
                        "attachments": _file_summary(path / "msg/attach"),
                        "files": _file_summary(path / "msg/file"),
                        "video": _file_summary(path / "msg/video"),
                    },
                    "migration": {
                        "message": _file_summary(path / "msg/migrate"),
                        "business": _file_summary(path / "business/migrate"),
                    },
                }
            )

    encrypted_count = sum(
        profile["databases"]["format_counts"]["encrypted_or_custom"]
        for profile in profiles
    )
    plain_count = sum(
        profile["databases"]["format_counts"]["sqlite_plain"]
        for profile in profiles
    )
    app = _app_summary(app_path)
    if not app["exists"] or not xwechat_root.is_dir():
        capability = "REQUIRES_USER_ACTION"
        reason = "wechat_app_or_data_root_not_found"
    elif not profiles:
        capability = "REQUIRES_USER_ACTION"
        reason = "no_local_profile_database_found"
    elif encrypted_count:
        capability = "REQUIRES_USER_ACTION"
        reason = "encrypted_or_custom_business_databases"
    elif plain_count:
        capability = "PARTIAL_EXPORT"
        reason = "plain_database_detected_but_no_accepted_parser"
    else:
        capability = "REQUIRES_USER_ACTION"
        reason = "no_readable_business_database_found"

    return {
        "schema": "personal-social-inbox/wechat-doctor/v1",
        "capability": capability,
        "reason": reason,
        "app": app,
        "data_root": {
            "exists": xwechat_root.is_dir(),
            "container_path": str(container_path),
            "profile_count": len(profiles),
        },
        "profiles": profiles,
        "backup": _file_summary(xwechat_root / "Backup"),
        "key_metadata": _key_metadata_summary(xwechat_root),
        "privacy": {
            "message_content_read": False,
            "key_values_read": False,
            "source_files_copied": False,
            "raw_account_names_reported": False,
        },
        "safe_next_inputs": [
            "a reviewed social-inbox-import/v1 export",
            "a separately authorized, copied and decrypted snapshot",
        ],
        "warnings": [
            "LIVE_SOURCE_NOT_COPIED",
            "MESSAGE_CONTENT_NOT_READ",
            "KEY_VALUES_NOT_READ",
        ],
    }
