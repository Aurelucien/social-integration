from __future__ import annotations

import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.wechat_doctor import diagnose_wechat


class WeChatDoctorTests(unittest.TestCase):
    def test_encrypted_profile_is_reported_without_account_or_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "WeChat.app"
            info = app / "Contents/Info.plist"
            info.parent.mkdir(parents=True)
            with info.open("wb") as destination:
                plistlib.dump(
                    {
                        "CFBundleIdentifier": "com.tencent.xinWeChat",
                        "CFBundleShortVersionString": "4.1.7",
                        "CFBundleVersion": "34371",
                    },
                    destination,
                )

            container = root / "container"
            xwechat = container / "Data/Documents/xwechat_files"
            raw_profile = "wxid_private_account"
            database = xwechat / raw_profile / "db_storage/message/message_0.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"not-a-sqlite-db" + b"\x00" * 32)
            attachment = xwechat / raw_profile / "msg/attach/secret-name.dat"
            attachment.parent.mkdir(parents=True)
            attachment.write_bytes(b"private payload")
            key_info = xwechat / "all_users/login/private/key_info.db"
            key_info.parent.mkdir(parents=True)
            key_info.write_bytes(b"SQLite format 3\x00" + b"\x00" * 32)
            (xwechat / "Backup").mkdir()

            result = diagnose_wechat(app, container)
            serialized = json.dumps(result)

            self.assertEqual(result["capability"], "REQUIRES_USER_ACTION")
            self.assertEqual(
                result["reason"], "encrypted_or_custom_business_databases"
            )
            self.assertEqual(result["data_root"]["profile_count"], 1)
            self.assertEqual(
                result["profiles"][0]["databases"]["format_counts"][
                    "encrypted_or_custom"
                ],
                1,
            )
            self.assertEqual(
                result["profiles"][0]["media"]["attachments"]["file_count"], 1
            )
            self.assertTrue(result["key_metadata"]["present"])
            self.assertFalse(result["key_metadata"]["values_read"])
            self.assertNotIn(raw_profile, serialized)
            self.assertNotIn("secret-name", serialized)
            self.assertNotIn("private payload", serialized)

    def test_missing_installation_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = diagnose_wechat(root / "missing.app", root / "missing-container")
            self.assertEqual(result["capability"], "REQUIRES_USER_ACTION")
            self.assertEqual(result["reason"], "wechat_app_or_data_root_not_found")
            self.assertEqual(result["profiles"], [])


if __name__ == "__main__":
    unittest.main()
