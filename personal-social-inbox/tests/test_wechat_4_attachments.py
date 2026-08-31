from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.wechat_4_attachments import (
    HEADER_SIZE,
    RESOURCE_MARKER,
    V2_MAGIC,
    ImageAttachmentResolver,
    LocalFileResolver,
    VideoAttachmentResolver,
    _aes_ecb,
    _month_candidates,
    decode_image_dat,
    extract_resource_md5,
)


def _v2_image(plain: bytes, key: bytes, xor_key: int) -> bytes:
    aes_size = min(16, len(plain))
    aes_plain = plain[:aes_size]
    raw = plain[aes_size:-2]
    xor_plain = plain[-2:]
    encrypted = _aes_ecb(aes_plain, key, decrypt=False, padding=True)
    return (
        V2_MAGIC
        + aes_size.to_bytes(4, "little")
        + len(xor_plain).to_bytes(4, "little")
        + b"\x00"
        + encrypted
        + raw
        + bytes(value ^ xor_key for value in xor_plain)
    )


class WeChat4AttachmentTests(unittest.TestCase):
    def test_extracts_marker_resource_md5(self) -> None:
        expected = "0123456789abcdef0123456789abcdef"
        blob = b"prefix" + RESOURCE_MARKER + expected.encode() + b"suffix"
        self.assertEqual(extract_resource_md5(blob), expected)

    def test_decodes_legacy_xor_and_v2(self) -> None:
        jpeg = b"\xff\xd8\xff\xe0synthetic jpeg body\xff\xd9"
        legacy = bytes(value ^ 0xA5 for value in jpeg)
        decoded, image_format, decoder = decode_image_dat(legacy, None, None)
        self.assertEqual(decoded, jpeg)
        self.assertEqual((image_format, decoder), ("jpg", "legacy_xor"))

        key = b"0123456789abcdef"
        v2 = _v2_image(jpeg, key, 0x2A)
        self.assertGreater(len(v2), HEADER_SIZE)
        decoded, image_format, decoder = decode_image_dat(v2, key, 0x2A)
        self.assertEqual(decoded, jpeg)
        self.assertEqual((image_format, decoder), ("jpg", "v2"))

    def test_resolves_resource_derives_key_and_writes_private_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_db = root / "message_resource.db"
            with closing(sqlite3.connect(resource_db)) as connection, connection:
                connection.executescript(
                    """
                    CREATE TABLE ChatName2Id(user_name TEXT PRIMARY KEY);
                    CREATE TABLE MessageResourceInfo(
                        chat_id INTEGER,
                        message_local_id INTEGER,
                        message_local_type INTEGER,
                        message_create_time INTEGER,
                        packed_info BLOB
                    );
                    INSERT INTO ChatName2Id(rowid, user_name) VALUES(1, 'friend');
                    """
                )
                resource_md5 = "fedcba9876543210fedcba9876543210"
                blob = RESOURCE_MARKER + resource_md5.encode()
                connection.execute(
                    "INSERT INTO MessageResourceInfo VALUES(?, ?, ?, ?, ?)",
                    (1, 7, 3, 1735689600, blob),
                )

            profile = root / "xwechat_files" / "wxid_test_abcd"
            kvcomm = root / "app_data" / "net" / "kvcomm"
            kvcomm.mkdir(parents=True)
            (kvcomm / "key_42_test.statistic").write_bytes(b"")
            key = hashlib.md5(b"42wxid_test", usedforsecurity=False).hexdigest()[:16].encode()
            jpeg = b"\xff\xd8\xff\xe0resolver jpeg body\xff\xd9"
            month = _month_candidates(1735689600)[1]
            chat_hash = hashlib.md5(b"friend", usedforsecurity=False).hexdigest()
            image_dir = profile / "msg" / "attach" / chat_hash / month / "Img"
            image_dir.mkdir(parents=True)
            (image_dir / f"{resource_md5}_t.dat").write_bytes(
                _v2_image(jpeg, key, 42)
            )

            output = root / "export"
            output.mkdir()
            resolver = ImageAttachmentResolver(resource_db, profile, output)
            try:
                part = resolver.resolve("friend", 7, 1735689600, 3)
                self.assertIsNotNone(part)
                assert part is not None
                self.assertEqual(part["wechat_decoder"], "v2")
                self.assertEqual(part["wechat_dat_variant"], "thumbnail")
                self.assertEqual((output / part["path"]).read_bytes(), jpeg)
                self.assertEqual(resolver.key_status, "verified")
                self.assertEqual(resolver.stats["image_attachments_decoded"], 1)
            finally:
                resolver.close()

    def test_copies_month_matched_file_without_changing_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            month = _month_candidates(1735689600)[1]
            source = profile / "msg" / "file" / month / "report.txt"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"source file payload")
            before = source.stat()
            output = root / "export"
            output.mkdir()

            resolver = LocalFileResolver(profile, output)
            part = resolver.resolve("report.txt", 1735689600)

            self.assertIsNotNone(part)
            assert part is not None
            self.assertEqual(part["wechat_attachment_status"], "copied")
            self.assertEqual((output / part["path"]).read_bytes(), b"source file payload")
            self.assertEqual(source.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(resolver.stats["file_attachments_copied"], 1)

    def test_resolves_verified_mp4_and_reports_absent_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_db = root / "message_resource.db"
            with closing(sqlite3.connect(resource_db)) as connection, connection:
                connection.executescript(
                    """
                    CREATE TABLE ChatName2Id(user_name TEXT PRIMARY KEY);
                    CREATE TABLE MessageResourceInfo(
                        message_id INTEGER PRIMARY KEY,
                        chat_id INTEGER,
                        message_local_id INTEGER,
                        message_local_type INTEGER,
                        message_create_time INTEGER,
                        packed_info BLOB
                    );
                    CREATE TABLE MessageResourceDetail(
                        resource_id INTEGER PRIMARY KEY,
                        message_id INTEGER,
                        type INTEGER,
                        size INTEGER
                    );
                    INSERT INTO ChatName2Id(rowid, user_name) VALUES(1, 'friend');
                    """
                )
                present_md5 = "0123456789abcdef0123456789abcdef"
                absent_md5 = "fedcba9876543210fedcba9876543210"
                connection.execute(
                    "INSERT INTO MessageResourceInfo VALUES(1,1,7,43,1735689600,?)",
                    (RESOURCE_MARKER + present_md5.encode(),),
                )
                connection.execute(
                    "INSERT INTO MessageResourceInfo VALUES(2,1,8,43,1735689600,?)",
                    (RESOURCE_MARKER + absent_md5.encode(),),
                )
                mp4 = b"\x00\x00\x00\x18ftypisom" + b"synthetic mp4 payload"
                connection.execute(
                    "INSERT INTO MessageResourceDetail VALUES(1,1,131074,?)",
                    (len(mp4),),
                )
                connection.execute(
                    "INSERT INTO MessageResourceDetail VALUES(2,2,131074,0)"
                )

            profile = root / "profile"
            month = _month_candidates(1735689600)[1]
            source = profile / "msg" / "video" / month / f"{present_md5}.mp4"
            source.parent.mkdir(parents=True)
            source.write_bytes(mp4)
            before = source.stat()
            output = root / "export"
            output.mkdir()

            resolver = VideoAttachmentResolver(resource_db, profile, output)
            try:
                present = resolver.resolve("friend", 7, 1735689600, 43)
                absent = resolver.resolve("friend", 8, 1735689600, 43)
                self.assertIsNotNone(present)
                self.assertIsNotNone(absent)
                assert present is not None and absent is not None
                self.assertEqual(present["wechat_attachment_status"], "copied")
                self.assertEqual((output / present["path"]).read_bytes(), mp4)
                self.assertEqual(absent["wechat_attachment_status"], "resource_body_not_local")
                self.assertEqual(source.stat().st_mtime_ns, before.st_mtime_ns)
                self.assertEqual(resolver.stats["video_attachments_copied"], 1)
                self.assertEqual(resolver.stats["video_resource_bodies_not_local"], 1)
            finally:
                resolver.close()


if __name__ == "__main__":
    unittest.main()
