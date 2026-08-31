from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import decrypt_db_copy as decryptor
import dingtalk_snapshot as snapshot


class DingTalkPocTests(unittest.TestCase):
    def test_embedded_aes_ecb_primitive_matches_standard_vector(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        expected = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            decryptor._decrypt_bytes(decryptor._load_crypto(), ciphertext, key),
            expected,
        )

    def test_wal_parser_keeps_only_frames_through_last_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wal = Path(directory) / "dingtalk.db-wal"
            salt = bytes.fromhex("0102030405060708")
            header = bytearray(decryptor.WAL_HEADER_SIZE)
            header[0:4] = (0x377F0682).to_bytes(4, "big")
            header[8:12] = decryptor.PAGE_SIZE.to_bytes(4, "big")
            header[16:24] = salt

            def frame(page: int, commit: int, fill: int) -> bytes:
                value = bytearray(decryptor.WAL_FRAME_HEADER_SIZE)
                value[0:4] = page.to_bytes(4, "big")
                value[4:8] = commit.to_bytes(4, "big")
                value[8:16] = salt
                return bytes(value) + bytes([fill]) * decryptor.PAGE_SIZE

            wal.write_bytes(
                bytes(header)
                + frame(2, 0, 1)
                + frame(3, 3, 2)
                + frame(4, 0, 3)
            )
            frames, commit_pages = decryptor._current_wal_frames(wal)
        self.assertEqual(commit_pages, 3)
        self.assertEqual([item[0] for item in frames], [2, 3])
        self.assertEqual(frames[1][1][:1], b"\x02")

    def test_sqlite_validation_reads_schema_but_not_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "sample.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE messages(body TEXT)")
            connection.execute("INSERT INTO messages VALUES ('PRIVATE')")
            connection.commit()
            connection.close()
            result = decryptor._validate_sqlite(database)
        self.assertEqual(result["quick_check"], "ok")
        self.assertEqual(result["schema_counts"]["table"], 1)
        self.assertFalse(result["rows_queried"])
        self.assertFalse(result["message_bodies_read"])

    def test_stable_candidate_copies_database_wal_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile"
            database = profile / snapshot.DATABASE_RELATIVE
            database.parent.mkdir(parents=True)
            database.write_bytes(b"database")
            database.with_name("dingtalk.db-wal").write_bytes(b"wal")
            (profile / snapshot.CONFIG_RELATIVE).write_bytes(b"config")
            candidate = root / "candidate"
            fingerprint, attempts, inventory = snapshot._copy_candidate(
                profile, candidate, 1
            )
        self.assertEqual(attempts, 1)
        self.assertEqual(fingerprint["database"]["size"], 8)
        self.assertEqual(inventory["wal"]["size"], 3)
        self.assertEqual(inventory["user_config"]["size"], 6)


if __name__ == "__main__":
    unittest.main()
