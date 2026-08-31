from __future__ import annotations

import ctypes
import hashlib
import hmac
import struct
import tempfile
import unittest
from pathlib import Path

import lldb_capture
import lldb_scan
import poc
import wechat_snapshot


def encrypt_aes_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    output = ctypes.create_string_buffer(len(plaintext) + 32)
    output_size = ctypes.c_size_t(0)
    status = poc.LIBSYSTEM.CCCrypt(
        0,
        0,
        0,
        key,
        len(key),
        iv,
        plaintext,
        len(plaintext),
        output,
        len(output),
        ctypes.byref(output_size),
    )
    if status != 0:
        raise RuntimeError(status)
    return output.raw[: output_size.value]


def encrypted_page1(key: bytes) -> tuple[bytes, bytes]:
    salt = bytes(range(16))
    plaintext = bytes((index * 17) % 256 for index in range(4000))
    iv = bytes(range(32, 48))
    ciphertext = encrypt_aes_cbc(key, iv, plaintext)
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", key, mac_salt, 2, dklen=32)
    calculated = hmac.new(mac_key, ciphertext + iv, hashlib.sha512)
    calculated.update(struct.pack("<I", 1))
    page = salt + ciphertext + iv + calculated.digest()
    return page, plaintext


class PocCryptoTests(unittest.TestCase):
    def test_hmac_and_page_decryption(self) -> None:
        key = bytes(range(32))
        page, plaintext = encrypted_page1(key)
        self.assertEqual(len(page), poc.PAGE_SIZE)
        self.assertTrue(poc.verify_key(key, page))
        self.assertFalse(poc.verify_key(bytes(reversed(key)), page))
        decrypted = poc._decrypt_page(key, page, 1)
        self.assertEqual(decrypted[:16], poc.SQLITE_HEADER)
        self.assertEqual(decrypted[16:4016], plaintext)
        self.assertEqual(decrypted[4016:], bytes(80))

    def test_lldb_candidate_requires_matching_salt_and_hmac(self) -> None:
        key = bytes(range(32))
        page, _ = encrypted_page1(key)
        target_salt = page[: poc.SALT_SIZE].hex()
        payload = b"prefix x'" + key.hex().encode() + target_salt.encode() + b"' suffix"
        self.assertEqual(
            lldb_scan.verified_key_in_bytes(payload, target_salt, page), key
        )
        self.assertIsNone(
            lldb_scan.verified_key_in_bytes(payload, "00" * 16, page)
        )

    def test_passphrase_derivation_requires_page1_hmac(self) -> None:
        passphrase = bytes(reversed(range(32)))
        salt = bytes(range(16))
        key = hashlib.pbkdf2_hmac(
            "sha512",
            passphrase,
            salt,
            lldb_capture.PBKDF2_ROUNDS,
            dklen=poc.KEY_SIZE,
        )
        page, _ = encrypted_page1(key)
        self.assertEqual(page[: poc.SALT_SIZE], salt)
        self.assertEqual(lldb_capture.derive_verified_key(passphrase, page), key)
        self.assertIsNone(
            lldb_capture.derive_verified_key(bytes(range(32)), page)
        )

    def test_snapshot_page_hmac_matches_single_database_verifier(self) -> None:
        key = bytes(range(32))
        page, _ = encrypted_page1(key)
        mac_key = wechat_snapshot._mac_key(key, page[: poc.SALT_SIZE])
        self.assertTrue(
            wechat_snapshot.verify_page(key, mac_key, page, 1, True)
        )
        self.assertFalse(
            wechat_snapshot.verify_page(key, mac_key, page, 2, True)
        )

    def test_wal_parser_filters_old_salt_and_uncommitted_tail(self) -> None:
        salt1 = bytes.fromhex("01020304")
        salt2 = bytes.fromhex("05060708")
        other1 = bytes.fromhex("11121314")
        other2 = bytes.fromhex("15161718")

        def frame(page_number: int, commit_pages: int, s1: bytes, s2: bytes) -> bytes:
            header = (
                page_number.to_bytes(4, "big")
                + commit_pages.to_bytes(4, "big")
                + s1
                + s2
                + bytes(8)
            )
            return header + bytes([page_number]) * poc.PAGE_SIZE

        header = bytearray(wechat_snapshot.WAL_HEADER_SIZE)
        header[8:12] = poc.PAGE_SIZE.to_bytes(4, "big")
        header[16:20] = salt1
        header[20:24] = salt2
        payload = bytes(header) + b"".join(
            [
                frame(1, 0, salt1, salt2),
                frame(9, 9, other1, other2),
                frame(2, 2, salt1, salt2),
                frame(3, 0, salt1, salt2),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.db-wal"
            path.write_bytes(payload)
            frames, commit_pages = wechat_snapshot._current_wal_frames(path)
        self.assertEqual([item[0] for item in frames], [1, 2])
        self.assertEqual(commit_pages, 2)


if __name__ == "__main__":
    unittest.main()
