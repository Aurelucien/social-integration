from __future__ import annotations

import ctypes
import hashlib
import mimetypes
import os
import re
import sqlite3
import tempfile
import unicodedata
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from .wechat_4_adapter import (
    WechatAdapterError,
    _connect,
    _private_directory,
    _write_private_bytes,
)


V2_MAGIC = b"\x07\x08V2\x08\x07"
V1_MAGIC = b"\x07\x08V1\x08\x07"
HEADER_SIZE = 15
RESOURCE_MARKER = b"\x12\x22\x0a\x20"
RESOURCE_MD5 = re.compile(rb"[0-9A-Fa-f]{32}")
KVCOMM_KEY = re.compile(r"^key_([0-9]+)_.+\.statistic$")
MAX_IMAGE_BYTES = 200 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024


def extract_resource_md5(blob: bytes) -> str | None:
    marker = blob.find(RESOURCE_MARKER)
    if marker >= 0:
        candidate = blob[marker + len(RESOURCE_MARKER) : marker + len(RESOURCE_MARKER) + 32]
        if len(candidate) == 32 and RESOURCE_MD5.fullmatch(candidate):
            return candidate.decode("ascii").lower()
    match = RESOURCE_MD5.search(blob)
    return match.group(0).decode("ascii").lower() if match else None


def detect_image_format(data: bytes) -> str | None:
    if data.startswith(b"wxgf"):
        return "wxgf"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"\x89PNG"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "tif"
    if data.startswith(b"BM"):
        return "bmp"
    return None


def _common_crypto() -> ctypes.CDLL:
    if os.uname().sysname != "Darwin":
        raise WechatAdapterError("WeChat V2 image decoding currently requires macOS")
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    except OSError as exc:  # pragma: no cover - macOS runtime failure
        raise WechatAdapterError("macOS CommonCrypto is unavailable") from exc
    library.CCCrypt.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.CCCrypt.restype = ctypes.c_int32
    return library


def _aes_ecb(data: bytes, key: bytes, *, decrypt: bool, padding: bool) -> bytes:
    if len(key) != 16:
        raise WechatAdapterError("image AES key must be 16 bytes")
    if not data or len(data) % 16:
        raise WechatAdapterError("AES-ECB input must be a non-empty block sequence")
    source = ctypes.create_string_buffer(data, len(data))
    key_buffer = ctypes.create_string_buffer(key, len(key))
    output = ctypes.create_string_buffer(len(data) + 16)
    moved = ctypes.c_size_t()
    options = 0x0002 | (0x0001 if padding else 0)
    status = _common_crypto().CCCrypt(
        1 if decrypt else 0,
        0,
        options,
        ctypes.cast(key_buffer, ctypes.c_void_p),
        len(key),
        None,
        ctypes.cast(source, ctypes.c_void_p),
        len(data),
        ctypes.cast(output, ctypes.c_void_p),
        len(output),
        ctypes.byref(moved),
    )
    if status != 0:
        raise WechatAdapterError(f"CommonCrypto AES-ECB failed with status {status}")
    return output.raw[: moved.value]


def _decode_legacy_xor(data: bytes) -> tuple[bytes, str, str]:
    magics = (
        b"\x89PNG",
        b"GIF8",
        b"II*\x00",
        b"RIFF",
        b"\xff\xd8\xff",
    )
    for magic in magics:
        if len(data) < len(magic):
            continue
        key = data[0] ^ magic[0]
        if all((data[index] ^ key) == value for index, value in enumerate(magic)):
            decoded = bytes(value ^ key for value in data)
            image_format = detect_image_format(decoded)
            if image_format:
                return decoded, image_format, "legacy_xor"
    raise WechatAdapterError("legacy XOR image magic was not recognized")


def decode_image_dat(
    data: bytes,
    aes_key: bytes | None,
    xor_key: int | None,
) -> tuple[bytes, str, str]:
    if not data:
        raise WechatAdapterError("image .dat is empty")
    if not data.startswith((V1_MAGIC, V2_MAGIC)):
        return _decode_legacy_xor(data)
    if len(data) < HEADER_SIZE:
        raise WechatAdapterError("V1/V2 image .dat header is truncated")
    if data.startswith(V1_MAGIC):
        effective_key = b"cfcd208495d565ef"
        effective_xor = 0x88 if xor_key is None else xor_key
        decoder = "v1_aes"
    else:
        if aes_key is None or xor_key is None:
            raise WechatAdapterError("V2 image key material is unavailable")
        effective_key = aes_key
        effective_xor = xor_key
        decoder = "v2"

    aes_size = int.from_bytes(data[6:10], "little")
    xor_size = int.from_bytes(data[10:14], "little")
    aligned_aes_size = aes_size + (16 - aes_size % 16)
    aes_end = HEADER_SIZE + aligned_aes_size
    raw_end = len(data) - xor_size
    if aes_end > len(data) or raw_end < aes_end:
        raise WechatAdapterError("V1/V2 image segment lengths are invalid")
    aes_plain = _aes_ecb(
        data[HEADER_SIZE:aes_end], effective_key, decrypt=True, padding=True
    )
    decoded = (
        aes_plain
        + data[aes_end:raw_end]
        + bytes(value ^ effective_xor for value in data[raw_end:])
    )
    image_format = detect_image_format(decoded)
    if image_format is None:
        raise WechatAdapterError("decoded V1/V2 image magic was not recognized")
    return decoded, image_format, decoder


def _normalize_profile_id(value: str) -> str:
    if value.startswith("wxid_"):
        body = value[5:]
        return "wxid_" + body.split("_", 1)[0]
    base, separator, suffix = value.rpartition("_")
    if separator and len(suffix) == 4 and all(character in "0123456789abcdefABCDEF" for character in suffix):
        return base
    return value


def _profile_candidates(profile_root: Path) -> list[str]:
    raw = profile_root.name
    normalized = _normalize_profile_id(raw)
    return list(dict.fromkeys((raw, normalized)))


def _kvcomm_codes(profile_root: Path) -> list[int]:
    kvcomm = profile_root.parent.parent / "app_data" / "net" / "kvcomm"
    if not kvcomm.is_dir():
        return []
    codes: list[int] = []
    for path in kvcomm.iterdir():
        match = KVCOMM_KEY.fullmatch(path.name)
        if match and path.is_file():
            codes.append(int(match.group(1)))
    return sorted(set(codes))


def _template_ciphertext(data: bytes) -> bytes | None:
    if len(data) < HEADER_SIZE + 16 or not data.startswith(V2_MAGIC):
        return None
    return data[HEADER_SIZE : HEADER_SIZE + 16]


def _derive_v2_key(profile_root: Path, templates: Iterable[bytes]) -> tuple[bytes, int] | None:
    blocks = [block for data in templates if (block := _template_ciphertext(data))]
    if not blocks:
        return None
    for code in _kvcomm_codes(profile_root):
        for profile_id in _profile_candidates(profile_root):
            digest = hashlib.md5(
                f"{code}{profile_id}".encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            key = digest[:16].encode("ascii")
            if all(detect_image_format(_aes_ecb(block, key, decrypt=True, padding=False)) for block in blocks):
                return key, code & 0xFF
    return None


def _stable_read(path: Path) -> bytes:
    before = path.stat()
    if before.st_size > MAX_IMAGE_BYTES:
        raise WechatAdapterError("image .dat exceeds the 200 MiB safety limit")
    data = path.read_bytes()
    after = path.stat()
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(data) != after.st_size
    ):
        raise WechatAdapterError("source image changed while it was being copied")
    return data


def _month_candidates(create_time: int) -> list[str]:
    current = datetime.fromtimestamp(create_time)
    values: list[str] = []
    for delta in (-1, 0, 1):
        month_index = current.year * 12 + current.month - 1 + delta
        year, month_zero = divmod(month_index, 12)
        values.append(f"{year:04d}-{month_zero + 1:02d}")
    return values


def _candidate_paths(
    attach_root: Path, chat: str, resource_md5: str, create_time: int
) -> list[tuple[str, Path]]:
    chat_hash = hashlib.md5(chat.encode("utf-8"), usedforsecurity=False).hexdigest()
    chat_root = attach_root / chat_hash
    if not chat_root.is_dir():
        return []
    months = [chat_root / month for month in _month_candidates(create_time)]
    months.extend(
        path
        for path in sorted(chat_root.iterdir())
        if path.is_dir() and path not in months
    )
    candidates: list[tuple[str, Path]] = []
    for month in months:
        image_root = month / "Img"
        for variant, suffix in (("full", ""), ("high", "_h"), ("thumbnail", "_t")):
            path = image_root / f"{resource_md5}{suffix}.dat"
            if path.is_file() and all(existing != path for _name, existing in candidates):
                candidates.append((variant, path))
    return candidates


class ImageAttachmentResolver:
    def __init__(self, resource_database: Path, profile_root: Path, export_root: Path):
        self._resource = _connect(resource_database)
        self._profile_root = profile_root.expanduser().resolve()
        self._attach_root = self._profile_root / "msg" / "attach"
        self._export_root = export_root
        self._key_material: tuple[bytes, int] | None = None
        self._key_attempted = False
        if not self._attach_root.is_dir():
            self._resource.close()
            raise WechatAdapterError("WeChat profile has no msg/attach directory")
        self.stats: dict[str, int] = {
            "image_rows_considered": 0,
            "image_resource_rows": 0,
            "image_dat_files_found": 0,
            "image_attachments_decoded": 0,
            "image_decode_failures": 0,
        }

    def close(self) -> None:
        self._resource.close()

    @property
    def key_status(self) -> str:
        if self._key_material:
            return "verified"
        return "unavailable" if self._key_attempted else "not_needed"

    def _lookup_md5(
        self, chat: str, local_id: int, create_time: int, base_type: int
    ) -> str | None:
        chat_row = self._resource.execute(
            "SELECT rowid FROM ChatName2Id WHERE user_name = ?", (chat,)
        ).fetchone()
        if chat_row is None:
            return None
        parameters = (int(chat_row[0]), local_id, base_type, create_time)
        row = self._resource.execute(
            "SELECT packed_info FROM MessageResourceInfo "
            "WHERE chat_id = ? AND message_local_id = ? "
            "AND (message_local_type = ? OR (message_local_type & 4294967295) = ?) "
            "AND message_create_time = ? ORDER BY rowid DESC LIMIT 1",
            (parameters[0], parameters[1], parameters[2], parameters[2], parameters[3]),
        ).fetchone()
        if row is None:
            row = self._resource.execute(
                "SELECT packed_info FROM MessageResourceInfo "
                "WHERE chat_id = ? AND message_local_id = ? "
                "AND (message_local_type = ? OR (message_local_type & 4294967295) = ?) "
                "ORDER BY message_create_time DESC, rowid DESC LIMIT 1",
                (parameters[0], parameters[1], parameters[2], parameters[2]),
            ).fetchone()
        if row is None or not isinstance(row[0], bytes):
            return None
        return extract_resource_md5(row[0])

    def resolve(
        self, chat: str, local_id: int, create_time: int, base_type: int
    ) -> dict[str, Any] | None:
        self.stats["image_rows_considered"] += 1
        resource_md5 = self._lookup_md5(chat, local_id, create_time, base_type)
        if resource_md5 is None:
            return None
        self.stats["image_resource_rows"] += 1
        candidates = _candidate_paths(
            self._attach_root, chat, resource_md5, create_time
        )
        if not candidates:
            return None
        self.stats["image_dat_files_found"] += 1

        payloads: list[tuple[str, bytes]] = []
        for variant, path in candidates:
            try:
                payloads.append((variant, _stable_read(path)))
            except (OSError, WechatAdapterError):
                continue
        if not payloads:
            self.stats["image_decode_failures"] += 1
            return None
        if any(data.startswith(V2_MAGIC) for _variant, data in payloads) and not self._key_attempted:
            self._key_attempted = True
            self._key_material = _derive_v2_key(
                self._profile_root, (data for _variant, data in payloads)
            )

        wxgf_fallback: tuple[bytes, str, str, str] | None = None
        for variant, data in payloads:
            try:
                decoded, image_format, decoder = decode_image_dat(
                    data,
                    self._key_material[0] if self._key_material else None,
                    self._key_material[1] if self._key_material else None,
                )
            except WechatAdapterError:
                continue
            if image_format == "wxgf":
                wxgf_fallback = wxgf_fallback or (decoded, image_format, decoder, variant)
                continue
            return self._store(decoded, image_format, decoder, variant, resource_md5)
        if wxgf_fallback:
            return self._store(*wxgf_fallback, resource_md5)
        self.stats["image_decode_failures"] += 1
        return None

    def _store(
        self,
        decoded: bytes,
        image_format: str,
        decoder: str,
        variant: str,
        resource_md5: str,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(decoded).hexdigest()
        extension = "wxgf" if image_format == "wxgf" else image_format
        relative = Path("attachments") / "images" / f"{digest}.{extension}"
        destination = self._export_root / relative
        if not destination.exists():
            _write_private_bytes(destination, decoded)
        self.stats["image_attachments_decoded"] += 1
        return {
            "type": "image",
            "path": relative.as_posix(),
            "file_name": relative.name,
            "mime_type": {
                "jpg": "image/jpeg",
                "png": "image/png",
                "gif": "image/gif",
                "webp": "image/webp",
                "tif": "image/tiff",
                "bmp": "image/bmp",
                "wxgf": "application/x-wechat-wxgf",
            }.get(image_format, "application/octet-stream"),
            "wechat_attachment_status": "decoded",
            "wechat_resource_md5": resource_md5,
            "wechat_dat_variant": variant,
            "wechat_decoder": decoder,
            "wechat_image_format": image_format,
        }


def _is_mp4(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(12)
    except OSError:
        return False
    return len(header) >= 12 and header[4:8] == b"ftyp"


class VideoAttachmentResolver:
    """Resolve locally cached WeChat video bodies without heuristic pairing."""

    VIDEO_DETAIL_TYPE = 131074

    def __init__(self, resource_database: Path, profile_root: Path, export_root: Path):
        self._resource = _connect(resource_database)
        self._video_root = profile_root.expanduser().resolve() / "msg" / "video"
        self._export_root = export_root
        self._by_stem: dict[str, list[Path]] = {}
        if self._video_root.is_dir():
            for path in self._video_root.rglob("*.mp4"):
                if path.is_file() and not path.is_symlink():
                    self._by_stem.setdefault(path.stem.lower(), []).append(path)
        self.stats: dict[str, int] = {
            "video_rows_considered": 0,
            "video_resource_rows": 0,
            "video_sources_found": 0,
            "video_attachments_copied": 0,
            "video_resource_bodies_not_local": 0,
            "video_copy_failures": 0,
        }

    def close(self) -> None:
        self._resource.close()

    def _lookup(
        self, chat: str, local_id: int, create_time: int, base_type: int
    ) -> tuple[str, int] | None:
        chat_row = self._resource.execute(
            "SELECT rowid FROM ChatName2Id WHERE user_name = ?", (chat,)
        ).fetchone()
        if chat_row is None:
            return None
        row = self._resource.execute(
            "SELECT message_id, packed_info FROM MessageResourceInfo "
            "WHERE chat_id = ? AND message_local_id = ? "
            "AND (message_local_type = ? OR (message_local_type & 4294967295) = ?) "
            "AND message_create_time = ? ORDER BY message_id DESC LIMIT 1",
            (int(chat_row[0]), local_id, base_type, base_type, create_time),
        ).fetchone()
        if row is None:
            row = self._resource.execute(
                "SELECT message_id, packed_info FROM MessageResourceInfo "
                "WHERE chat_id = ? AND message_local_id = ? "
                "AND (message_local_type = ? OR (message_local_type & 4294967295) = ?) "
                "ORDER BY message_create_time DESC, message_id DESC LIMIT 1",
                (int(chat_row[0]), local_id, base_type, base_type),
            ).fetchone()
        if row is None or not isinstance(row[1], bytes):
            return None
        resource_md5 = extract_resource_md5(row[1])
        if resource_md5 is None:
            return None
        detail = self._resource.execute(
            "SELECT size FROM MessageResourceDetail WHERE message_id = ? AND type = ? "
            "ORDER BY resource_id DESC LIMIT 1",
            (int(row[0]), self.VIDEO_DETAIL_TYPE),
        ).fetchone()
        declared_size = int(detail[0] or 0) if detail is not None else 0
        return resource_md5, declared_size

    def _source(self, resource_md5: str, create_time: int) -> Path | None:
        neighboring_months = _month_candidates(create_time)
        for month in (
            neighboring_months[1],
            neighboring_months[0],
            neighboring_months[2],
        ):
            candidate = self._video_root / month / f"{resource_md5}.mp4"
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        candidates = self._by_stem.get(resource_md5, [])
        return candidates[0] if len(candidates) == 1 else None

    def resolve(
        self, chat: str, local_id: int, create_time: int, base_type: int
    ) -> dict[str, Any] | None:
        self.stats["video_rows_considered"] += 1
        resource = self._lookup(chat, local_id, create_time, base_type)
        if resource is None:
            return None
        self.stats["video_resource_rows"] += 1
        resource_md5, declared_size = resource
        missing_part: dict[str, Any] = {
            "type": "video",
            "file_name": f"{resource_md5}.mp4",
            "mime_type": "video/mp4",
            "wechat_attachment_status": "resource_body_not_local",
            "wechat_resource_md5": resource_md5,
            "wechat_declared_size": declared_size,
        }
        source = self._source(resource_md5, create_time)
        if source is None:
            self.stats["video_resource_bodies_not_local"] += 1
            return missing_part
        self.stats["video_sources_found"] += 1
        try:
            source_size = source.stat().st_size
            if declared_size <= 0 or source_size != declared_size or not _is_mp4(source):
                raise WechatAdapterError("local video failed size or MP4 validation")
            relative, copied_size = _copy_private_source(
                source, self._export_root, "videos", f"{resource_md5}.mp4"
            )
            if copied_size != declared_size:
                raise WechatAdapterError("copied video size differs from resource detail")
        except (OSError, WechatAdapterError):
            self.stats["video_copy_failures"] += 1
            missing_part["wechat_attachment_status"] = "resource_validation_failed"
            return missing_part
        self.stats["video_attachments_copied"] += 1
        return {
            "type": "video",
            "path": relative,
            "file_name": f"{resource_md5}.mp4",
            "mime_type": "video/mp4",
            "size_bytes": copied_size,
            "wechat_attachment_status": "copied",
            "wechat_resource_md5": resource_md5,
            "wechat_source_match": "message_resource_packed_info",
        }


def _safe_source_name(value: str) -> str | None:
    if not value or value in {".", ".."} or "\x00" in value:
        return None
    normalized = value.replace("\\", "/").split("/")[-1].strip()
    return normalized if normalized not in {"", ".", ".."} else None


def _name_forms(value: str) -> list[str]:
    return list(
        dict.fromkeys(
            (
                value,
                unicodedata.normalize("NFC", value),
                unicodedata.normalize("NFD", value),
            )
        )
    )


def _copy_private_source(
    source: Path, export_root: Path, category: str, file_name: str
) -> tuple[str, int]:
    before = source.stat()
    if before.st_size > MAX_FILE_BYTES:
        raise WechatAdapterError("attachment exceeds the 4 GiB safety limit")
    staging_root = export_root / "attachments" / ".staging"
    _private_directory(staging_root)
    temporary_name: str | None = None
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("rb") as source_handle, tempfile.NamedTemporaryFile(
            dir=staging_root, prefix="attachment.", delete=False
        ) as temporary:
            temporary_name = temporary.name
            while chunk := source_handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                temporary.write(chunk)
            temporary.flush()
            os.fsync(temporary.fileno())
        after = source.stat()
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or size != after.st_size
        ):
            raise WechatAdapterError("source attachment changed while it was being copied")
        digest_hex = digest.hexdigest()
        destination = export_root / "attachments" / category / digest_hex / file_name
        _private_directory(destination.parent)
        if destination.exists():
            Path(temporary_name).unlink()
            temporary_name = None
        else:
            if os.name == "posix":
                os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, destination)
            temporary_name = None
        return destination.relative_to(export_root).as_posix(), size
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink()


class LocalFileResolver:
    def __init__(self, profile_root: Path, export_root: Path):
        self._file_root = profile_root.expanduser().resolve() / "msg" / "file"
        self._export_root = export_root
        self._by_name: dict[str, list[Path]] = {}
        if self._file_root.is_dir():
            for path in self._file_root.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    for form in _name_forms(path.name):
                        self._by_name.setdefault(form, []).append(path)
        self.stats: dict[str, int] = {
            "file_rows_considered": 0,
            "file_sources_found": 0,
            "file_attachments_copied": 0,
            "file_copy_failures": 0,
        }

    def resolve(self, file_name: str, create_time: int) -> dict[str, Any] | None:
        self.stats["file_rows_considered"] += 1
        safe_name = _safe_source_name(file_name)
        if safe_name is None:
            return None
        candidates: list[Path] = []
        for month in _month_candidates(create_time):
            for form in _name_forms(safe_name):
                candidate = self._file_root / month / form
                if candidate.is_file() and not candidate.is_symlink():
                    candidates.append(candidate)
        if not candidates:
            for form in _name_forms(safe_name):
                candidates.extend(self._by_name.get(form, []))
        candidates = list(dict.fromkeys(candidates))
        if not candidates:
            return None
        self.stats["file_sources_found"] += 1
        source = candidates[0]
        try:
            relative, size = _copy_private_source(
                source, self._export_root, "files", safe_name
            )
        except (OSError, WechatAdapterError):
            self.stats["file_copy_failures"] += 1
            return None
        self.stats["file_attachments_copied"] += 1
        mime_type, _encoding = mimetypes.guess_type(safe_name)
        return {
            "type": "file",
            "path": relative,
            "file_name": safe_name,
            "mime_type": mime_type or "application/octet-stream",
            "size_bytes": size,
            "wechat_subtype": "appmsg_file",
            "wechat_attachment_status": "copied",
            "wechat_source_match": "message_title",
        }
