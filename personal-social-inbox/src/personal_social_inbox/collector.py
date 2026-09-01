from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Protocol

from .database import connect, initialize
from .paths import database_path, default_data_home
from .qq_doctor import (
    DEFAULT_DEPLOYMENT_ROOT,
    DEFAULT_DOCKER_APP_PATH,
    diagnose_qq_docker,
)


CONFIG_SCHEMA = "personal-social-inbox/collector-config/v1"
WECHAT_TARGETS = (
    "session/session.db",
    "contact/contact.db",
    "message/message_0.db",
    "message/message_1.db",
    "message/message_resource.db",
    "message/media_0.db",
    "message/media_1.db",
)
DINGTALK_TARGETS = ("DBFiles/dingtalk.db", "user_config")
WECHAT_REQUIRED_TARGETS = {
    "session/session.db",
    "contact/contact.db",
    "message/message_0.db",
    "message/message_1.db",
}
OBSERVATION_SCOPES = {
    "source_profile_metadata",
    "explicit_export_metadata",
    "acquisition_readiness",
}
STATES = {
    "BASELINE_ESTABLISHED",
    "OK_UNCHANGED",
    "CHANGE_OBSERVED",
    "REQUIRES_USER_ACTION",
    "RETRYABLE_ERROR",
}


class CollectorConfigError(ValueError):
    pass


@dataclass(frozen=True)
class DetectorConfig:
    detector_id: str
    source_kind: str
    external_account_id: str
    interval_seconds: float
    stale_after_seconds: float
    source_root: Path | None = None
    deployment_root: Path = DEFAULT_DEPLOYMENT_ROOT
    docker_app_path: Path = DEFAULT_DOCKER_APP_PATH
    max_files: int = 20_000


@dataclass(frozen=True)
class ProbeResult:
    observation_scope: str
    source_token: str | None
    source_observed: bool
    state: str | None = None
    error_code: str | None = None
    details: dict[str, Any] | None = None


class Detector(Protocol):
    config: DetectorConfig

    async def probe(self) -> ProbeResult: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_token(payload: object) -> str:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_relative(value: str) -> PurePosixPath:
    if "\\" in value:
        raise CollectorConfigError("detector target uses an unsupported path separator")
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise CollectorConfigError("detector target must be a safe relative path")
    return relative


def _metadata(path: Path) -> dict[str, int] | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        stat = path.stat()
    except OSError:
        return None
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "inode": stat.st_ino}


def _fingerprint_selected(
    root: Path, targets: tuple[str, ...], required_targets: set[str]
) -> tuple[str, int]:
    selected_root = root.expanduser().resolve(strict=True)
    if not selected_root.is_dir():
        raise OSError("selected source root is not a directory")
    inventory: dict[str, object] = {}
    present = 0
    for value in targets:
        relative = _safe_relative(value)
        unresolved = selected_root / Path(*relative.parts)
        if unresolved.is_symlink():
            raise OSError("selected detector target must not be a symlink")
        candidate = unresolved.resolve()
        try:
            candidate.relative_to(selected_root)
        except ValueError as exc:
            raise OSError("selected detector target escapes its source root") from exc
        summary = _metadata(candidate)
        inventory[value] = summary
        if summary is not None:
            present += 1
        wal = candidate.with_name(candidate.name + "-wal")
        wal_summary = _metadata(wal)
        inventory[f"{value}-wal"] = wal_summary
        if wal_summary is not None:
            present += 1
    if any(inventory.get(value) is None for value in required_targets):
        raise OSError("required detector files are unavailable")
    return _canonical_token(inventory), present


def _fingerprint_tree(root: Path, max_files: int) -> tuple[str, int]:
    selected_root = root.expanduser().resolve(strict=True)
    if not selected_root.is_dir():
        raise OSError("selected export root is not a directory")
    inventory: list[dict[str, object]] = []
    for directory, directory_names, file_names in os.walk(
        selected_root, followlinks=False
    ):
        base = Path(directory)
        directory_names[:] = sorted(
            name for name in directory_names if not (base / name).is_symlink()
        )
        for name in sorted(file_names):
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(selected_root).as_posix()
            summary = _metadata(path)
            if summary is None:
                continue
            inventory.append({"relative_path": relative, **summary})
            if len(inventory) > max_files:
                raise OSError("selected export root exceeds the detector file limit")
    if not inventory:
        raise OSError("selected export root contains no regular files")
    return _canonical_token(inventory), len(inventory)


class WeChatDetector:
    def __init__(self, config: DetectorConfig):
        self.config = config

    async def probe(self) -> ProbeResult:
        assert self.config.source_root is not None
        token, count = await asyncio.to_thread(
            _fingerprint_selected,
            self.config.source_root,
            WECHAT_TARGETS,
            WECHAT_REQUIRED_TARGETS,
        )
        return ProbeResult(
            observation_scope="source_profile_metadata",
            source_token=token,
            source_observed=True,
            details={"observed_file_count": count, "message_content_read": False},
        )


class DingTalkDetector:
    def __init__(self, config: DetectorConfig):
        self.config = config

    async def probe(self) -> ProbeResult:
        assert self.config.source_root is not None
        token, count = await asyncio.to_thread(
            _fingerprint_selected,
            self.config.source_root,
            DINGTALK_TARGETS,
            set(DINGTALK_TARGETS),
        )
        return ProbeResult(
            observation_scope="source_profile_metadata",
            source_token=token,
            source_observed=True,
            details={"observed_file_count": count, "message_content_read": False},
        )


class QQDetector:
    def __init__(self, config: DetectorConfig):
        self.config = config

    async def probe(self) -> ProbeResult:
        readiness = await asyncio.to_thread(
            diagnose_qq_docker,
            self.config.deployment_root,
            self.config.docker_app_path,
        )
        capability = str(readiness.get("capability", "REQUIRES_USER_ACTION"))
        reason = str(readiness.get("reason", "qq_readiness_unknown"))
        details = {
            "capability": capability,
            "reason": reason,
            "message_content_read": False,
            "access_token_read": False,
        }
        if self.config.source_root is None:
            return ProbeResult(
                observation_scope="acquisition_readiness",
                source_token=None,
                source_observed=False,
                state=(
                    None if capability == "PARTIAL_EXPORT" else "REQUIRES_USER_ACTION"
                ),
                error_code=None if capability == "PARTIAL_EXPORT" else reason,
                details=details,
            )
        token, count = await asyncio.to_thread(
            _fingerprint_tree, self.config.source_root, self.config.max_files
        )
        details["observed_file_count"] = count
        return ProbeResult(
            observation_scope="explicit_export_metadata",
            source_token=token,
            source_observed=True,
            state=(None if capability == "PARTIAL_EXPORT" else "REQUIRES_USER_ACTION"),
            error_code=None if capability == "PARTIAL_EXPORT" else reason,
            details=details,
        )


class HeartbeatLedger:
    def __init__(self, data_home: Path | None = None):
        self.data_home = (data_home or default_data_home()).resolve()

    def _connect(self) -> sqlite3.Connection:
        connection = connect(database_path(self.data_home))
        initialize(connection)
        return connection

    def current(self, detector_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM collector_heartbeats WHERE detector_id = ?",
                (detector_id,),
            ).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def record_probe(
        self,
        config: DetectorConfig,
        probe: ProbeResult,
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        if probe.observation_scope not in OBSERVATION_SCOPES:
            raise ValueError("unsupported collector observation scope")
        now = observed_at or _utc_now()
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            previous_row = connection.execute(
                "SELECT * FROM collector_heartbeats WHERE detector_id = ?",
                (config.detector_id,),
            ).fetchone()
            previous = dict(previous_row) if previous_row is not None else None
            binding_row = connection.execute(
                """
                SELECT detector_id FROM collector_heartbeats
                WHERE source_kind = ? AND external_account_id = ?
                """,
                (config.source_kind, config.external_account_id),
            ).fetchone()
            if previous is not None and (
                previous["source_kind"] != config.source_kind
                or previous["external_account_id"] != config.external_account_id
            ):
                raise ValueError("collector detector binding is immutable")
            if binding_row is not None and binding_row["detector_id"] != config.detector_id:
                raise ValueError("collector source binding already belongs to another detector")
            effective_source_token = probe.source_token
            if (
                effective_source_token is None
                and probe.state == "RETRYABLE_ERROR"
                and previous is not None
            ):
                effective_source_token = previous.get("source_token")
            if probe.state is not None:
                state = probe.state
            elif effective_source_token is None:
                state = "OK_UNCHANGED"
            elif previous is None or previous.get("source_token") is None:
                state = "BASELINE_ESTABLISHED"
            elif previous["source_token"] == effective_source_token:
                state = "OK_UNCHANGED"
            else:
                state = "CHANGE_OBSERVED"
            if state not in STATES:
                raise ValueError("unsupported collector state")

            failed = state in {"REQUIRES_USER_ACTION", "RETRYABLE_ERROR"}
            consecutive_failures = (
                int(previous["consecutive_failures"]) + 1
                if failed and previous is not None
                else (1 if failed else 0)
            )
            retry_delay_seconds = (
                min(
                    config.interval_seconds
                    * (2 ** min(max(consecutive_failures - 1, 0), 10)),
                    max(config.interval_seconds, config.stale_after_seconds / 2),
                    900.0,
                )
                if failed
                else config.interval_seconds
            )
            next_retry_at = (
                _timestamp(now + timedelta(seconds=retry_delay_seconds))
                if failed
                else None
            )
            source_observed_at = (
                timestamp
                if probe.source_observed
                else (previous.get("source_observed_at") if previous else None)
            )
            last_change_at = (
                timestamp
                if state == "CHANGE_OBSERVED"
                else (previous.get("last_change_at") if previous else None)
            )
            details_json = json.dumps(
                probe.details or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            transition = (
                previous is None
                or previous["state"] != state
                or previous["source_token"] != effective_source_token
                or previous["error_code"] != probe.error_code
            )
            with connection:
                connection.execute(
                    """
                    INSERT INTO collector_heartbeats(
                        detector_id, source_kind, external_account_id,
                        observation_scope, state, worker_heartbeat_at,
                        source_observed_at, last_change_at, source_token,
                        consecutive_failures, next_retry_at, error_code,
                        stale_after_seconds, details_json, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(detector_id) DO UPDATE SET
                        source_kind = excluded.source_kind,
                        external_account_id = excluded.external_account_id,
                        observation_scope = excluded.observation_scope,
                        state = excluded.state,
                        worker_heartbeat_at = excluded.worker_heartbeat_at,
                        source_observed_at = excluded.source_observed_at,
                        last_change_at = excluded.last_change_at,
                        source_token = excluded.source_token,
                        consecutive_failures = excluded.consecutive_failures,
                        next_retry_at = excluded.next_retry_at,
                        error_code = excluded.error_code,
                        stale_after_seconds = excluded.stale_after_seconds,
                        details_json = excluded.details_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        config.detector_id,
                        config.source_kind,
                        config.external_account_id,
                        probe.observation_scope,
                        state,
                        timestamp,
                        source_observed_at,
                        last_change_at,
                        effective_source_token,
                        consecutive_failures,
                        next_retry_at,
                        probe.error_code,
                        config.stale_after_seconds,
                        details_json,
                        timestamp,
                    ),
                )
                if transition:
                    connection.execute(
                        """
                        INSERT INTO collector_events(
                            id, detector_id, occurred_at, state, observation_scope,
                            source_token, error_code, details_json
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"cev_{uuid.uuid4().hex}",
                            config.detector_id,
                            timestamp,
                            state,
                            probe.observation_scope,
                            effective_source_token,
                            probe.error_code,
                            details_json,
                        ),
                    )
            return {
                "detector_id": config.detector_id,
                "source_kind": config.source_kind,
                "observation_scope": probe.observation_scope,
                "state": state,
                "worker_heartbeat_at": timestamp,
                "source_observed_at": source_observed_at,
                "last_change_at": last_change_at,
                "consecutive_failures": consecutive_failures,
                "next_retry_at": next_retry_at,
                "error_code": probe.error_code,
                "retry_delay_seconds": retry_delay_seconds,
                "transition_recorded": transition,
            }
        finally:
            connection.close()

    def record_lifecycle(
        self,
        source_kind: str,
        external_account_id: str,
        generation_id: str,
        *,
        completed_at: datetime | None = None,
    ) -> bool:
        now = completed_at or _utc_now()
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT detector_id, observation_scope, last_generation_id, last_import_at
                FROM collector_heartbeats
                WHERE source_kind = ? AND external_account_id = ?
                """,
                (source_kind, external_account_id),
            ).fetchone()
            if row is None:
                return False
            if row["last_generation_id"] == generation_id and row["last_import_at"]:
                return False
            with connection:
                connection.execute(
                    """
                    UPDATE collector_heartbeats
                    SET last_generation_id = ?, last_import_at = ?, updated_at = ?
                    WHERE detector_id = ?
                    """,
                    (generation_id, timestamp, timestamp, row["detector_id"]),
                )
                connection.execute(
                    """
                    INSERT INTO collector_events(
                        id, detector_id, occurred_at, state, observation_scope,
                        source_token, error_code, details_json
                    ) VALUES(?, ?, ?, 'IMPORT_COMPLETE', ?, NULL, NULL, ?)
                    """,
                    (
                        f"cev_{uuid.uuid4().hex}",
                        row["detector_id"],
                        timestamp,
                        row["observation_scope"],
                        json.dumps(
                            {"generation_id": generation_id},
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
            return True
        finally:
            connection.close()

    def record_error(
        self,
        config: DetectorConfig,
        error: BaseException,
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        error_code = type(error).__name__
        return self.record_probe(
            config,
            ProbeResult(
                observation_scope=(
                    "acquisition_readiness"
                    if config.source_kind == "qq" and config.source_root is None
                    else (
                        "explicit_export_metadata"
                        if config.source_kind == "qq"
                        else "source_profile_metadata"
                    )
                ),
                source_token=None,
                source_observed=False,
                state="RETRYABLE_ERROR",
                error_code=error_code,
                details={"error_code": error_code, "message_content_read": False},
            ),
            observed_at=observed_at,
        )


def _required_text(container: dict[str, Any], key: str, where: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CollectorConfigError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _positive_number(
    container: dict[str, Any], key: str, default: float, where: str
) -> float:
    value = container.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise CollectorConfigError(f"{where}.{key} must be a positive number")
    return float(value)


def load_collector_config(path: Path) -> list[DetectorConfig]:
    try:
        payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CollectorConfigError("collector config is unavailable") from exc
    except json.JSONDecodeError as exc:
        raise CollectorConfigError("collector config is invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema") != CONFIG_SCHEMA:
        raise CollectorConfigError("collector config schema is unsupported")
    raw_detectors = payload.get("detectors")
    if not isinstance(raw_detectors, list) or not raw_detectors:
        raise CollectorConfigError("collector config must contain detectors")

    configs: list[DetectorConfig] = []
    ids: set[str] = set()
    bindings: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_detectors):
        where = f"detectors[{index}]"
        if not isinstance(raw, dict):
            raise CollectorConfigError(f"{where} must be an object")
        detector_id = _required_text(raw, "id", where)
        source_kind = _required_text(raw, "source_kind", where)
        account_id = _required_text(raw, "account_id", where)
        if source_kind not in {"wechat", "dingtalk", "qq"}:
            raise CollectorConfigError(f"{where}.source_kind is unsupported")
        if detector_id in ids or (source_kind, account_id) in bindings:
            raise CollectorConfigError("collector detector identifiers must be unique")
        ids.add(detector_id)
        bindings.add((source_kind, account_id))
        interval = _positive_number(raw, "interval_seconds", 30.0, where)
        stale_after = _positive_number(
            raw, "stale_after_seconds", max(interval * 3, 60.0), where
        )
        if stale_after <= interval:
            raise CollectorConfigError(
                f"{where}.stale_after_seconds must exceed interval_seconds"
            )
        source_root_value = raw.get("source_root")
        if source_root_value is not None and not isinstance(source_root_value, str):
            raise CollectorConfigError(f"{where}.source_root must be a string")
        if source_kind in {"wechat", "dingtalk"} and not source_root_value:
            raise CollectorConfigError(f"{where}.source_root is required")
        max_files_value = raw.get("max_files", 20_000)
        if (
            isinstance(max_files_value, bool)
            or not isinstance(max_files_value, int)
            or max_files_value < 1
            or max_files_value > 100_000
        ):
            raise CollectorConfigError(
                f"{where}.max_files must be between 1 and 100000"
            )
        deployment = raw.get("deployment_root", str(DEFAULT_DEPLOYMENT_ROOT))
        docker_app = raw.get("docker_app_path", str(DEFAULT_DOCKER_APP_PATH))
        if not isinstance(deployment, str) or not isinstance(docker_app, str):
            raise CollectorConfigError(
                f"{where}.deployment_root and docker_app_path must be strings"
            )
        configs.append(
            DetectorConfig(
                detector_id=detector_id,
                source_kind=source_kind,
                external_account_id=account_id,
                interval_seconds=interval,
                stale_after_seconds=stale_after,
                source_root=(
                    Path(source_root_value).expanduser()
                    if source_root_value is not None
                    else None
                ),
                deployment_root=Path(deployment).expanduser(),
                docker_app_path=Path(docker_app).expanduser(),
                max_files=max_files_value,
            )
        )
    return configs


def build_detector(config: DetectorConfig) -> Detector:
    if config.source_kind == "wechat":
        return WeChatDetector(config)
    if config.source_kind == "dingtalk":
        return DingTalkDetector(config)
    return QQDetector(config)


async def _observe_once(
    detector: Detector, ledger: HeartbeatLedger, write_lock: asyncio.Lock
) -> dict[str, Any]:
    try:
        probe = await detector.probe()
    except (OSError, sqlite3.Error, ValueError) as exc:
        async with write_lock:
            return await asyncio.to_thread(ledger.record_error, detector.config, exc)
    async with write_lock:
        return await asyncio.to_thread(ledger.record_probe, detector.config, probe)


async def _detector_loop(
    detector: Detector,
    ledger: HeartbeatLedger,
    write_lock: asyncio.Lock,
    stop: asyncio.Event,
    emit: Callable[[dict[str, Any]], None] | None,
) -> None:
    while not stop.is_set():
        result = await _observe_once(detector, ledger, write_lock)
        if emit is not None and result["transition_recorded"]:
            emit(result)
        try:
            await asyncio.wait_for(
                stop.wait(), timeout=float(result["retry_delay_seconds"])
            )
        except TimeoutError:
            pass


async def run_supervisor(
    configs: list[DetectorConfig],
    data_home: Path | None = None,
    *,
    once: bool = False,
    emit: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    ledger = HeartbeatLedger(data_home)
    detectors = [build_detector(config) for config in configs]
    write_lock = asyncio.Lock()
    if once:
        results = await asyncio.gather(
            *(_observe_once(detector, ledger, write_lock) for detector in detectors)
        )
        return {"status": "COMPLETE", "mode": "once", "items": results}

    stop = asyncio.Event()
    try:
        async with asyncio.TaskGroup() as group:
            for detector in detectors:
                group.create_task(
                    _detector_loop(detector, ledger, write_lock, stop, emit)
                )
    except asyncio.CancelledError:
        stop.set()
        raise
    return {"status": "STOPPED", "mode": "continuous"}


def run_collector(
    config_path: Path,
    data_home: Path | None = None,
    *,
    once: bool = False,
) -> dict[str, Any]:
    configs = load_collector_config(config_path)

    def emit(item: dict[str, Any]) -> None:
        print(json.dumps(item, ensure_ascii=False, sort_keys=True), flush=True)

    return asyncio.run(run_supervisor(configs, data_home, once=once, emit=emit))
