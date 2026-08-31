from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .qq_generation import QCE_IMAGE_DIGEST, QCE_SOURCE_COMMIT, QCE_VERSION


DEFAULT_DOCKER_APP_PATH = Path("/Applications/Docker.app")
DEFAULT_DEPLOYMENT_ROOT = (
    Path(__file__).resolve().parents[3] / "experiments" / "qq-qce-docker"
)
CONTAINER_NAME = "personal-social-inbox-qq-qce"
IMAGE_REFERENCE = f"ghcr.io/shuakami/napcat-qce:{QCE_VERSION}@{QCE_IMAGE_DIGEST}"


def _command(arguments: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    return result.returncode == 0, result.stdout.strip()


def _web_ready() -> bool:
    request = urllib.request.Request(
        "http://127.0.0.1:40653/security-status",
        headers={"User-Agent": "personal-social-inbox-qq-doctor/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            payload = json.loads(response.read(64 * 1024).decode("utf-8"))
    except (OSError, urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return response.status == 200 and isinstance(payload, dict)


def diagnose_qq_docker(
    deployment_root: Path = DEFAULT_DEPLOYMENT_ROOT,
    docker_app_path: Path = DEFAULT_DOCKER_APP_PATH,
) -> dict[str, Any]:
    """Inspect Docker/QCE readiness without reading logs, tokens or QQ data."""

    deployment = deployment_root.expanduser().resolve()
    compose_path = deployment / "compose.yaml"
    docker_path = shutil.which("docker")
    compose_text = ""
    if compose_path.is_file():
        try:
            compose_text = compose_path.read_text(encoding="utf-8")
        except OSError:
            pass
    pinned_configuration = (
        IMAGE_REFERENCE in compose_text
        and "127.0.0.1:40653:40653" in compose_text
        and "127.0.0.1:6099:6099" in compose_text
    )

    daemon_ready = False
    server_version: str | None = None
    if docker_path:
        daemon_ready, server_version = _command(
            [docker_path, "info", "--format", "{{.ServerVersion}}"]
        )
        server_version = server_version or None

    image_present = False
    container_present = False
    container_running = False
    if daemon_ready and docker_path:
        image_present, _ = _command([docker_path, "image", "inspect", IMAGE_REFERENCE])
        container_present, state = _command(
            [
                docker_path,
                "container",
                "inspect",
                CONTAINER_NAME,
                "--format",
                "{{.State.Status}}",
            ]
        )
        container_running = container_present and state == "running"

    web_ready = container_running and _web_ready()
    if not docker_path or not docker_app_path.is_dir():
        capability = "REQUIRES_USER_ACTION"
        reason = "docker_not_installed"
    elif not daemon_ready:
        capability = "REQUIRES_USER_ACTION"
        reason = "docker_daemon_not_running"
    elif not compose_path.is_file() or not pinned_configuration:
        capability = "UNSUPPORTED_VERSION"
        reason = "pinned_qce_compose_unavailable_or_changed"
    elif not image_present:
        capability = "REQUIRES_USER_ACTION"
        reason = "pinned_qce_image_not_pulled"
    elif not container_running:
        capability = "REQUIRES_USER_ACTION"
        reason = "qce_container_not_running"
    elif not web_ready:
        capability = "REQUIRES_USER_ACTION"
        reason = "qce_web_service_not_ready"
    else:
        capability = "PARTIAL_EXPORT"
        reason = "qce_web_ready_login_and_group_scope_not_verified"

    return {
        "schema": "personal-social-inbox/qq-docker-doctor/v1",
        "capability": capability,
        "reason": reason,
        "docker": {
            "cli_present": bool(docker_path),
            "desktop_present": docker_app_path.is_dir(),
            "daemon_ready": daemon_ready,
            "server_version": server_version,
        },
        "deployment": {
            "compose_present": compose_path.is_file(),
            "pinned_configuration": pinned_configuration,
            "qce_version": QCE_VERSION,
            "qce_source_commit": QCE_SOURCE_COMMIT,
            "qce_image_digest": QCE_IMAGE_DIGEST,
            "image_present": image_present,
            "container_present": container_present,
            "container_running": container_running,
            "web_ready": web_ready,
            "loopback_only": pinned_configuration,
        },
        "privacy": {
            "message_content_read": False,
            "access_token_read": False,
            "container_logs_read": False,
            "qq_session_files_read": False,
            "account_identifier_reported": False,
        },
        "safe_next_inputs": [
            "account-owner QR confirmation",
            "an explicit QQ group allowlist",
            "a completed QCE JSON export",
        ],
    }
