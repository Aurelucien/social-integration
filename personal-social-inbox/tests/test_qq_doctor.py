from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.qq_doctor import IMAGE_REFERENCE, diagnose_qq_docker


class QQDockerDoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.deployment = self.root / "deployment"
        self.deployment.mkdir()
        self.docker_app = self.root / "Docker.app"
        self.docker_app.mkdir()
        (self.deployment / "compose.yaml").write_text(
            f"image: {IMAGE_REFERENCE}\n"
            'ports:\n  - "127.0.0.1:40653:40653"\n'
            '  - "127.0.0.1:6099:6099"\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @patch("personal_social_inbox.qq_doctor._web_ready", return_value=True)
    @patch("personal_social_inbox.qq_doctor._command")
    @patch("personal_social_inbox.qq_doctor.shutil.which", return_value="/usr/local/bin/docker")
    def test_reports_redacted_ready_runtime(
        self, _which: object, command: object, _web: object
    ) -> None:
        command.side_effect = [  # type: ignore[attr-defined]
            (True, "29.5.3"),
            (True, ""),
            (True, "running"),
        ]
        result = diagnose_qq_docker(self.deployment, self.docker_app)
        self.assertEqual(result["capability"], "PARTIAL_EXPORT")
        self.assertTrue(result["deployment"]["loopback_only"])
        self.assertTrue(result["deployment"]["container_running"])
        self.assertFalse(result["privacy"]["message_content_read"])
        self.assertFalse(result["privacy"]["access_token_read"])
        self.assertFalse(result["privacy"]["container_logs_read"])

    @patch("personal_social_inbox.qq_doctor.shutil.which", return_value=None)
    def test_missing_docker_is_explicit(self, _which: object) -> None:
        result = diagnose_qq_docker(self.deployment, self.root / "missing.app")
        self.assertEqual(result["capability"], "REQUIRES_USER_ACTION")
        self.assertEqual(result["reason"], "docker_not_installed")


if __name__ == "__main__":
    unittest.main()
