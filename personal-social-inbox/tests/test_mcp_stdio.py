from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from personal_social_inbox.importer import import_manifest
from personal_social_inbox.service import InboxService


class MCPStdioTests(unittest.TestCase):
    def test_initialize_list_and_call_over_stdio(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_home = Path(temporary) / "data"
            import_manifest(
                ROOT / "examples" / "sample-export" / "export.json", data_home
            )
            with InboxService(data_home) as service:
                group_id = service.list_conversations(
                    {"conversation_type": "group"}
                )["items"][0]["id"]
                attachment_message = service.search_messages(
                    {"query": "shopping", "media_type": "file"}
                )["items"][0]
                attachment_id = next(
                    part["attachment"]["id"]
                    for part in attachment_message["parts"]
                    if "attachment" in part
                )
            requests = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "social_search_messages",
                        "arguments": {"query": "Monday"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "social_get_attachment",
                        "arguments": {
                            "attachment_id": attachment_id,
                            "mode": "content",
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "social_get_conversation",
                        "arguments": {"conversation_id": group_id},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "social_get_source_status",
                        "arguments": {},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "social_list_event_candidates",
                        "arguments": {},
                    },
                },
            ]
            process = subprocess.run(
                [sys.executable, str(ROOT / "server.py")],
                input="".join(json.dumps(item) + "\n" for item in requests),
                text=True,
                capture_output=True,
                env={**os.environ, "PERSONAL_SOCIAL_INBOX_HOME": str(data_home)},
                cwd=ROOT,
                timeout=10,
                check=True,
            )
            responses = [json.loads(line) for line in process.stdout.splitlines()]
            self.assertEqual(len(responses), 7)
            self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-06-18")
            tools = responses[1]["result"]["tools"]
            self.assertEqual(len(tools), 9)
            self.assertTrue(all(tool["annotations"]["readOnlyHint"] for tool in tools))
            search_result = responses[2]["result"]["structuredContent"]
            self.assertEqual(len(search_result["items"]), 1)
            self.assertEqual(search_result["items"][0]["conversation_title"], "Project Check-in")
            resource = responses[3]["result"]["content"][1]["resource"]
            self.assertEqual(base64.b64decode(resource["blob"]), b"Milk\nTea\nFruit\n")
            self.assertEqual(resource["mimeType"], "text/plain")
            conversation = responses[4]["result"]["structuredContent"]
            self.assertEqual(conversation["group"]["owner_id"], "me")
            self.assertEqual(conversation["participant_count"], 2)
            source_status = responses[5]["result"]["structuredContent"]
            self.assertEqual(
                source_status["items"][0]["collector_freshness_state"],
                "NOT_RECORDED",
            )
            self.assertEqual(
                responses[6]["result"]["structuredContent"]["items"], []
            )
            self.assertEqual(process.stderr, "")


if __name__ == "__main__":
    unittest.main()
