from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .service import InboxService, QueryError


TOOL_DEFINITIONS = [
    {
        "name": "social_get_source_status",
        "title": "Inspect source and collector status",
        "description": "Report imported evidence coverage, collector heartbeat, and source observation without inferring freshness from message timestamps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_kind": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_list_conversations",
        "title": "List imported conversations",
        "description": "List normalized conversations across explicitly imported personal message exports, newest first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_kind": {"type": "string"},
                "conversation_type": {"type": "string", "enum": ["single", "group"]},
                "query": {"type": "string", "description": "Literal title substring."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                "cursor": {"type": "string", "description": "Opaque cursor from the previous result."},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_get_conversation",
        "title": "Get conversation metadata and participants",
        "description": "Read normalized conversation metadata plus a bounded page of group or direct-chat participants.",
        "inputSchema": {
            "type": "object",
            "required": ["conversation_id"],
            "properties": {
                "conversation_id": {"type": "string"},
                "participant_limit": {"type": "integer", "minimum": 1, "maximum": 500},
                "participant_offset": {"type": "integer", "minimum": 0},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_search_messages",
        "title": "Search imported messages",
        "description": "Run literal text search over normalized messages with source, conversation, sender, date, media filters, and preserved source metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Literal words; this is not semantic search."},
                "source_kind": {"type": "string"},
                "conversation_id": {"type": "string"},
                "sender": {"type": "string"},
                "date_after": {"type": "string", "description": "Exclusive ISO 8601 lower bound."},
                "date_before": {"type": "string", "description": "Exclusive ISO 8601 upper bound."},
                "media_type": {"type": "string", "enum": ["any", "image", "audio", "video", "file"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                "cursor": {"type": "string", "description": "Opaque cursor from the previous result."},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_read_context",
        "title": "Read message context",
        "description": "Read bounded messages and preserved source metadata before and after one normalized message in the same conversation.",
        "inputSchema": {
            "type": "object",
            "required": ["message_id"],
            "properties": {
                "message_id": {"type": "string"},
                "before": {"type": "integer", "minimum": 1, "maximum": 50},
                "after": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_get_attachment",
        "title": "Get imported attachment",
        "description": "Return attachment provenance, preserved source URL/cache metadata, and optionally embed a bounded local content blob when present.",
        "inputSchema": {
            "type": "object",
            "required": ["attachment_id"],
            "properties": {
                "attachment_id": {"type": "string"},
                "mode": {"type": "string", "enum": ["metadata", "content"], "default": "metadata"},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 26214400},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_build_digest",
        "title": "Build an evidence digest packet",
        "description": "Build a deterministic, provenance-linked inbox packet for the Agent to summarize; does not call an AI model.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_kind": {"type": "string"},
                "date_after": {"type": "string"},
                "date_before": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_list_event_candidates",
        "title": "List important-event candidates",
        "description": "List deterministic, review-required event candidates derived from imported messages; source evidence remains unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "review_status": {
                    "type": "string",
                    "enum": ["REVIEW_REQUIRED", "APPROVED", "DISMISSED"],
                },
                "event_type": {"type": "string"},
                "source_kind": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                "cursor": {"type": "string", "description": "Opaque cursor from the previous result."},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "social_get_event_candidate",
        "title": "Get an event candidate and its evidence",
        "description": "Read one derived event candidate, rule rationale, and the unchanged source messages that support it.",
        "inputSchema": {
            "type": "object",
            "required": ["candidate_id"],
            "properties": {"candidate_id": {"type": "string"}},
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
]


def _json_content(value: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "type": "text",
            "text": json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True),
        }
    ]


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise QueryError("tool arguments must be an object")
    handlers: dict[str, Callable[[InboxService, dict[str, Any]], dict[str, Any]]] = {
        "social_get_source_status": InboxService.get_source_status,
        "social_list_conversations": InboxService.list_conversations,
        "social_get_conversation": InboxService.get_conversation,
        "social_search_messages": InboxService.search_messages,
        "social_read_context": InboxService.read_context,
        "social_get_attachment": InboxService.get_attachment,
        "social_build_digest": InboxService.build_digest,
        "social_list_event_candidates": InboxService.list_event_candidates,
        "social_get_event_candidate": InboxService.get_event_candidate,
    }
    handler = handlers.get(name)
    if handler is None:
        raise QueryError(f"unknown tool: {name}")

    with InboxService() as service:
        value = handler(service, arguments)

    if name == "social_build_digest":
        return {
            "content": [{"type": "text", "text": value["markdown"]}],
            "structuredContent": value,
        }

    content = _json_content(value)
    if name == "social_get_attachment" and arguments.get("mode", "metadata") == "content":
        if value["status"] != "present" or not value.get("local_path"):
            raise QueryError("attachment content is unavailable because the source file was missing")
        maximum = arguments.get("max_bytes", 2097152)
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 26214400:
            raise QueryError("max_bytes must be between 1 and 26214400")
        path = Path(value["local_path"])
        payload = path.read_bytes()
        if len(payload) > maximum:
            raise QueryError(
                f"attachment is {len(payload)} bytes, above the requested {maximum}-byte embedding limit"
            )
        if hashlib.sha256(payload).hexdigest() != value["blob_sha256"]:
            raise QueryError("attachment content hash no longer matches the imported evidence")
        content.append(
            {
                "type": "resource",
                "resource": {
                    "uri": path.as_uri(),
                    "mimeType": value.get("mime_type") or "application/octet-stream",
                    "blob": base64.b64encode(payload).decode("ascii"),
                },
            }
        )
    return {"content": content, "structuredContent": value}


def _success(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion")
        supported = {"2025-06-18", "2024-11-05"}
        protocol = requested if requested in supported else "2025-06-18"
        return _success(
            request_id,
            {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "personal-social-inbox", "version": "0.2.0"},
                "instructions": "Read-only access to explicitly imported local message evidence. Import is not available through MCP.",
            },
        )
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    if method == "ping":
        return _success(request_id, {})
    if method == "tools/list":
        return _success(request_id, {"tools": TOOL_DEFINITIONS})
    if method == "tools/call":
        try:
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str):
                raise QueryError("tool name is required")
            return _success(request_id, _call_tool(name, arguments))
        except (QueryError, OSError) as exc:
            return _success(
                request_id,
                {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            )
    if request_id is None:
        return None
    return _error(request_id, -32601, f"method not found: {method}")


def serve() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                response = _error(None, -32600, "request must be an object")
            else:
                response = handle_request(request)
        except json.JSONDecodeError:
            response = _error(None, -32700, "parse error")
        except Exception as exc:  # defensive process boundary
            print(f"personal-social-inbox internal error: {exc}", file=sys.stderr)
            response = _error(None, -32603, "internal error")
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve()
