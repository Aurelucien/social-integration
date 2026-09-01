from __future__ import annotations

import os
import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    external_account_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(kind, external_account_id)
);

CREATE TABLE IF NOT EXISTS import_runs (
    id TEXT PRIMARY KEY,
    manifest_sha256 TEXT NOT NULL UNIQUE,
    source_id TEXT NOT NULL REFERENCES sources(id),
    source_manifest_path TEXT NOT NULL,
    exported_at TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    inserted_messages INTEGER NOT NULL DEFAULT 0,
    reused_messages INTEGER NOT NULL DEFAULT 0,
    present_attachments INTEGER NOT NULL DEFAULT 0,
    missing_attachments INTEGER NOT NULL DEFAULT 0,
    warnings_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(id),
    external_identity_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_self INTEGER NOT NULL DEFAULT 0 CHECK(is_self IN (0, 1)),
    raw_json TEXT NOT NULL,
    UNIQUE(source_id, external_identity_id)
);

CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(id),
    external_conversation_id TEXT NOT NULL,
    title TEXT NOT NULL,
    conversation_type TEXT NOT NULL CHECK(conversation_type IN ('single', 'group')),
    last_activity TEXT,
    raw_json TEXT NOT NULL,
    UNIQUE(source_id, external_conversation_id)
);

CREATE TABLE IF NOT EXISTS conversation_participants (
    conversation_id TEXT NOT NULL REFERENCES conversations(id),
    identity_id TEXT NOT NULL REFERENCES identities(id),
    raw_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(conversation_id, identity_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(id),
    conversation_id TEXT NOT NULL REFERENCES conversations(id),
    external_message_id TEXT NOT NULL,
    sender_identity_id TEXT REFERENCES identities(id),
    sender_display_name TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('incoming', 'outgoing', 'system', 'unknown')),
    raw_json TEXT NOT NULL,
    import_run_id TEXT NOT NULL REFERENCES import_runs(id),
    UNIQUE(source_id, external_message_id)
);

CREATE INDEX IF NOT EXISTS messages_conversation_time
ON messages(conversation_id, sent_at, id);

CREATE INDEX IF NOT EXISTS messages_source_time
ON messages(source_id, sent_at, id);

CREATE TABLE IF NOT EXISTS blobs (
    sha256 TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    stored_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages(id),
    part_index INTEGER NOT NULL,
    blob_sha256 TEXT REFERENCES blobs(sha256),
    file_name TEXT NOT NULL,
    mime_type TEXT,
    source_relative_path TEXT,
    status TEXT NOT NULL CHECK(status IN ('present', 'missing')),
    size_bytes INTEGER,
    raw_json TEXT NOT NULL,
    UNIQUE(message_id, part_index)
);

CREATE TABLE IF NOT EXISTS message_parts (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages(id),
    part_index INTEGER NOT NULL,
    part_type TEXT NOT NULL,
    text_content TEXT,
    attachment_id TEXT REFERENCES attachments(id),
    raw_json TEXT NOT NULL,
    UNIQUE(message_id, part_index)
);

CREATE TABLE IF NOT EXISTS derived_artifacts (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    content TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    definition_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_runs (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES monitor_rules(id),
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('complete', 'partial')),
    scanned_messages INTEGER NOT NULL,
    candidate_count INTEGER NOT NULL,
    remaining_messages INTEGER NOT NULL,
    source_status_json TEXT NOT NULL,
    warnings_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS event_candidates (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES monitor_rules(id),
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    review_status TEXT NOT NULL DEFAULT 'REVIEW_REQUIRED'
        CHECK(review_status IN ('REVIEW_REQUIRED', 'APPROVED', 'DISMISSED')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    event_at TEXT,
    deadline_at TEXT,
    time_uncertain INTEGER NOT NULL DEFAULT 1 CHECK(time_uncertain IN (0, 1)),
    importance TEXT NOT NULL DEFAULT 'normal',
    dedup_key TEXT NOT NULL,
    rationale_json TEXT NOT NULL,
    UNIQUE(rule_id, dedup_key)
);

CREATE INDEX IF NOT EXISTS event_candidates_status_seen
ON event_candidates(review_status, last_seen_at, id);

CREATE TABLE IF NOT EXISTS event_evidence (
    candidate_id TEXT NOT NULL REFERENCES event_candidates(id),
    message_id TEXT NOT NULL REFERENCES messages(id),
    evidence_role TEXT NOT NULL DEFAULT 'trigger',
    evidence_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(candidate_id, message_id)
);

CREATE TABLE IF NOT EXISTS monitor_message_state (
    rule_id TEXT NOT NULL REFERENCES monitor_rules(id),
    message_id TEXT NOT NULL REFERENCES messages(id),
    scanned_at TEXT NOT NULL,
    matched INTEGER NOT NULL CHECK(matched IN (0, 1)),
    monitor_run_id TEXT NOT NULL REFERENCES monitor_runs(id),
    PRIMARY KEY(rule_id, message_id)
);

CREATE TABLE IF NOT EXISTS collector_heartbeats (
    detector_id TEXT PRIMARY KEY,
    source_kind TEXT NOT NULL,
    external_account_id TEXT NOT NULL,
    observation_scope TEXT NOT NULL CHECK(observation_scope IN (
        'source_profile_metadata',
        'explicit_export_metadata',
        'acquisition_readiness'
    )),
    state TEXT NOT NULL CHECK(state IN (
        'BASELINE_ESTABLISHED',
        'OK_UNCHANGED',
        'CHANGE_OBSERVED',
        'REQUIRES_USER_ACTION',
        'RETRYABLE_ERROR'
    )),
    worker_heartbeat_at TEXT NOT NULL,
    source_observed_at TEXT,
    last_change_at TEXT,
    source_token TEXT,
    last_generation_id TEXT,
    generation_complete_at TEXT,
    last_import_at TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,
    error_code TEXT,
    stale_after_seconds REAL NOT NULL CHECK(stale_after_seconds > 0),
    details_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL,
    UNIQUE(source_kind, external_account_id)
);

CREATE TABLE IF NOT EXISTS collector_events (
    id TEXT PRIMARY KEY,
    detector_id TEXT NOT NULL REFERENCES collector_heartbeats(detector_id),
    occurred_at TEXT NOT NULL,
    state TEXT NOT NULL,
    observation_scope TEXT NOT NULL,
    source_token TEXT,
    error_code TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS collector_events_detector_time
ON collector_events(detector_id, occurred_at, id);

CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
    message_id UNINDEXED,
    body,
    tokenize='unicode61'
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        db_path.parent.chmod(0o700)
    connection = sqlite3.connect(db_path)
    if os.name == "posix":
        db_path.chmod(0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    participant_columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(conversation_participants)")
    }
    if "raw_json" not in participant_columns:
        connection.execute(
            "ALTER TABLE conversation_participants "
            "ADD COLUMN raw_json TEXT NOT NULL DEFAULT '{}'"
        )
    connection.execute(
        "INSERT OR IGNORE INTO schema_info(version, applied_at) VALUES(1, datetime('now'))"
    )
    connection.execute(
        "INSERT OR IGNORE INTO schema_info(version, applied_at) VALUES(2, datetime('now'))"
    )
    connection.execute(
        "INSERT OR IGNORE INTO schema_info(version, applied_at) VALUES(3, datetime('now'))"
    )
    connection.execute(
        "INSERT OR IGNORE INTO schema_info(version, applied_at) VALUES(4, datetime('now'))"
    )
    connection.commit()
