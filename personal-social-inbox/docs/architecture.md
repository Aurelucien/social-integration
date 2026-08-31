# Architecture and trust boundaries

```text
explicit export directory
        |
        v
source adapter / v1 manifest
        |
        v
validation + immutable normalization ----> import diagnostics
        |                                      |
        +-------------> SQLite <---------------+
                              |
                              +--> deterministic event candidates
        |
        +-------------> SHA-256 blob store
                              |
                              v
                     read-only MCP server
                              |
                              v
                            Agent
```

## Authority layers

1. **Source authority**: the explicitly selected export and its files. These
   are never modified.
2. **Normalized evidence**: immutable messages, message parts, identities,
   conversations, hashes, and import receipts.
3. **Derived material**: transcripts, summaries, themes, and other output that
   can be regenerated. Derived material cannot silently become source truth.

Important-event candidates are derived material. They default to
`REVIEW_REQUIRED`, retain links to unchanged source messages, and record
uncertain time fields explicitly. Rule scans keep per-rule/per-message state so
newly imported messages are processed incrementally even when their source
timestamp is older than the previous scan.

## Adapter boundary

Platform-specific acquisition remains outside the core. A WeChat, QQ, or
DingTalk adapter is responsible for producing `social-inbox-import/v1` from an
explicitly selected input. This keeps fragile client-version knowledge out of
the database, query service, and MCP tool contracts.

An adapter must report its capability state explicitly, for example:

- `SUPPORTED_EXPORT`
- `PARTIAL_EXPORT`
- `UNSUPPORTED_VERSION`
- `REQUIRES_USER_ACTION`
- `EXPERIMENTAL_REVERSE_ENGINEERING`

No adapter may weaken operating-system security settings or inspect a running
client without a separate, explicit user authorization.

The macOS WeChat diagnostic is intentionally pre-adapter: it emits redacted
readiness evidence but cannot produce messages. See
[WeChat acquisition status](wechat-macos-adapter.md).

The QQ acquisition companion is separately authorized and Docker-isolated. A
redacted doctor establishes environment readiness without reading credentials
or messages. Completed, allowlisted QCE JSON exports are copied into immutable
generations whose receipts bind the pinned runtime, hashed scope, file
inventory, sizes, and digests. The QQ adapter then applies an
inclusive/exclusive time window before producing the v1 manifest; a second
receipt binds generation, configuration, manifest, and import. See
[QQ QCE adapter](qq-qce-adapter.md).

The DingTalk 8.3.5 acquisition experiment is also outside the core. Its
accepted route is normal-login, account-bound, copy-only, and receipt-bound.
The core adapter consumes only that completed private generation, verifies its
receipt, digest, fresh `quick_check`, safety flags, and account binding, then
produces a bounded v1 manifest and a second lifecycle receipt. Optional local
media roots are read-only capabilities: only exact row-recorded paths beneath
those roots may be copied into the private export, with source stability and
SHA-256 evidence. It does not make the acquisition method generic, search
unrelated files, fetch URLs, or control the live client. See
[DingTalk macOS PoC status](dingtalk-macos-poc.md).

## MCP boundary

The MCP server exposes exactly nine tools:

- `social_get_source_status`
- `social_list_conversations`
- `social_get_conversation`
- `social_search_messages`
- `social_read_context`
- `social_get_attachment`
- `social_build_digest`
- `social_list_event_candidates`
- `social_get_event_candidate`

Import is intentionally not an MCP tool. It is an explicit local CLI action.
All cursors are opaque, all limits are bounded, and attachment embedding is
size-limited. Source status distinguishes local import coverage from collector
freshness; until a collector heartbeat ledger exists, it reports freshness as
`NOT_RECORDED` rather than inferring it from message timestamps.
