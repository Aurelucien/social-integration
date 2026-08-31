# Personal Social Inbox

Personal Social Inbox is a local-first, read-only Codex plugin for aggregating
personal message exports. It does not log in to, inject into, or modify WeChat,
QQ, DingTalk, or any other source application.

The first vertical slice provides:

- a versioned, platform-neutral import contract;
- an immutable normalized message store backed by SQLite;
- a content-addressed attachment store with missing-file diagnostics;
- idempotent imports with conflict warnings;
- nine read-only MCP tools for imported-source status, conversations, group metadata and participants,
  search, context, attachments, deterministic digest packets, and review-required
  important-event candidates.
- a bounded WeChat 4.x adapter for separately copied and decrypted macOS
  database snapshots, including zstd text decoding, raw SILK voice export,
  verified ordinary-image `.dat` decoding, and local app-message file copying.
  Locally cached video bodies are also resolved through `MessageResourceInfo`
  and copied only after database-size and MP4-header validation.
- a bounded QQ adapter for explicitly selected QQ Chat Exporter (QCE)
  single-chat JSON files, with a mandatory group allowlist, optional time
  window, stable self-identity direction mapping, and local attachment copying.
- a bounded DingTalk macOS 8.3.5 adapter and receipt-bound generation bridge.
  It verifies the copied database digest and SQLite integrity, resolves the
  personal identity against the capture account binding, scans only the
  private decrypted generation, and imports an idempotent v1 manifest.

## Safety boundary

Source applications and source exports are read-only. Importing writes only to
the plugin's own data directory. AI-generated summaries must remain derived
artifacts and must never replace source messages.

The plugin deliberately does **not** include credential capture, client
injection, database decryption, SIP changes, message sending, recall, reply, or
read-receipt operations. The WeChat adapter only accepts a separately
authorized, decrypted snapshot and never opens the live source database.
The QQ adapter accepts only already exported group JSON files; it neither runs
QCE nor opens, patches, signs, or controls QQ.
The DingTalk adapter accepts only the separately authorized 8.3.5 private
generation. It does not inspect the live client, bypass login, replay network
protocols, or write to the source profile.

For WeChat on macOS, a separate diagnostic can inspect acquisition readiness
without reading message content, key values, account names, or filenames:

```bash
python3 social_inbox.py wechat-doctor
```

It reports a redacted capability state only; it does not import or decrypt
anything. See [WeChat acquisition status](docs/wechat-macos-adapter.md).

Export a bounded import manifest from an already decrypted snapshot:

```bash
python3 social_inbox.py wechat-export /path/to/decrypted /path/to/private-export \
  --wechat-profile-root /path/to/read-only-wechat-profile \
  --include-all-groups \
  --account-id personal-wechat --max-conversations 100 --max-messages 200
```

The command writes private files with owner-only permissions. Its terminal
result contains counts and hashes, not conversation identifiers or message
content. Omit `--wechat-profile-root` for a database-only export; when supplied,
the profile is read-only and ordinary images/files are copied into the private
export. The account profile directory also supplies a verified self-identity
anchor. Messages whose stable sender resolves to that identity are outgoing;
other resolved senders are incoming, while unresolved/system rows remain
`unknown`. A database-only export can obtain the same result when `--account-id`
is the exact stable WeChat username.

A completed generation from the conservative copy-on-change prototype can be
verified again, exported, and imported in one idempotent step:

```bash
python3 social_inbox.py --data-home /path/to/normalized \
  wechat-ingest-generation /path/to/generation /path/to/private-export \
  --account-id personal-wechat --wechat-profile-root /path/to/read-only-profile \
  --include-all-groups --max-conversations 100 --max-messages 200
```

The bridge accepts only a `COMPLETE` generation whose directory identity,
database inventory, SHA-256 digests, and fresh SQLite `quick_check` all agree
with its capture receipt. It writes a private lifecycle receipt after export so
an interrupted import can resume without regenerating or silently trusting an
unattributed manifest.

The companion capture prototype exposes `sync` for one-shot operation and
`watch-ingest` for a foreground loop. If normalization fails after capture, the
next iteration retries the saved generation before observing new source
changes. High-frequency operation is database-only unless
`--wechat-profile-root` is explicitly supplied, avoiding a full media-cache
copy for every database checkpoint.

`--include-all-groups` adds metadata-only records for groups outside the
bounded recent-session window. Current member rosters, owner roles, group
announcements, and verified session metadata become available through
`social_get_conversation` after import. Verified group-specific nicknames are
decoded from `chat_room.ext_buffer`; administrator roles remain explicitly
unresolved because the observed member-state values do not have a validated
role mapping.

Convert one or more already exported QCE group JSON files into a bounded import
manifest:

```bash
python3 social_inbox.py qq-qce-export /path/to/new-private-export \
  /path/to/qce/group-a.json /path/to/qce/group-b.json \
  --account-id personal-qq \
  --group-id 123456789 --group-id group-peer-uid \
  --since 2026-08-01T00:00:00+08:00 \
  --until 2026-09-01T00:00:00+08:00
```

`--group-id` is mandatory and repeatable; either QCE `peerUin` or `peerUid`
may be used. `--since` is inclusive and `--until` is exclusive. Both bounds,
when supplied, must include a timezone. The output must be outside every source
export directory and must not already contain `export.json`. See
[QQ QCE adapter](docs/qq-qce-adapter.md) for the accepted format and limits.

The authorized Docker acquisition companion is under
`../experiments/qq-qce-docker`. It pins QCE v6.2.8 by OCI digest, binds its
interfaces to host loopback only, keeps QQ/QCE state in Docker named volumes,
copies only selected completed batches into ignored owner-only directories,
and never mounts the host QQ application or data. Inspect its redacted
readiness state with:

```bash
python3 social_inbox.py qq-doctor
```

After QCE completes an allowlisted JSON export, freeze it as an immutable
generation and ingest it through a receipt-bound bridge:

```bash
python3 social_inbox.py qq-capture-generation /path/to/generation \
  /path/to/qce/group-a.json --group-id 123456789

python3 social_inbox.py --data-home /path/to/normalized \
  qq-ingest-generation /path/to/generation /path/to/private-export \
  --account-id personal-qq --group-id 123456789 \
  --since 2026-08-01T00:00:00+08:00 \
  --until 2026-09-01T00:00:00+08:00
```

The capture receipt inventories every copied JSON/resource file with size and
SHA-256 and binds the batch to the fixed QCE runtime and hashed group scope.
The ingest bridge revalidates those facts and resumes the same manifest after
an interruption. Login and account-security confirmation remain human-only.

Verify and import a completed personal DingTalk generation:

```bash
python3 social_inbox.py --data-home /path/to/normalized \
  dingtalk-ingest-generation /path/to/generation /path/to/private-export \
  --account-id personal-dingtalk --max-conversations 34 --max-messages 200 \
  --media-root /path/to/read-only-dingtalk-profile
```

The bridge automatically resolves the self UID by matching profile candidates
to the capture receipt's account binding; `--self-uid` is optional. Terminal
output contains only counts and hashes. Text, card summaries, message extension
objects, original HTTP(S) attachment URLs, identifiers, and the lifecycle
receipt remain in owner-only private storage. `--media-root` is repeatable and
permits only exact database-recorded paths beneath the selected read-only root;
it never performs a filename search or network download. Copied bodies are
SHA-256 addressed and revalidated by the importer. A cached thumbnail or
blurred image remains labelled as that variant rather than as the original.
Message search/context responses expose the preserved message extension as
`source_metadata`; attachment metadata exposes the original URL, media ID,
cache variant, source size, and source SHA-256 when present. Attachment content
continues to use the existing bounded, digest-checked read interface.

## Quick start

Initialize an isolated data directory:

```bash
PERSONAL_SOCIAL_INBOX_HOME=/path/to/data python3 social_inbox.py init
```

Import the bundled example:

```bash
PERSONAL_SOCIAL_INBOX_HOME=/path/to/data \
  python3 social_inbox.py import examples/sample-export/export.json
```

Inspect local statistics:

```bash
PERSONAL_SOCIAL_INBOX_HOME=/path/to/data python3 social_inbox.py stats
```

Incrementally scan previously unexamined immutable messages with the initial
deterministic registration/deadline rule pack:

```bash
PERSONAL_SOCIAL_INBOX_HOME=/path/to/data \
  python3 social_inbox.py monitor-scan --profile signup-deadline-v1
```

Every match starts as `REVIEW_REQUIRED` and retains its source message as
evidence. Version 1 deliberately leaves event/deadline timestamps unresolved
and marks them uncertain; it does not ask a model to invent a date. Re-running
the scan only examines newly imported messages for that rule version.

Without `PERSONAL_SOCIAL_INBOX_HOME`, runtime data is stored under
`~/Library/Application Support/PersonalSocialInbox` on macOS and the standard
user data directory on other platforms.

See [architecture](docs/architecture.md), the
[QQ QCE adapter](docs/qq-qce-adapter.md), the
[DingTalk macOS 8.3.5 adapter](docs/dingtalk-macos-poc.md), and the
[import format](docs/import-format-v1.md) for the stable boundaries.

## Development

The runtime uses only the Python standard library. Run the full suite with:

```bash
python3 -m unittest discover -s tests -v
```

Validate the Codex plugin manifest using the `plugin-creator` validator before
installation.
