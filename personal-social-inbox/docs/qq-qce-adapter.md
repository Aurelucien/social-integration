# QQ QCE group adapter

## Accepted boundary

`qq-qce-export` converts explicitly selected QQ Chat Exporter (QCE)
single-chat JSON files into one `social-inbox-import/v1` manifest. The adapter
itself does not install or run QCE, log in to QQ, inspect a running client,
patch or re-sign the QQ application, or send any message.

The current adapter accepts group exports only. A mandatory, repeatable
`--group-id` allowlist is matched against both `chatInfo.peerUid` and
`chatInfo.peerUin`; a private or temporary chat is rejected rather than
silently skipped. This makes the inclusion decision before messages or
attachments are written to the normalized export.

```bash
python3 social_inbox.py qq-qce-export /path/to/new-private-export \
  /path/to/qce/group-a.json /path/to/qce/group-b.json \
  --account-id personal-qq \
  --group-id 123456789 \
  --since 2026-08-01T00:00:00+08:00 \
  --until 2026-09-01T00:00:00+08:00
```

The receipt prints aggregate counts and the manifest hash. It does not print
group IDs, titles, sender IDs, filenames, or message content.

## Docker acquisition and generations

The separately authorized acquisition companion lives at
`../experiments/qq-qce-docker`. It uses the official QCE v6.2.8 image fixed to
OCI index digest
`sha256:b5d4be820d2d097475981c3b1f3870e699ebfc73439d928ff174d24ea2780753`
and source commit `aa85135d8e94654970051c359735e2dbd9535fa2`.

The container does not mount or modify the host QQ application or its local
profile. QCE and NapCat are bound to `127.0.0.1` only. QQ session data, QCE
state, and export staging are kept in Docker named volumes; only selected
completed batches are copied into ignored owner-only host storage. Account
login and account-security confirmation are human checkpoints. Any explicitly
authorized local WebUI authentication must keep the QCE token out of command
output, project files, and receipts.

`qq-doctor` reports Docker, pinned-image, container, and loopback WebUI
readiness without reading container logs, QCE tokens, QQ session files, or
message content. WebUI readiness remains `PARTIAL_EXPORT` until login and the
explicit group scope are independently verified.

`qq-capture-generation` copies only allowlisted group JSON files and their
contained local resource paths into an owner-only generation. Its
`qq-qce-docker-capture/v1` receipt binds the directory identity, QCE version,
source commit, image digest, hashed group scope, complete file inventory,
sizes, and SHA-256 digests.

`qq-ingest-generation` revalidates the generation before calling this adapter
and the normalized importer. Its private lifecycle receipt binds the
generation fingerprint, account/display identity hashes, group-scope hash,
time window, and manifest digest. An interrupted run resumes the same export;
an unattributed manifest, changed capture, or changed configuration is
rejected.

## Supported QCE subset

The versioned adapter schema is
`personal-social-inbox/qq-qce-single-json/v1`. It currently requires:

- one JSON object per QCE chat export;
- `chatInfo.type: group`, a non-empty `chatInfo.name`, and at least one of
  `peerUid` or `peerUin`;
- a `messages` array whose items carry a string `id`, millisecond `timestamp`,
  sender object, and content object;
- QCE resource records in `content.resources` for `image`, `audio`, `video`,
  or `file` attachments.

QCE JSONL/chunked exports, HTML exports, private chats, and temporary chats are
not accepted in this first slice.

## Window and identity semantics

`--since` is inclusive and `--until` is exclusive. Supplied values must be ISO
8601 timestamps with a timezone and are normalized to UTC. The source QCE
millisecond timestamp remains preserved in each message's raw QQ provenance.

Direction is reported only from QCE's stable self identifiers:

- a sender matching `selfUid` or `selfUin` is `outgoing`;
- a different stable sender is `incoming` when a self identifier exists;
- a QCE system message is `system`;
- without a stable self anchor, direction remains `unknown`.

The adapter does not treat display-name equality as identity evidence. QCE's
single-chat JSON does not provide a complete current group roster, so
`participants_complete` is always false. Participants represent windowed
senders plus the verified self identity when available.

## Attachments and source immutability

Only relative `localPath` values contained by the selected QCE export
directory are accepted. Capture first resolves the path beside the JSON and,
for QCE's official Docker layout, safely falls back to
`resources/<localPath>`. Absolute paths, `..` escapes, and symlinks resolving
outside that directory fail closed. Remote URLs are preserved in raw QQ
metadata but are never downloaded.

Present files are copied to a content-addressed, owner-only attachment tree.
Missing files become explicit missing attachment records during import. The
output directory must be separate from every selected source export directory,
and an existing `export.json` is never overwritten.

The adapter preserves each QCE message, sender, resource, and chat-info object
as raw JSON alongside the normalized fields. Unsupported element types remain
available there for future mappings instead of being guessed.

## Capability state

For the accepted single-file group JSON subset, a completed conversion reports
`SUPPORTED_EXPORT`. Docker service readiness, QQ login, scheduled-export
configuration, generation verification, and normalized import are reported as
separate states; none may be inferred from adapter success alone.
