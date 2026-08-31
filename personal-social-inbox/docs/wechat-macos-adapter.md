# WeChat for macOS read-only adapter

## Accepted boundary

The integration has two deliberately separate surfaces:

1. `wechat-doctor` inspects acquisition readiness without reading message
   rows, key values, account names, or filenames.
2. `wechat-export` reads only separately copied and decrypted WeChat 4.x
   database files. It does not acquire keys, attach to WeChat, open the live
   database, or change the source application.

The exporter writes `social-inbox-import/v1` JSON and attachment payloads into
an owner-only output directory. Its terminal receipt reports aggregate counts,
the manifest hash, and capability gaps; it never prints message content,
conversation identifiers, or contact identifiers.

`wechat-ingest-generation` is the accepted bridge from the separate
copy-on-change prototype. It revalidates the completed capture receipt, every
decrypted database digest, and a fresh SQLite `quick_check` before calling this
exporter and the normalized importer. Existing exports are reusable only when
their private lifecycle receipt names the same capture generation and manifest
hash; an unattributed pre-existing manifest is rejected.

```bash
python3 social_inbox.py wechat-export \
  /path/to/decrypted-snapshot /path/to/new-private-export \
  --wechat-profile-root /path/to/read-only-wechat-profile \
  --account-id personal-wechat \
  --max-conversations 100 --max-messages 200
```

The output directory must not already contain `export.json`; the adapter will
not overwrite an earlier export. Compressed message rows currently require
Python 3.14 or newer for the standard-library `compression.zstd` decoder.

## Validated WeChat 4.x mapping

The versioned adapter schema is `personal-social-inbox/wechat-macos-4/v1`.
Its current mapping is:

- `session.db.SessionTable.username` identifies a conversation.
- The message table is `Msg_<md5(username)>` in a `message_N.db` shard.
- Message rows use `local_id`, `server_id`, `local_type`, `sort_seq`,
  `real_sender_id`, `create_time`, `message_content`, and
  `WCDB_CT_message_content`.
- `local_type` is masked to its low 32 bits. Type 1 is text, 3 is image, 34 is
  voice, 43 is video, 47 is sticker, 48 is location, 49 is an app message, and
  10000 is a system message.
- Compression type 4 is zstd. Text and BLOB storage are both accepted.
- `Name2Id(rowid, user_name)` supplies the sender mapping; group-message
  prefixes are a guarded fallback.
- Contact display names prefer remark, nickname, alias, then username.
- `media_N.db.Name2Id` plus `VoiceInfo(chat_name_id, local_id, create_time)`
  resolves voice payloads. They are retained as source `.silk` bytes without
  transcoding or model transcription.
- Ordinary images follow `ChatName2Id.rowid` to an exact
  `MessageResourceInfo(chat_id, message_local_id, message_local_type,
  message_create_time)` row. The resource MD5 is read from `packed_info` and
  resolved below `msg/attach/<md5(chat)>/<YYYY-MM>/Img/`.
- WeChat V1/V2 `.dat` images are decoded only after their header and segment
  lengths validate. V2 derives the account-local AES/XOR material from the
  macOS profile metadata and verifies it against known image magic before use.
  Legacy one-byte-XOR images are also detected by file magic.
- App-message files use the message's XML title as the source filename and are
  matched read-only below `msg/file/<YYYY-MM>/`. Every artifact is copied into
  the export's content-addressed, owner-only attachment tree.
- Video bodies use the first 32-hex resource identifier in
  `MessageResourceInfo.packed_info` and resolve to
  `msg/video/<YYYY-MM>/<resource-id>.mp4`. A candidate is accepted only when
  `MessageResourceDetail` type `131074` reports a positive matching size and
  the source has an ISO Base Media `ftyp` header.
- `SessionTable` supplies verified session metadata such as unread count,
  hidden state, last activity, last message type, and source preview. Drafts
  are deliberately excluded.
- `chat_room` supplies the group and owner; `chatroom_member` IDs resolve
  through the contact/name map to stable usernames; `chat_room_info_detail`
  supplies announcement text, editor, publish time, and source status.
  `chat_room.ext_buffer` is decoded as a protobuf whose repeated field 1 holds
  member records: nested field 1 is the stable username, field 2 is the
  optional group-specific nickname, and field 3 is retained as an opaque
  source member-state value. Administrator roles remain unclaimed because no
  validated mapping from that state to the administrator role is available.
- Self identity is accepted only from an exact `account_id`/contact match or a
  unique stable-username prefix match against the authorized account profile
  directory. Direction is then derived from the message's resolved sender:
  self is outgoing, a resolved non-self sender is incoming, and unresolved or
  system rows remain unknown.

This is based on the same schema chain used by the mature
[wx-cli](https://github.com/jackwener/wx-cli) implementation and independently
described by the WeChat 4.x notes in
[wechatauto-replica](https://github.com/fanyuantaier/wechatauto-replica/blob/main/docs/%E6%8A%80%E6%9C%AF%E6%96%87%E6%A1%A3.md).
The sender-ID caution is also consistent with the local-schema workflow in
[wechat-group-stats](https://github.com/punk2898/wechat-group-stats/blob/main/SKILL.md).
The member protobuf layout is independently implemented by
[tool-WeChatMsg](https://github.com/amtech/tool-WeChatMsg/blob/master/app/util/protocbuf/roomdata.proto),
while the identity-first direction contract is consistent with the public
output of [wechat-cli](https://github.com/r266-tech/wechat-cli).
Those projects are references, not runtime dependencies.

## Current verified capability

Against the authorized 4.1.7 staged copy, seven databases passed SQLite
`quick_check`. The schema probe found 131 message tables and 76,952 message
rows without returning content. A bounded real export then produced:

- 64 conversations and 2,479 messages;
- 937 zstd-compressed rows successfully decoded;
- 45 of 45 encountered voice rows resolved to real SILK payloads;
- 122 of 122 ordinary-image rows resolved through `MessageResourceInfo`, found
  their `.dat` source, and decoded to 114 JPEG and 8 PNG artifacts;
- 67 of 70 encountered app-message files were found and copied; the other three
  were not present in the local profile tree;
- all 2,479 messages imported into the normalized store;
- 234 present attachments and 100 explicit missing-resource records.

The remaining 100 records in that bounded export are 90 stickers, 7 videos,
and 3 locally absent app-message files. Subsequent corpus validation corrected
the earlier video-mapping hypothesis: across all 199 indexed video resources,
all 39 rows with a positive local-body size had an exact same-month MP4 whose
filename matched the first packed resource identifier; all 160 zero-size rows
lacked that MP4. The original seven bounded messages are all zero-size rows, so
their bodies are genuinely not present in the local profile rather than merely
unresolved.

A broader 64-conversation, 8,069-message acceptance export encountered 40 video
messages. Five were copied as validated MP4 files, while 35 were retained as
explicit `resource_body_not_local` records; no size or format validation failed.
Sticker decoding is still not verified and remains the next media-specific gap.

## Verified conversation and group metadata

With `--include-all-groups`, the authorized snapshot exported 83 conversations:
37 bounded direct chats plus all 46 locally indexed groups. All 46 group rosters
were complete, covering 2,417 current membership relations and 46 owner roles.
Sixteen groups carried announcements. Nineteen groups were retained as
metadata-only records because they were outside the bounded message-bearing
session result.

The export also retained 30 senders observed in the bounded message window who
were not in the current roster. They are labeled `observed_sender` with
`membership.current: false` and never counted as current members. The normalized
store exposes these distinctions through `social_get_conversation`.

The 46 group protobufs contained 2,418 member chunks, all of which anchored to
known current-member usernames; one duplicated source chunk was ignored by the
per-identity map. They supplied 1,328 non-empty group nicknames across 32
groups. Self-identity verification used two independent observations: one
stable username was the unique highest-coverage group member (43 of 46 groups),
and the authorized live profile directory began with that same username.

Across the full 76,952-row corpus, this identity classified 15,958 direct and
2,023 group messages as outgoing. It classified 19,739 direct and 36,629 group
messages as incoming. As an independent direction check, all 36,624 ordinary
group messages from resolved non-self senders had a content-prefix identity
that agreed with `Name2Id`, whereas none of the 2,023 self-sent group messages
had that prefix. The remaining 2,603 unresolved/system rows stay `unknown`.

The attachment option opens the authorized profile only for stable reads and
never writes below it. Source files are stat-checked before and after copying;
the decrypted snapshot and private export remain separate.

## Unresolved semantics

Administrator roles are still unresolved. The member protobuf's field 3 has
multiple bit-pattern values, but group owners and the four observed non-owner
announcement editors did not yield a consistent role discriminator. The raw
integer is retained as `membership.source_member_state`, and non-owner members
carry `administrator_status: unresolved_member_state_semantics`; it is never
promoted to an administrator label.

Special, business, or system rows without a stable sender remain direction
`unknown`. Special or business sessions without a matching `Msg_<md5>` table
are skipped and counted in the receipt. Raw WeChat provenance stays attached to
each normalized message so future mappings can be independently rechecked.

## Acquisition status

`wechat-doctor` still uses `personal-social-inbox/wechat-doctor/v1`. It reports
`REQUIRES_USER_ACTION` when a live source is encrypted or custom-formatted and
`PARTIAL_EXPORT` only when a plain database is detected. Neither state
authorizes decryption, memory inspection, client injection, operating-system
security changes, or source copying.
