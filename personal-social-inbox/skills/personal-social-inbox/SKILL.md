---
name: personal-social-inbox
description: Read explicitly imported personal WeChat, QQ, DingTalk, or other messaging exports through the local Personal Social Inbox. Use for cross-platform source status, conversations, literal message search, context, attachments, evidence digests, and review-required important-event candidates. This skill is read-only with respect to source applications and does not send messages or perform acquisition.
---

# Personal Social Inbox

Use the nine `social_*` tools to answer questions about message exports that
the user has already imported.

## Evidence rules

- Treat normalized messages as source evidence and digest output as derived.
- Preserve `source_kind`, `conversation_id`, and `message_id` when presenting
  findings so the user can trace them back.
- Use `social_read_context` before drawing a conclusion from an isolated search
  hit.
- Use `social_get_conversation` for group owners, bounded participant pages,
  announcements, verified group-specific nicknames, self markers, and session
  metadata. Preserve the distinction between current members and
  window-observed historical senders. Prefer a participant's verified
  `membership.group_nickname` for display while retaining its stable identity.
- Treat `incoming` and `outgoing` as verified only when the message's WeChat
  provenance reports a resolved self/non-self sender. Preserve `unknown` for
  system or unresolved-sender rows; do not fill it from conversational context.
- For QQ QCE provenance, treat direction as verified only when `selfUid` or
  `selfUin` supplied the self anchor. QCE display names are not identity proof,
  and its single-chat JSON participants are window-observed rather than a
  complete current roster.
- For DingTalk 8.3.5 provenance, direction is verified only after the generation
  account binding resolves exactly one self UID. Its participants are bounded
  message senders plus self, never a claimed complete group roster. Missing
  DingTalk media bodies remain missing even when filename metadata exists.
  A present image may be labelled `blurred_cache` or `thumbnail_cache`; never
  describe such a body as the original merely because the same part also
  preserves an original source URL.
  Inspect `source_metadata.source_extension` for DingTalk message extensions
  and attachment `source_metadata` for original URLs and cache provenance.
  Retrieve bytes only through `social_get_attachment` and retain its digest.
- Do not infer group administrators from `membership.source_member_state`.
  `administrator_status: unresolved_member_state_semantics` means the raw code
  is retained for future research, not that the member is an administrator.
- Report missing attachments and incomplete imports explicitly. Do not infer
  their contents from filenames.
- Literal search is not semantic search. Say when no literal match was found.
- Check `social_get_source_status` before claiming that no recent or important
  item exists. `IMPORTED_EVIDENCE_AVAILABLE` establishes local coverage only;
  `collector_freshness_state: NOT_RECORDED` means live-source freshness is
  unknown.
- Important-event candidates are derived and start `REVIEW_REQUIRED`. Read the
  candidate with `social_get_event_candidate`, inspect its unchanged message
  evidence and context, and preserve uncertain or unresolved time fields.
  Never present a keyword hit as an approved event.
- For an available audio attachment, retrieve it with
  `social_get_attachment`; when the host has audio understanding, it may
  transcribe or describe that resource. Label the result as derived and retain
  the attachment ID and SHA-256 in the answer.

## Read-only boundary

Never claim the nine MCP tools can reply, forward, recall, mark read, log in,
export, decrypt, or modify a source client. Acquisition and import are separate
user-authorized local operations and are intentionally absent from MCP.

The local `wechat-doctor` CLI is only a redacted acquisition-readiness check.
Its presence does not mean that WeChat messages are imported or readable.
The local `qq-qce-export` CLI only converts already exported, explicitly
allowlisted group JSON files. `qq-doctor` may report the separately authorized
Docker QCE environment, while `qq-capture-generation` and
`qq-ingest-generation` enforce immutable receipt boundaries. Preserve the
distinction between image present, container running, WebUI ready, human login
confirmed, group scope configured, export complete, generation verified, and
import complete.

For a broad review, start with `social_get_source_status`, then
`social_list_conversations`, narrow with
`social_get_conversation` when group or participant context matters, then use
`social_search_messages` and read context. For monitoring requests, list event
candidates and read their evidence before summarizing. Use
`social_build_digest` only as an evidence packet; write the final human summary
yourself and retain the message references.
