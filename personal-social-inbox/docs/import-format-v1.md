# Import format: `social-inbox-import/v1`

An import is a UTF-8 JSON file. Attachment paths are relative to the JSON file
and may not escape its directory.

```json
{
  "schema_version": "social-inbox-import/v1",
  "exported_at": "2026-08-30T08:00:00Z",
  "source": {
    "kind": "wechat",
    "account_id": "personal-account",
    "display_name": "My WeChat"
  },
  "conversations": [
    {
      "source_conversation_id": "chat-1",
      "title": "Example chat",
      "type": "single",
      "last_activity": "2026-08-30T08:00:00Z",
      "participants_complete": true,
      "participant_scope": "current_roster",
      "metadata": {"unread_count": 0, "is_hidden": false},
      "participants": [
        {
          "source_identity_id": "me",
          "display_name": "Me",
          "is_self": true,
          "role": "owner",
          "membership": {"current": true}
        }
      ],
      "messages": [
        {
          "source_message_id": "message-1",
          "timestamp": "2026-08-30T08:00:00Z",
          "sender_id": "me",
          "sender_name": "Me",
          "direction": "outgoing",
          "parts": [
            {"type": "text", "text": "Hello"},
            {
              "type": "file",
              "path": "attachments/example.txt",
              "file_name": "example.txt",
              "mime_type": "text/plain"
            }
          ]
        }
      ]
    }
  ]
}
```

## Required identifiers

`source.kind`, `source.account_id`, `source_conversation_id`, and
`source_message_id` form the platform provenance boundary. All are strings.
The importer derives stable internal IDs from them and never coerces numeric
identifiers into JSON numbers.

## Message parts

Supported part types are `text`, `image`, `audio`, `video`, `file`, `link`,
and `system`. Non-text parts may provide `path`, `file_name`, and `mime_type`.
An audio part may also provide a source-supplied `transcription`, which is
stored as text but remains identified as source material.

Missing attachment files do not abort the import. They produce an attachment
record with `status: missing` and a diagnostic warning. Unsupported fields are
preserved in the message or part raw JSON for future adapter upgrades.
Read APIs return adapter-owned message and part fields as `source_metadata`;
these remain source provenance and are not interpreted as platform-independent
truth. Attachment content is still returned separately under bounded size and
digest checks.

## Conversation metadata and participants

`last_activity` is an optional timezone-qualified timestamp used even when a
conversation has no messages in the bounded export. `metadata`, `group`, and
participant-specific fields are adapter-owned source metadata preserved in raw
JSON and exposed by `social_get_conversation`.

When `participants_complete` is true, a later manifest replaces that
conversation's prior participant relations before importing the supplied
roster. Without it, participants are merged. `participant_scope` must explain
what the supplied list represents, such as `current_roster` or
`current_roster_plus_windowed_senders`. Group-specific roles and membership
state belong to the conversation-participant relation, not the global identity.

## Idempotence and conflicts

Re-importing an identical manifest returns the previous completed import run.
If a later manifest repeats a source message ID with different content, the
first normalized record remains immutable and the new run reports a
`SOURCE_MESSAGE_CONFLICT` warning.
