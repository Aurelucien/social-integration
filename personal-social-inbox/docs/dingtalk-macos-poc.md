# DingTalk for macOS personal-account acquisition status

The separately authorized experiment under
`../experiments/dingtalk-8.3.5-poc` has an account-bound, read-only acquisition
PoC for DingTalk macOS 8.3.5. It operates on a copied personal profile, uses no
login bypass in the accepted route, applies committed WAL frames, and requires
a fresh SQLite `quick_check` before producing a `COMPLETE` generation receipt.

The approved next phase adds a bounded adapter and import bridge to Personal
Social Inbox. The bridge revalidates the immutable generation, resolves the
personal UID against the receipt's account binding, exports
`social-inbox-import/v1`, and imports it idempotently. Its terminal result
contains counts and hashes only.

The accepted capability state is:

```text
ACQUISITION_POC_COMPLETE
NORMALIZED_ADAPTER_ACCEPTED_FOR_8_3_5
PERSONAL_GENERATION_IMPORT_VERIFIED
```

The PoC is deliberately version- and account-bound. It is not a reusable
multi-account extractor, does not contact DingTalk servers, does not send
messages, and does not modify the source profile.

## Accepted data mapping

- `tbconversation` supplies bounded recent conversations and source metadata.
- `tbmsg_000` through `tbmsg_127` are scanned read-only for each selected
  conversation; rows are merged and capped per conversation.
- `tbuser_profile_v2` supplies display names and the candidate set for the
  capture account-binding check.
- content type `1` is text and type `2` is image metadata. Type `500` is file
  metadata. Observed card types use only validated title, description, or
  Markdown fields; an unresolved type stays a system placeholder.
- participants are bounded message senders plus the verified self identity.
  They are explicitly not claimed to be a complete current roster.
- every valid message `extension` JSON object is retained under private message
  metadata. Original HTTP(S) URLs and media identifiers are retained on image
  or file parts without appearing in terminal output.
- optional media roots resolve only exact local paths from the same message
  row. Each copied body is stable-copy checked, SHA-256 addressed, owner-only,
  and labelled with its cache variant. No URL is fetched.

The current real private-generation acceptance imported 34 conversations and
64 messages and retained 64 extension objects plus four valid original image
URLs. Four exact cached image bodies were copied and digest-verified as
`blurred_cache` WebP variants. The one file body's recorded path no longer
exists, so it remains an explicit missing attachment. A second run returned
`already_imported`.
