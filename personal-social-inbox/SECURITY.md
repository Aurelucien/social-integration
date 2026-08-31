# Security and privacy

This project handles highly sensitive personal communications. Keep real
exports, normalized databases, attachment blobs, transcripts, and summaries
outside version control.

## Current guarantees

- Source export files are opened read-only.
- Attachment paths are resolved beneath the selected export directory; path
  traversal and absolute paths are rejected.
- Imported attachment bytes are checked with SHA-256 and stored by digest.
- The private data directory is mode `0700`; database and blob files are mode
  `0600` on POSIX systems.
- Reused source message IDs cannot overwrite the first normalized message.
- MCP exposes only bounded read operations. Import is not an MCP tool.
- Embedded attachment content defaults to a 2 MiB cap and cannot exceed 25 MiB
  per tool call.
- The WeChat diagnostic reports hashed profile identifiers and aggregate file
  metadata only. It does not read database rows, key values, filenames, or
  attachment contents and does not copy source files.
- The DingTalk generation bridge requires the unchanged `COMPLETE` capture
  receipt, safe database path, matching SHA-256, fresh SQLite `quick_check`,
  accepted no-bypass/no-attach/no-network flags, and an exact personal-account
  binding before reading message rows.
- DingTalk media copying accepts only exact paths recorded by the selected
  message beneath an explicitly allowlisted read-only root. Resolved symlinks
  may not escape that root, output may not be placed inside it, and source file
  size/inode/mtime must remain stable across the copy. No directory-wide
  filename matching or URL download is performed.

## Current limitations

- The local SQLite database and blob store are not application-level encrypted.
  They rely on macOS account permissions and disk encryption.
- The v1 importer trusts the user-selected manifest's semantic claims about
  sender identity and timestamps; it validates shape, not platform signatures.
- DingTalk support is intentionally fixed to the observed macOS 8.3.5 schema.
  Only locally present bodies referenced by exact allowlisted paths can be
  resolved. The observed four image bodies are blurred WebP cache variants,
  not the original JPG resources, and the observed file body is unavailable at
  its recorded path. Card types with no validated title or description remain
  explicit system placeholders instead of guessed content.

Do not add credential capture, operating-system security changes, live client
inspection, or write operations under the existing read-only project scope.
