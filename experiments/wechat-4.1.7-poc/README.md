# WeChat 4.1.7 single-database PoC

This experiment is intentionally narrower than a message extractor. It stages
one encrypted `session.db`, attempts a read-only raw-key scan against the local
WeChat process, validates the candidate with the database page-1 HMAC, and
decrypts only the staged copy. It never queries SQLite rows.

For a process that cannot be opened by a normal `task_for_pid` call, the PoC
also contains two LLDB-only backends. `lldb_scan.py` scans readable regions
without printing candidates. `lldb_capture.py` places a narrowly conditioned
breakpoint on the system `CCKeyDerivationPBKDF` call, derives the target
database key in memory, and persists it only if page-1 HMAC verification passes.
The 32-byte passphrase itself is never saved.

The memory scanner and SQLCipher 4 parameters were independently reduced from
`TANGandXUE/wcdb-key-tool` commit
`79f1b5b92e12c66aa281b4a60a3c478b5f547dfa` (MIT). The upstream program is not
executed because it writes secrets outside the project and globally kills LLDB
processes during cleanup.

## Safety properties

- The live WeChat database is opened read-only and copied once into `private/`.
- Raw account-directory names, database salt, key, and process IDs are not
  printed.
- A key is accepted only when SQLCipher page-1 HMAC-SHA512 matches.
- Secret files and database copies are mode `0600`; `private/` is mode `0700`.
- Only a staged database copy can be decrypted.
- No database rows, network sockets, WeChat messages, or server protocols are
  accessed.
- LLDB output reports only verification status; it does not print the key,
  passphrase, database salt, or message content.

## Commands

```bash
python3 poc.py stage
sudo python3 poc.py scan-raw
python3 poc.py decrypt
python3 poc.py status
```

`scan-raw` returns exit code 3 when the process is readable but a verified raw
key is absent. That is the only condition that can justify a separately
reviewed LLDB passphrase-capture attempt.

## Local validation record

On macOS with WeChat 4.1.7 (build 34371), an ad-hoc-signed disposable app copy
passed `codesign --verify --deep --strict`. A direct raw-memory pattern scan
found no verified raw key. The PBKDF2 breakpoint path then captured a candidate,
derived the target database key with PBKDF2-HMAC-SHA512 (256000 rounds), and
passed the staged `session.db` page-1 HMAC. Decryption of that staged copy
produced the exact 16-byte `SQLite format 3\0` header. The receipt records
`rows_queried: false`.

## Read-only incremental capture prototype

`wechat_incremental.py` adds a deliberately conservative copy-on-change layer.
It does not attach to WeChat, read process memory, make network requests, or
write below the WeChat profile. It polls only database and WAL file metadata.
After a configurable quiet window, it performs a double-observation copy:

1. record the size, nanosecond mtime, and inode for all target databases/WALs;
2. copy every target to a private candidate generation and hash-check each copy;
3. record the source metadata again and discard the candidate if anything moved;
4. reverify every saved database key against encrypted page 1;
5. decrypt the candidate, apply only committed WAL frames, and require
   `PRAGMA quick_check = ok` for every database;
6. publish the generation atomically and retain opaque per-message-table
   `(row count, max local_id, max create_time)` watermarks.

The watermark delta is an insert estimate, not an exact change stream. A lower
row count, missing stream, replacement database, key-verification failure, or
SQLite consistency failure is reported as a regression/failure and is never
silently imported. Message text and raw table names are not written to the
incremental receipt or state file. The first accepted generation is explicitly
marked as a baseline and does not claim that the existing corpus is newly
arrived content.

One-shot status and capture:

```bash
python3 wechat_incremental.py probe
python3 wechat_incremental.py capture
```

Foreground monitoring, with a five-second quiet window:

```bash
python3 wechat_incremental.py watch --poll-seconds 2 --quiet-seconds 5
```

One-shot capture plus normalized ingest uses the latest completed generation
when the source is unchanged, so an interrupted ingest can resume without
recapturing:

```bash
PERSONAL_SOCIAL_INBOX_ACCOUNT_ID=personal-wechat \
python3 wechat_incremental.py sync \
  --ingest-exports-root private/incremental-exports \
  --data-home private/incremental-normalized
```

The equivalent foreground loop is `watch-ingest`. It retries a failed ingest
from `state.json.last_generation_id` before waiting for another source change:

```bash
PERSONAL_SOCIAL_INBOX_ACCOUNT_ID=personal-wechat \
python3 wechat_incremental.py watch-ingest \
  --poll-seconds 2 --quiet-seconds 5 \
  --ingest-exports-root private/incremental-exports \
  --data-home private/incremental-normalized
```

Frequent operation is database-only by default. This still includes voice
payloads stored in the media databases. Pass `--wechat-profile-root` only when
the loop should also copy locally cached images, videos, and files; each
generation retains a private export for recovery, so full-media mode can use
substantial disk space.

Capture-only commands still stop at a validated decrypted generation. The
explicit `sync` and `watch-ingest` commands cross that boundary only after the
generation receipt, database hashes, and SQLite checks are revalidated by
Personal Social Inbox. The source profile remains read-only throughout.
