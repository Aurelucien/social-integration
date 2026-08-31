# DingTalk 8.3.5 personal-account database PoC

Status: `ACCOUNT_BOUND_POC_COMPLETE` for one authorized macOS personal account.

This experiment creates a stable copy of that account's local DingTalk
database, decrypts only the copy, applies the copied WAL through its last
committed frame, and accepts the result only when SQLite reports
`PRAGMA quick_check = ok`.

## Hard boundary

- DingTalk macOS 8.3.5 only.
- The user's current personal account and its explicit profile only.
- Normal login state; no login bypass is part of the accepted route.
- No server protocol replay, network collection, message sending, recall, or
  read-receipt operation.
- No writes beneath the selected DingTalk profile.
- No key or account identifier is printed or stored in receipts.
- This phase validates database structure only and does not read message
  bodies.

The retained LLDB and injected-library files are exploratory evidence from the
earlier investigation. They are not used by the accepted personal-account
snapshot route.

## Verified codec path

The 8.3.5 binary's embedded ArkSQLite path was traced from
`DBManager::Open` to its local `sqlite3_key` implementation. For this build:

1. the account UID and `user_config` salt feed the locally observed DingTalk
   PBKDF2/MD5 derivation;
2. ArkSQLite uses the first 16 bytes of the resulting ASCII passphrase as an
   AES-128 key;
3. database pages and WAL page bodies are transformed as independent 16-byte
   ECB blocks;
4. only WAL frames through the last commit marker are applied to the plaintext
   copy.

This is version-bound evidence, not a claim about other DingTalk releases or
accounts.

## Reproduce on a copied profile

The source profile must contain `user_config`, `DBFiles/dingtalk.db`, and,
when present, `DBFiles/dingtalk.db-wal`.

```bash
python3 scripts/dingtalk_snapshot.py \
  --profile /path/to/authorized/copied-profile \
  --output-root /path/to/private-generations \
  --uid '<current-personal-account-uid>'
```

The command performs a before/copy/after metadata observation, hashes every
copy, writes owner-only files, decrypts the staged generation, applies committed
WAL frames, and runs a fresh SQLite integrity check. Re-running unchanged input
returns `UNCHANGED`.

To validate page-1 structure without creating a plaintext database:

```bash
python3 scripts/probe_db_key.py \
  --db /path/to/copied-profile/DBFiles/dingtalk.db \
  --user-config /path/to/copied-profile/user_config \
  --uid '<current-personal-account-uid>'
```

The successful 8.3.5 profile is reported as one
`ecb/ark-aes128-first16` structural match with a 4096-byte page size. No key is
printed.

Run the non-personal synthetic tests with:

```bash
python3 test_dingtalk_poc.py -v
```

## Current stopping point

The acquisition/decryption PoC and the bounded normalized DingTalk adapter are
complete. The accepted adapter preserves message extensions and original
attachment URLs, copies only exact recorded local bodies beneath explicit media
roots, and keeps unavailable bodies explicit. Continuous `watch-ingest`
supervision remains a separate phase; the current snapshot command is
change-aware but one-shot.
