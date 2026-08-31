# QQ QCE Docker acquisition

This deployment is the acquisition side of Personal Social Inbox. It runs the
official QCE v6.2.8 Docker image, pinned by OCI digest, without modifying the
host `/Applications/QQ.app`.

## Fixed runtime

- QCE release: `v6.2.8`
- QCE source commit: `aa85135d8e94654970051c359735e2dbd9535fa2`
- OCI index digest:
  `sha256:b5d4be820d2d097475981c3b1f3870e699ebfc73439d928ff174d24ea2780753`
- linux/amd64 manifest digest:
  `sha256:cee5585a46f5c37bb94a2260d19ab2b46c702b7fdc3cb57e11d6709723b61ce0`

The service binds QCE and NapCat only to host loopback. It has no privileged
mode, no host QQ data mount, and no host-wide directory mount. Runtime state,
QQ session data, QCE internal data, and export staging live in four Docker
named volumes. This avoids exposing account state through a macOS bind mount.
Only an explicitly selected export batch is copied into ignored `private/`
storage for immutable capture and ingestion.

## Lifecycle

Prepare the owner-only local capture directory:

```bash
python3 prepare_runtime.py
```

Start the pinned service:

```bash
docker compose up -d
```

Login is a human checkpoint. The account owner scans the QR code; automation
must not retrieve credentials or confirm an account-security prompt.

After login, the QCE interface is available only at
`http://127.0.0.1:40653/qce`. Export and scheduled-export destinations are
fixed to `/app/QQChatExporter/exports` and
`/app/QQChatExporter/scheduled-exports`, which reside in the `exports` named
volume. Copy only the selected completed batch to ignored host storage before
capturing it, for example:

```bash
docker cp \
  personal-social-inbox-qq-qce:/app/QQChatExporter/exports/SELECTED_BATCH \
  ./private/exports/SELECTED_BATCH
```

The first accepted task must use JSON, download local resources, include only
explicitly selected groups, and use a bounded time range. QCE export completion
does not itself count as Personal Social Inbox ingestion; the resulting files
must enter a verified QQ generation and pass the normalized importer.

Stop the service without deleting any persistent data:

```bash
docker compose stop
```

Do not run `docker compose down -v`: deleting the named-volume session or
export state is outside the normal lifecycle.
