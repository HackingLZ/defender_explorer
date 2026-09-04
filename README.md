# Defender Explorer

Browse, search, and analyze Microsoft Defender signature definitions. Parses VDM files to expose 8.6M+ signatures and 358K+ threat families through a searchable web interface.

**Live instance:** https://defender.hackpwn.net/

## What it does

- Parses Defender VDM (virus definition) files and imports them into a database
- Provides full-text search across signatures, threats, ASR rules, and Lua scripts
- Decompiles embedded Lua bytecode for analysis
- Generates YARA rules from signature patterns
- Auto-syncs with Microsoft's definition update servers on a schedule

## Requirements

- Docker and Docker Compose
- 8 GB RAM recommended (6 GB container limit + DB overhead)
- ~5 GB disk for the database after initial sync

## Setup

**1. Clone and configure**

```bash
git clone <repo-url>
cd defender_explorer
cp .env.example .env
```

Edit `.env` and set:
```
POSTGRES_PASSWORD=<your-password>       # generate: openssl rand -hex 24
ADMIN_API_KEY=<your-api-key>            # generate: openssl rand -hex 32
```

The `VDM_PATH` and `EXTRACTED_PATH` in `.env` point to `./data/vdm` and `./data/extracted` by default — those directories are already in the repo. Leave them unless you have pre-downloaded VDM files elsewhere.

**2. Start**

```bash
docker compose up -d
```

**3. Wait for initial sync (15–30 minutes)**

On first start the app detects an empty database and automatically downloads and imports the current Defender definitions from Microsoft's update servers. You can watch progress in the logs:

```bash
docker compose logs -f app
```

The UI will show a sync status indicator. Once complete you'll have ~8.6M signatures and ~358K threats loaded.

**4. Open the app**

```
http://localhost:8000
```

## Pre-downloaded VDM files (optional)

If you have VDM files already, drop them in `./data/vdm/` before starting. The app will use those instead of downloading. Files should be named `mpavbase.vdm`, `mpavdlta.vdm`, `mpasdlta.vdm`, `mpasbase.vdm`.

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_PASSWORD` | Yes | — | Database password |
| `ADMIN_API_KEY` | Yes | — | API key for write endpoints |
| `VDM_PATH` | No | `./data/vdm` | Host path to VDM files |
| `EXTRACTED_PATH` | No | `./data/extracted` | Host path to pre-extracted data |
| `CORS_ORIGINS` | No | localhost only | Comma-separated allowed origins |
| `TRUSTED_PROXY_IPS` | No | empty | Exact proxy IP addresses trusted to supply `X-Real-IP` |

When using a reverse proxy, set `TRUSTED_PROXY_IPS` to its exact address as seen
by the app. The proxy must overwrite incoming `X-Real-IP` headers. With no trusted
proxy configured, requests share the connecting peer's rate limit. Private
network ranges are not trusted automatically.
Docker starts Uvicorn with `--no-proxy-headers` so this check uses the actual
connecting peer. Use the same flag when running Uvicorn directly.

Search supports combined field/operator filters and URL-based navigation. Bulk
exports include all selected threats across pages; JSON can include signature
bytes as hexadecimal. Exports exceeding 500 threats, 5,000 included signatures,
or 16 MiB are rejected with an explanation rather than silently truncated.

Threat and ASR history is recorded transactionally from the first startup of
this version. Existing rows are not presented as historical events. History
stores compact metadata and definition fingerprints, not duplicate signature
payloads; the activity chart counts recorded threat changes by UTC day. Normal
VDM imports attach the source version hash to their changes.

PDF rendering and Lua decompilation run in bounded worker processes with hard
deadlines. A busy PDF service returns a retryable error. Public status exposes
sync progress without administrator diagnostics or credentials.

## Updating definitions

After initial sync, the app schedules automatic updates. To trigger a manual
sync, export your configured `ADMIN_API_KEY` in the shell and call:

```bash
curl -X POST http://localhost:8000/api/admin/sync -H "X-API-Key: $ADMIN_API_KEY"
```

## Architecture

```
frontend/     React + Vite + Tailwind — SPA served by the backend
backend/      FastAPI + SQLAlchemy (async) + PostgreSQL
defender_sig_extractor/   VDM parser and signature extractor
```

The multi-stage Dockerfile builds the frontend, compiles `luadec` from source for Lua decompilation, then assembles the final Python image with everything bundled.

## Ports

| Service | Port | Bound to |
|---------|------|----------|
| App (HTTP) | 8000 | 127.0.0.1 |
| PostgreSQL | 5432 | 127.0.0.1 |

Both are bound to localhost only. Put a reverse proxy (nginx, Caddy) in front for public exposure.

## Regression checks

Install `backend/requirements.txt` into a Python 3.11 environment. Run the worker
and rate-policy tests with `PYTHONPATH=backend:. python -m unittest discover -s backend/tests -p 'test_security_*.py'`.
The database tests additionally require `TEST_DATABASE_URL` pointing to a
**disposable localhost database named `defender_test`**; they clear that test
database's application tables. Run them with
`PYTHONPATH=backend:. python -m unittest discover -s backend/tests -p 'test_explorer_integration.py'`.
Run `npm run build` in `frontend/` for the frontend type check and production build.
