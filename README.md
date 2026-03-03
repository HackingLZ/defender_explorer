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

## Updating definitions

After initial sync, the app schedules automatic updates. To trigger a manual sync hit the admin endpoint or restart the container with an empty database volume:

```bash
docker compose down -v   # drops the DB volume
docker compose up -d     # fresh sync on next start
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
