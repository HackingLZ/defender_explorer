"""FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import select, func

from .api import router as api_router
from .config import get_settings
from .database import init_db
from .rate_limit import client_key
from .services.import_service import import_asr_rules
from .services.decompilation_service import start_background_worker, stop_background_worker
from .services.sync_service import run_sync
from .services.scheduler_service import start_scheduler_on_startup
from .database import async_session_maker
from .models import Threat, SyncStatus

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await init_db()

    # Import ASR rules on startup
    async with async_session_maker() as db:
        try:
            count = await import_asr_rules(db)
            print(f"Imported {count} ASR rules")
        except Exception as e:
            print(f"Warning: ASR rules import failed: {e}")

    # Start background Lua decompilation worker
    start_background_worker()
    print("Started background Lua decompilation worker")

    # Auto-sync on first startup if database is empty
    async with async_session_maker() as db:
        result = await db.execute(select(func.count(Threat.id)))
        threat_count = result.scalar() or 0

        if threat_count == 0:
            print("No threat data found - starting initial sync automatically...")
            # Create sync status record
            sync_status = SyncStatus(
                started_at=datetime.utcnow(),
                status="running",
            )
            db.add(sync_status)
            await db.commit()
            await db.refresh(sync_status)

            # Start sync in background (non-blocking)
            asyncio.create_task(run_sync(sync_status.id))
            print(f"Initial sync started (sync_id={sync_status.id})")
        else:
            print(f"Database has {threat_count} threats - skipping auto-sync")

    # Restore scheduled sync from DB settings
    await start_scheduler_on_startup()

    yield

    # Shutdown
    await stop_background_worker()
    print("Stopped background Lua decompilation worker")


app = FastAPI(
    title="Defender Explorer API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Rate limiting
limiter = Limiter(key_func=client_key, default_limits=["120/minute"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Configure CORS with configurable origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Requested-With"],
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Include API router
app.include_router(api_router, prefix=settings.api_prefix)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


# Serve static files (frontend) if the directory exists
# This must be after API routes to avoid conflicts
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    from fastapi.staticfiles import StaticFiles  # noqa: F811
    from fastapi.responses import FileResponse

    @app.get("/")
    async def serve_index():
        """Serve the frontend index.html."""
        return FileResponse(static_dir / "index.html")

    # Catch-all for client-side routing - serve index.html for non-API routes
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve static files or index.html for SPA routing."""
        # Don't serve for API routes
        if full_path.startswith("api/"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")

        file_path = (static_dir / full_path).resolve()
        if not file_path.is_relative_to(static_dir.resolve()):
            raise HTTPException(status_code=403, detail="Forbidden")
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        # Return index.html for SPA routing
        return FileResponse(static_dir / "index.html")
else:
    @app.get("/")
    async def root():
        """Root endpoint when no static files."""
        return {
            "name": "Defender Explorer API",
            "version": "1.0.0",
            "docs": "/docs",
        }
