"""FastAPI application entry point."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select

from .api import router as api_router
from .config import get_settings
from .database import init_db
from .rate_limit import limiter, RateLimitMiddleware
from .services.import_service import import_asr_rules
from .services.decompilation_service import start_background_worker, stop_background_worker
from .services.scheduler_service import start_scheduler_on_startup, stop_scheduler
from .services.sync_lifecycle import resume_startup_sync
from .services.report_service import stop_report_workers
from .database import async_session_maker
from .models import SyncStatus

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

    initial_task = asyncio.create_task(resume_startup_sync())

    # Restore scheduled sync from DB settings
    await start_scheduler_on_startup()

    yield

    # Shutdown
    await stop_scheduler()
    if initial_task:
        initial_task.cancel()
        await asyncio.gather(initial_task, return_exceptions=True)
    await stop_report_workers()
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
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(RateLimitMiddleware)

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


@app.get("/ready")
async def ready():
    """Database and schema readiness; initial ingestion may still be running."""
    try:
        async with async_session_maker() as db:
            await db.execute(select(SyncStatus.phase).limit(1))
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable"})


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
