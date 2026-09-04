"""Database setup and session management."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text, event
from sqlalchemy.orm import Session
from .config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@event.listens_for(Session, "after_begin")
def set_history_version(session, transaction, connection):
    """Apply import provenance to each committed batch without leaking pool state."""
    version_hash = session.info.get("vdm_version_hash")
    if version_hash:
        connection.execute(text("SELECT set_config('app.vdm_version_hash', :version_hash, true)"),
                           {"version_hash": version_hash})


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


async def get_db() -> AsyncSession:
    """Dependency to get database session."""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Run migrations for new columns
    try:
        async with engine.begin() as conn:
            # Ensure required extensions
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))

            # Ensure search vector trigger/function exists
            await conn.execute(text("""
                CREATE OR REPLACE FUNCTION update_threat_search_vector()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.search_vector := to_tsvector('english',
                        COALESCE(NEW.threat_name, '') || ' ' ||
                        COALESCE(NEW.category, '') || ' ' ||
                        COALESCE(NEW.family, '')
                    );
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
            """))
            await conn.execute(text("DROP TRIGGER IF EXISTS threat_search_vector_update ON threats"))
            await conn.execute(text("""
                CREATE TRIGGER threat_search_vector_update
                BEFORE INSERT OR UPDATE ON threats
                FOR EACH ROW
                EXECUTE FUNCTION update_threat_search_vector()
            """))

            # Add extracted_data column to asr_rules if it doesn't exist
            await conn.execute(
                text("""
                    ALTER TABLE asr_rules
                    ADD COLUMN IF NOT EXISTS extracted_data JSONB DEFAULT '{}'::jsonb
                """)
            )

            # Add individual VDM file hash columns for incremental sync
            await conn.execute(
                text("""
                    ALTER TABLE vdm_versions
                    ADD COLUMN IF NOT EXISTS av_base_hash VARCHAR(64),
                    ADD COLUMN IF NOT EXISTS av_delta_hash VARCHAR(64),
                    ADD COLUMN IF NOT EXISTS as_base_hash VARCHAR(64),
                    ADD COLUMN IF NOT EXISTS as_delta_hash VARCHAR(64)
                """)
            )

            # Add content_hash column to threats for change detection
            await conn.execute(
                text("""
                    ALTER TABLE threats
                    ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64)
                """)
            )
            # Backfill search vectors for existing rows
            await conn.execute(text("""
                UPDATE threats
                SET search_vector = to_tsvector('english',
                    COALESCE(threat_name, '') || ' ' ||
                    COALESCE(category, '') || ' ' ||
                    COALESCE(family, '')
                )
                WHERE search_vector IS NULL
            """))
    except Exception as e:
        print(f"Migration note: {e}")

    # Tracking must install successfully; otherwise do not claim that activity is tracked.
    from .services.history_migrations import install_history_tracking
    async with engine.begin() as conn:
        await install_history_tracking(conn)
