"""Database-wide sync reservation, ownership, and interruption recovery."""

import asyncio
import logging
from datetime import datetime, timedelta
from functools import wraps

from sqlalchemy import select, text, update

from ..database import engine, async_session_maker
from ..models import SyncStatus

logger = logging.getLogger(__name__)

SYNC_LOCK = 0x44454653


class SyncBusy(Exception):
    pass


async def _recover(db):
    # A queued job may be between its reservation commit and worker startup.
    cutoff = datetime.utcnow() - timedelta(minutes=1)
    result = await db.execute(
        update(SyncStatus).where(
            SyncStatus.status == "running",
            (SyncStatus.phase != "queued") | (SyncStatus.started_at < cutoff),
        ).values(status="failed", phase="interrupted", completed_at=datetime.utcnow(),
                 error_message="Sync interrupted; retry the update to resume unchanged records.")
    )
    return result.rowcount


async def recover_interrupted_syncs(db):
    locked = await db.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": SYNC_LOCK})
    if not locked:
        await db.rollback()
        return 0
    count = await _recover(db)
    await db.commit()
    return count


async def reserve_sync(db):
    """Serialize every startup, scheduled, and manual import reservation."""
    locked = await db.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": SYNC_LOCK})
    if not locked:
        await db.rollback()
        raise SyncBusy("Sync already in progress")
    await _recover(db)
    running = await db.scalar(select(SyncStatus.id).where(SyncStatus.status == "running").limit(1))
    if running:
        await db.commit()
        raise SyncBusy("Sync already in progress")
    status = SyncStatus(status="running", phase="queued", heartbeat_at=datetime.utcnow())
    db.add(status)
    await db.commit()
    await db.refresh(status)
    return status


async def set_progress(db, sync_id, phase, **values):
    await db.execute(update(SyncStatus).where(SyncStatus.id == sync_id).values(
        phase=phase, heartbeat_at=datetime.utcnow(), **values,
    ))
    await db.commit()


async def _heartbeat(sync_id, connection):
    while True:
        await asyncio.sleep(15)
        await connection.execute(text("SELECT 1"))
        await connection.commit()
        async with async_session_maker() as db:
            values = {"heartbeat_at": datetime.utcnow()}
            phase = await db.scalar(select(SyncStatus.phase).where(SyncStatus.id == sync_id))
            if phase == "decompiling":
                from .decompilation_service import get_decompilation_stats
                stats = await get_decompilation_stats()
                values.update(lua_completed=stats.get("completed", 0), lua_failed=stats.get("failed", 0),
                              lua_pending=stats.get("pending", 0))
            await db.execute(update(SyncStatus).where(
                SyncStatus.id == sync_id, SyncStatus.status == "running",
            ).values(**values))
            await db.commit()


def exclusive_sync(function):
    """Hold a dedicated DB connection lock across commits and slow CPU work.

    PostgreSQL releases ownership even on process death; startup can safely
    recover abandoned records without declaring another instance's job stale.
    """
    @wraps(function)
    async def wrapped(sync_id, *args, **kwargs):
        async with engine.connect() as connection:
            locked = await connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": SYNC_LOCK})
            await connection.commit()
            if not locked:
                return
            heartbeat = None
            try:
                async with async_session_maker() as db:
                    status = await db.get(SyncStatus, sync_id)
                    if not status or status.status != "running":
                        return
                    await set_progress(db, sync_id, "starting")
                owner = asyncio.current_task()
                heartbeat = asyncio.create_task(_heartbeat(sync_id, connection))
                def heartbeat_finished(task):
                    if not task.cancelled() and task.exception():
                        logger.error("Sync heartbeat lost: %s", task.exception())
                        owner.cancel()
                heartbeat.add_done_callback(heartbeat_finished)
                try:
                    return await function(sync_id, *args, **kwargs)
                except BaseException:
                    async with async_session_maker() as db:
                        await db.execute(update(SyncStatus).where(
                            SyncStatus.id == sync_id, SyncStatus.status == "running",
                        ).values(status="failed", phase="interrupted", completed_at=datetime.utcnow(),
                                 error_message="Sync interrupted. Retry to resume."))
                        await db.commit()
                    raise
            finally:
                if heartbeat:
                    heartbeat.cancel()
                    await asyncio.gather(heartbeat, return_exceptions=True)
                try:
                    await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": SYNC_LOCK})
                    await connection.commit()
                except Exception:
                    # Never put a possibly lock-owning connection back in the pool.
                    await connection.invalidate()
    return wrapped


async def resume_startup_sync():
    """Resume abandoned work, including a crash just after queue reservation."""
    from ..models import VDMVersion
    from .sync_service import run_sync
    for attempt in range(2):
        reserved = None
        async with async_session_maker() as db:
            recovered = await recover_interrupted_syncs(db)
            current = await db.scalar(select(VDMVersion.id).where(VDMVersion.is_current.is_(True)).limit(1))
            queued = await db.scalar(select(SyncStatus.id).where(
                SyncStatus.status == "running", SyncStatus.phase == "queued",
            ).limit(1))
            if not current or recovered:
                try:
                    reserved = await reserve_sync(db)
                except SyncBusy:
                    pass
        if reserved:
            await run_sync(reserved.id)
            return
        if not queued or attempt:
            return
        await asyncio.sleep(61)
