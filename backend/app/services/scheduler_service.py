"""Simple scheduler service for auto-sync."""

import asyncio
import json
from datetime import datetime, time, timedelta
from typing import Optional
import logging

from sqlalchemy import select

logger = logging.getLogger(__name__)

# Global state for scheduler
_scheduler_task: Optional[asyncio.Task] = None
_auto_sync_enabled: bool = False
_auto_sync_time: time = time(3, 0)  # Default 3:00 AM


def get_schedule_status() -> dict:
    """Get current auto-sync schedule status."""
    return {
        "enabled": _auto_sync_enabled,
        "time": _auto_sync_time.strftime("%H:%M"),
        "next_run": _get_next_run_time() if _auto_sync_enabled else None,
    }


def _get_next_run_time() -> Optional[str]:
    """Calculate next scheduled run time."""
    now = datetime.now()
    scheduled = datetime.combine(now.date(), _auto_sync_time)
    if scheduled <= now:
        # Already passed today, schedule for tomorrow
        scheduled = datetime.combine(now.date() + timedelta(days=1), _auto_sync_time)
    return scheduled.isoformat()


async def _save_schedule_to_db():
    """Persist schedule settings to the database."""
    from ..database import async_session_maker
    from ..models import AppSetting

    try:
        async with async_session_maker() as db:
            value = json.dumps({
                "enabled": _auto_sync_enabled,
                "time": _auto_sync_time.strftime("%H:%M"),
            })
            existing = await db.execute(
                select(AppSetting).where(AppSetting.key == "sync_schedule")
            )
            setting = existing.scalar_one_or_none()
            if setting:
                setting.value = value
            else:
                db.add(AppSetting(key="sync_schedule", value=value))
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to save schedule to DB: {e}")


async def _load_schedule_from_db() -> Optional[dict]:
    """Load schedule settings from the database."""
    from ..database import async_session_maker
    from ..models import AppSetting

    try:
        async with async_session_maker() as db:
            result = await db.execute(
                select(AppSetting).where(AppSetting.key == "sync_schedule")
            )
            setting = result.scalar_one_or_none()
            if setting:
                return json.loads(setting.value)
    except Exception as e:
        logger.error(f"Failed to load schedule from DB: {e}")
    return None


async def set_schedule(enabled: bool, sync_time: str) -> dict:
    """Set auto-sync schedule."""
    global _auto_sync_enabled, _auto_sync_time, _scheduler_task

    _auto_sync_enabled = enabled

    # Parse time
    try:
        parts = sync_time.split(":")
        _auto_sync_time = time(int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        _auto_sync_time = time(3, 0)

    # Persist to database
    await _save_schedule_to_db()

    # Restart scheduler task if enabled
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass

    if enabled:
        _scheduler_task = asyncio.create_task(_scheduler_loop())
        logger.info(f"Auto-sync scheduled for {_auto_sync_time.strftime('%H:%M')}")
    else:
        logger.info("Auto-sync disabled")

    return get_schedule_status()


async def _scheduler_loop():
    """Background loop that triggers sync at scheduled time."""
    from .sync_service import run_sync
    from ..database import async_session_maker
    from ..models import SyncStatus

    logger.info("Scheduler loop started")

    while _auto_sync_enabled:
        now = datetime.now()
        scheduled = datetime.combine(now.date(), _auto_sync_time)

        if scheduled <= now:
            # Already passed today, schedule for tomorrow
            scheduled = scheduled + timedelta(days=1)

        # Calculate seconds until next run
        wait_seconds = (scheduled - now).total_seconds()
        logger.info(f"Next auto-sync in {wait_seconds / 3600:.1f} hours at {scheduled.isoformat()}")

        try:
            await asyncio.sleep(wait_seconds)
        except asyncio.CancelledError:
            logger.info("Scheduler cancelled")
            return

        if not _auto_sync_enabled:
            return

        # Time to sync!
        logger.info("Starting scheduled auto-sync")

        try:
            async with async_session_maker() as db:
                # Create sync status
                sync_status = SyncStatus(
                    started_at=datetime.utcnow(),
                    status="running",
                )
                db.add(sync_status)
                await db.commit()
                await db.refresh(sync_status)

                # Trigger sync (runs in current task)
                await run_sync(sync_status.id)
                logger.info("Scheduled auto-sync completed")
        except Exception as e:
            logger.error(f"Scheduled auto-sync failed: {e}")


async def start_scheduler_on_startup():
    """Load saved schedule from DB and start scheduler if enabled."""
    global _auto_sync_enabled, _auto_sync_time

    saved = await _load_schedule_from_db()
    if saved is not None:
        sync_time = saved.get("time", "03:00")
        enabled = bool(saved.get("enabled", False))
        logger.info("Restoring saved schedule: enabled=%s, time=%s", enabled, sync_time)
        await set_schedule(enabled, sync_time)
    else:
        logger.info("No saved schedule found, enabling default 3 AM daily sync")
        await set_schedule(True, "03:00")
