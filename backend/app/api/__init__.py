"""API routes."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from . import threats, signatures, lua, asr, admin
from . import yara
from . import functions
from ..database import get_db
from ..models import Threat, Signature, LuaScript, ASRRule, SyncStatus, VDMVersion, EntityHistory, AppSetting
from ..schemas.common import StatsResponse

router = APIRouter()

# Public routes
router.include_router(threats.router, prefix="/threats", tags=["threats"])
router.include_router(signatures.router, prefix="/signatures", tags=["signatures"])
router.include_router(lua.router, prefix="/lua", tags=["lua"])
router.include_router(asr.router, prefix="/asr", tags=["asr"])
router.include_router(functions.router, prefix="/functions", tags=["functions"])
router.include_router(admin.router, prefix="/admin", tags=["admin"])
router.include_router(yara.router, prefix="/yara", tags=["yara"])


def _utc(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value else None


@router.get("/status", tags=["public"])
async def get_public_status(db: AsyncSession = Depends(get_db)):
    """Read-only progress without admin diagnostics, keys, or filesystem paths."""
    latest = (await db.execute(select(SyncStatus).order_by(SyncStatus.id.desc()).limit(1))).scalar_one_or_none()
    running = (await db.execute(select(SyncStatus).where(SyncStatus.status == "running")
                               .order_by(SyncStatus.id.desc()).limit(1))).scalar_one_or_none()
    current = (await db.execute(select(VDMVersion.version_hash).where(VDMVersion.is_current.is_(True))
                               .order_by(VDMVersion.id.desc()).limit(1))).scalar_one_or_none()
    last_sync = (await db.execute(select(func.max(SyncStatus.completed_at))
                                 .where(SyncStatus.status == "completed"))).scalar()
    progress = running or latest
    status = "running" if running else "failed" if latest and latest.status == "failed" else "ready" if current else "initializing"
    return {
        "status": status, "last_sync": _utc(last_sync), "current_version": current,
        "sync_started_at": _utc(progress.started_at) if progress else None,
        "threats_added": (progress.threats_added or 0) if progress else 0,
        "threats_updated": (progress.threats_updated or 0) if progress else 0,
        "threats_removed": (progress.threats_removed or 0) if progress else 0,
    }


@router.get("/activity", tags=["public"])
async def get_activity(days: int = Query(365, ge=1, le=365), db: AsyncSession = Depends(get_db)):
    """Observed threat changes by UTC day; never invent pre-tracking history."""
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)
    end = today + timedelta(days=1)
    tracked_since = (await db.execute(select(AppSetting.value)
                                     .where(AppSetting.key == "history_tracked_since"))).scalar()
    day = func.date(EntityHistory.changed_at)
    rows = (await db.execute(select(day, func.count(EntityHistory.id))
                            .where(EntityHistory.entity_type == "threat",
                                   EntityHistory.changed_at >= datetime.combine(start, datetime.min.time()),
                                   EntityHistory.changed_at < datetime.combine(end, datetime.min.time()))
                            .group_by(day).order_by(day))).all()
    counts = {date: count for date, count in rows}
    items = []
    if tracked_since:
        first_tracked_day = datetime.fromisoformat(tracked_since.replace("Z", "+00:00")).date()
        date = max(start, first_tracked_day)
        while date <= today:
            items.append({"date": date.isoformat(), "count": counts.get(date, 0)})
            date += timedelta(days=1)
    return {"items": items, "tracked_since": tracked_since}


@router.get("/stats", response_model=StatsResponse, tags=["public"])
async def get_public_stats(db: AsyncSession = Depends(get_db)):
    """Public database statistics (no auth required)."""
    threat_count = (await db.execute(select(func.count(Threat.id)))).scalar()
    signature_count = (await db.execute(select(func.count(Signature.id)))).scalar()
    lua_script_count = (await db.execute(select(func.count(LuaScript.id)))).scalar()
    asr_rule_count = (await db.execute(select(func.count(ASRRule.guid)))).scalar()

    last_sync_query = (
        select(SyncStatus.completed_at)
        .where(SyncStatus.status == "completed")
        .order_by(SyncStatus.completed_at.desc())
        .limit(1)
    )
    last_sync = (await db.execute(last_sync_query)).scalar()

    return StatsResponse(
        threat_count=threat_count or 0,
        signature_count=signature_count or 0,
        lua_script_count=lua_script_count or 0,
        asr_rule_count=asr_rule_count or 0,
        last_sync=last_sync,
    )
