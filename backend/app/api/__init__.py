"""API routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from . import threats, signatures, lua, asr, admin
from . import yara
from . import functions
from ..database import get_db
from ..models import Threat, Signature, LuaScript, ASRRule, SyncStatus
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
