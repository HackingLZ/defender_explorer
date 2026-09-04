"""Lua script API endpoints."""

import asyncio
import hmac
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from ..config import get_settings
from ..database import get_db
from ..models import LuaScript, Threat
from ..rate_limit import limiter as _limiter
from ..schemas.lua_script import LuaScriptResponse, LuaScriptDetail
from ..schemas.common import PaginatedResponse

router = APIRouter()
_settings = get_settings()


async def _require_api_key(x_api_key: str = Header()):
    """Require ADMIN_API_KEY for protected operations."""
    if not _settings.admin_api_key:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY not configured")
    if not hmac.compare_digest(x_api_key, _settings.admin_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")

# Limit concurrent on-demand decompilations to prevent DoS
_decompile_semaphore = asyncio.Semaphore(3)


@router.get("", response_model=PaginatedResponse[LuaScriptResponse], dependencies=[Depends(_require_api_key)])
async def list_lua_scripts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    has_asr: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),

):
    """List Lua scripts with pagination."""
    query = select(LuaScript)

    if has_asr is True:
        query = query.where(func.array_length(LuaScript.asr_guids, 1) > 0)
    elif has_asr is False:
        query = query.where(
            (LuaScript.asr_guids == None) | (func.array_length(LuaScript.asr_guids, 1) == 0)
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    scripts = result.scalars().all()

    pages = (total + page_size - 1) // page_size if total else 0

    return PaginatedResponse(
        items=[
            LuaScriptResponse(
                id=s.id,
                signature_id=s.signature_id,
                threat_id=s.threat_id,
                bytecode_hash=s.bytecode_hash,
                asr_guids=s.asr_guids or [],
                mitre_techniques=s.mitre_techniques or [],
                has_source=s.decompiled_source is not None,
                decompilation_status=s.decompilation_status or "pending",
                is_asr_script=s.is_asr_script or False,
            )
            for s in scripts
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{script_id}", response_model=LuaScriptDetail)
@_limiter.limit("30/minute")
async def get_lua_script(
    request: Request,
    script_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get Lua script details with decompiled source.

    If the script hasn't been decompiled yet, triggers on-demand decompilation.
    """
    from ..services.decompilation_service import decompile_on_demand

    query = (
        select(LuaScript)
        .options(selectinload(LuaScript.threat))
        .where(LuaScript.id == script_id)
    )

    result = await db.execute(query)
    script = result.scalar_one_or_none()

    if not script:
        raise HTTPException(status_code=404, detail="Lua script not found")

    # Trigger on-demand decompilation if needed (rate-limited)
    decompiled_source = script.decompiled_source
    if script.decompilation_status == "pending" and script.bytecode:
        try:
            async with asyncio.timeout(15):
                async with _decompile_semaphore:
                    decompiled_source = await decompile_on_demand(db, script.id)
        except TimeoutError:
            pass  # Return without decompiled source

    return LuaScriptDetail(
        id=script.id,
        signature_id=script.signature_id,
        threat_id=script.threat_id,
        bytecode_hash=script.bytecode_hash,
        asr_guids=script.asr_guids or [],
        mitre_techniques=script.mitre_techniques or [],
        has_source=decompiled_source is not None,
        decompiled_source=decompiled_source,
        threat_name=script.threat.threat_name if script.threat else None,
    )


@router.get("/by-hash/{bytecode_hash}", response_model=LuaScriptDetail, dependencies=[Depends(_require_api_key)])
@_limiter.limit("30/minute")
async def get_lua_script_by_hash(
    request: Request,
    bytecode_hash: str,
    db: AsyncSession = Depends(get_db),
):
    """Get Lua script by bytecode hash.

    If the script hasn't been decompiled yet, triggers on-demand decompilation.
    """
    from ..services.decompilation_service import decompile_on_demand

    query = (
        select(LuaScript)
        .options(selectinload(LuaScript.threat))
        .where(LuaScript.bytecode_hash == bytecode_hash)
    )

    result = await db.execute(query)
    script = result.scalar_one_or_none()

    if not script:
        raise HTTPException(status_code=404, detail="Lua script not found")

    # Trigger on-demand decompilation if needed (rate-limited)
    decompiled_source = script.decompiled_source
    if script.decompilation_status == "pending" and script.bytecode:
        try:
            async with asyncio.timeout(15):
                async with _decompile_semaphore:
                    decompiled_source = await decompile_on_demand(db, script.id)
        except TimeoutError:
            pass  # Return without decompiled source

    return LuaScriptDetail(
        id=script.id,
        signature_id=script.signature_id,
        threat_id=script.threat_id,
        bytecode_hash=script.bytecode_hash,
        asr_guids=script.asr_guids or [],
        mitre_techniques=script.mitre_techniques or [],
        has_source=decompiled_source is not None,
        decompiled_source=decompiled_source,
        threat_name=script.threat.threat_name if script.threat else None,
    )


@router.get("/{script_id}/logic", dependencies=[Depends(_require_api_key)])
async def get_lua_script_logic(
    script_id: int,
    db: AsyncSession = Depends(get_db),

):
    """Get logic analysis for a Lua script, including ASR rule patterns."""
    from ..services.lua_logic_analyzer import analyze_lua_script
    from ..models import ASRRule
    from sqlalchemy import any_

    query = select(LuaScript).where(LuaScript.id == script_id)
    result = await db.execute(query)
    script = result.scalar_one_or_none()

    if not script:
        raise HTTPException(status_code=404, detail="Lua script not found")

    # Get ASR rule patterns if this script is associated with any ASR rules
    asr_patterns = None
    if script.asr_guids:
        # Get the first ASR rule's extracted data
        for guid in script.asr_guids:
            asr_query = select(ASRRule).where(ASRRule.guid == guid)
            asr_result = await db.execute(asr_query)
            asr_rule = asr_result.scalar_one_or_none()
            if asr_rule and asr_rule.extracted_data:
                asr_patterns = asr_rule.extracted_data
                break

    if not script.decompiled_source:
        # Even without source, return ASR patterns if available
        response = {
            "error": "No decompiled source available",
            "rule_name": None,
            "rule_guid": script.asr_guids[0] if script.asr_guids else None,
            "entry_point": None,
            "functions": [],
            "conditions": [],
            "actions": [],
            "flow": [],
        }
        if asr_patterns:
            response["asr_patterns"] = asr_patterns
        return response

    logic = analyze_lua_script(script.decompiled_source)

    # Add ASR patterns to the response
    if asr_patterns:
        logic["asr_patterns"] = asr_patterns

    return logic
