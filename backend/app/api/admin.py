"""Admin API endpoints."""

import hmac
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, Header, Request
from pydantic import BaseModel
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update

from ..database import get_db
from ..config import get_settings
from ..models import Threat, Signature, LuaScript, ASRRule, VDMVersion, SyncStatus, FunctionDefinition
from ..rate_limit import client_key
from ..schemas.common import StatsResponse, SyncStatusResponse
from ..services.sync_service import run_sync, run_local_import
from ..services.extracted_import_service import import_extracted_data
from ..services.yara_service import get_available_rules
from ..services.scheduler_service import get_schedule_status, set_schedule

logger = logging.getLogger(__name__)

_limiter = Limiter(key_func=client_key)
settings = get_settings()


async def require_api_key(x_api_key: str = Header()):
    """Require ADMIN_API_KEY header for all admin operations."""
    if not settings.admin_api_key:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY not configured")
    if not hmac.compare_digest(x_api_key, settings.admin_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")


router = APIRouter(dependencies=[Depends(require_api_key)])

# Default paths for local VDM files
DEFAULT_VDM_PATHS = [
    "/data/vdm/mpavbase.vdm",
    "/data/vdm/mpasbase.vdm",
    "/app/vdm/mpavbase.vdm",
]

EXTRACTED_PATH = os.environ.get("EXTRACTED_PATH", "/data/extracted")

# Allowed paths for import operations (security: prevent path traversal)
ALLOWED_IMPORT_ROOTS = [
    Path("/data/extracted").resolve(),
    Path("/data/vdm").resolve(),
]


def validate_import_path(path: str) -> Path:
    """Validate that a path is within allowed directories to prevent path traversal attacks."""
    resolved = Path(path).resolve()

    for allowed_root in ALLOWED_IMPORT_ROOTS:
        if resolved == allowed_root or resolved.is_relative_to(allowed_root):
            return resolved

    raise HTTPException(
        status_code=403,
        detail="Path not in allowed directories"
    )


class LocalImportRequest(BaseModel):
    """Request to import from local VDM file."""
    vdm_path: Optional[str] = None


class ScheduleRequest(BaseModel):
    """Request to set auto-sync schedule."""
    enabled: bool
    time: str = "03:00"  # HH:MM format


def _ensure_imports_enabled():
    if not settings.admin_imports_enabled:
        raise HTTPException(status_code=403, detail="Admin imports are disabled")


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Get database statistics."""
    threat_count = (await db.execute(select(func.count(Threat.id)))).scalar()
    signature_count = (await db.execute(select(func.count(Signature.id)))).scalar()
    lua_script_count = (await db.execute(select(func.count(LuaScript.id)))).scalar()
    asr_rule_count = (await db.execute(select(func.count(ASRRule.guid)))).scalar()

    # Get last sync time
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


@router.get("/decompilation/stats")
async def get_decompilation_stats():
    """Get Lua decompilation progress statistics."""
    from ..services.decompilation_service import get_decompilation_stats
    return await get_decompilation_stats()


@router.get("/schedule")
async def get_sync_schedule():
    """Get current auto-sync schedule."""
    return get_schedule_status()


@router.post("/schedule")
async def set_sync_schedule(
    request: ScheduleRequest,

):
    """Set auto-sync schedule."""
    return await set_schedule(request.enabled, request.time)


@router.post("/sync", response_model=SyncStatusResponse)
async def trigger_sync(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),

):
    """Trigger a new sync operation (download from Microsoft)."""
    # Check if sync is already running
    running_query = select(SyncStatus).where(SyncStatus.status == "running")
    running = (await db.execute(running_query)).scalar()

    if running:
        raise HTTPException(status_code=409, detail="Sync already in progress")

    # Create new sync status
    sync_status = SyncStatus(
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(sync_status)
    await db.commit()
    await db.refresh(sync_status)

    # Start sync in background
    background_tasks.add_task(run_sync, sync_status.id)

    return SyncStatusResponse.model_validate(sync_status)


@router.get("/sync/status", response_model=SyncStatusResponse)
async def get_sync_status(db: AsyncSession = Depends(get_db)):
    """Get current sync status."""
    # Get most recent sync
    query = select(SyncStatus).order_by(SyncStatus.started_at.desc()).limit(1)
    result = await db.execute(query)
    sync_status = result.scalar_one_or_none()

    if not sync_status:
        raise HTTPException(status_code=404, detail="No sync status found")

    return SyncStatusResponse.model_validate(sync_status)


@router.get("/sync/history", response_model=list[SyncStatusResponse])
async def get_sync_history(
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Get sync history."""
    query = select(SyncStatus).order_by(SyncStatus.started_at.desc()).limit(limit)
    result = await db.execute(query)
    history = result.scalars().all()

    return [SyncStatusResponse.model_validate(s) for s in history]


@router.get("/versions", response_model=list)
async def list_versions(
    db: AsyncSession = Depends(get_db),

):
    """List VDM versions."""
    query = select(VDMVersion).order_by(VDMVersion.download_timestamp.desc()).limit(50)
    result = await db.execute(query)
    versions = result.scalars().all()

    return [
        {
            "id": v.id,
            "version_hash": v.version_hash,
            "download_timestamp": v.download_timestamp,
            "threat_count": v.threat_count,
            "signature_count": v.signature_count,
            "is_current": v.is_current,
        }
        for v in versions
    ]


@router.post("/import/local", response_model=SyncStatusResponse)
async def import_local_vdm(
    background_tasks: BackgroundTasks,
    request: LocalImportRequest,
    db: AsyncSession = Depends(get_db),

):
    """Import from a local VDM file."""
    _ensure_imports_enabled()
    # Check if sync is already running
    running_query = select(SyncStatus).where(SyncStatus.status == "running")
    running = (await db.execute(running_query)).scalar()

    if running:
        raise HTTPException(status_code=409, detail="Import already in progress")

    # Find VDM file
    vdm_path = request.vdm_path
    if vdm_path:
        validate_import_path(vdm_path)
    if not vdm_path:
        # Try default paths
        for default_path in DEFAULT_VDM_PATHS:
            if os.path.exists(default_path):
                vdm_path = default_path
                break

    if not vdm_path or not os.path.exists(vdm_path):
        raise HTTPException(
            status_code=404,
            detail="VDM file not found"
        )

    # Create new sync status
    sync_status = SyncStatus(
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(sync_status)
    await db.commit()
    await db.refresh(sync_status)

    # Start import in background
    background_tasks.add_task(run_local_import, sync_status.id, vdm_path)

    return SyncStatusResponse.model_validate(sync_status)


@router.get("/vdm/available")
async def list_available_vdm():
    """List available local VDM files."""
    _ensure_imports_enabled()
    available = []

    # Check default paths
    for path in DEFAULT_VDM_PATHS:
        if os.path.exists(path):
            stat = os.stat(path)
            available.append({
                "path": path,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })

    # Also check /data/vdm directory for any VDM files
    vdm_dir = Path("/data/vdm")
    if vdm_dir.exists():
        for vdm_file in vdm_dir.glob("*.vdm"):
            if str(vdm_file) not in [v["path"] for v in available]:
                stat = vdm_file.stat()
                available.append({
                    "path": str(vdm_file),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })

    return available


@router.post("/import/extracted", response_model=dict)
async def import_extracted_endpoint(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),

):
    """Import pre-extracted data (ASR scripts, IOCs, hashes)."""
    _ensure_imports_enabled()
    # Check if sync is already running
    running_query = select(SyncStatus).where(SyncStatus.status == "running")
    running = (await db.execute(running_query)).scalar()

    if running:
        raise HTTPException(status_code=409, detail="Import already in progress")

    if not os.path.exists(EXTRACTED_PATH):
        raise HTTPException(
            status_code=404,
            detail="Extracted data directory not found"
        )

    # Create sync status
    sync_status = SyncStatus(
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(sync_status)
    await db.commit()
    await db.refresh(sync_status)

    async def run_extracted_import(sync_id: int):
        from ..database import async_session_maker
        async with async_session_maker() as session:
            try:
                stats = await import_extracted_data(EXTRACTED_PATH)
                await session.execute(
                    update(SyncStatus)
                    .where(SyncStatus.id == sync_id)
                    .values(
                        status="completed",
                        completed_at=datetime.utcnow(),
                        threats_added=stats.threats,
                        threats_updated=stats.lua_scripts + stats.asr_rules,
                        error_message="; ".join(stats.errors) if stats.errors else None,
                    )
                )
                await session.commit()
            except Exception:
                logger.exception("Extracted import %s failed", sync_id)
                await session.execute(
                    update(SyncStatus)
                    .where(SyncStatus.id == sync_id)
                    .values(
                        status="failed",
                        completed_at=datetime.utcnow(),
                        error_message="Import failed. Check server logs for details.",
                    )
                )
                await session.commit()

    background_tasks.add_task(run_extracted_import, sync_status.id)

    return {
        "status": "started",
        "sync_id": sync_status.id,
        "message": "Importing extracted data"
    }


@router.get("/extracted/available")
async def list_extracted_data():
    """List available extracted data directories."""
    _ensure_imports_enabled()
    extracted_dir = Path(EXTRACTED_PATH)
    if not extracted_dir.exists():
        return {"available": False, "path": EXTRACTED_PATH, "contents": []}

    contents = []
    for item in extracted_dir.iterdir():
        if item.is_dir():
            # Count files in directory
            file_count = sum(1 for _ in item.rglob("*") if _.is_file())
            contents.append({
                "name": item.name,
                "type": "directory",
                "file_count": file_count,
            })
        elif item.is_file():
            contents.append({
                "name": item.name,
                "type": "file",
                "size": item.stat().st_size,
            })

    return {
        "available": True,
        "path": EXTRACTED_PATH,
        "contents": contents,
    }


@router.get("/yara/rules")
async def list_yara_rules():
    """List available YARA rule files."""
    return get_available_rules()


@router.post("/fix/threat-names")
@_limiter.limit("5/minute")
async def fix_threat_names(
    request: Request,
    db: AsyncSession = Depends(get_db),

):
    """Fix threat names and recompute categories for all threats."""
    result = await db.execute(select(Threat))
    threats = result.scalars().all()

    fixed_count = 0
    recategorized_count = 0
    for threat in threats:
        original_name = threat.threat_name
        fixed_name = Threat.fix_threat_name(original_name)
        parsed = Threat.parse_threat_name(fixed_name)

        name_changed = fixed_name != original_name
        category_changed = parsed["category"] != threat.category
        family_changed = parsed["family"] != threat.family

        if name_changed:
            threat.threat_name = fixed_name
            fixed_count += 1

        if name_changed or category_changed or family_changed:
            threat.category = parsed["category"]
            threat.family = parsed["family"]
            recategorized_count += 1

    await db.commit()

    return {
        "status": "completed",
        "total_threats": len(threats),
        "fixed_count": fixed_count,
        "recategorized_count": recategorized_count,
    }


@router.post("/import/asr-only")
async def import_asr_scripts_only(
    db: AsyncSession = Depends(get_db),

):
    """Import only ASR scripts from extracted data (fast operation)."""
    _ensure_imports_enabled()
    from ..services.extracted_import_service import ExtractedImportService, ExtractedImportStats

    asr_dir = Path(EXTRACTED_PATH) / "asr"
    if not asr_dir.exists():
        raise HTTPException(status_code=404, detail="ASR data directory not found")

    service = ExtractedImportService(db, EXTRACTED_PATH)
    stats = ExtractedImportStats()

    await service.import_asr_scripts(stats)
    await db.commit()

    return {
        "status": "completed",
        "asr_rules": stats.asr_rules,
        "lua_scripts": stats.lua_scripts,
        "errors": stats.errors,
    }


class LuaImportRequest(BaseModel):
    """Request to import Lua scripts from a path."""
    lua_path: str


@router.post("/import/lua-scripts")
async def import_lua_scripts_from_path(
    request: LuaImportRequest,
    db: AsyncSession = Depends(get_db),

):
    """Import Lua scripts from a specified directory and link to ASR rules."""
    _ensure_imports_enabled()
    import hashlib
    import re
    from sqlalchemy.dialects.postgresql import insert
    from ..services.extracted_import_service import ASR_RULE_NAME_TO_GUID

    # Validate path to prevent path traversal attacks
    lua_dir = validate_import_path(request.lua_path)
    if not lua_dir.exists():
        raise HTTPException(status_code=404, detail="Import path not found")

    imported = 0
    linked = 0
    errors = []

    # Walk through all .lua files
    for lua_file in lua_dir.rglob("*.lua"):
        try:
            content = lua_file.read_text(errors="replace")
            # Remove null bytes and problematic characters
            content = content.replace('\x00', '').replace('\x13', '').replace('\x0f', '')
            bytecode_hash = hashlib.sha256(content.encode()).hexdigest()

            # Extract ASR GUIDs using multiple patterns
            asr_guids = set()

            # Pattern 1: IsHipsRuleEnabled calls
            hips_matches = re.findall(r'IsHipsRuleEnabled\s*\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', content)
            for g in hips_matches:
                asr_guids.add(g.lower())

            # Pattern 2: mp.IsHipsRuleEnabled calls
            hips_matches = re.findall(r'\(mp\.IsHipsRuleEnabled\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', content)
            for g in hips_matches:
                asr_guids.add(g.lower())

            # Pattern 3: GetRuleInfo with Name
            rule_info_match = re.search(r'GetRuleInfo\s*=\s*function.*?\.Name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
            if rule_info_match:
                rule_name = rule_info_match.group(1).lower().strip()
                if rule_name in ASR_RULE_NAME_TO_GUID:
                    asr_guids.add(ASR_RULE_NAME_TO_GUID[rule_name])

            # Pattern 4: l_x_y.Name = "rule name"
            name_matches = re.findall(r'l_\d+_\d+\.Name\s*=\s*["\']([^"\']+)["\']', content)
            for name in name_matches:
                name_lower = name.lower().strip()
                if name_lower in ASR_RULE_NAME_TO_GUID:
                    asr_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

            # Pattern 5: {}.Name = "rule name"
            name_matches = re.findall(r'\{\}\.Name\s*=\s*["\']([^"\']+)["\']', content)
            for name in name_matches:
                name_lower = name.lower().strip()
                if name_lower in ASR_RULE_NAME_TO_GUID:
                    asr_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

            # Insert or update script
            stmt = insert(LuaScript).values(
                bytecode_hash=bytecode_hash,
                decompiled_source=content[:100000],
                asr_guids=list(asr_guids),
            ).on_conflict_do_update(
                index_elements=["bytecode_hash"],
                set_={
                    "asr_guids": list(asr_guids),
                    "decompiled_source": content[:100000],
                }
            )
            await db.execute(stmt)
            imported += 1

            if asr_guids:
                linked += 1

        except Exception as e:
            errors.append(f"{lua_file.name}: {str(e)}")

    await db.commit()

    # Refresh ASR rule counts and patterns
    from ..services.lua_pattern_extractor import extract_patterns_from_scripts
    from sqlalchemy import any_

    rules_result = await db.execute(select(ASRRule))
    rules = rules_result.scalars().all()

    rules_updated = 0
    for rule in rules:
        scripts_query = select(LuaScript.decompiled_source).where(
            rule.guid == any_(LuaScript.asr_guids)
        )
        scripts_result = await db.execute(scripts_query)
        sources = [row[0] for row in scripts_result.all() if row[0]]

        if sources:
            patterns = extract_patterns_from_scripts(sources, rule.guid)
            extracted_data = patterns.to_dict()
        else:
            extracted_data = {}

        rule.extracted_data = extracted_data
        rule.script_count = len(sources)
        rules_updated += 1

    await db.commit()

    return {
        "status": "completed",
        "scripts_imported": imported,
        "scripts_linked_to_asr": linked,
        "asr_rules_updated": rules_updated,
        "errors": errors[:10] if errors else [],
        "total_errors": len(errors),
    }


# =============================================================================
# Import V2 API Endpoints - Improved import pipeline
# =============================================================================


class ExtractAndImportRequest(BaseModel):
    """Request for full extract and import pipeline."""
    vdm_path: Optional[str] = None
    extracted_path: Optional[str] = None
    skip_extraction: bool = False


@router.post("/import/v2/full")
@_limiter.limit("3/minute")
async def extract_and_import_v2(
    request: Request,
    background_tasks: BackgroundTasks,
    import_request: ExtractAndImportRequest,
    db: AsyncSession = Depends(get_db),

):
    """
    Run the full V2 import pipeline: Extract VDMs → Import Lua → Resolve ASR.

    This is the recommended import method. It:
    1. Extracts and decompiles all VDM files to text
    2. Imports Lua scripts and builds function registry
    3. Resolves ASR function dependencies across scripts

    Query parameters:
    - vdm_path: Directory containing VDM files (default: /data/vdm)
    - extracted_path: Directory for extracted data (default: /data/extracted)
    - skip_extraction: Skip VDM extraction and use existing files
    """
    _ensure_imports_enabled()

    # Check if sync is already running
    running_query = select(SyncStatus).where(SyncStatus.status == "running")
    running = (await db.execute(running_query)).scalar()

    if running:
        raise HTTPException(status_code=409, detail="Import already in progress")

    # Validate paths if provided
    if import_request.vdm_path:
        validate_import_path(import_request.vdm_path)
    if import_request.extracted_path:
        validate_import_path(import_request.extracted_path)

    # Create sync status
    sync_status = SyncStatus(
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(sync_status)
    await db.commit()
    await db.refresh(sync_status)

    async def run_import_v2(sync_id: int):
        from ..database import async_session_maker
        from ..services.import_service_v2 import ImportServiceV2

        async with async_session_maker() as session:
            try:
                service = ImportServiceV2(session)
                stats = await service.full_import(
                    vdm_dir=import_request.vdm_path,
                    extracted_dir=import_request.extracted_path,
                    skip_extraction=import_request.skip_extraction,
                )

                await session.execute(
                    update(SyncStatus)
                    .where(SyncStatus.id == sync_id)
                    .values(
                        status="completed",
                        completed_at=datetime.utcnow(),
                        threats_added=stats.total_lua_scripts,
                        threats_updated=stats.total_functions,
                        error_message="; ".join(stats.errors[:5]) if stats.errors else None,
                    )
                )
                await session.commit()
            except Exception:
                logger.exception("V2 import %s failed", sync_id)
                await session.execute(
                    update(SyncStatus)
                    .where(SyncStatus.id == sync_id)
                    .values(
                        status="failed",
                        completed_at=datetime.utcnow(),
                        error_message="Import failed. Check server logs for details.",
                    )
                )
                await session.commit()

    background_tasks.add_task(run_import_v2, sync_status.id)

    return {
        "status": "started",
        "sync_id": sync_status.id,
        "message": "V2 import pipeline started",
        "params": {
            "vdm_path": import_request.vdm_path or "/data/vdm",
            "extracted_path": import_request.extracted_path or "/data/extracted",
            "skip_extraction": import_request.skip_extraction,
        }
    }


@router.post("/import/v2/from-extracted")
@_limiter.limit("3/minute")
async def import_from_extracted_v2(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),

):
    """
    Import from pre-extracted Lua files (skip VDM extraction).

    Use this when defender_sig_extractor has already run and Lua files
    are available in /data/extracted/lua/
    """
    _ensure_imports_enabled()

    # Check if sync is already running
    running_query = select(SyncStatus).where(SyncStatus.status == "running")
    running = (await db.execute(running_query)).scalar()

    if running:
        raise HTTPException(status_code=409, detail="Import already in progress")

    lua_dir = Path(EXTRACTED_PATH) / "lua"
    if not lua_dir.exists():
        raise HTTPException(
            status_code=404,
            detail="Lua directory not found. Run extraction first."
        )

    # Create sync status
    sync_status = SyncStatus(
        started_at=datetime.utcnow(),
        status="running",
    )
    db.add(sync_status)
    await db.commit()
    await db.refresh(sync_status)

    async def run_import(sync_id: int):
        from ..database import async_session_maker
        from ..services.import_service_v2 import ImportServiceV2

        async with async_session_maker() as session:
            try:
                service = ImportServiceV2(session)
                stats = await service.full_import(
                    extracted_dir=EXTRACTED_PATH,
                    skip_extraction=True,
                )

                await session.execute(
                    update(SyncStatus)
                    .where(SyncStatus.id == sync_id)
                    .values(
                        status="completed",
                        completed_at=datetime.utcnow(),
                        threats_added=stats.total_lua_scripts,
                        threats_updated=stats.total_functions,
                        error_message="; ".join(stats.errors[:5]) if stats.errors else None,
                    )
                )
                await session.commit()
            except Exception:
                logger.exception("Lua import %s failed", sync_id)
                await session.execute(
                    update(SyncStatus)
                    .where(SyncStatus.id == sync_id)
                    .values(
                        status="failed",
                        completed_at=datetime.utcnow(),
                        error_message="Import failed. Check server logs for details.",
                    )
                )
                await session.commit()

    background_tasks.add_task(run_import, sync_status.id)

    return {
        "status": "started",
        "sync_id": sync_status.id,
        "message": "Importing from extracted Lua files",
    }


@router.post("/asr/resolve-functions")
@_limiter.limit("3/minute")
async def resolve_asr_functions(
    request: Request,
    db: AsyncSession = Depends(get_db),

):
    """
    Re-run ASR function resolution.

    This resolves function dependencies for all ASR rules by:
    1. Loading the function registry (Is*/Get* function definitions)
    2. Finding scripts associated with each ASR GUID
    3. Detecting function calls and merging data from the registry
    4. Updating extracted_data for each ASR rule
    """
    from ..services.asr_resolver_service import ASRResolverService

    resolver = ASRResolverService(db)
    stats = await resolver.resolve_all_asr_rules()

    return {
        "status": "completed",
        "rules_processed": stats.rules_processed,
        "rules_updated": stats.rules_updated,
        "functions_resolved": stats.functions_resolved,
        "scripts_analyzed": stats.total_scripts_analyzed,
        "errors": stats.errors[:10] if stats.errors else [],
    }


@router.get("/function-registry")
async def get_function_registry(
    db: AsyncSession = Depends(get_db),
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(100, le=500),
):
    """
    Get discovered function definitions from the registry.

    Returns functions like IsRmmToolFilePath with their data entries.
    """
    from ..models import FunctionDefinition

    query = select(FunctionDefinition)

    if category:
        query = query.where(FunctionDefinition.category == category)

    query = query.order_by(FunctionDefinition.entry_count.desc()).limit(limit)

    result = await db.execute(query)
    functions = result.scalars().all()

    return {
        "count": len(functions),
        "functions": [
            {
                "name": f.name,
                "category": f.category,
                "entry_count": f.entry_count,
                "mapped_field": f.mapped_field,
                "is_mapped": f.is_mapped == "Y",
                "source_script": f.source_script,
                "data_entries": f.data_entries[:50] if f.data_entries else [],  # Truncate for response
                "total_entries": len(f.data_entries) if f.data_entries else 0,
            }
            for f in functions
        ],
    }


@router.get("/function-registry/{func_name}")
async def get_function_details(
    func_name: str,
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific function from the registry."""
    from ..models import FunctionDefinition

    result = await db.execute(
        select(FunctionDefinition).where(FunctionDefinition.name == func_name)
    )
    func = result.scalar_one_or_none()

    if not func:
        raise HTTPException(status_code=404, detail=f"Function not found: {func_name}")

    return {
        "name": func.name,
        "category": func.category,
        "entry_count": func.entry_count,
        "mapped_field": func.mapped_field,
        "is_mapped": func.is_mapped == "Y",
        "source_script": func.source_script,
        "body": func.body[:2000] if func.body else None,
        "data_entries": func.data_entries or [],
        "created_at": func.created_at.isoformat() if func.created_at else None,
        "updated_at": func.updated_at.isoformat() if func.updated_at else None,
    }


@router.get("/function-registry/categories/list")
async def list_function_categories(
    db: AsyncSession = Depends(get_db),
):
    """List all function categories with counts."""
    from sqlalchemy import func as sqla_func

    result = await db.execute(
        select(
            FunctionDefinition.category,
            sqla_func.count(FunctionDefinition.id).label("count"),
            sqla_func.sum(FunctionDefinition.entry_count).label("total_entries"),
        )
        .group_by(FunctionDefinition.category)
        .order_by(sqla_func.count(FunctionDefinition.id).desc())
    )

    return {
        "categories": [
            {
                "category": row[0],
                "function_count": row[1],
                "total_entries": row[2] or 0,
            }
            for row in result.all()
        ]
    }
