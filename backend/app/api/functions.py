"""Function Registry API endpoints."""

import hmac
from fastapi import APIRouter, Depends, HTTPException, Header, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from ..database import get_db
from ..models import FunctionDefinition, FUNCTION_MAPPINGS
from ..schemas.function_definition import (
    FunctionDefinitionResponse,
    FunctionDefinitionDetail,
    FunctionDefinitionSummary,
    FunctionRegistryStats,
    FunctionCategoryInfo,
)
from ..services.function_registry_service import FunctionRegistryService
from ..config import get_settings

_settings = get_settings()


async def _require_api_key(x_api_key: str = Header()):
    """Require ADMIN_API_KEY header for all function registry operations."""
    if not _settings.admin_api_key:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY not configured")
    if not hmac.compare_digest(x_api_key, _settings.admin_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")


router = APIRouter(dependencies=[Depends(_require_api_key)])


@router.get("", response_model=List[FunctionDefinitionSummary])
async def list_functions(
    category: str = Query(None, description="Filter by category"),
    mapped_only: bool = Query(False, description="Only show mapped functions"),
    unmapped_only: bool = Query(False, description="Only show unmapped functions"),
    limit: int = Query(500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List all discovered function definitions."""
    query = select(FunctionDefinition)

    if category:
        query = query.where(FunctionDefinition.category == category)
    if mapped_only:
        query = query.where(FunctionDefinition.is_mapped == "Y")
    if unmapped_only:
        query = query.where(FunctionDefinition.is_mapped == "N")

    query = query.order_by(FunctionDefinition.category, FunctionDefinition.name).limit(limit)

    result = await db.execute(query)
    functions = result.scalars().all()

    return [
        FunctionDefinitionSummary(
            id=f.id,
            name=f.name,
            category=f.category,
            entry_count=f.entry_count,
            is_mapped=f.is_mapped,
            mapped_field=f.mapped_field,
        )
        for f in functions
    ]


@router.get("/stats", response_model=FunctionRegistryStats)
async def get_function_stats(
    db: AsyncSession = Depends(get_db),

):
    """Get statistics about the function registry."""
    service = FunctionRegistryService(db)
    stats = await service.get_stats()
    return FunctionRegistryStats(**stats)


@router.get("/categories")
async def list_categories(
    db: AsyncSession = Depends(get_db),

):
    """List all function categories with their functions."""
    service = FunctionRegistryService(db)
    stats = await service.get_stats()

    categories = []
    for category, count in stats["categories"].items():
        functions = await service.get_functions_by_category(category)
        total_entries = sum(f.entry_count for f in functions)

        categories.append({
            "category": category,
            "function_count": count,
            "total_entries": total_entries,
            "functions": [
                FunctionDefinitionSummary(
                    id=f.id,
                    name=f.name,
                    category=f.category,
                    entry_count=f.entry_count,
                    is_mapped=f.is_mapped,
                    mapped_field=f.mapped_field,
                )
                for f in functions
            ],
        })

    return sorted(categories, key=lambda x: x["category"])


@router.get("/unmapped")
async def list_unmapped_functions(
    db: AsyncSession = Depends(get_db),

):
    """
    List functions that have data but are not mapped to any ExtractedPatterns field.

    These represent potential additions to the cross-script resolution logic.
    """
    service = FunctionRegistryService(db)
    functions = await service.get_unmapped_functions()

    return {
        "count": len(functions),
        "message": (
            "These functions have data tables but are not mapped to pattern fields. "
            "Consider adding mappings in FUNCTION_MAPPINGS and merge_external_function_data()."
        ),
        "functions": [
            FunctionDefinitionResponse(
                id=f.id,
                name=f.name,
                source_script=f.source_script,
                category=f.category,
                is_mapped=f.is_mapped,
                mapped_field=f.mapped_field,
                entry_count=f.entry_count,
                data_entries=f.data_entries[:20],  # Limit preview
                created_at=f.created_at,
                updated_at=f.updated_at,
                vdm_version=f.vdm_version,
            )
            for f in functions
        ],
    }


@router.get("/mappings")
async def get_function_mappings(

):
    """Get the known function mappings configuration."""
    return {
        "description": "Known function names and their target pattern fields",
        "mappings": FUNCTION_MAPPINGS,
    }


@router.get("/{name}", response_model=FunctionDefinitionDetail)
async def get_function(
    name: str,
    db: AsyncSession = Depends(get_db),

):
    """Get detailed information about a specific function."""
    service = FunctionRegistryService(db)
    func = await service.get_function(name)

    if not func:
        raise HTTPException(status_code=404, detail=f"Function '{name}' not found")

    return FunctionDefinitionDetail(
        id=func.id,
        name=func.name,
        source_script=func.source_script,
        category=func.category,
        is_mapped=func.is_mapped,
        mapped_field=func.mapped_field,
        entry_count=func.entry_count,
        data_entries=func.data_entries,
        body=func.body,
        created_at=func.created_at,
        updated_at=func.updated_at,
        vdm_version=func.vdm_version,
    )


@router.get("/{name}/data")
async def get_function_data(
    name: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),

):
    """Get the data entries from a function definition."""
    service = FunctionRegistryService(db)
    func = await service.get_function(name)

    if not func:
        raise HTTPException(status_code=404, detail=f"Function '{name}' not found")

    entries = func.data_entries or []
    total = len(entries)
    paginated = entries[offset:offset + limit]

    return {
        "function_name": name,
        "total_entries": total,
        "offset": offset,
        "limit": limit,
        "entries": paginated,
    }


@router.post("/discover")
async def discover_functions(
    db: AsyncSession = Depends(get_db),

):
    """
    Re-discover function definitions from all Lua scripts.

    This scans the extracted data directories for function definitions
    with data tables and updates the function registry.
    """
    from pathlib import Path
    from ..services.function_registry_service import discover_functions_from_directory

    extracted_path = Path("/data/extracted")
    stats = {
        "directories_scanned": 0,
        "total_files_scanned": 0,
        "total_functions_found": 0,
        "total_errors": 0,
    }

    # Scan all relevant directories
    search_dirs = [
        extracted_path / "lua",
        extracted_path / "asr",
        extracted_path / "lolbin",
    ]

    for directory in search_dirs:
        if directory.exists():
            result = await discover_functions_from_directory(db, directory)
            stats["directories_scanned"] += 1
            stats["total_files_scanned"] += result["files_scanned"]
            stats["total_functions_found"] += result["functions_found"]
            stats["total_errors"] += result["errors"]

    return {
        "message": "Function discovery completed",
        **stats,
    }


@router.delete("/clear")
async def clear_function_registry(
    db: AsyncSession = Depends(get_db),

):
    """Clear all function definitions from the registry."""
    service = FunctionRegistryService(db)
    count = await service.clear_all()
    return {
        "message": f"Cleared {count} function definitions",
        "deleted_count": count,
    }
