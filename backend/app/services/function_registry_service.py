"""
Function Registry Service

Manages function definitions discovered in Lua scripts.
Provides cross-script function resolution for ASR rules.
"""

import re
import logging
from typing import Dict, List, Optional, Set
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import select, func, delete

from ..models import FunctionDefinition, FUNCTION_MAPPINGS
from ..database import async_session_maker

logger = logging.getLogger(__name__)

# Pattern to match function definitions: FuncName = function(...)...end
FUNCTION_DEFINITION_PATTERN = re.compile(
    r'((?:Is|Get)[A-Za-z]+)\s*=\s*function\s*\([^)]*\)(.*?)(?:\nend|\bend\b)',
    re.DOTALL
)

# Pattern to extract data entries from function bodies: {}[n] = "value"
DATA_ENTRY_PATTERN = re.compile(r'\{\}\[\d+\]\s*=\s*"([^"]+)"')


class FunctionRegistryService:
    """
    Service for managing function definitions in the database.

    This replaces the in-memory FunctionRegistry for persistence.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def discover_from_source(
        self,
        source: str,
        script_id: str,
        vdm_version: Optional[str] = None
    ) -> int:
        """
        Discover and register function definitions from decompiled Lua source.

        Args:
            source: Decompiled Lua source code
            script_id: Identifier for the source script
            vdm_version: Optional VDM version string

        Returns:
            Number of functions discovered/updated
        """
        if not source:
            return 0

        count = 0
        for match in FUNCTION_DEFINITION_PATTERN.finditer(source):
            func_name = match.group(1)
            func_body = match.group(2)

            # Extract data entries
            data_entries = [m.group(1) for m in DATA_ENTRY_PATTERN.finditer(func_body)]

            # Only register functions with data entries
            if not data_entries:
                continue

            # Determine category and mapping
            mapping = FUNCTION_MAPPINGS.get(func_name, {})
            category = mapping.get("category", "unknown")
            mapped_field = mapping.get("mapped_field")
            is_mapped = "Y" if mapped_field else "N"

            # Upsert function definition
            stmt = insert(FunctionDefinition).values(
                name=func_name,
                source_script=script_id,
                body=func_body[:50000],  # Limit body size
                data_entries=data_entries,
                entry_count=len(data_entries),
                category=category,
                is_mapped=is_mapped,
                mapped_field=mapped_field,
                vdm_version=vdm_version,
            ).on_conflict_do_update(
                index_elements=["name"],
                set_={
                    "source_script": script_id,
                    "body": func_body[:50000],
                    "data_entries": data_entries,
                    "entry_count": len(data_entries),
                    "category": category,
                    "is_mapped": is_mapped,
                    "mapped_field": mapped_field,
                    "vdm_version": vdm_version,
                }
            )
            await self.db.execute(stmt)
            count += 1

            logger.debug(
                f"Registered function {func_name} ({category}) "
                f"with {len(data_entries)} entries from {script_id}"
            )

        return count

    async def get_function(self, name: str) -> Optional[FunctionDefinition]:
        """Get a function definition by name."""
        query = select(FunctionDefinition).where(FunctionDefinition.name == name)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_all_functions(self) -> List[FunctionDefinition]:
        """Get all function definitions."""
        query = select(FunctionDefinition).order_by(FunctionDefinition.category, FunctionDefinition.name)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def get_functions_by_category(self, category: str) -> List[FunctionDefinition]:
        """Get all functions in a category."""
        query = select(FunctionDefinition).where(
            FunctionDefinition.category == category
        ).order_by(FunctionDefinition.name)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def get_unmapped_functions(self) -> List[FunctionDefinition]:
        """Get all functions that are not mapped to a pattern field."""
        query = select(FunctionDefinition).where(
            FunctionDefinition.is_mapped == "N"
        ).order_by(FunctionDefinition.name)
        result = await self.db.execute(query)
        return result.scalars().all()

    async def get_function_data(self, name: str) -> List[str]:
        """Get data entries for a specific function."""
        func = await self.get_function(name)
        return func.data_entries if func else []

    async def get_stats(self) -> Dict:
        """Get statistics about the function registry."""
        # Total functions
        total_query = select(func.count(FunctionDefinition.id))
        total_result = await self.db.execute(total_query)
        total = total_result.scalar() or 0

        # Mapped vs unmapped
        mapped_query = select(func.count(FunctionDefinition.id)).where(
            FunctionDefinition.is_mapped == "Y"
        )
        mapped_result = await self.db.execute(mapped_query)
        mapped = mapped_result.scalar() or 0

        # Total data entries
        entries_query = select(func.sum(FunctionDefinition.entry_count))
        entries_result = await self.db.execute(entries_query)
        total_entries = entries_result.scalar() or 0

        # Category breakdown
        category_query = select(
            FunctionDefinition.category,
            func.count(FunctionDefinition.id)
        ).group_by(FunctionDefinition.category)
        category_result = await self.db.execute(category_query)
        categories = {row[0]: row[1] for row in category_result.all()}

        # Functions by category
        functions_by_category = {}
        for category in categories.keys():
            funcs = await self.get_functions_by_category(category)
            functions_by_category[category] = [f.name for f in funcs]

        return {
            "total_functions": total,
            "mapped_functions": mapped,
            "unmapped_functions": total - mapped,
            "total_data_entries": total_entries,
            "categories": categories,
            "functions_by_category": functions_by_category,
        }

    async def clear_all(self) -> int:
        """Clear all function definitions. Returns count of deleted records."""
        count_query = select(func.count(FunctionDefinition.id))
        count_result = await self.db.execute(count_query)
        count = count_result.scalar() or 0

        await self.db.execute(delete(FunctionDefinition))
        await self.db.commit()
        return count


async def discover_functions_from_directory(
    db: AsyncSession,
    directory: Path,
    vdm_version: Optional[str] = None
) -> Dict[str, int]:
    """
    Discover function definitions from all Lua files in a directory.

    Args:
        db: Database session
        directory: Directory to scan
        vdm_version: Optional VDM version string

    Returns:
        Dictionary with discovery statistics
    """
    service = FunctionRegistryService(db)
    stats = {
        "files_scanned": 0,
        "functions_found": 0,
        "errors": 0,
    }

    if not directory.exists():
        return stats

    for lua_file in directory.rglob("*.lua"):
        try:
            content = lua_file.read_text(errors="replace")
            content = content.replace('\x00', '').replace('\x13', '').replace('\x0f', '')

            found = await service.discover_from_source(
                content,
                str(lua_file.relative_to(directory)),
                vdm_version
            )

            stats["files_scanned"] += 1
            stats["functions_found"] += found

        except Exception as e:
            logger.debug(f"Error processing {lua_file}: {e}")
            stats["errors"] += 1

    await db.commit()
    return stats


async def get_function_registry_service() -> FunctionRegistryService:
    """Get a FunctionRegistryService instance with a new session."""
    async with async_session_maker() as db:
        yield FunctionRegistryService(db)
