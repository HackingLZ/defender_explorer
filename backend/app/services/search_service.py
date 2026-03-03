"""Search service for full-text and fuzzy search."""

from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, text
from sqlalchemy.orm import selectinload

from ..models import Threat, LuaScript


def _escape_like(s: str) -> str:
    """Escape SQL LIKE/ILIKE special characters."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class SearchService:
    """Service for searching across all entity types."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def search_threats(
        self,
        query: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[Threat], int]:
        """
        Search threats by name using full-text and trigram search.

        Returns:
            Tuple of (threats, total_count)
        """
        # Use both full-text search and ILIKE for best results
        search_query = select(Threat).where(
            or_(
                Threat.threat_name.ilike(f"%{_escape_like(query)}%"),
                Threat.search_vector.match(query),
            )
        )

        # Get count
        count_query = select(func.count()).select_from(search_query.subquery())
        total = (await self.db.execute(count_query)).scalar()

        # Get results
        search_query = search_query.order_by(Threat.threat_name).offset(offset).limit(limit)
        result = await self.db.execute(search_query)
        threats = result.scalars().all()

        return threats, total

    async def search_lua_scripts(
        self,
        query: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[LuaScript], int]:
        """
        Search Lua scripts by decompiled source.

        Returns:
            Tuple of (scripts, total_count)
        """
        search_query = select(LuaScript).where(
            LuaScript.decompiled_source.ilike(f"%{_escape_like(query)}%")
        )

        # Get count
        count_query = select(func.count()).select_from(search_query.subquery())
        total = (await self.db.execute(count_query)).scalar()

        # Get results with threat info
        search_query = (
            search_query
            .options(selectinload(LuaScript.threat))
            .offset(offset)
            .limit(limit)
        )
        result = await self.db.execute(search_query)
        scripts = result.scalars().all()

        return scripts, total

    async def global_search(
        self,
        query: str,
        limit: int = 10,
    ) -> dict:
        """
        Search across all entity types.

        Returns:
            Dictionary with results from each entity type
        """
        results = {}

        # Search threats
        threats, threats_total = await self.search_threats(query, limit=limit)
        results["threats"] = {
            "items": [
                {
                    "id": t.id,
                    "signature_id": t.signature_id,
                    "threat_name": t.threat_name,
                    "category": t.category,
                }
                for t in threats
            ],
            "total": threats_total,
        }

        return results
