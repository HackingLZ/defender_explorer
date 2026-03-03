"""Common schemas."""

from datetime import datetime
from typing import Generic, TypeVar, List, Optional
from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    items: List[T]
    total: int
    page: int
    page_size: int
    pages: int


class StatsResponse(BaseModel):
    """Database statistics response."""

    threat_count: int
    signature_count: int
    lua_script_count: int
    asr_rule_count: int
    last_sync: Optional[datetime] = None


class SyncStatusResponse(BaseModel):
    """Sync operation status."""

    id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    threats_added: int
    threats_updated: int
    threats_removed: int
    error_message: Optional[str] = None

    class Config:
        from_attributes = True
