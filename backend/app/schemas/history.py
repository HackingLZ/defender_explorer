"""History schemas for entity timeline tracking."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class EntityHistoryBase(BaseModel):
    """Base history schema."""

    entity_type: str
    entity_id: str
    change_type: str


class EntityHistoryCreate(EntityHistoryBase):
    """Schema for creating a history entry."""

    vdm_version_id: Optional[int] = None
    previous_data: Dict[str, Any] = {}
    current_data: Dict[str, Any] = {}
    diff_summary: Optional[str] = None


class EntityHistoryResponse(EntityHistoryBase):
    """Schema for history response."""

    id: int
    changed_at: datetime
    vdm_version_id: Optional[int]
    previous_data: Dict[str, Any]
    current_data: Dict[str, Any]
    diff_summary: Optional[str]

    class Config:
        from_attributes = True


class TimelineEvent(BaseModel):
    """Simplified timeline event for UI display."""

    date: datetime
    type: str  # 'created', 'updated', 'deleted'
    vdm_version: Optional[str] = None
    changes: List[str] = []
    details: Optional[Dict[str, Any]] = None


class TimelineResponse(BaseModel):
    """Timeline response with list of events."""

    entity_type: str
    entity_id: str
    events: List[TimelineEvent]
    total_events: int
