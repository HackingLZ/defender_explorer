"""Threat schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class ThreatBase(BaseModel):
    """Base threat schema."""

    signature_id: int
    threat_name: str
    category: Optional[str] = None
    family: Optional[str] = None


class ThreatCreate(ThreatBase):
    """Schema for creating a threat."""

    signature_count: int = 0
    content_hash: Optional[str] = None


class ThreatResponse(ThreatBase):
    """Schema for threat response."""

    id: int
    signature_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SignatureSummary(BaseModel):
    """Summary of a signature for threat detail."""

    id: int
    sig_type: int
    sig_type_name: Optional[str]
    size: Optional[int]

    class Config:
        from_attributes = True


class LuaScriptSummary(BaseModel):
    """Summary of a Lua script for threat detail."""

    id: int
    bytecode_hash: Optional[str]
    asr_guids: List[str] = []
    has_source: bool = False

    class Config:
        from_attributes = True


class ThreatDetail(ThreatResponse):
    """Detailed threat response with signatures."""

    signatures: List[SignatureSummary] = []
    lua_scripts: List[LuaScriptSummary] = []
    signature_types: Dict[str, int] = {}

    class Config:
        from_attributes = True


class ThreatList(BaseModel):
    """Paginated list of threats."""

    items: List[ThreatResponse]
    total: int
    page: int
    page_size: int
    pages: int
