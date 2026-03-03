"""Lua script schemas."""

from typing import Optional, List
from pydantic import BaseModel


class LuaScriptResponse(BaseModel):
    """Lua script response schema."""

    id: int
    signature_id: Optional[int]
    threat_id: Optional[int]
    bytecode_hash: Optional[str]
    asr_guids: List[str] = []
    mitre_techniques: List[str] = []
    has_source: bool = False
    decompilation_status: str = "pending"  # pending, completed, failed
    is_asr_script: bool = False

    class Config:
        from_attributes = True


class LuaScriptDetail(LuaScriptResponse):
    """Detailed Lua script with source."""

    decompiled_source: Optional[str] = None
    threat_name: Optional[str] = None

    class Config:
        from_attributes = True
