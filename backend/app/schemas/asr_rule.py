"""ASR Rule schemas."""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class ExtractedPatternsResponse(BaseModel):
    """Extracted patterns from Lua scripts."""
    exclusion_paths: List[str] = []
    detection_paths: List[str] = []
    process_names: List[str] = []
    file_extensions: List[str] = []
    mitre_techniques: List[str] = []
    registry_keys: List[str] = []
    native_functions: List[str] = []
    related_asr_guids: List[str] = []
    domains: List[str] = []
    command_patterns: List[str] = []
    vulnerable_drivers: List[str] = []
    # RMM tool detection data (from IsRmmTool* functions)
    rmm_file_paths: List[str] = []
    rmm_version_info: List[str] = []
    rmm_original_filenames: List[str] = []


class ASRRuleResponse(BaseModel):
    """ASR rule response schema."""

    guid: str
    name: Optional[str]
    short_name: Optional[str]
    description: Optional[str]
    script_count: int = 0
    extracted_data: Optional[ExtractedPatternsResponse] = None

    class Config:
        from_attributes = True


class ASRRuleDetail(ASRRuleResponse):
    """Detailed ASR rule with scripts and extracted patterns."""

    scripts: List["LuaScriptSummary"] = []
    extracted_data: Optional[ExtractedPatternsResponse] = None

    class Config:
        from_attributes = True


class LuaScriptSummary(BaseModel):
    """Lua script summary for ASR detail."""

    id: int
    threat_id: Optional[int]
    threat_name: Optional[str]
    bytecode_hash: Optional[str]

    class Config:
        from_attributes = True


# Update forward reference
ASRRuleDetail.model_rebuild()
