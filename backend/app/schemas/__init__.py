"""Pydantic schemas for API."""

from .threat import (
    ThreatBase,
    ThreatCreate,
    ThreatResponse,
    ThreatDetail,
    ThreatList,
)
from .signature import SignatureResponse, SignatureDetail
from .lua_script import LuaScriptResponse, LuaScriptDetail
from .asr_rule import ASRRuleResponse, ASRRuleDetail
from .common import PaginatedResponse, StatsResponse, SyncStatusResponse
from .history import (
    EntityHistoryCreate,
    EntityHistoryResponse,
    TimelineEvent,
    TimelineResponse,
)
from .similarity import (
    SignatureSimilarityResponse,
    RelatedThreat,
    RelatedThreatsResponse,
    SignatureAnalysis,
    ThreatAnalysis,
)

__all__ = [
    "ThreatBase",
    "ThreatCreate",
    "ThreatResponse",
    "ThreatDetail",
    "ThreatList",
    "SignatureResponse",
    "SignatureDetail",
    "LuaScriptResponse",
    "LuaScriptDetail",
    "ASRRuleResponse",
    "ASRRuleDetail",
    "PaginatedResponse",
    "StatsResponse",
    "SyncStatusResponse",
    # History
    "EntityHistoryCreate",
    "EntityHistoryResponse",
    "TimelineEvent",
    "TimelineResponse",
    # Similarity
    "SignatureSimilarityResponse",
    "RelatedThreat",
    "RelatedThreatsResponse",
    "SignatureAnalysis",
    "ThreatAnalysis",
]
