"""Signature similarity schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class SignatureSimilarityResponse(BaseModel):
    """Schema for similarity response."""

    signature_id: int
    similarity_score: float
    similarity_type: str
    computed_at: datetime

    class Config:
        from_attributes = True


class RelatedThreat(BaseModel):
    """Related threat with similarity information."""

    signature_id: int
    threat_name: str
    category: Optional[str]
    family: Optional[str]
    similarity_score: float
    similarity_types: List[str]
    shared_strings: List[str] = []
    matching_bytes: int = 0


class RelatedThreatsResponse(BaseModel):
    """Response containing related threats."""

    threat_id: int
    threat_name: str
    related: List[RelatedThreat]
    total: int


class SignatureAnalysis(BaseModel):
    """Detailed signature analysis with regions and magic bytes."""

    signature_id: int
    size: int
    data_hash: str
    regions: List[Dict[str, Any]] = []
    magic_bytes: List[Dict[str, Any]] = []
    strings: List[Dict[str, Any]] = []
    entropy: float = 0.0
    hex_preview: str = ""


class ThreatAnalysis(BaseModel):
    """Combined analysis for a threat."""

    threat_id: int
    signature_id: int
    threat_name: str
    signatures: List[SignatureAnalysis]
    total_size: int
    unique_strings: int
    detected_patterns: List[str] = []
