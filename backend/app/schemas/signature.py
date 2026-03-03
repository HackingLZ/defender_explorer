"""Signature schemas."""

from typing import Optional
from pydantic import BaseModel


class SignatureResponse(BaseModel):
    """Signature response schema."""

    id: int
    threat_id: Optional[int]
    sig_type: int
    sig_type_name: Optional[str]
    size: Optional[int]
    data_hash: Optional[str]

    class Config:
        from_attributes = True


class SignatureDetail(SignatureResponse):
    """Detailed signature with data."""

    threat_name: Optional[str] = None
    threat_signature_id: Optional[int] = None
    data_hex: Optional[str] = None
    data_preview: Optional[str] = None
    hex_dump: Optional[str] = None  # Formatted hex dump with offsets and ASCII

    class Config:
        from_attributes = True


# ============= Browse/Search Schemas =============


class SubcategoryCount(BaseModel):
    """Subcategory with count."""
    name: str
    count: int


class CategoryCount(BaseModel):
    """Category with count and optional subcategories."""
    name: str
    count: int
    subcategories: Optional[list[SubcategoryCount]] = None


class CategoriesResponse(BaseModel):
    """Response for GET /signatures/categories."""
    categories: list[CategoryCount]
    total: int


class SignatureBrowseItem(BaseModel):
    """Single item in browse results."""
    id: int
    sig_type_name: Optional[str]
    size: Optional[int]
    preview: Optional[str]
    threat_id: Optional[int]
    threat_name: Optional[str]
    category: Optional[str]
    subcategory: Optional[str]


class SignatureBrowseResponse(BaseModel):
    """Paginated response for GET /signatures/browse."""
    items: list[SignatureBrowseItem]
    total: int
    page: int
    pages: int


class SignatureSearchItem(BaseModel):
    """Single item in search results."""
    id: int
    sig_type_name: Optional[str]
    preview: Optional[str]
    match_highlight: Optional[str]
    threat_id: Optional[int]
    threat_name: Optional[str]
    category: Optional[str]


class SignatureSearchResponse(BaseModel):
    """Response for GET /signatures/search."""
    items: list[SignatureSearchItem]
    total: int
    query: str
    page: int
    pages: int
