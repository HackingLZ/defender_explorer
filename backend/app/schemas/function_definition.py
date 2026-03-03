"""Function definition schemas."""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class FunctionDefinitionBase(BaseModel):
    """Base schema for function definition."""
    name: str
    source_script: Optional[str] = None
    category: str = "unknown"
    is_mapped: str = "N"
    mapped_field: Optional[str] = None


class FunctionDefinitionCreate(FunctionDefinitionBase):
    """Schema for creating a function definition."""
    body: Optional[str] = None
    data_entries: List[str] = []
    vdm_version: Optional[str] = None


class FunctionDefinitionResponse(FunctionDefinitionBase):
    """Schema for function definition response."""
    id: int
    entry_count: int
    data_entries: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    vdm_version: Optional[str] = None

    class Config:
        from_attributes = True


class FunctionDefinitionDetail(FunctionDefinitionResponse):
    """Detailed function definition with body."""
    body: Optional[str] = None

    class Config:
        from_attributes = True


class FunctionDefinitionSummary(BaseModel):
    """Summary of a function definition for list views."""
    id: int
    name: str
    category: str
    entry_count: int
    is_mapped: str
    mapped_field: Optional[str] = None

    class Config:
        from_attributes = True


class FunctionRegistryStats(BaseModel):
    """Statistics about the function registry."""
    total_functions: int
    mapped_functions: int
    unmapped_functions: int
    total_data_entries: int
    categories: dict  # category -> count
    functions_by_category: dict  # category -> list of function names


class FunctionCategoryInfo(BaseModel):
    """Information about a function category."""
    category: str
    function_count: int
    total_entries: int
    functions: List[FunctionDefinitionSummary]
