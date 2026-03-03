"""Signature model."""

from sqlalchemy import Column, Integer, String, LargeBinary, ForeignKey, Text
from sqlalchemy.orm import relationship
from ..database import Base


class Signature(Base):
    """Individual signature within a threat."""

    __tablename__ = "signatures"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), index=True)
    sig_type = Column(Integer, nullable=False, index=True)
    sig_type_name = Column(String(50))
    size = Column(Integer)
    data_hash = Column(String(64), index=True)
    data = Column(LargeBinary)

    # Category columns for browsing/searching
    category = Column(String(50), index=True)  # e.g., "PE/StringPatterns"
    subcategory = Column(String(100), index=True)  # e.g., "Run" (nullable)
    extracted_text = Column(Text)  # Cached strings for full-text search

    # Relationships
    threat = relationship("Threat", back_populates="signatures")
    lua_script = relationship("LuaScript", back_populates="signature", uselist=False)
