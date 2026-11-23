"""Lua script model."""

from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship
from ..database import Base


class LuaScript(Base):
    """Extracted and decompiled Lua script."""

    __tablename__ = "lua_scripts"

    id = Column(Integer, primary_key=True, index=True)
    signature_id = Column(Integer, ForeignKey("signatures.id", ondelete="CASCADE"), index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), index=True)
    bytecode_hash = Column(String(64), unique=True, index=True)
    bytecode = Column(LargeBinary)  # Raw bytecode for lazy decompilation
    decompiled_source = Column(Text)
    decompilation_status = Column(String(20), default="pending")  # pending, completed, failed
    decompilation_error = Column(Text)
    decompilation_attempts = Column(Integer, default=0, nullable=False)
    is_asr_script = Column(Boolean, default=False)  # Flag for ASR-related scripts
    asr_guids = Column(ARRAY(String), default=[])
    mitre_techniques = Column(ARRAY(String), default=[])

    # Relationships
    signature = relationship("Signature", back_populates="lua_script")
    threat = relationship("Threat", back_populates="lua_scripts")
