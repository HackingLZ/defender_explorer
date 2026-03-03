"""Entity history model for tracking changes over time."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from ..database import Base


class EntityHistory(Base):
    """Track changes to entities (threats, ASR rules, signatures) over time."""

    __tablename__ = "entity_history"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(50), nullable=False)  # 'threat', 'asr_rule', 'signature'
    entity_id = Column(String(100), nullable=False)  # signature_id for threats, guid for ASR
    change_type = Column(String(20), nullable=False)  # 'created', 'updated', 'deleted'
    changed_at = Column(DateTime, default=func.now(), nullable=False)
    vdm_version_id = Column(Integer, ForeignKey("vdm_versions.id"), nullable=True)
    previous_data = Column(JSONB, default={})  # Snapshot before change
    current_data = Column(JSONB, default={})  # Snapshot after change
    diff_summary = Column(Text)  # Human-readable summary of changes

    __table_args__ = (
        Index("idx_history_entity", entity_type, entity_id),
        Index("idx_history_changed_at", changed_at),
        Index("idx_history_entity_time", entity_type, entity_id, changed_at),
    )
