"""VDM Version, Sync Status, and App Settings models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from ..database import Base


class VDMVersion(Base):
    """VDM version tracking for delta updates."""

    __tablename__ = "vdm_versions"

    id = Column(Integer, primary_key=True, index=True)
    version_hash = Column(String(64), unique=True, index=True)
    download_timestamp = Column(DateTime, default=datetime.utcnow)
    threat_count = Column(Integer)
    signature_count = Column(Integer)
    is_current = Column(Boolean, default=False, index=True)

    # Individual VDM file hashes for incremental sync
    av_base_hash = Column(String(64))
    av_delta_hash = Column(String(64))
    as_base_hash = Column(String(64))
    as_delta_hash = Column(String(64))


class SyncStatus(Base):
    """Sync operation status tracking."""

    __tablename__ = "sync_status"

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String(20), default="running")  # running, completed, failed
    threats_added = Column(Integer, default=0)
    threats_updated = Column(Integer, default=0)
    threats_removed = Column(Integer, default=0)
    error_message = Column(Text)


class AppSetting(Base):
    """Key-value store for persistent application settings."""

    __tablename__ = "app_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)
