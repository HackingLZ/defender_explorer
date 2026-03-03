"""ASR Rule model."""

from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from ..database import Base


class ASRRule(Base):
    """Attack Surface Reduction rule."""

    __tablename__ = "asr_rules"

    guid = Column(String(36), primary_key=True)
    name = Column(String(255))
    short_name = Column(String(50))
    description = Column(Text)
    script_count = Column(Integer, default=0)

    # Extracted metadata from Lua scripts (auto-populated during import)
    extracted_data = Column(JSONB, default=dict)
    # Structure:
    # {
    #     "exclusion_paths": ["\\path\\pattern\\", ...],
    #     "detection_paths": ["\\suspicious\\path\\", ...],
    #     "process_names": ["outlook.exe", ...],
    #     "file_extensions": ["exe", "dll", ...],
    #     "mitre_techniques": ["T1021.002", ...],
    #     "registry_keys": ["HKLM\\...", ...],
    #     "native_functions": ["IsRmmToolFilePath", ...],
    #     "related_asr_guids": ["guid1", "guid2", ...],
    # }
