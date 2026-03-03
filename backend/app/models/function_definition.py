"""Function definition model for cross-script function resolution."""

from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.sql import func
from ..database import Base


class FunctionDefinition(Base):
    """
    Stores function definitions discovered in Lua scripts.

    These are functions like IsRmmToolFilePath that contain data tables
    ({}[n] = "value" patterns) and may be called from other scripts.
    """

    __tablename__ = "function_definitions"

    id = Column(Integer, primary_key=True, index=True)

    # Function name (e.g., "IsRmmToolFilePath", "IsRmmToolVersionInfo")
    name = Column(String(255), unique=True, index=True, nullable=False)

    # Source script identifier (threat name or file path)
    source_script = Column(String(512))

    # The function body text (for reference)
    body = Column(Text)

    # Extracted data entries from the function (the {}[n] = "value" values)
    data_entries = Column(ARRAY(String), default=[])

    # Number of data entries for quick reference
    entry_count = Column(Integer, default=0)

    # Category of function for UI grouping
    # e.g., "rmm_tool", "file_extension", "process", "path", "unknown"
    category = Column(String(50), default="unknown", index=True)

    # Whether this function is mapped to a pattern field (for UI indicator)
    is_mapped = Column(String(1), default="N")  # Y/N

    # Target field in ExtractedPatterns if mapped
    # e.g., "rmm_file_paths", "file_extensions", "process_names"
    mapped_field = Column(String(100))

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # VDM version when this was discovered
    vdm_version = Column(String(50))


# Mapping of function names to their categories and target fields
FUNCTION_MAPPINGS = {
    "IsRmmToolFilePath": {
        "category": "rmm_tool",
        "mapped_field": "rmm_file_paths",
        "description": "RMM tool installation paths",
    },
    "IsRmmToolVersionInfo": {
        "category": "rmm_tool",
        "mapped_field": "rmm_version_info",
        "description": "RMM tool version identifiers",
    },
    "IsRmmToolOFN": {
        "category": "rmm_tool",
        "mapped_field": "rmm_original_filenames",
        "description": "RMM tool original filename patterns",
    },
    "IsSuspiciousFileExt": {
        "category": "file_extension",
        "mapped_field": "file_extensions",
        "description": "Suspicious file extensions",
    },
    "IsArchiveFileExt": {
        "category": "file_extension",
        "mapped_field": "file_extensions",
        "description": "Archive file extensions",
    },
    "IsExecutableFileExt": {
        "category": "file_extension",
        "mapped_field": "file_extensions",
        "description": "Executable file extensions",
    },
    "IsOfficeProcess": {
        "category": "process",
        "mapped_field": "process_names",
        "description": "Office application processes",
    },
    "IsScriptInterpreter": {
        "category": "process",
        "mapped_field": "process_names",
        "description": "Script interpreter processes",
    },
    "GetPathExclusions": {
        "category": "path",
        "mapped_field": "exclusion_paths",
        "description": "Path exclusion patterns",
    },
    "GetMonitoredLocations": {
        "category": "path",
        "mapped_field": "detection_paths",
        "description": "Monitored location patterns",
    },
}
