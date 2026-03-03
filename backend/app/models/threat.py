"""Threat model."""

from datetime import datetime
from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Index
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import relationship
from ..database import Base


class Threat(Base):
    """Threat definition from VDM."""

    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    signature_id = Column(BigInteger, unique=True, nullable=False, index=True)
    threat_name = Column(String(255), nullable=False)
    category = Column(String(100), index=True)
    family = Column(String(100), index=True)
    signature_count = Column(Integer, default=0)
    content_hash = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    search_vector = Column(TSVECTOR)

    # Relationships
    signatures = relationship("Signature", back_populates="threat", cascade="all, delete-orphan")
    lua_scripts = relationship("LuaScript", back_populates="threat", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_threats_search", search_vector, postgresql_using="gin"),
        Index("idx_threats_name_trgm", threat_name, postgresql_using="gin", postgresql_ops={"threat_name": "gin_trgm_ops"}),
    )

    # Known threat prefixes that may have their first character stripped
    TRUNCATED_PREFIX_MAP = {
        "rojan": "Trojan",
        "rojanDownloader": "TrojanDownloader",
        "rojanDropper": "TrojanDropper",
        "rojanSpy": "TrojanSpy",
        "rojanClicker": "TrojanClicker",
        "irus": "Virus",
        "orm": "Worm",
        "ansom": "Ransom",
        "ackdoor": "Backdoor",
        "xploit": "Exploit",
        "ackTool": "HackTool",
        "UA": "PUA",
        "ehavior": "Behavior",
        "dware": "Adware",
        "pammer": "Spammer",
        "upportScam": "SupportScam",
        "oS": "DoS",
        "irTool": "VirTool",
        "WS": "PWS",
        "hish": "Phish",
        "onitoringTool": "MonitoringTool",
        "rogram": "Program",
        "rowserModifier": "BrowserModifier",
        "isleading": "Misleading",
        "oftwareBundler": "SoftwareBundler",
        "ogue": "Rogue",
        "emoteAccess": "RemoteAccess",
        "ettingsModifier": "SettingsModifier",
        "pyware": "Spyware",
        "ulnerableDriver": "VulnerableDriver",
    }

    @staticmethod
    def fix_threat_name(name: str) -> str:
        """Fix threat names that have their first character stripped."""
        if not name:
            return name

        # Strip any leading control characters and Unicode replacement chars
        while name and (ord(name[0]) < 32 or name[0] == '\ufffd'):
            name = name[1:]

        if not name:
            return name

        # Check if the name starts with a truncated prefix
        parts = name.split(":")
        if len(parts) >= 1:
            prefix = parts[0]
            # Check against known truncated prefixes
            if prefix in Threat.TRUNCATED_PREFIX_MAP:
                fixed_prefix = Threat.TRUNCATED_PREFIX_MAP[prefix]
                return fixed_prefix + name[len(prefix):]

            # Also check if prefix without first char matches a known prefix
            for truncated, full in Threat.TRUNCATED_PREFIX_MAP.items():
                if prefix.startswith(truncated):
                    return full + prefix[len(truncated):] + name[len(prefix):]

        return name

    @staticmethod
    def parse_threat_name(name: str) -> dict:
        """Parse threat name into components."""
        # First fix the name if it has truncated prefix
        name = Threat.fix_threat_name(name)

        parts = name.split(":")
        if len(parts) >= 2:
            prefix = parts[0]
            rest = ":".join(parts[1:])

            # Extract family from the name
            name_parts = rest.split("/")
            family = name_parts[0] if name_parts else rest

            # Determine category from prefix
            category_map = {
                "Trojan": "Trojan",
                "TrojanDownloader": "TrojanDownloader",
                "TrojanDropper": "TrojanDropper",
                "TrojanSpy": "TrojanSpy",
                "TrojanClicker": "TrojanClicker",
                "Virus": "Virus",
                "Worm": "Worm",
                "Ransom": "Ransom",
                "Backdoor": "Backdoor",
                "Exploit": "Exploit",
                "HackTool": "HackTool",
                "PUA": "PUA",
                "Behavior": "Behavior",
                "Adware": "Adware",
                "Spammer": "Spammer",
                "SupportScam": "SupportScam",
                "DoS": "DoS",
                "VirTool": "VirTool",
                "PWS": "PWS",
                "Phish": "Phish",
                "MonitoringTool": "MonitoringTool",
                "Program": "Program",
                "BrowserModifier": "BrowserModifier",
                "Misleading": "Misleading",
                "SoftwareBundler": "SoftwareBundler",
                "Rogue": "Rogue",
                "RemoteAccess": "RemoteAccess",
                "SettingsModifier": "SettingsModifier",
                "Spyware": "Spyware",
                "VulnerableDriver": "VulnerableDriver",
            }
            category = category_map.get(prefix, prefix)

            return {"category": category, "family": family}

        return {"category": name, "family": "Unknown"}
