"""Signature classification service.

Maps signature types to semantic categories for browsing and
extracts searchable text for content search.
"""

import re
from typing import Optional


# Map sig_type_name -> (category, subcategory)
# Subcategory is None when determined from content
CATEGORY_MAP: dict[str, tuple[str, Optional[str]]] = {
    # PE Signatures
    "PEHSTR": ("PE/StringPatterns", None),
    "PEHSTR_EXT": ("PE/StringPatterns", None),
    "PEHSTR_EXT2": ("PE/StringPatterns", None),
    "PEBMPAT": ("PE/BinaryPatterns", None),
    "PEIMPFUZZY": ("PE/ImportHash", None),
    "PESTATIC": ("PE/Static", None),
    "PESTATICEX": ("PE/Static", None),

    # Script Signatures
    "PSHSTR": ("Script/PowerShell", None),
    "PSHSTR_EXT": ("Script/PowerShell", None),
    "JSHSTR": ("Script/JavaScript", None),
    "JSHSTR_EXT": ("Script/JavaScript", None),
    "VBSHSTR": ("Script/VBScript", None),
    "VBSHSTR_EXT": ("Script/VBScript", None),
    "PHPHSTR": ("Script/PHP", None),
    "PHPHSTR_EXT": ("Script/PHP", None),
    "PYHSTR": ("Script/Python", None),
    "PYHSTR_EXT": ("Script/Python", None),
    "RBHSTR": ("Script/Ruby", None),
    "RBHSTR_EXT": ("Script/Ruby", None),
    "MACROHSTR": ("Script/Macro", None),
    "MACROHSTR_EXT": ("Script/Macro", None),

    # AMSI (Antimalware Scan Interface) Signatures
    "AMSI_JSCRIPT": ("AMSI/JavaScript", None),
    "AMSI_POWERSHELL": ("AMSI/PowerShell", None),
    "AMSI_VBS": ("AMSI/VBScript", None),
    "AMSI_GENERIC": ("AMSI/Generic", None),

    # Persistence Signatures - subcategory derived from content
    "REGKEY": ("Persistence/Registry", None),
    "REGVAL": ("Persistence/Registry", None),
    "FILEPATH": ("Persistence/FilePath", None),
    "FILENAME": ("Persistence/FilePath", None),
    "FOLDERNAME": ("Persistence/FilePath", None),
    "ASEP_FILEPATH": ("Persistence/ASEP", None),
    "ASEP_FOLDERNAME": ("Persistence/ASEP", None),

    # Network Signatures
    "URLHSTR": ("Network/URL", None),
    "URLHSTR_EXT": ("Network/URL", None),

    # Command Signatures
    "CMDHSTR": ("Behavior/CommandLine", None),
    "CMDHSTR_EXT": ("Behavior/CommandLine", None),

    # Behavior/Lua Scripts
    "LUASCRIPT": ("Behavior/Lua", None),
    "LUASTANDALONE": ("Behavior/Lua", None),

    # Installer Signatures
    "INNOSCRIPT": ("Installer/Inno", None),
    "INNOHSTR": ("Installer/Inno", None),
    "INNOHSTR_EXT": ("Installer/Inno", None),
    "AUTOIT_HSTR": ("Installer/AutoIt", None),
    "AUTOIT_HSTR_EXT": ("Installer/AutoIt", None),
    "MSIHSTR": ("Installer/MSI", None),
    "MSIHSTR_EXT": ("Installer/MSI", None),

    # Hash Signatures
    "THREATHASH_SHA1": ("Hash/Threat", "SHA1"),
    "THREATHASH_SHA256": ("Hash/Threat", "SHA256"),
    "THREATHASH_MD5": ("Hash/Threat", "MD5"),
    "FRIENDLYHASH_SHA1": ("Hash/Friendly", "SHA1"),
    "FRIENDLYHASH_SHA256": ("Hash/Friendly", "SHA256"),
    "FRIENDLYHASH_MD5": ("Hash/Friendly", "MD5"),

    # Archive/Database Signatures
    "ARHSTR": ("Archive/Strings", None),
    "ARHSTR_EXT": ("Archive/Strings", None),
    "DBHSTR": ("Database/Strings", None),
    "DBHSTR_EXT": ("Database/Strings", None),

    # Platform-specific Signatures
    "ELFHSTR": ("ELF/Strings", None),
    "ELFHSTR_EXT": ("ELF/Strings", None),
    "MACHOHSTR": ("Macho/Strings", None),
    "MACHOHSTR_EXT": ("Macho/Strings", None),
    "DEXHSTR": ("Android/DEX", None),
    "DEXHSTR_EXT": ("Android/DEX", None),
    "SWFHSTR": ("Flash/SWF", None),
    "SWFHSTR_EXT": ("Flash/SWF", None),
    "JAVAHSTR": ("Java/Strings", None),
    "PDFTTHSTR": ("PDF/Strings", None),
    "PDFTTHSTR_EXT": ("PDF/Strings", None),
    "DOSHSTR": ("DOS/Strings", None),
    "DOSHSTR_EXT": ("DOS/Strings", None),

    # Named Objects
    "MUTEX": ("NamedObject/Mutex", None),
    "EVENT": ("NamedObject/Event", None),
    "SEMAPHORE": ("NamedObject/Semaphore", None),
    "ATOM": ("NamedObject/Atom", None),
    "SECTION": ("NamedObject/Section", None),
    "PIPE": ("NamedObject/Pipe", None),
    "MAILSLOT": ("NamedObject/Mailslot", None),
    "CLSID": ("NamedObject/CLSID", None),
}

# Registry key patterns for subcategory detection
REGISTRY_SUBCATEGORY_PATTERNS = [
    (r"CurrentVersion\\Run", "Run"),
    (r"CurrentVersion\\RunOnce", "RunOnce"),
    (r"Services\\", "Services"),
    (r"CLSID\\", "COM"),
    (r"InprocServer", "COM"),
    (r"LocalServer", "COM"),
    (r"ShellExecuteHooks", "ShellHooks"),
    (r"AppInit_DLLs", "AppInit"),
    (r"Winlogon", "Winlogon"),
    (r"Explorer\\", "Explorer"),
    (r"Policies\\", "Policies"),
    (r"CurrentControlSet\\Control", "SystemControl"),
]

# File path patterns for subcategory detection
FILEPATH_SUBCATEGORY_PATTERNS = [
    (r"\\Startup\\", "Startup"),
    (r"\\Start Menu\\", "StartMenu"),
    (r"\\Tasks\\", "ScheduledTasks"),
    (r"\\Windows\\System32\\", "System32"),
    (r"\\Windows\\SysWOW64\\", "SysWOW64"),
    (r"\\Temp\\", "Temp"),
    (r"\\AppData\\", "AppData"),
    (r"\\ProgramData\\", "ProgramData"),
]

# Signature types that contain readable strings
STRING_BASED_TYPES = {
    "URLHSTR", "URLHSTR_EXT",
    "CMDHSTR", "CMDHSTR_EXT",
    "PEHSTR", "PEHSTR_EXT", "PEHSTR_EXT2",
    "JSHSTR", "JSHSTR_EXT",
    "VBSHSTR", "VBSHSTR_EXT",
    "PSHSTR", "PSHSTR_EXT",
    "PHPHSTR", "PHPHSTR_EXT",
    "PYHSTR", "PYHSTR_EXT",
    "RBHSTR", "RBHSTR_EXT",
    "FILEPATH", "FILENAME", "FOLDERNAME",
    "REGKEY", "REGVAL",
    "ASEP_FILEPATH", "ASEP_FOLDERNAME",
    "DBHSTR", "DBHSTR_EXT",
    "ARHSTR", "ARHSTR_EXT",
    "ELFHSTR", "ELFHSTR_EXT",
    "MACHOHSTR", "MACHOHSTR_EXT",
    "INNOHSTR", "INNOHSTR_EXT",
    "AUTOIT_HSTR", "AUTOIT_HSTR_EXT",
    "MACROHSTR", "MACROHSTR_EXT",
    "MSIHSTR", "MSIHSTR_EXT",
    "DEXHSTR", "DEXHSTR_EXT",
    "PDFTTHSTR", "PDFTTHSTR_EXT",
    "DOSHSTR", "DOSHSTR_EXT",
    "SWFHSTR", "SWFHSTR_EXT",
    "JAVAHSTR",
    "AMSI_JSCRIPT", "AMSI_POWERSHELL", "AMSI_VBS", "AMSI_GENERIC",
    "MUTEX", "EVENT", "SEMAPHORE", "ATOM", "SECTION", "PIPE", "MAILSLOT", "CLSID",
}


def _clean_sig_type_name(sig_type_name: str) -> str:
    """Strip SIGNATURE_TYPE_ prefix if present."""
    return sig_type_name.replace("SIGNATURE_TYPE_", "")


def _detect_registry_subcategory(text: str) -> Optional[str]:
    """Detect subcategory from registry key content."""
    for pattern, subcategory in REGISTRY_SUBCATEGORY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return subcategory
    return None


def _detect_filepath_subcategory(text: str) -> Optional[str]:
    """Detect subcategory from file path content."""
    for pattern, subcategory in FILEPATH_SUBCATEGORY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return subcategory
    return None


def classify_signature(
    sig_type_name: str | None,
    data: bytes | None = None
) -> tuple[str, Optional[str]]:
    """
    Return (category, subcategory) for a signature.

    Args:
        sig_type_name: The signature type name (e.g., "PEHSTR", "REGKEY")
        data: Optional signature data for content-based subcategory detection

    Returns:
        Tuple of (category, subcategory). Category is always set,
        subcategory may be None.
    """
    if not sig_type_name:
        return ("Unknown", None)

    clean_name = _clean_sig_type_name(sig_type_name)

    # Look up in category map
    if clean_name in CATEGORY_MAP:
        category, subcategory = CATEGORY_MAP[clean_name]

        # Try to detect subcategory from content if not set
        if subcategory is None and data:
            text = extract_searchable_text(data, sig_type_name)
            if text:
                if category.startswith("Persistence/Registry"):
                    subcategory = _detect_registry_subcategory(text)
                elif category.startswith("Persistence/FilePath") or category.startswith("Persistence/ASEP"):
                    subcategory = _detect_filepath_subcategory(text)

        return (category, subcategory)

    # Unknown type - try to categorize by name pattern
    if "HSTR" in clean_name:
        return ("Other/Strings", None)
    if "HASH" in clean_name:
        return ("Hash/Other", None)
    if "SCRIPT" in clean_name:
        return ("Script/Other", None)

    return ("Unknown", None)


def extract_searchable_text(
    data: bytes | None,
    sig_type_name: str | None,
    min_length: int = 3
) -> str:
    """
    Extract readable strings from signature data for full-text search.

    Args:
        data: Binary signature data
        sig_type_name: The signature type name
        min_length: Minimum string length to extract

    Returns:
        Space-separated string of extracted text, or empty string if
        the signature type is not string-based or no strings found.
    """
    if not data:
        return ""

    # Check if this is a string-based signature type
    if sig_type_name:
        clean_name = _clean_sig_type_name(sig_type_name)
        if clean_name not in STRING_BASED_TYPES:
            return ""

    # Extract readable ASCII strings
    strings = []
    current = []

    for b in data:
        if 32 <= b < 127:  # Printable ASCII
            current.append(chr(b))
        else:
            if len(current) >= min_length:
                strings.append(''.join(current))
            current = []

    # Don't forget the last string
    if len(current) >= min_length:
        strings.append(''.join(current))

    return " ".join(strings)


def get_all_categories() -> list[str]:
    """Return all unique top-level categories."""
    categories = set()
    for category, _ in CATEGORY_MAP.values():
        top_level = category.split("/")[0]
        categories.add(top_level)
    return sorted(categories)


def get_category_tree() -> dict[str, list[str]]:
    """
    Return category tree structure.

    Returns:
        Dict mapping top-level category to list of subcategories.
        E.g., {"PE": ["StringPatterns", "BinaryPatterns"], ...}
    """
    tree: dict[str, set[str]] = {}

    for category, _ in CATEGORY_MAP.values():
        parts = category.split("/")
        top_level = parts[0]
        if top_level not in tree:
            tree[top_level] = set()
        if len(parts) > 1:
            tree[top_level].add(parts[1])

    # Convert sets to sorted lists
    return {k: sorted(v) for k, v in sorted(tree.items())}
