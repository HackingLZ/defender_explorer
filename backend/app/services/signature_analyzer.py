"""Signature analysis service for hex visualization and pattern detection."""

import math
import struct
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


# Magic byte signatures for common file formats
MAGIC_SIGNATURES = [
    {"signature": b"MZ", "meaning": "PE/DOS Executable", "offset": 0},
    {"signature": b"\x7FELF", "meaning": "ELF Executable", "offset": 0},
    {"signature": b"PK\x03\x04", "meaning": "ZIP Archive", "offset": 0},
    {"signature": b"PK\x05\x06", "meaning": "ZIP Archive (empty)", "offset": 0},
    {"signature": b"\x50\x4B\x07\x08", "meaning": "ZIP Archive (spanned)", "offset": 0},
    {"signature": b"\x89PNG\r\n\x1a\n", "meaning": "PNG Image", "offset": 0},
    {"signature": b"GIF87a", "meaning": "GIF Image (87a)", "offset": 0},
    {"signature": b"GIF89a", "meaning": "GIF Image (89a)", "offset": 0},
    {"signature": b"\xff\xd8\xff", "meaning": "JPEG Image", "offset": 0},
    {"signature": b"%PDF", "meaning": "PDF Document", "offset": 0},
    {"signature": b"Rar!\x1a\x07", "meaning": "RAR Archive", "offset": 0},
    {"signature": b"\x1f\x8b", "meaning": "GZIP Compressed", "offset": 0},
    {"signature": b"BZ", "meaning": "BZIP2 Compressed", "offset": 0},
    {"signature": b"\xd0\xcf\x11\xe0", "meaning": "OLE/MS Office", "offset": 0},
    {"signature": b"RIFF", "meaning": "RIFF Container (WAV/AVI)", "offset": 0},
    {"signature": b"\xca\xfe\xba\xbe", "meaning": "Java Class File", "offset": 0},
    {"signature": b"\xfe\xed\xfa\xce", "meaning": "Mach-O 32-bit", "offset": 0},
    {"signature": b"\xfe\xed\xfa\xcf", "meaning": "Mach-O 64-bit", "offset": 0},
    {"signature": b"\xcf\xfa\xed\xfe", "meaning": "Mach-O 64-bit (reversed)", "offset": 0},
    {"signature": b"SQLite format 3", "meaning": "SQLite Database", "offset": 0},
    {"signature": b"regf", "meaning": "Windows Registry Hive", "offset": 0},
    {"signature": b"<!DOCTYPE", "meaning": "HTML/XML Document", "offset": 0},
    {"signature": b"<?xml", "meaning": "XML Document", "offset": 0},
]

# Known suspicious patterns
SUSPICIOUS_PATTERNS = [
    {"pattern": b"cmd.exe", "type": "command", "description": "Command shell reference"},
    {"pattern": b"powershell", "type": "command", "description": "PowerShell reference"},
    {"pattern": b"WScript.Shell", "type": "com", "description": "WScript Shell COM object"},
    {"pattern": b"CreateObject", "type": "vbs", "description": "VBS Object creation"},
    {"pattern": b"VirtualAlloc", "type": "api", "description": "Memory allocation API"},
    {"pattern": b"VirtualProtect", "type": "api", "description": "Memory protection API"},
    {"pattern": b"WriteProcessMemory", "type": "api", "description": "Process memory write"},
    {"pattern": b"CreateRemoteThread", "type": "api", "description": "Remote thread creation"},
    {"pattern": b"NtUnmapViewOfSection", "type": "api", "description": "Section unmapping (hollowing)"},
    {"pattern": b"LoadLibrary", "type": "api", "description": "DLL loading API"},
    {"pattern": b"GetProcAddress", "type": "api", "description": "Function address resolution"},
    {"pattern": b"\\x00M\\x00Z", "type": "pe", "description": "Wide-char MZ header"},
    {"pattern": b"TVqQAAMAAAA", "type": "base64", "description": "Base64 encoded MZ header"},
    {"pattern": b"http://", "type": "url", "description": "HTTP URL"},
    {"pattern": b"https://", "type": "url", "description": "HTTPS URL"},
    {"pattern": b"\\\\\\\\", "type": "path", "description": "UNC path"},
    {"pattern": b"HKEY_", "type": "registry", "description": "Registry key reference"},
    {"pattern": b"RegOpenKey", "type": "api", "description": "Registry access API"},
    {"pattern": b"ShellExecute", "type": "api", "description": "Shell execution API"},
    {"pattern": b"WinExec", "type": "api", "description": "Windows execute API"},
    {"pattern": b"IsDebuggerPresent", "type": "evasion", "description": "Anti-debugging check"},
    {"pattern": b"NtQueryInformationProcess", "type": "evasion", "description": "Process query (anti-analysis)"},
]


@dataclass
class Region:
    """A region within the signature data."""
    type: str  # 'magic', 'string', 'pattern', 'null', 'binary'
    offset: int
    length: int
    value: str
    description: str
    color: str = "#6366f1"  # Default indigo


@dataclass
class SignatureAnalysis:
    """Complete analysis of a signature."""
    size: int
    data_hash: str
    hex_preview: str
    entropy: float
    regions: List[Dict[str, Any]] = field(default_factory=list)
    magic_bytes: List[Dict[str, Any]] = field(default_factory=list)
    strings: List[Dict[str, Any]] = field(default_factory=list)
    patterns: List[Dict[str, Any]] = field(default_factory=list)


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def detect_magic_bytes(data: bytes) -> List[Dict[str, Any]]:
    """Detect known file format magic bytes."""
    detected = []

    for magic in MAGIC_SIGNATURES:
        offset = magic["offset"]
        sig = magic["signature"]

        if len(data) >= offset + len(sig):
            if data[offset:offset + len(sig)] == sig:
                detected.append({
                    "offset": offset,
                    "signature": sig.hex(),
                    "signature_text": sig.decode('latin-1', errors='replace'),
                    "meaning": magic["meaning"],
                    "length": len(sig),
                })

    return detected


def detect_suspicious_patterns(data: bytes) -> List[Dict[str, Any]]:
    """Detect suspicious patterns in data."""
    detected = []

    for pattern_info in SUSPICIOUS_PATTERNS:
        pattern = pattern_info["pattern"]
        idx = 0
        while True:
            pos = data.find(pattern, idx)
            if pos == -1:
                break
            detected.append({
                "offset": pos,
                "pattern": pattern.decode('latin-1', errors='replace'),
                "pattern_hex": pattern.hex(),
                "type": pattern_info["type"],
                "description": pattern_info["description"],
                "length": len(pattern),
            })
            idx = pos + 1

    return detected


def extract_strings_with_context(
    data: bytes,
    min_len: int = 4,
    context_bytes: int = 16
) -> List[Dict[str, Any]]:
    """Extract readable strings with surrounding context."""
    strings = []
    current = []
    start_offset = 0

    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                start_offset = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                string_value = ''.join(current)

                # Get context
                ctx_start = max(0, start_offset - context_bytes)
                ctx_end = min(len(data), start_offset + len(current) + context_bytes)

                context_before = data[ctx_start:start_offset].hex()
                context_after = data[start_offset + len(current):ctx_end].hex()

                # Classify string
                classification = classify_string(string_value)

                strings.append({
                    "string": string_value,
                    "offset": start_offset,
                    "length": len(current),
                    "context_before": context_before,
                    "context_after": context_after,
                    "classification": classification,
                })
            current = []

    # Handle string at end of data
    if len(current) >= min_len:
        string_value = ''.join(current)
        ctx_start = max(0, start_offset - context_bytes)
        context_before = data[ctx_start:start_offset].hex()

        strings.append({
            "string": string_value,
            "offset": start_offset,
            "length": len(current),
            "context_before": context_before,
            "context_after": "",
            "classification": classify_string(string_value),
        })

    return strings


def classify_string(s: str) -> str:
    """Classify a string by its content type."""
    lower = s.lower()

    if any(ext in lower for ext in ['.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs']):
        return "executable"
    if '\\' in s or '/' in s:
        return "path"
    if any(key in lower for key in ['hkey_', 'software\\', 'system\\', 'currentversion']):
        return "registry"
    if 'http://' in lower or 'https://' in lower or 'ftp://' in lower:
        return "url"
    if '@' in s and '.' in s:
        return "email"
    if s.endswith('.com') or s.endswith('.net') or s.endswith('.org') or '.' in s and len(s.split('.')[-1]) <= 4:
        return "domain"
    if any(api in s for api in ['Alloc', 'Create', 'Write', 'Read', 'Open', 'Query', 'Get', 'Set', 'Load']):
        return "api"
    if any(cmd in lower for cmd in ['cmd', 'powershell', 'wscript', 'cscript', 'mshta']):
        return "command"

    return "string"


def identify_regions(data: bytes, strings: List[Dict], magic_bytes: List[Dict], patterns: List[Dict]) -> List[Dict[str, Any]]:
    """Identify distinct regions within the data."""
    regions = []
    used_ranges = set()

    # Add magic byte regions (blue)
    for magic in magic_bytes:
        offset = magic["offset"]
        length = magic["length"]
        for i in range(offset, offset + length):
            used_ranges.add(i)
        regions.append({
            "type": "magic",
            "offset": offset,
            "length": length,
            "value": magic["signature_text"],
            "description": magic["meaning"],
            "color": "#3b82f6",  # Blue
        })

    # Add string regions (green)
    for s in strings:
        offset = s["offset"]
        length = s["length"]
        for i in range(offset, offset + length):
            used_ranges.add(i)
        regions.append({
            "type": "string",
            "offset": offset,
            "length": length,
            "value": s["string"][:50] + ("..." if len(s["string"]) > 50 else ""),
            "description": f'{s["classification"]} string',
            "color": "#22c55e",  # Green
        })

    # Add pattern regions (yellow/orange)
    for p in patterns:
        offset = p["offset"]
        length = p["length"]
        # Don't mark if already used by string
        if not any(i in used_ranges for i in range(offset, offset + length)):
            for i in range(offset, offset + length):
                used_ranges.add(i)
            regions.append({
                "type": "pattern",
                "offset": offset,
                "length": length,
                "value": p["pattern"],
                "description": p["description"],
                "color": "#f59e0b",  # Amber
            })

    # Identify null regions
    null_start = None
    for i, b in enumerate(data):
        if b == 0 and i not in used_ranges:
            if null_start is None:
                null_start = i
        else:
            if null_start is not None and i - null_start >= 8:
                regions.append({
                    "type": "null",
                    "offset": null_start,
                    "length": i - null_start,
                    "value": "00 " * min(4, i - null_start),
                    "description": "Null padding",
                    "color": "#6b7280",  # Gray
                })
            null_start = None

    # Sort regions by offset
    regions.sort(key=lambda r: r["offset"])

    return regions


def analyze_signature(data: bytes, data_hash: str) -> Dict[str, Any]:
    """Perform complete analysis of signature data."""
    if not data:
        return {
            "size": 0,
            "data_hash": data_hash,
            "hex_preview": "",
            "entropy": 0.0,
            "regions": [],
            "magic_bytes": [],
            "strings": [],
            "patterns": [],
        }

    # Calculate entropy
    entropy = calculate_entropy(data)

    # Detect magic bytes
    magic_bytes = detect_magic_bytes(data)

    # Extract strings with context
    strings = extract_strings_with_context(data)

    # Detect suspicious patterns
    patterns = detect_suspicious_patterns(data)

    # Identify regions
    regions = identify_regions(data, strings, magic_bytes, patterns)

    # Create hex preview (first 256 bytes)
    preview_len = min(256, len(data))
    hex_preview = " ".join(f"{b:02X}" for b in data[:preview_len])
    if len(data) > preview_len:
        hex_preview += " ..."

    return {
        "size": len(data),
        "data_hash": data_hash,
        "hex_preview": hex_preview,
        "entropy": entropy,
        "regions": regions,
        "magic_bytes": magic_bytes,
        "strings": strings,
        "patterns": patterns,
    }


def generate_hex_dump(data: bytes, bytes_per_line: int = 16) -> List[Dict[str, Any]]:
    """Generate a formatted hex dump for display."""
    lines = []

    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_bytes = [{"byte": b, "hex": f"{b:02X}"} for b in chunk]

        # Pad if last line is short
        while len(hex_bytes) < bytes_per_line:
            hex_bytes.append({"byte": None, "hex": "  "})

        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

        lines.append({
            "offset": offset,
            "offset_hex": f"{offset:08X}",
            "bytes": hex_bytes,
            "ascii": ascii_repr,
        })

    return lines
