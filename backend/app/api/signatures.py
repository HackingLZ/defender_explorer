"""Signature API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from typing import Optional
import math
import re

from ..database import get_db
from ..models import Signature, Threat
from ..schemas.signature import (
    SignatureResponse,
    SignatureDetail,
    CategoriesResponse,
    CategoryCount,
    SubcategoryCount,
    SignatureBrowseResponse,
    SignatureBrowseItem,
    SignatureSearchResponse,
    SignatureSearchItem,
)

router = APIRouter()


def _escape_like(s: str) -> str:
    """Escape SQL LIKE/ILIKE special characters."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def is_printable_string(data: bytes, threshold: float = 0.8) -> bool:
    """Check if data is mostly printable ASCII."""
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= threshold


def signature_to_yara_pattern(data: bytes) -> str:
    """Convert signature data to YARA pattern."""
    if not data:
        return ""
    if is_printable_string(data):
        try:
            s = data.decode("utf-8", errors="replace").strip("\x00")
            s = s.replace("\\", "\\\\").replace('"', '\\"')
            return f"\"{s}\""
        except Exception:
            pass
    return "{ " + " ".join(f"{b:02X}" for b in data) + " }"

# Signature types that contain readable string patterns
# These get cleaned preview with extracted strings
STRING_BASED_TYPES = {
    # URL signatures
    "URLHSTR", "URLHSTR_EXT",
    # Command line
    "CMDHSTR", "CMDHSTR_EXT",
    # PE strings (contain readable patterns)
    "PEHSTR", "PEHSTR_EXT", "PEHSTR_EXT2",
    # Script strings
    "JSHSTR", "JSHSTR_EXT",     # JavaScript
    "VBSHSTR", "VBSHSTR_EXT",   # VBScript
    "PSHSTR", "PSHSTR_EXT",     # PowerShell
    "PHPHSTR", "PHPHSTR_EXT",   # PHP
    "PYHSTR", "PYHSTR_EXT",     # Python
    "RBHSTR", "RBHSTR_EXT",     # Ruby
    # File/registry patterns
    "FILEPATH", "FILENAME", "FOLDERNAME",
    "REGKEY", "REGVAL",
    "ASEP_FILEPATH", "ASEP_FOLDERNAME",
    # Database/Archive strings
    "DBHSTR", "DBHSTR_EXT",
    "ARHSTR", "ARHSTR_EXT",
    # ELF/Macho strings
    "ELFHSTR", "ELFHSTR_EXT",
    "MACHOHSTR", "MACHOHSTR_EXT",
    # Inno/AutoIT/Macro strings
    "INNOHSTR", "INNOHSTR_EXT",
    "AUTOIT_HSTR", "AUTOIT_HSTR_EXT",
    "MACROHSTR", "MACROHSTR_EXT",
    # MSI/DEX strings
    "MSIHSTR", "MSIHSTR_EXT",
    "DEXHSTR", "DEXHSTR_EXT",
    # PDF strings
    "PDFTTHSTR", "PDFTTHSTR_EXT",
    # DOS strings
    "DOSHSTR", "DOSHSTR_EXT",
    # SWF strings
    "SWFHSTR", "SWFHSTR_EXT",
    # Java/AMSI
    "JAVAHSTR",
    "AMSI_JSCRIPT", "AMSI_POWERSHELL", "AMSI_VBS", "AMSI_GENERIC",
    # Named objects
    "MUTEX", "EVENT", "SEMAPHORE", "ATOM", "SECTION", "PIPE", "MAILSLOT", "CLSID",
}


def extract_readable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract readable ASCII strings from binary data."""
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

    return strings


def format_clean_preview(data: bytes, sig_type_name: str | None) -> str | None:
    """
    Format a human-readable preview based on signature type.

    For string-based signatures: extract and join readable strings
    For binary signatures: return None (use hex dump instead)
    """
    if not data:
        return None

    # Check if this is a string-based signature type
    is_string_type = False
    if sig_type_name:
        # Strip "SIGNATURE_TYPE_" prefix if present
        clean_name = sig_type_name.replace("SIGNATURE_TYPE_", "")
        is_string_type = clean_name in STRING_BASED_TYPES

    if is_string_type:
        # Extract readable strings and join them
        strings = extract_readable_strings(data, min_length=3)
        if strings:
            # Join with a separator, showing the actual string content
            return " | ".join(strings)
        # If no strings found, fall back to basic decode
        try:
            decoded = data.decode("ascii", errors="replace")
            # Clean up replacement characters for readability
            return decoded.replace("\ufffd", "·")
        except Exception:
            return None
    else:
        # Binary type - return None to signal frontend to show hex only
        return None


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format binary data as a hex dump with offsets and ASCII."""
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        # Offset
        offset_str = f"{offset:04x}"
        # Hex bytes
        hex_parts = [f"{b:02x}" for b in chunk]
        hex_str = " ".join(hex_parts)
        # Pad if needed
        if len(chunk) < bytes_per_line:
            hex_str += "   " * (bytes_per_line - len(chunk))
        # ASCII representation
        ascii_str = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{offset_str}  {hex_str}  {ascii_str}")
    return "\n".join(lines)


@router.get("/categories", response_model=CategoriesResponse)
async def get_signature_categories(
    db: AsyncSession = Depends(get_db),

):
    """Get all signature categories with counts."""
    # Query category counts
    category_query = (
        select(Signature.category, func.count(Signature.id).label("count"))
        .where(Signature.category.isnot(None))
        .group_by(Signature.category)
        .order_by(func.count(Signature.id).desc())
    )
    category_result = await db.execute(category_query)
    category_rows = category_result.all()

    # Query subcategory counts
    subcategory_query = (
        select(
            Signature.category,
            Signature.subcategory,
            func.count(Signature.id).label("count")
        )
        .where(
            and_(
                Signature.category.isnot(None),
                Signature.subcategory.isnot(None)
            )
        )
        .group_by(Signature.category, Signature.subcategory)
        .order_by(func.count(Signature.id).desc())
    )
    subcategory_result = await db.execute(subcategory_query)
    subcategory_rows = subcategory_result.all()

    # Build subcategory map
    subcategory_map: dict[str, list[SubcategoryCount]] = {}
    for row in subcategory_rows:
        cat = row.category
        if cat not in subcategory_map:
            subcategory_map[cat] = []
        subcategory_map[cat].append(
            SubcategoryCount(name=row.subcategory, count=row.count)
        )

    # Build response
    categories = []
    total = 0
    for row in category_rows:
        cat = row.category
        count = row.count
        total += count
        categories.append(
            CategoryCount(
                name=cat,
                count=count,
                subcategories=subcategory_map.get(cat),
            )
        )

    return CategoriesResponse(categories=categories, total=total)


@router.get("/browse", response_model=SignatureBrowseResponse)
async def browse_signatures(
    category: Optional[str] = Query(None, description="Category to filter by"),
    subcategory: Optional[str] = Query(None, description="Subcategory to filter by"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),

):
    """Browse signatures by category."""
    # Build base query
    query = (
        select(Signature)
        .options(selectinload(Signature.threat))
        .join(Threat, Signature.threat_id == Threat.id, isouter=True)
    )

    # Apply filters
    conditions = []
    if category:
        conditions.append(Signature.category == category)
    if subcategory:
        conditions.append(Signature.subcategory == subcategory)

    if conditions:
        query = query.where(and_(*conditions))

    # Count total
    count_query = select(func.count()).select_from(Signature)
    if conditions:
        count_query = count_query.where(and_(*conditions))
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    # Execute
    result = await db.execute(query)
    signatures = result.scalars().all()

    # Build items
    items = []
    for sig in signatures:
        # Generate preview
        preview = None
        if sig.data:
            preview = format_clean_preview(sig.data, sig.sig_type_name)
            if preview and len(preview) > 200:
                preview = preview[:200] + "..."

        # Get threat name
        threat_name = None
        if sig.threat:
            threat_name = sig.threat.threat_name

        items.append(
            SignatureBrowseItem(
                id=sig.id,
                sig_type_name=sig.sig_type_name,
                size=sig.size,
                preview=preview,
                threat_id=sig.threat_id,
                threat_name=threat_name,
                category=sig.category,
                subcategory=sig.subcategory,
            )
        )

    pages = math.ceil(total / page_size) if total > 0 else 1

    return SignatureBrowseResponse(
        items=items,
        total=total,
        page=page,
        pages=pages,
    )


@router.get("/search", response_model=SignatureSearchResponse)
async def search_signatures(
    q: str = Query(..., min_length=2, description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),

):
    """Search signature content."""
    # Build base query with ILIKE on extracted_text
    query = (
        select(Signature)
        .options(selectinload(Signature.threat))
        .join(Threat, Signature.threat_id == Threat.id, isouter=True)
        .where(Signature.extracted_text.ilike(f"%{_escape_like(q)}%"))
    )

    if category:
        query = query.where(Signature.category == category)

    # Count total
    count_subquery = (
        select(func.count())
        .select_from(Signature)
        .where(Signature.extracted_text.ilike(f"%{_escape_like(q)}%"))
    )
    if category:
        count_subquery = count_subquery.where(Signature.category == category)
    count_result = await db.execute(count_subquery)
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    # Execute
    result = await db.execute(query)
    signatures = result.scalars().all()

    # Build items
    items = []
    for sig in signatures:
        # Generate preview with match highlight
        preview = None
        match_highlight = None
        if sig.extracted_text:
            # Find the match position and extract surrounding context
            lower_text = sig.extracted_text.lower()
            lower_q = q.lower()
            match_pos = lower_text.find(lower_q)
            if match_pos >= 0:
                start = max(0, match_pos - 30)
                end = min(len(sig.extracted_text), match_pos + len(q) + 30)
                preview = sig.extracted_text[start:end]
                if start > 0:
                    preview = "..." + preview
                if end < len(sig.extracted_text):
                    preview = preview + "..."
                match_highlight = q

        # Get threat name
        threat_name = None
        if sig.threat:
            threat_name = sig.threat.threat_name

        items.append(
            SignatureSearchItem(
                id=sig.id,
                sig_type_name=sig.sig_type_name,
                preview=preview,
                match_highlight=match_highlight,
                threat_id=sig.threat_id,
                threat_name=threat_name,
                category=sig.category,
            )
        )

    pages = math.ceil(total / page_size) if total > 0 else 1

    return SignatureSearchResponse(
        items=items,
        total=total,
        query=q,
        page=page,
        pages=pages,
    )


@router.get("/{signature_id}", response_model=SignatureDetail)
async def get_signature(
    signature_id: int,
    db: AsyncSession = Depends(get_db),

):
    """Get signature details by ID."""
    query = (
        select(Signature, Threat)
        .join(Threat, Signature.threat_id == Threat.id, isouter=True)
        .where(Signature.id == signature_id)
    )
    result = await db.execute(query)
    row = result.first()
    signature = row[0] if row else None
    threat = row[1] if row else None

    if not signature:
        raise HTTPException(status_code=404, detail="Signature not found")

    # Prepare data preview
    data_hex = None
    data_preview = None
    hex_dump = None
    if signature.data:
        data_hex = signature.data.hex()
        # Generate clean preview based on signature type
        data_preview = format_clean_preview(signature.data, signature.sig_type_name)
        # Generate formatted hex dump
        hex_dump = format_hex_dump(signature.data)

    return SignatureDetail(
        id=signature.id,
        threat_id=signature.threat_id,
        threat_name=threat.threat_name if threat else None,
        threat_signature_id=threat.signature_id if threat else None,
        sig_type=signature.sig_type,
        sig_type_name=signature.sig_type_name,
        size=signature.size,
        data_hash=signature.data_hash,
        data_hex=data_hex,
        data_preview=data_preview,
        hex_dump=hex_dump,
    )


@router.get("/{signature_id}/download")
async def download_signature(
    signature_id: int,
    format: str = Query("hex", pattern="^(hex|raw|c)$"),
    db: AsyncSession = Depends(get_db),

):
    """Download a single signature in hex, raw, or C array format."""
    result = await db.execute(select(Signature).where(Signature.id == signature_id))
    signature = result.scalar_one_or_none()
    if not signature:
        raise HTTPException(status_code=404, detail="Signature not found")

    sig_type = signature.sig_type_name or f"UNKNOWN_0x{signature.sig_type:02X}"
    lines = [
        f"// Signature ID: {signature.id}",
        f"// Type: {sig_type}",
        f"// Size: {signature.size} bytes" if signature.size is not None else "// Size: unknown",
        "",
    ]

    if not signature.data:
        lines.append("// No signature data available")
    else:
        if format == "c":
            hex_bytes = ", ".join(f"0x{b:02X}" for b in signature.data)
            var_name = f"signature_{signature.id}"
            lines.append(f"unsigned char {var_name}[] = {{ {hex_bytes} }};")
        elif format == "hex":
            for offset in range(0, len(signature.data), 16):
                chunk = signature.data[offset:offset + 16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{offset:04X}  {hex_part:<48}  {ascii_part}")
        else:
            lines.append(signature.data.hex())

    content = "\n".join(lines)
    filename = f"signature_{signature.id}.txt"
    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{signature_id}/yara")
async def export_signature_yara(
    signature_id: int,
    db: AsyncSession = Depends(get_db),

):
    """Export a single signature as a YARA rule."""
    result = await db.execute(select(Signature).where(Signature.id == signature_id))
    signature = result.scalar_one_or_none()
    if not signature:
        raise HTTPException(status_code=404, detail="Signature not found")
    if not signature.data:
        raise HTTPException(status_code=400, detail="Signature has no data")

    rule_name = f"signature_{signature.id}"
    pattern = signature_to_yara_pattern(signature.data)

    lines = [
        f"rule {rule_name} {{",
        "    meta:",
        f'        description = "Defender signature {signature.id}"',
        f'        signature_id = "{signature.id}"',
        f'        sig_type = "{signature.sig_type_name or signature.sig_type}"',
        "",
        "    strings:",
        f"        $s1 = {pattern}",
        "",
        "    condition:",
        "        $s1",
        "}",
    ]

    content = "\n".join(lines)
    filename = f"signature_{signature.id}.yar"
    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
