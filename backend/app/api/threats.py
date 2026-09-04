"""Threat API endpoints."""

import logging
import re
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, text
from sqlalchemy.orm import selectinload

from ..database import get_db
from ..models import Threat, Signature
from ..rate_limit import client_key
from ..schemas.threat import ThreatResponse, ThreatDetail, ThreatList, SignatureSummary, LuaScriptSummary
from ..config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter()
_limiter = Limiter(key_func=client_key)
settings = get_settings()

# Some threats have millions of signatures (e.g. InfrastructureShared has 426k+).
# Loading them all via selectinload causes OOM. Cap at this many per request.
SIG_LOAD_LIMIT = 5000


async def _load_signatures_capped(
    db: AsyncSession, threat_id: int, threat_sig_count: int
) -> tuple[list, bool]:
    """Load signatures for a threat, capped at SIG_LOAD_LIMIT. Returns (sigs, truncated)."""
    result = await db.execute(
        select(Signature)
        .where(Signature.threat_id == threat_id)
        .order_by(Signature.id)
        .limit(SIG_LOAD_LIMIT)
    )
    sigs = result.scalars().all()
    return sigs, threat_sig_count > SIG_LOAD_LIMIT


def _escape_like(s: str) -> str:
    """Escape SQL LIKE/ILIKE special characters."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def is_printable_string(data: bytes, threshold: float = 0.8) -> bool:
    """Check if data is mostly printable ASCII."""
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= threshold


def classify_signature(data: bytes) -> dict:
    """Classify signature data as string or binary."""
    if not data:
        return {"type": "empty", "content": None, "is_string": False}

    # Check if it's a printable string
    if is_printable_string(data):
        try:
            decoded = data.decode('utf-8', errors='replace').strip('\x00')
            return {"type": "string", "content": decoded, "is_string": True}
        except Exception:
            pass

    # It's binary data
    return {"type": "binary", "content": data.hex(), "is_string": False}


def extract_strings_from_signature(data: bytes, min_len: int = 4) -> list[str]:
    """Extract readable strings from binary data."""
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings


def signature_to_yara_pattern(data: bytes) -> str:
    """Convert signature data to YARA hex pattern."""
    if not data:
        return ""

    # If it's a string, use string syntax
    if is_printable_string(data):
        try:
            s = data.decode('utf-8', errors='replace').strip('\x00')
            # Escape special chars for YARA string
            s = s.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{s}"'
        except Exception:
            pass

    # Use hex pattern
    return "{ " + " ".join(f"{b:02X}" for b in data) + " }"


@router.get("", response_model=ThreatList)
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    category: Optional[str] = None,
    family: Optional[str] = None,
    db: AsyncSession = Depends(get_db),

):
    """List threats with pagination and filtering."""
    query = select(Threat)

    if category:
        query = query.where(Threat.category == category)
    if family:
        query = query.where(Threat.family == family)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    # Apply pagination
    offset = (page - 1) * page_size
    query = query.order_by(Threat.threat_name).offset(offset).limit(page_size)

    result = await db.execute(query)
    threats = result.scalars().all()

    pages = (total + page_size - 1) // page_size if total else 0

    return ThreatList(
        items=[ThreatResponse.model_validate(t) for t in threats],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/search", response_model=ThreatList)
async def search_threats(
    q: str = Query(..., min_length=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),

):
    """Full-text search for threats."""
    # Use ILIKE with trigram index for fast fuzzy matching
    search_pattern = f"%{_escape_like(q)}%"

    # Also match numeric signature_id if the query looks like a number
    sig_id_filter = None
    stripped = q.strip()
    if stripped.isdigit():
        sig_id_filter = Threat.signature_id == int(stripped)
    elif stripped.lower().startswith("0x"):
        try:
            sig_id_filter = Threat.signature_id == int(stripped, 16)
        except ValueError:
            pass

    name_filter = Threat.threat_name.ilike(search_pattern)
    where_clause = or_(name_filter, sig_id_filter) if sig_id_filter is not None else name_filter

    # Get results first (fast with GIN index)
    offset = (page - 1) * page_size
    query = (
        select(Threat)
        .where(where_clause)
        .order_by(Threat.threat_name)
        .offset(offset)
        .limit(page_size)
    )

    result = await db.execute(query)
    threats = result.scalars().all()

    # Only count if we need pagination info (skip on first page with few results)
    if len(threats) < page_size and page == 1:
        total = len(threats)
    else:
        # Use faster count with same index
        count_query = select(func.count(Threat.id)).where(where_clause)
        total = (await db.execute(count_query)).scalar()

    pages = (total + page_size - 1) // page_size if total else 0

    return ThreatList(
        items=[ThreatResponse.model_validate(t) for t in threats],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{sig_id}", response_model=ThreatDetail)
async def get_threat(
    sig_id: int,
    db: AsyncSession = Depends(get_db),

):
    """Get threat details by signature ID."""
    query = (
        select(Threat)
        .options(selectinload(Threat.lua_scripts))
        .where(Threat.signature_id == sig_id)
    )

    result = await db.execute(query)
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    signatures, _ = await _load_signatures_capped(db, threat.id, threat.signature_count)

    # Build signature type counts
    sig_types = {}
    for sig in signatures:
        type_name = sig.sig_type_name or f"UNKNOWN_0x{sig.sig_type:02X}"
        sig_types[type_name] = sig_types.get(type_name, 0) + 1

    # Build response
    response = ThreatDetail(
        id=threat.id,
        signature_id=threat.signature_id,
        threat_name=threat.threat_name,
        category=threat.category,
        family=threat.family,
        signature_count=threat.signature_count,
        created_at=threat.created_at,
        updated_at=threat.updated_at,
        signatures=[
            SignatureSummary(
                id=s.id,
                sig_type=s.sig_type,
                sig_type_name=s.sig_type_name,
                size=s.size,
            )
            for s in signatures
        ],
        lua_scripts=[
            LuaScriptSummary(
                id=ls.id,
                bytecode_hash=ls.bytecode_hash,
                asr_guids=ls.asr_guids or [],
                has_source=ls.decompiled_source is not None,
            )
            for ls in threat.lua_scripts
        ],
        signature_types=sig_types,
    )

    return response


@router.get("/categories/list")
async def list_categories(db: AsyncSession = Depends(get_db)):
    """List top categories by count."""
    query = (
        select(Threat.category, func.count(Threat.id))
        .where(Threat.category.isnot(None))
        .group_by(Threat.category)
        .order_by(func.count(Threat.id).desc())
        .limit(50)  # Only return top 50 categories
    )

    result = await db.execute(query)
    categories = result.all()

    return [{"category": c, "count": count} for c, count in categories]


@router.get("/families/list")
async def list_families(
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db),

):
    """List all unique families."""
    query = select(Threat.family, func.count(Threat.id)).where(
        Threat.family.isnot(None)
    )

    if category:
        query = query.where(Threat.category == category)

    query = query.group_by(Threat.family).order_by(func.count(Threat.id).desc()).limit(100)

    result = await db.execute(query)
    families = result.all()

    return [{"family": f, "count": count} for f, count in families]


@router.get("/{sig_id}/signatures/download")
async def download_signatures(
    sig_id: int,
    format: str = Query("hex", pattern="^(hex|raw|c)$"),
    db: AsyncSession = Depends(get_db),

):
    """Download all signatures for a threat."""
    result = await db.execute(
        select(Threat).where(Threat.signature_id == sig_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    signatures, truncated = await _load_signatures_capped(db, threat.id, threat.signature_count)

    # Build output based on format
    lines = []
    lines.append(f"// Threat: {threat.threat_name}")
    lines.append(f"// Signature ID: 0x{threat.signature_id:08X}")
    lines.append(f"// Total signatures: {threat.signature_count}")
    if truncated:
        lines.append(f"// WARNING: Output truncated to first {SIG_LOAD_LIMIT} signatures")
    lines.append("")

    for i, sig in enumerate(signatures):
        classification = classify_signature(sig.data)
        sig_type = sig.sig_type_name or f"UNKNOWN_0x{sig.sig_type:02X}"

        lines.append(f"// Signature {i+1}: {sig_type} ({sig.size} bytes)")
        lines.append(f"// Classification: {classification['type']}")

        if sig.data:
            if format == "c":
                # C array format
                hex_bytes = ", ".join(f"0x{b:02X}" for b in sig.data)
                var_name = f"sig_{i+1}_{sig_type.lower().replace(' ', '_')}"
                lines.append(f"unsigned char {var_name}[] = {{ {hex_bytes} }};")
            elif format == "hex":
                # Hex dump format
                for offset in range(0, len(sig.data), 16):
                    chunk = sig.data[offset:offset+16]
                    hex_part = " ".join(f"{b:02X}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    lines.append(f"{offset:04X}  {hex_part:<48}  {ascii_part}")
            else:  # raw
                lines.append(sig.data.hex())

            # Show extracted strings if binary
            if classification['type'] == 'binary':
                strings = extract_strings_from_signature(sig.data)
                if strings:
                    lines.append(f"// Extracted strings: {strings}")

        lines.append("")

    content = "\n".join(lines)
    # Sanitize filename - remove control characters and invalid chars
    import re
    safe_name = re.sub(r'[^\w\s\-\.]', '', threat.threat_name.replace('/', '_').replace(':', '_'))
    safe_name = safe_name.strip() or f"threat_{threat.signature_id}"
    filename = f"{safe_name}_signatures.txt"

    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/{sig_id}/signatures/yara")
async def export_yara(
    sig_id: int,
    db: AsyncSession = Depends(get_db),

):
    """Export signatures as YARA rule."""
    result = await db.execute(
        select(Threat).where(Threat.signature_id == sig_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    signatures, truncated = await _load_signatures_capped(db, threat.id, threat.signature_count)

    # Create a safe rule name
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', threat.threat_name)
    if rule_name[0].isdigit():
        rule_name = '_' + rule_name

    lines = []
    lines.append(f"rule {rule_name} {{")
    lines.append("    meta:")
    lines.append(f'        description = "Defender signature for {threat.threat_name}"')
    lines.append(f'        signature_id = "0x{threat.signature_id:08X}"')
    lines.append(f"        signature_count = {threat.signature_count}")
    if truncated:
        lines.append(f"        truncated = true  // Only first {SIG_LOAD_LIMIT} of {threat.signature_count} signatures included")
    lines.append("")
    lines.append("    strings:")

    string_sigs = []
    binary_sigs = []

    for i, sig in enumerate(signatures):
        if not sig.data:
            continue

        classification = classify_signature(sig.data)
        pattern = signature_to_yara_pattern(sig.data)

        if classification['is_string']:
            string_sigs.append((i, sig, pattern))
        else:
            binary_sigs.append((i, sig, pattern))

    # Add string signatures first
    for i, sig, pattern in string_sigs:
        sig_type = sig.sig_type_name or f"type_{sig.sig_type}"
        var_name = f"$str_{i}_{sig_type.lower().replace(' ', '_').replace('-', '_')}"
        lines.append(f"        {var_name} = {pattern} nocase")

    # Add binary signatures
    for i, sig, pattern in binary_sigs:
        sig_type = sig.sig_type_name or f"type_{sig.sig_type}"
        var_name = f"$bin_{i}_{sig_type.lower().replace(' ', '_').replace('-', '_')}"
        lines.append(f"        {var_name} = {pattern}")

    lines.append("")
    lines.append("    condition:")

    total_sigs = len(string_sigs) + len(binary_sigs)
    if total_sigs > 0:
        # Require any of the signatures to match
        lines.append("        any of them")
    else:
        lines.append("        false")

    lines.append("}")

    content = "\n".join(lines)
    filename = f"{rule_name}.yar"

    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/{sig_id}/signatures/classified")
async def get_classified_signatures(
    sig_id: int,
    db: AsyncSession = Depends(get_db),

):
    """Get signatures classified as strings vs binary."""
    result = await db.execute(
        select(Threat).where(Threat.signature_id == sig_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    signatures, truncated = await _load_signatures_capped(db, threat.id, threat.signature_count)

    string_sigs = []
    binary_sigs = []

    for sig in signatures:
        classification = classify_signature(sig.data)
        sig_info = {
            "id": sig.id,
            "sig_type": sig.sig_type,
            "sig_type_name": sig.sig_type_name,
            "size": sig.size,
            "classification": classification['type'],
            "is_string": classification['is_string'],
        }

        if classification['is_string']:
            sig_info["content"] = classification['content']
            string_sigs.append(sig_info)
        else:
            sig_info["extracted_strings"] = extract_strings_from_signature(sig.data) if sig.data else []
            binary_sigs.append(sig_info)

    return {
        "threat_name": threat.threat_name,
        "signature_id": threat.signature_id,
        "total": threat.signature_count,
        "truncated": truncated,
        "truncated_at": SIG_LOAD_LIMIT if truncated else None,
        "string_signatures": string_sigs,
        "binary_signatures": binary_sigs,
        "string_count": len(string_sigs),
        "binary_count": len(binary_sigs),
    }


@router.get("/{sig_id}/analysis")
@_limiter.limit("5/minute")
async def get_threat_analysis(
    request: Request,
    sig_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Get detailed signature analysis with hex regions and pattern detection."""
    from ..services.signature_analyzer import analyze_signature, generate_hex_dump

    result = await db.execute(
        select(Threat).where(Threat.signature_id == sig_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    signatures, _ = await _load_signatures_capped(db, threat.id, threat.signature_count)

    signatures_analysis = []
    total_size = 0
    all_strings = set()

    for sig in signatures:
        if sig.data:
            analysis = analyze_signature(sig.data, sig.data_hash or "")
            analysis["signature_id"] = sig.id
            analysis["sig_type"] = sig.sig_type
            analysis["sig_type_name"] = sig.sig_type_name

            # Add hex dump for smaller signatures
            if len(sig.data) <= 4096:
                analysis["hex_dump"] = generate_hex_dump(sig.data)

            signatures_analysis.append(analysis)
            total_size += sig.size or 0

            # Collect unique strings
            for s in analysis.get("strings", []):
                all_strings.add(s["string"])

    return {
        "threat_id": threat.id,
        "signature_id": threat.signature_id,
        "threat_name": threat.threat_name,
        "category": threat.category,
        "family": threat.family,
        "signatures": signatures_analysis,
        "total_size": total_size,
        "unique_strings": len(all_strings),
        "detected_patterns": list(set(
            p["description"]
            for sig in signatures_analysis
            for p in sig.get("patterns", [])
        )),
    }


@router.get("/{sig_id}/related")
@_limiter.limit("5/minute")
async def get_related_threats(
    request: Request,
    sig_id: int,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Get threats related by signature similarity."""
    from ..services.similarity_service import compute_similarity

    # Get the threat
    query = select(Threat).where(Threat.signature_id == sig_id)
    result = await db.execute(query)
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Compute similarity
    related = await compute_similarity(db, threat.id, limit=limit)

    return {
        "threat_id": threat.id,
        "signature_id": threat.signature_id,
        "threat_name": threat.threat_name,
        "related": related,
        "total": len(related),
    }


@router.get("/{sig_id}/timeline")
async def get_threat_timeline(
    sig_id: int,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),

):
    """Get timeline of changes for a threat."""
    from ..services.history_service import get_entity_timeline

    # Verify threat exists
    query = select(Threat).where(Threat.signature_id == sig_id)
    result = await db.execute(query)
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    timeline = await get_entity_timeline(db, "threat", str(sig_id), limit=limit)

    # Add current state info if no history yet
    if not timeline["events"]:
        timeline["events"] = [{
            "date": threat.created_at.isoformat() if threat.created_at else None,
            "type": "created",
            "vdm_version": None,
            "changes": ["Initial import"],
            "details": None,
        }]
        timeline["message"] = "Timeline tracking starts from this point forward"

    return timeline


@router.get("/{sig_id}/report")
async def get_threat_report(
    sig_id: int,
    format: str = Query("html", pattern="^(html|pdf)$"),
    db: AsyncSession = Depends(get_db),

):
    """Generate a detailed report for a threat."""
    from ..services.report_service import generate_threat_report_html, generate_pdf_from_html

    # Get threat with lua_scripts (small), signatures loaded separately with cap
    query = (
        select(Threat)
        .options(selectinload(Threat.lua_scripts))
        .where(Threat.signature_id == sig_id)
    )
    result = await db.execute(query)
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    signatures, _ = await _load_signatures_capped(db, threat.id, threat.signature_count)

    # Build threat data
    sig_types = {}
    for sig in signatures:
        type_name = sig.sig_type_name or f"UNKNOWN_0x{sig.sig_type:02X}"
        sig_types[type_name] = sig_types.get(type_name, 0) + 1

    threat_data = {
        "signature_id": threat.signature_id,
        "threat_name": threat.threat_name,
        "category": threat.category,
        "family": threat.family,
        "signature_count": threat.signature_count,
        "signature_types": sig_types,
        "lua_scripts": [{"id": ls.id} for ls in threat.lua_scripts],
    }

    # Get classified signatures
    string_sigs = []
    binary_sigs = []
    for sig in signatures:
        classification = classify_signature(sig.data)
        sig_info = {
            "sig_type_name": sig.sig_type_name,
            "is_string": classification['is_string'],
        }
        if classification['is_string']:
            sig_info["content"] = classification['content']
            string_sigs.append(sig_info)
        else:
            binary_sigs.append(sig_info)

    signatures_data = {
        "string_signatures": string_sigs,
        "binary_signatures": binary_sigs,
        "string_count": len(string_sigs),
        "binary_count": len(binary_sigs),
    }

    # Generate YARA rule
    yara_rule = None
    try:
        # Use the existing YARA generation logic
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', threat.threat_name)
        if rule_name[0].isdigit():
            rule_name = '_' + rule_name

        lines = []
        lines.append(f"rule {rule_name} {{")
        lines.append("    meta:")
        lines.append(f'        description = "Defender signature for {threat.threat_name}"')
        lines.append(f'        signature_id = "0x{threat.signature_id:08X}"')
        lines.append("")
        lines.append("    strings:")

        for i, sig in enumerate(string_sigs[:20]):
            content = sig.get("content", "")
            if content:
                escaped = content.replace('\\', '\\\\').replace('"', '\\"')
                lines.append(f'        $str_{i} = "{escaped}" nocase')

        lines.append("")
        lines.append("    condition:")
        lines.append("        any of them")
        lines.append("}")
        yara_rule = "\n".join(lines)
    except Exception:
        pass

    # Generate report
    html = generate_threat_report_html(threat_data, signatures_data, yara_rule)

    if format == "pdf":
        try:
            pdf_content = generate_pdf_from_html(html)
        except RuntimeError:
            logger.exception("PDF generation failed for threat %s", sig_id)
            raise HTTPException(status_code=501, detail="PDF generation is not available")
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="threat_{sig_id}_report.pdf"'}
        )

    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="threat_{sig_id}_report.html"'}
    )
