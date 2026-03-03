"""YARA rule building API endpoints."""

import asyncio
import hmac
import multiprocessing
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Form, Header, Request
from pydantic import BaseModel
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..config import get_settings
from ..models import Threat, Signature
from ..rate_limit import client_key
from ..services.yara_service import get_available_rules

router = APIRouter()
_limiter = Limiter(key_func=client_key)
_settings = get_settings()


async def _require_api_key(x_api_key: str = Header()):
    """Require ADMIN_API_KEY for write operations."""
    if not _settings.admin_api_key:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY not configured")
    if not hmac.compare_digest(x_api_key, _settings.admin_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")


@router.get("/threat/{threat_id}/rule", dependencies=[Depends(_require_api_key)])
async def get_yara_rule_for_threat(
    threat_id: int,
    db: AsyncSession = Depends(get_db),

):
    """
    Generate a YARA rule for a threat without testing it.

    Args:
        threat_id: The threat signature_id

    Returns:
        Generated YARA rule content
    """
    import re

    result = await db.execute(
        select(Threat).where(Threat.signature_id == threat_id)
    )
    threat = result.scalar_one_or_none()

    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # Only fetch the 30 signatures we'll actually use
    sigs_result = await db.execute(
        select(Signature)
        .where(Signature.threat_id == threat.id)
        .order_by(Signature.id)
        .limit(30)
    )
    threat_sigs = sigs_result.scalars().all()

    # Generate YARA rule
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', threat.threat_name)
    if rule_name[0].isdigit():
        rule_name = '_' + rule_name

    lines = []
    lines.append(f"rule {rule_name} {{")
    lines.append("    meta:")
    lines.append(f'        description = "Detection for {threat.threat_name}"')
    lines.append(f'        signature_id = "0x{threat.signature_id:08X}"')
    if threat.category:
        lines.append(f'        category = "{threat.category}"')
    if threat.family:
        lines.append(f'        family = "{threat.family}"')
    lines.append("")
    lines.append("    strings:")

    string_count = 0
    for i, sig in enumerate(threat_sigs):
        if not sig.data:
            continue

        # Check if string or binary
        is_string = all(32 <= b < 127 or b in (9, 10, 13) for b in sig.data)

        if is_string:
            try:
                s = sig.data.decode('utf-8', errors='replace').strip('\x00')
                if len(s) < 4:  # Skip very short strings
                    continue
                s = s.replace('\\', '\\\\').replace('"', '\\"')
                sig_name = sig.sig_type_name or f"sig_{i}"
                sig_name = re.sub(r'[^a-zA-Z0-9_]', '_', sig_name).lower()
                lines.append(f'        $str_{string_count}_{sig_name} = "{s}" nocase')
                string_count += 1
            except Exception:
                hex_pattern = " ".join(f"{b:02X}" for b in sig.data[:64])
                if len(sig.data) > 64:
                    hex_pattern += " // truncated"
                lines.append(f"        $bin_{string_count} = {{ {hex_pattern} }}")
                string_count += 1
        else:
            hex_pattern = " ".join(f"{b:02X}" for b in sig.data[:64])
            if len(sig.data) > 64:
                hex_pattern += " // truncated"
            sig_name = sig.sig_type_name or f"sig_{i}"
            sig_name = re.sub(r'[^a-zA-Z0-9_]', '_', sig_name).lower()
            lines.append(f"        $bin_{string_count}_{sig_name} = {{ {hex_pattern} }}")
            string_count += 1

    if string_count == 0:
        lines.append('        $empty = "NO_SIGNATURES_FOUND"')

    lines.append("")
    lines.append("    condition:")
    lines.append("        any of them")
    lines.append("}")
    yara_rule = "\n".join(lines)

    return {
        "threat_id": threat.signature_id,
        "threat_name": threat.threat_name,
        "rule_content": yara_rule,
        "signature_count": string_count,
    }


class BuildCombinedRequest(BaseModel):
    threat_ids: list[int]
    rule_name: str = "combined_detection"


@router.post("/build")
async def build_combined_yara_rule(
    request: BuildCombinedRequest,
    db: AsyncSession = Depends(get_db),

):
    """
    Generate a combined YARA rule from multiple threats.

    Args:
        threat_ids: List of threat signature_ids to combine
        rule_name: Name for the combined rule

    Returns:
        Combined YARA rule content
    """
    import re

    threat_ids = request.threat_ids
    rule_name = request.rule_name

    if not threat_ids:
        raise HTTPException(status_code=400, detail="No threats selected")

    if len(threat_ids) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 threats allowed")

    # Fetch threats (no signatures yet — load per-threat with a limit below)
    result = await db.execute(
        select(Threat).where(Threat.signature_id.in_(threat_ids))
    )
    threats = result.scalars().all()

    if not threats:
        raise HTTPException(status_code=404, detail="No threats found")

    # Build a map of threat.id -> threat for quick lookup
    threat_by_id = {t.id: t for t in threats}

    # Fetch at most 20 signatures per threat in a single query, then group in Python
    sigs_result = await db.execute(
        select(Signature)
        .where(Signature.threat_id.in_(list(threat_by_id.keys())))
        .order_by(Signature.threat_id, Signature.id)
        .limit(20 * len(threats))
    )
    all_sigs = sigs_result.scalars().all()

    # Group sigs by threat_id, capping at 20 per threat
    sigs_by_threat: dict[int, list] = {}
    for sig in all_sigs:
        bucket = sigs_by_threat.setdefault(sig.threat_id, [])
        if len(bucket) < 20:
            bucket.append(sig)

    # Sanitize rule name
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
    if rule_name[0].isdigit():
        rule_name = '_' + rule_name

    # Collect unique strings and patterns
    string_patterns = {}  # hash -> (pattern, type, source_threats)
    binary_patterns = {}  # hash -> (pattern, source_threats)

    # Track which variable maps to which threats
    pattern_to_threats = {}  # var_name -> list of threat names

    threat_names = []
    categories = set()
    families = set()

    for threat in threats:
        threat_names.append(threat.threat_name)
        if threat.category:
            categories.add(threat.category)
        if threat.family:
            families.add(threat.family)

        for sig in sigs_by_threat.get(threat.id, []):
            if not sig.data:
                continue

            data_hash = sig.data_hash or str(hash(sig.data))

            # Check if string or binary
            is_string = all(32 <= b < 127 or b in (9, 10, 13) for b in sig.data)

            if is_string:
                try:
                    s = sig.data.decode('utf-8', errors='replace').strip('\x00')
                    if len(s) < 4:
                        continue
                    s = s.replace('\\', '\\\\').replace('"', '\\"')
                    if data_hash not in string_patterns:
                        string_patterns[data_hash] = (s, sig.sig_type_name, [])
                    string_patterns[data_hash][2].append(threat.threat_name)
                except Exception:
                    hex_pattern = " ".join(f"{b:02X}" for b in sig.data[:64])
                    if data_hash not in binary_patterns:
                        binary_patterns[data_hash] = (hex_pattern, [])
                    binary_patterns[data_hash][1].append(threat.threat_name)
            else:
                hex_pattern = " ".join(f"{b:02X}" for b in sig.data[:64])
                if data_hash not in binary_patterns:
                    binary_patterns[data_hash] = (hex_pattern, [])
                binary_patterns[data_hash][1].append(threat.threat_name)

    # Build YARA rule
    lines = []
    lines.append(f"rule {rule_name} {{")
    lines.append("    meta:")
    lines.append(f'        description = "Combined detection for {len(threats)} threats"')
    lines.append(f'        threat_count = {len(threats)}')
    if categories:
        lines.append(f'        categories = "{", ".join(sorted(categories))}"')
    if families:
        lines.append(f'        families = "{", ".join(sorted(list(families)[:10]))}"')
    lines.append(f'        generated_by = "Defender Explorer YARA Builder"')
    lines.append("")
    lines.append("    strings:")

    pattern_count = 0
    max_patterns = 500  # YARA can handle up to ~10000 strings

    # Add string patterns
    for i, (data_hash, (pattern, sig_type, sources)) in enumerate(list(string_patterns.items())[:max_patterns // 2]):
        var_name = f"str_{i}"
        lines.append(f'        ${var_name} = "{pattern}" nocase')
        pattern_to_threats[var_name] = list(set(sources))  # Dedupe threat names
        pattern_count += 1

    # Add binary patterns
    for i, (data_hash, (pattern, sources)) in enumerate(list(binary_patterns.items())[:max_patterns - pattern_count]):
        var_name = f"bin_{i}"
        lines.append(f"        ${var_name} = {{ {pattern} }}")
        pattern_to_threats[var_name] = list(set(sources))  # Dedupe threat names
        pattern_count += 1

    if pattern_count == 0:
        lines.append('        $empty = "NO_PATTERNS_FOUND"')

    lines.append("")
    lines.append("    condition:")
    lines.append("        any of them")
    lines.append("}")

    yara_rule = "\n".join(lines)

    return {
        "rule_name": rule_name,
        "rule_content": yara_rule,
        "threat_count": len(threats),
        "pattern_count": pattern_count,
        "string_patterns": len(string_patterns),
        "binary_patterns": len(binary_patterns),
        "threats": [{"id": t.signature_id, "name": t.threat_name} for t in threats],
        "categories": list(categories),
        "families": list(families),
        "pattern_map": pattern_to_threats,  # Maps $var_name -> [threat names]
    }


@router.get("/rules", dependencies=[Depends(_require_api_key)])
async def list_yara_rules():
    """List available YARA rule files."""
    rules = get_available_rules()
    return {
        "rules": rules,
        "total": len(rules),
    }


def _compile_yara_worker(source: str, result_queue: multiprocessing.Queue) -> None:
    """Child-process target: compile a YARA rule and push errors to queue."""
    import yara

    try:
        yara.compile(source=source, includes=False)
        result_queue.put([])
    except yara.SyntaxError as e:
        result_queue.put([str(e)])
    except yara.Error as e:
        result_queue.put([str(e)])
    except Exception:
        result_queue.put(["Compilation failed"])


_YARA_TIMEOUT = 5  # seconds


def _run_yara_in_subprocess(source: str) -> list[str]:
    """Spawn a child process for YARA compilation with a hard kill timeout.

    Unlike asyncio.to_thread, a hung C extension in the child process can
    be terminated/killed by the OS, preventing resource leaks.
    """
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    proc = ctx.Process(target=_compile_yara_worker, args=(source, q))
    proc.start()
    proc.join(timeout=_YARA_TIMEOUT)

    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=2)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=1)
        return ["Compilation timed out (rule too complex)"]

    try:
        return q.get_nowait()
    except Exception:
        return ["Compilation failed unexpectedly"]


@router.post("/validate", dependencies=[Depends(_require_api_key)])
@_limiter.limit("10/minute")
async def validate_yara_rule(
    request: Request,
    rule_content: str = Form(..., max_length=100_000),
):
    """Validate YARA rule syntax without scanning."""
    warnings = []

    # Run compilation in a killable subprocess
    errors = await asyncio.to_thread(_run_yara_in_subprocess, rule_content)

    if "rule " not in rule_content:
        warnings.append("No 'rule' keyword found")
    if "strings:" not in rule_content and "condition:" not in rule_content:
        warnings.append("Missing 'strings:' or 'condition:' section")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "yara_available": True,
    }
