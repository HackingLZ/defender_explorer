"""YARA rule building API endpoints."""

import asyncio
import hmac
import json
import multiprocessing
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Form, Header, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, true
from sqlalchemy.orm import aliased

from ..database import get_db
from ..config import get_settings
from ..models import Threat, Signature
from ..rate_limit import limiter as _limiter
from ..services.yara_service import get_available_rules

router = APIRouter()
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
    threat_ids: list[int] = Field(min_length=1, max_length=500)
    rule_name: str = Field(default="combined_detection", min_length=1, max_length=128)


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
    if len(threats) != len(set(threat_ids)):
        raise HTTPException(status_code=409, detail="Some selected threats no longer exist. Refresh your selection and retry.")

    # Build a map of threat.id -> threat for quick lookup
    threat_by_id = {t.id: t for t in threats}

    # Fetch at most 20 signatures per threat in a single query, then group in Python
    sample = (
        select(Signature).where(Signature.threat_id == Threat.id)
        .order_by(Signature.id).limit(20).correlate(Threat).lateral()
    )
    sampled_signature = aliased(Signature, sample)
    sigs_result = await db.execute(
        select(sampled_signature).select_from(Threat).join(sample, true())
        .where(Threat.id.in_(list(threat_by_id.keys())))
        .order_by(Threat.id, sampled_signature.id)
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
                    s = json.dumps(s, ensure_ascii=True)[1:-1]
                    if data_hash not in string_patterns:
                        string_patterns[data_hash] = (s, sig.sig_type_name, [])
                    string_patterns[data_hash][2].append(threat.signature_id)
                except Exception:
                    hex_pattern = " ".join(f"{b:02X}" for b in sig.data[:64])
                    if data_hash not in binary_patterns:
                        binary_patterns[data_hash] = (hex_pattern, [])
                    binary_patterns[data_hash][1].append(threat.signature_id)
            else:
                hex_pattern = " ".join(f"{b:02X}" for b in sig.data[:64])
                if data_hash not in binary_patterns:
                    binary_patterns[data_hash] = (hex_pattern, [])
                binary_patterns[data_hash][1].append(threat.signature_id)

    # Build YARA rule
    lines = []
    lines.append(f"rule {rule_name} {{")
    lines.append("    meta:")
    lines.append(f'        description = "Combined detection for {len(threats)} threats"')
    lines.append(f'        threat_count = {len(threats)}')
    if categories:
        lines.append(f'        categories = {json.dumps(", ".join(sorted(categories)), ensure_ascii=True)}')
    if families:
        lines.append(f'        families = {json.dumps(", ".join(sorted(families)[:10]), ensure_ascii=True)}')
    lines.append(f'        generated_by = "Defender Explorer YARA Builder"')
    lines.append("")
    lines.append("    strings:")

    max_patterns = 500
    candidates = [("str", pattern, sources) for pattern, _, sources in string_patterns.values()]
    candidates += [("bin", pattern, sources) for pattern, sources in binary_patterns.values()]
    first_for_threat = {}
    for index, (_, _, sources) in enumerate(candidates):
        for source in sources:
            first_for_threat.setdefault(source, index)
    if any(t.signature_id not in first_for_threat for t in threats):
        raise HTTPException(status_code=422, detail="A selected threat has no usable patterns in its signature sample. Remove it and retry.")
    # Reserve representation for every selection before filling the output cap.
    selected = list(dict.fromkeys(first_for_threat[t.signature_id] for t in threats))
    selected_set = set(selected)
    selected.extend(i for i in range(len(candidates)) if i not in selected_set)
    selected = selected[:max_patterns]
    names = {t.signature_id: t.threat_name for t in threats}
    for i, index in enumerate(selected):
        kind, pattern, sources = candidates[index]
        var_name = f"{kind}_{i}"
        value = f'"{pattern}" nocase' if kind == "str" else f"{{ {pattern} }}"
        lines.append(f"        ${var_name} = {value}")
        pattern_to_threats[var_name] = sorted({names[source] for source in sources})
    pattern_count = len(selected)

    lines.append("")
    lines.append("    condition:")
    lines.append("        any of them")
    lines.append("}")

    yara_rule = "\n".join(lines)
    if len(yara_rule.encode()) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Generated rule exceeds 2 MiB. Select fewer threats.")

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
