"""ASR Rule API endpoints."""

import hmac
import logging
import re
from fastapi import APIRouter, Depends, HTTPException, Query, Header, Request
from fastapi.responses import Response
from slowapi import Limiter
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, any_, update

from ..database import get_db
from ..config import get_settings
from ..models import ASRRule, LuaScript, Threat
from ..rate_limit import client_key
from ..schemas.asr_rule import ASRRuleResponse, ASRRuleDetail, LuaScriptSummary, ExtractedPatternsResponse

logger = logging.getLogger(__name__)

router = APIRouter()
_limiter = Limiter(key_func=client_key)
_settings = get_settings()


async def _require_api_key(x_api_key: str = Header()):
    """Require ADMIN_API_KEY for write operations."""
    if not _settings.admin_api_key:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY not configured")
    if not hmac.compare_digest(x_api_key, _settings.admin_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")


async def _find_function_definitions_in_db(db: AsyncSession) -> dict[str, list[str]]:
    """
    Find function definitions across all Lua scripts in the database.

    This searches for function definitions like IsRmmToolFilePath, GetPathExclusions, etc.
    that contain data tables and extracts their entries.

    Supports multiple patterns:
    - {}[n] = "value" pattern
    - ipairs({'value1', 'value2', ...}) pattern
    - Table assignments: l_x_y["key"] = value pattern

    Returns:
        Dictionary mapping function names to their extracted data entries
    """
    import re
    from ..services.lua_pattern_extractor import extract_lua_function_body

    function_data: dict[str, list[str]] = {}

    # Pattern to extract data entries from function bodies - multiple formats
    # Pattern 1: {}[n] = "value" or {}[n] = 'value'
    data_entry_pattern1 = re.compile(r'\{\}\[\d+\]\s*=\s*["\']([^"\']+)["\']')
    # Pattern 2: ipairs({'value1', 'value2', ...}) - table literals in ipairs
    ipairs_table_pattern = re.compile(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)')
    # Pattern 3: l_x_y["key"] = value (table key assignments)
    table_key_pattern = re.compile(r'(?:l_\d+_\d+|\{\})\s*\[["\']([^"\']+)["\']\]\s*=')

    # Pattern to find function names (Is* or Get*)
    func_name_pattern = re.compile(r'((?:Is|Get)[A-Za-z]+)\s*=\s*function\s*\(')

    # Query all Lua scripts with decompiled source
    scripts_result = await db.execute(
        select(LuaScript.decompiled_source).where(LuaScript.decompiled_source.isnot(None))
    )

    for (content,) in scripts_result.all():
        if not content:
            continue

        # Find all function names, then extract their full bodies
        for name_match in func_name_pattern.finditer(content):
            func_name = name_match.group(1)
            body = extract_lua_function_body(content, func_name)
            if not body:
                continue

            entries = []

            # Pattern 1: {}[n] = "value"
            entries.extend([m.group(1) for m in data_entry_pattern1.finditer(body)])

            # Pattern 2: ipairs table literals - extract all string values
            for ipairs_match in ipairs_table_pattern.finditer(body):
                table_content = ipairs_match.group(1)
                string_values = re.findall(r'["\']([^"\']+)["\']', table_content)
                entries.extend(string_values)

            # Pattern 3: Table key assignments
            entries.extend([m.group(1) for m in table_key_pattern.finditer(body)])

            if entries:
                if func_name not in function_data:
                    function_data[func_name] = []
                function_data[func_name].extend(entries)

    # Deduplicate entries
    for func_name in function_data:
        function_data[func_name] = list(set(function_data[func_name]))

    return function_data


@router.post("/refresh-counts")
@_limiter.limit("5/minute")
async def refresh_asr_counts(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(_require_api_key),
):
    """Refresh script counts for all ASR rules based on actual database content."""
    # Get all ASR rules
    rules_result = await db.execute(select(ASRRule))
    rules = rules_result.scalars().all()

    updated = 0
    for rule in rules:
        # Count scripts that have this GUID in their asr_guids array
        count_query = select(func.count(LuaScript.id)).where(
            rule.guid == any_(LuaScript.asr_guids)
        )
        count_result = await db.execute(count_query)
        actual_count = count_result.scalar() or 0

        if rule.script_count != actual_count:
            rule.script_count = actual_count
            updated += 1

    await db.commit()
    return {"updated": updated, "total_rules": len(rules)}


@router.post("/extract-patterns")
@_limiter.limit("3/minute")
async def extract_all_patterns(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(_require_api_key),
):
    """Re-extract patterns from all Lua scripts for each ASR rule, including external function resolution."""
    import re
    from ..services.lua_pattern_extractor import extract_patterns_from_scripts, merge_external_function_data

    # STEP 1: Find function definitions across ALL Lua scripts
    # This finds IsRmmToolFilePath, IsRmmToolVersionInfo, IsRmmToolOFN, GetPathExclusions, etc.
    function_data = await _find_function_definitions_in_db(db)

    # Get all ASR rules
    rules_result = await db.execute(select(ASRRule))
    rules = rules_result.scalars().all()

    updated = 0
    for rule in rules:
        # Get all scripts for this rule
        scripts_query = select(LuaScript.decompiled_source).where(
            rule.guid == any_(LuaScript.asr_guids)
        )
        scripts_result = await db.execute(scripts_query)
        sources = [row[0] for row in scripts_result.all() if row[0]]

        if sources:
            # Extract patterns from the rule's own scripts
            patterns = extract_patterns_from_scripts(sources, rule.guid)

            # STEP 2: Check if any scripts call external functions and merge their data
            calls_external = False
            for source in sources:
                for func_name in function_data.keys():
                    if f'{func_name}(' in source:
                        calls_external = True
                        break
                if calls_external:
                    break

            if calls_external and function_data:
                merge_external_function_data(patterns, function_data)

            extracted_data = patterns.to_dict()

            # Update rule
            rule.extracted_data = extracted_data
            rule.script_count = len(sources)
            updated += 1

    await db.commit()
    return {"updated": updated, "total_rules": len(rules), "functions_found": list(function_data.keys())}


@router.post("/relink-scripts")
@_limiter.limit("3/minute")
async def relink_scripts_to_asr(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(_require_api_key),
):
    """Re-scan all Lua scripts and link them to ASR rules based on content."""
    from ..services.extracted_import_service import ASR_RULE_NAME_TO_GUID
    import re

    # Get all Lua scripts
    scripts_result = await db.execute(select(LuaScript))
    scripts = scripts_result.scalars().all()

    updated = 0
    for script in scripts:
        if not script.decompiled_source:
            continue

        content = script.decompiled_source
        new_guids = set(script.asr_guids or [])
        original_count = len(new_guids)

        # Pattern 1: IsHipsRuleEnabled calls
        hips_matches = re.findall(r'IsHipsRuleEnabled\s*\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', content)
        for g in hips_matches:
            new_guids.add(g.lower())

        # Pattern 2: mp.IsHipsRuleEnabled calls
        hips_matches = re.findall(r'\(mp\.IsHipsRuleEnabled\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', content)
        for g in hips_matches:
            new_guids.add(g.lower())

        # Pattern 3: GetRuleInfo with Name (supports both .Name and {Name formats)
        rule_info_match = re.search(r'GetRuleInfo\s*=\s*function.*?(?:\.Name|\{Name)\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
        if rule_info_match:
            rule_name = rule_info_match.group(1).lower().strip()
            if rule_name in ASR_RULE_NAME_TO_GUID:
                new_guids.add(ASR_RULE_NAME_TO_GUID[rule_name])

        # Pattern 4: l_x_y.Name = "rule name"
        name_matches = re.findall(r'l_\d+_\d+\.Name\s*=\s*["\']([^"\']+)["\']', content)
        for name in name_matches:
            name_lower = name.lower().strip()
            if name_lower in ASR_RULE_NAME_TO_GUID:
                new_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

        # Pattern 5: Direct {}.Name = "rule name" (table constructor)
        name_matches = re.findall(r'\{\}\.Name\s*=\s*["\']([^"\']+)["\']', content)
        for name in name_matches:
            name_lower = name.lower().strip()
            if name_lower in ASR_RULE_NAME_TO_GUID:
                new_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

        # Pattern 6: Table literal with Name key: return {Name = "rule name", ...}
        name_matches = re.findall(r'return\s*\{[^}]*Name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
        for name in name_matches:
            name_lower = name.lower().strip()
            if name_lower in ASR_RULE_NAME_TO_GUID:
                new_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

        # Update if changed
        if len(new_guids) > original_count:
            script.asr_guids = list(new_guids)
            updated += 1

    await db.commit()

    # STEP 2: Find function definitions across ALL Lua scripts
    function_data = await _find_function_definitions_in_db(db)

    # Now refresh counts and extract patterns
    rules_result = await db.execute(select(ASRRule))
    rules = rules_result.scalars().all()

    rules_updated = 0
    from ..services.lua_pattern_extractor import extract_patterns_from_scripts, merge_external_function_data

    for rule in rules:
        scripts_query = select(LuaScript.decompiled_source).where(
            rule.guid == any_(LuaScript.asr_guids)
        )
        scripts_result = await db.execute(scripts_query)
        sources = [row[0] for row in scripts_result.all() if row[0]]

        # Extract patterns
        patterns = extract_patterns_from_scripts(sources, rule.guid) if sources else None

        # Merge external function data if this rule calls external functions
        if patterns and sources and function_data:
            calls_external = False
            for source in sources:
                for func_name in function_data.keys():
                    if f'{func_name}(' in source:
                        calls_external = True
                        break
                if calls_external:
                    break

            if calls_external:
                merge_external_function_data(patterns, function_data)

        extracted_data = patterns.to_dict() if patterns else {}

        rule.extracted_data = extracted_data
        rule.script_count = len(sources)
        rules_updated += 1

    await db.commit()

    return {
        "scripts_updated": updated,
        "total_scripts": len(scripts),
        "rules_updated": rules_updated,
        "functions_found": list(function_data.keys()),
    }


@router.get("", response_model=list[ASRRuleResponse])
async def list_asr_rules(db: AsyncSession = Depends(get_db)):
    """List all ASR rules with extracted pattern data."""
    query = select(ASRRule).order_by(ASRRule.script_count.desc())
    result = await db.execute(query)
    rules = result.scalars().all()

    response = []
    for rule in rules:
        extracted = None
        if rule.extracted_data and isinstance(rule.extracted_data, dict) and len(rule.extracted_data) > 0:
            try:
                extracted = ExtractedPatternsResponse(**rule.extracted_data)
            except Exception:
                extracted = None

        response.append(ASRRuleResponse(
            guid=rule.guid,
            name=rule.name,
            short_name=rule.short_name,
            description=rule.description,
            script_count=rule.script_count,
            extracted_data=extracted,
        ))

    return response


@router.get("/overlapping-exclusions", dependencies=[Depends(_require_api_key)])
async def get_overlapping_exclusions(
    db: AsyncSession = Depends(get_db),
):
    """Get paths and processes that appear as exclusions in multiple ASR rules."""
    from ..services.exclusion_analyzer import find_overlapping_exclusions

    result = await find_overlapping_exclusions(db)
    return result


@router.get("/{guid}", response_model=ASRRuleDetail)
async def get_asr_rule(
    guid: str,
    db: AsyncSession = Depends(get_db),

):
    """Get ASR rule details."""
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    # Parse extracted_data into response model
    extracted = None
    if rule.extracted_data and isinstance(rule.extracted_data, dict) and len(rule.extracted_data) > 0:
        try:
            extracted = ExtractedPatternsResponse(**rule.extracted_data)
        except Exception:
            extracted = None

    return ASRRuleDetail(
        guid=rule.guid,
        name=rule.name,
        short_name=rule.short_name,
        description=rule.description,
        script_count=rule.script_count,
        scripts=[],
        extracted_data=extracted,
    )


@router.get("/{guid}/scripts", response_model=list[LuaScriptSummary])
async def get_asr_scripts(
    guid: str,
    db: AsyncSession = Depends(get_db),

):
    """Get Lua scripts associated with an ASR rule."""
    # Find scripts that contain this GUID
    query = (
        select(LuaScript, Threat.threat_name)
        .join(Threat, LuaScript.threat_id == Threat.id, isouter=True)
        .where(guid.lower() == any_(LuaScript.asr_guids))
        .limit(500)
    )

    result = await db.execute(query)
    rows = result.all()

    return [
        LuaScriptSummary(
            id=script.id,
            threat_id=script.threat_id,
            threat_name=threat_name,
            bytecode_hash=script.bytecode_hash,
        )
        for script, threat_name in rows
    ]


@router.get("/{guid}/logic")
async def get_asr_rule_logic(
    guid: str,
    db: AsyncSession = Depends(get_db),

):
    """Get comprehensive logic summary for an ASR rule from all associated scripts."""
    from ..services.lua_logic_analyzer import LuaLogicAnalyzer, build_rule_logic_summary

    # Get the ASR rule
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    # Get all scripts with decompiled source for this rule
    scripts_query = select(LuaScript).where(guid.lower() == any_(LuaScript.asr_guids))
    scripts_result = await db.execute(scripts_query)
    scripts = scripts_result.scalars().all()

    # Analyze each script individually
    analyzer = LuaLogicAnalyzer()
    script_analyses = []
    for script in scripts:
        if script.decompiled_source:
            analysis = analyzer.analyze_script(script.decompiled_source)
            script_analyses.append(analysis)

    # Build unified summary
    return build_rule_logic_summary(
        rule_name=rule.name,
        rule_guid=rule.guid,
        short_name=rule.short_name or rule.guid,
        script_analyses=script_analyses,
        extracted_data=rule.extracted_data or {},
    )


@router.get("/{guid}/flowchart")
async def get_asr_flowchart(
    guid: str,
    db: AsyncSession = Depends(get_db),

):
    """Get flowchart data for visualizing ASR rule logic with ReactFlow."""
    from ..services.lua_logic_analyzer import LuaLogicAnalyzer

    # Get the ASR rule
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    # Build flowchart nodes and edges
    nodes = []
    edges = []
    node_id = 1

    # Start node
    nodes.append({
        "id": str(node_id),
        "type": "input",
        "data": {"label": "🚀 Entry Point", "description": "Detection handler triggered"},
        "position": {"x": 250, "y": 0},
        "style": {"background": "#22c55e", "color": "white", "borderRadius": "50%", "width": 80, "height": 80},
    })
    start_id = str(node_id)
    node_id += 1

    # Rule enabled check
    nodes.append({
        "id": str(node_id),
        "type": "default",
        "data": {
            "label": "Rule Enabled?",
            "description": f"Check if '{rule.short_name or rule.guid}' is enabled",
            "expandable": False,
        },
        "position": {"x": 225, "y": 100},
        "style": {"background": "#3b82f6", "color": "white", "borderRadius": "8px"},
    })
    rule_check_id = str(node_id)
    edges.append({"id": f"e{start_id}-{rule_check_id}", "source": start_id, "target": rule_check_id})
    node_id += 1

    # Not enabled -> Allow
    nodes.append({
        "id": str(node_id),
        "type": "output",
        "data": {"label": "✅ ALLOW", "description": "Rule not enabled"},
        "position": {"x": 50, "y": 200},
        "style": {"background": "#22c55e", "color": "white", "borderRadius": "8px"},
    })
    allow_disabled_id = str(node_id)
    edges.append({
        "id": f"e{rule_check_id}-{allow_disabled_id}",
        "source": rule_check_id,
        "target": allow_disabled_id,
        "label": "No",
        "style": {"stroke": "#22c55e"},
    })
    node_id += 1

    # Get exclusions and detections
    extracted = rule.extracted_data or {}
    exclusions = extracted.get("exclusion_paths", [])
    processes = extracted.get("process_names", [])
    detections = extracted.get("detection_paths", [])
    commands = extracted.get("command_patterns", [])

    prev_id = rule_check_id
    y_pos = 200

    # Exclusion check (if there are exclusions)
    if exclusions or processes:
        nodes.append({
            "id": str(node_id),
            "type": "default",
            "data": {
                "label": "📋 Check Exclusions",
                "description": f"{len(exclusions)} path exclusions, {len(processes)} process exclusions",
                "expandable": True,
                "details": {
                    "paths": exclusions[:10],
                    "processes": processes[:10],
                },
            },
            "position": {"x": 225, "y": y_pos},
            "style": {"background": "#f59e0b", "color": "white", "borderRadius": "8px"},
        })
        excl_id = str(node_id)
        edges.append({
            "id": f"e{prev_id}-{excl_id}",
            "source": prev_id,
            "target": excl_id,
            "label": "Yes",
        })
        node_id += 1
        y_pos += 100

        # Exclusion match -> Allow
        nodes.append({
            "id": str(node_id),
            "type": "output",
            "data": {"label": "✅ ALLOW", "description": "Matches exclusion"},
            "position": {"x": 50, "y": y_pos - 50},
            "style": {"background": "#22c55e", "color": "white", "borderRadius": "8px"},
        })
        allow_excl_id = str(node_id)
        edges.append({
            "id": f"e{excl_id}-{allow_excl_id}",
            "source": excl_id,
            "target": allow_excl_id,
            "label": "Match",
            "style": {"stroke": "#22c55e"},
        })
        node_id += 1
        prev_id = excl_id

    # Detection conditions
    if detections or commands:
        nodes.append({
            "id": str(node_id),
            "type": "default",
            "data": {
                "label": "🔍 Detection Checks",
                "description": f"Evaluate {len(detections)} paths, {len(commands)} patterns",
                "expandable": True,
                "details": {
                    "detection_paths": detections[:10],
                    "command_patterns": commands[:10],
                },
            },
            "position": {"x": 225, "y": y_pos},
            "style": {"background": "#8b5cf6", "color": "white", "borderRadius": "8px"},
        })
        detect_id = str(node_id)
        edges.append({
            "id": f"e{prev_id}-{detect_id}",
            "source": prev_id,
            "target": detect_id,
            "label": "No Match" if exclusions else "Yes",
        })
        node_id += 1
        y_pos += 100
        prev_id = detect_id

    # Final decision node
    nodes.append({
        "id": str(node_id),
        "type": "default",
        "data": {
            "label": "⚖️ Evaluate Result",
            "description": "Check detection outcome",
        },
        "position": {"x": 225, "y": y_pos},
        "style": {"background": "#6366f1", "color": "white", "borderRadius": "8px"},
    })
    decision_id = str(node_id)
    edges.append({
        "id": f"e{prev_id}-{decision_id}",
        "source": prev_id,
        "target": decision_id,
    })
    node_id += 1
    y_pos += 100

    # Block outcome
    nodes.append({
        "id": str(node_id),
        "type": "output",
        "data": {"label": "🚫 BLOCK", "description": "Detection triggered - execution blocked"},
        "position": {"x": 350, "y": y_pos},
        "style": {"background": "#dc2626", "color": "white", "borderRadius": "8px"},
    })
    block_id = str(node_id)
    edges.append({
        "id": f"e{decision_id}-{block_id}",
        "source": decision_id,
        "target": block_id,
        "label": "Detected",
        "style": {"stroke": "#dc2626"},
    })
    node_id += 1

    # Allow outcome
    nodes.append({
        "id": str(node_id),
        "type": "output",
        "data": {"label": "✅ ALLOW", "description": "No detection - execution allowed"},
        "position": {"x": 100, "y": y_pos},
        "style": {"background": "#22c55e", "color": "white", "borderRadius": "8px"},
    })
    allow_id = str(node_id)
    edges.append({
        "id": f"e{decision_id}-{allow_id}",
        "source": decision_id,
        "target": allow_id,
        "label": "Not Detected",
        "style": {"stroke": "#22c55e"},
    })

    return {
        "rule_guid": rule.guid,
        "rule_name": rule.name,
        "nodes": nodes,
        "edges": edges,
    }


@router.get("/{guid}/exclusion-analysis", dependencies=[Depends(_require_api_key)])
async def get_exclusion_analysis(
    guid: str,
    db: AsyncSession = Depends(get_db),

):
    """Get risk analysis for exclusions in an ASR rule."""
    from ..services.exclusion_analyzer import analyze_all_exclusions

    # Get the ASR rule
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    extracted = rule.extracted_data or {}
    analysis = analyze_all_exclusions(extracted)

    return {
        "rule_guid": rule.guid,
        "rule_name": rule.name,
        **analysis,
    }


@router.get("/{guid}/related-rules")
async def get_related_asr_rules(
    guid: str,
    db: AsyncSession = Depends(get_db),

):
    """Get ASR rules that share exclusions with this rule."""
    from ..services.exclusion_analyzer import get_related_rules_by_exclusion

    # Verify rule exists
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    related = await get_related_rules_by_exclusion(db, guid.lower())

    return {
        "rule_guid": rule.guid,
        "rule_name": rule.name,
        "related_rules": related,
        "total": len(related),
    }


@router.get("/{guid}/timeline")
async def get_asr_timeline(
    guid: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),

):
    """Get timeline of changes for an ASR rule."""
    from ..services.history_service import get_entity_timeline

    # Verify rule exists
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    timeline = await get_entity_timeline(db, "asr_rule", guid.lower(), limit=limit)

    # Add current state info if no history yet
    if not timeline["events"]:
        timeline["events"] = [{
            "date": None,
            "type": "created",
            "vdm_version": None,
            "changes": ["Initial import"],
            "details": None,
        }]
        timeline["message"] = "Timeline tracking starts from this point forward"

    return timeline


@router.get("/{guid}/report")
async def get_asr_report(
    guid: str,
    format: str = Query("html", regex="^(html|pdf)$"),
    db: AsyncSession = Depends(get_db),

):
    """Generate a detailed report for an ASR rule."""
    from ..services.report_service import generate_asr_report_html, generate_pdf_from_html
    from ..services.exclusion_analyzer import analyze_all_exclusions, get_related_rules_by_exclusion

    # Get the ASR rule
    query = select(ASRRule).where(ASRRule.guid == guid.lower())
    result = await db.execute(query)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="ASR rule not found")

    # Build rule data
    rule_data = {
        "guid": rule.guid,
        "name": rule.name,
        "short_name": rule.short_name,
        "description": rule.description,
        "script_count": rule.script_count,
        "extracted_data": rule.extracted_data or {},
    }

    # Get exclusion analysis
    exclusion_analysis = analyze_all_exclusions(rule.extracted_data or {})

    # Get related rules
    related_rules = await get_related_rules_by_exclusion(db, guid.lower())

    # Generate report
    html = generate_asr_report_html(rule_data, exclusion_analysis, related_rules)

    safe_guid = re.sub(r'[^a-fA-F0-9\-]', '', guid)

    if format == "pdf":
        try:
            pdf_content = generate_pdf_from_html(html)
        except RuntimeError:
            logger.exception("PDF generation failed for ASR rule %s", guid)
            raise HTTPException(status_code=501, detail="PDF generation is not available")
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="asr_{safe_guid}_report.pdf"'}
        )

    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="asr_{safe_guid}_report.html"'}
    )
