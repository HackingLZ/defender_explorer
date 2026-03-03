"""Exclusion impact analysis service for ASR rules."""

import re
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models import ASRRule


# Risk patterns for exclusion paths
RISK_PATTERNS = {
    "critical": [
        (r"^\*$", "Wildcard matches everything"),
        (r"\*\*", "Double wildcard can match deeply nested paths"),
        (r"\\temp\\", "Temp folder is commonly abused"),
        (r"\\downloads\\", "Downloads folder is user-writable"),
        (r"\\appdata\\local\\temp", "Local temp is commonly abused"),
        (r"\\public\\", "Public folder is world-writable"),
    ],
    "high": [
        (r"\\appdata\\", "AppData is user-writable"),
        (r"\\programdata\\", "ProgramData may be writable"),
        (r"\\users\\", "User directories are writable"),
        (r"\\\*\.exe$", "Wildcard executable match"),
        (r"\\\*\.dll$", "Wildcard DLL match"),
        (r"\\\*\.ps1$", "Wildcard PowerShell script"),
        (r"\\\*\.bat$", "Wildcard batch file"),
        (r"\\\*\.cmd$", "Wildcard command file"),
        (r"\\\*\.vbs$", "Wildcard VBScript"),
        (r"\\\*\.js$", "Wildcard JavaScript"),
    ],
    "medium": [
        (r"\\windows\\", "Windows directory exclusion"),
        (r"\\program files", "Program Files exclusion"),
        (r"\\syswow64\\", "SysWOW64 exclusion"),
        (r"\\\*\.", "Wildcard with extension"),
        (r"\\[^\\]+\\\*$", "Directory-level wildcard"),
    ],
    "low": [
        (r"\\windows\\system32\\", "System32 exclusion (usually legitimate)"),
        (r"\.log$", "Log file exclusion"),
        (r"\.txt$", "Text file exclusion"),
        (r"\.tmp$", "Temp file exclusion"),
    ],
}

# Known abuse scenarios
ABUSE_SCENARIOS = {
    "temp_folder": {
        "patterns": [r"\\temp\\", r"\\tmp\\"],
        "scenario": "Attackers commonly drop and execute malware from temp folders",
        "technique": "T1059 - Command and Scripting Interpreter",
    },
    "user_writable": {
        "patterns": [r"\\downloads\\", r"\\desktop\\", r"\\documents\\"],
        "scenario": "User-writable locations can be used for malware staging",
        "technique": "T1204 - User Execution",
    },
    "appdata": {
        "patterns": [r"\\appdata\\"],
        "scenario": "AppData is used by many legitimate apps but also by malware for persistence",
        "technique": "T1547 - Boot or Logon Autostart Execution",
    },
    "wildcard_exe": {
        "patterns": [r"\*\.exe", r"\*\.dll", r"\*\.scr"],
        "scenario": "Wildcard executable exclusions can allow any malicious binary",
        "technique": "T1059 - Command and Scripting Interpreter",
    },
    "script_exclusion": {
        "patterns": [r"\*\.ps1", r"\*\.vbs", r"\*\.js", r"\*\.bat"],
        "scenario": "Script exclusions enable living-off-the-land attacks",
        "technique": "T1059 - Command and Scripting Interpreter",
    },
}


@dataclass
class ExclusionRisk:
    """Risk assessment for an exclusion."""
    path: str
    risk_level: str  # 'critical', 'high', 'medium', 'low'
    risk_reasons: List[str]
    abuse_scenarios: List[Dict[str, str]]
    recommendations: List[str]


def analyze_exclusion(path: str) -> Dict[str, Any]:
    """
    Analyze a single exclusion path for risk.

    Returns:
        Dict with risk_level, risk_reasons, abuse_scenarios, recommendations
    """
    path_lower = path.lower()
    risk_reasons = []
    abuse_scenarios = []
    recommendations = []

    # Check each risk level
    detected_level = "low"

    for level in ["critical", "high", "medium", "low"]:
        for pattern, reason in RISK_PATTERNS[level]:
            if re.search(pattern, path_lower, re.IGNORECASE):
                risk_reasons.append(reason)
                if level in ["critical", "high"] and detected_level not in ["critical"]:
                    detected_level = level
                elif level == "medium" and detected_level == "low":
                    detected_level = "medium"

    # Check abuse scenarios
    for scenario_name, scenario_info in ABUSE_SCENARIOS.items():
        for pattern in scenario_info["patterns"]:
            if re.search(pattern, path_lower, re.IGNORECASE):
                abuse_scenarios.append({
                    "name": scenario_name,
                    "scenario": scenario_info["scenario"],
                    "technique": scenario_info["technique"],
                })
                break

    # Generate recommendations
    if detected_level in ["critical", "high"]:
        recommendations.append("Consider removing or restricting this exclusion")
        recommendations.append("Use more specific paths instead of wildcards")
        recommendations.append("Monitor this path for suspicious activity")
    elif detected_level == "medium":
        recommendations.append("Review if this exclusion is necessary")
        recommendations.append("Consider using more specific file extensions")

    # If no specific risks found, it's probably okay
    if not risk_reasons:
        risk_reasons.append("No significant risk patterns detected")
        detected_level = "low"

    return {
        "path": path,
        "risk_level": detected_level,
        "risk_reasons": list(set(risk_reasons)),
        "abuse_scenarios": abuse_scenarios,
        "recommendations": recommendations,
    }


def analyze_process_exclusion(process_name: str) -> Dict[str, Any]:
    """Analyze a process name exclusion for risk."""
    process_lower = process_name.lower()
    risk_reasons = []
    abuse_scenarios = []
    recommendations = []

    # Check for wildcards
    if "*" in process_name:
        risk_reasons.append("Process wildcard can match unintended executables")

    # Check for commonly abused processes
    abused_processes = [
        ("powershell", "PowerShell is commonly used in attacks"),
        ("cmd.exe", "Command prompt is used in many attack chains"),
        ("wscript", "Windows Script Host runs malicious scripts"),
        ("cscript", "Console Script Host runs malicious scripts"),
        ("mshta", "MSHTA runs malicious HTA files"),
        ("regsvr32", "Can be used for proxy execution"),
        ("rundll32", "Can be used for proxy execution"),
        ("msiexec", "Can be abused for code execution"),
        ("certutil", "Can download and decode files"),
    ]

    for proc, reason in abused_processes:
        if proc in process_lower:
            risk_reasons.append(reason)
            abuse_scenarios.append({
                "name": f"{proc}_abuse",
                "scenario": f"Excluding {proc} may allow living-off-the-land attacks",
                "technique": "T1218 - System Binary Proxy Execution",
            })

    risk_level = "low"
    if abuse_scenarios:
        risk_level = "high"
    elif "*" in process_name:
        risk_level = "medium"

    if risk_level in ["high", "medium"]:
        recommendations.append("Consider if this process exclusion is necessary")
        recommendations.append("Monitor excluded process for suspicious child processes")

    if not risk_reasons:
        risk_reasons.append("No significant risk patterns detected")

    return {
        "process": process_name,
        "risk_level": risk_level,
        "risk_reasons": list(set(risk_reasons)),
        "abuse_scenarios": abuse_scenarios,
        "recommendations": recommendations,
    }


async def find_overlapping_exclusions(db: AsyncSession) -> Dict[str, Any]:
    """
    Find exclusion paths and processes that appear in multiple ASR rules.

    Returns:
        Dict with overlapping paths and processes grouped by exclusion
    """
    # Get all ASR rules with extracted data
    query = select(ASRRule).where(ASRRule.extracted_data.isnot(None))
    result = await db.execute(query)
    rules = result.scalars().all()

    # Track exclusions across rules
    path_rules: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    process_rules: Dict[str, List[Dict[str, str]]] = defaultdict(list)

    for rule in rules:
        extracted = rule.extracted_data or {}

        # Track exclusion paths
        for path in extracted.get("exclusion_paths", []):
            path_lower = path.lower()
            path_rules[path_lower].append({
                "guid": rule.guid,
                "name": rule.name,
                "short_name": rule.short_name,
            })

        # Track process names
        for process in extracted.get("process_names", []):
            process_lower = process.lower()
            process_rules[process_lower].append({
                "guid": rule.guid,
                "name": rule.name,
                "short_name": rule.short_name,
            })

    # Filter to only overlapping (2+ rules)
    overlapping_paths = {
        path: {
            "exclusion": path,
            "rules": rules_list,
            "rule_count": len(rules_list),
            "risk_analysis": analyze_exclusion(path),
        }
        for path, rules_list in path_rules.items()
        if len(rules_list) > 1
    }

    overlapping_processes = {
        process: {
            "exclusion": process,
            "rules": rules_list,
            "rule_count": len(rules_list),
            "risk_analysis": analyze_process_exclusion(process),
        }
        for process, rules_list in process_rules.items()
        if len(rules_list) > 1
    }

    return {
        "overlapping_paths": list(overlapping_paths.values()),
        "overlapping_processes": list(overlapping_processes.values()),
        "total_paths": len(overlapping_paths),
        "total_processes": len(overlapping_processes),
    }


async def get_related_rules_by_exclusion(
    db: AsyncSession,
    guid: str
) -> List[Dict[str, Any]]:
    """
    Find ASR rules that share exclusions with the given rule.

    Returns:
        List of related rules with shared exclusion information
    """
    # Get the source rule
    source_query = select(ASRRule).where(ASRRule.guid == guid)
    source_result = await db.execute(source_query)
    source_rule = source_result.scalar_one_or_none()

    if not source_rule or not source_rule.extracted_data:
        return []

    source_data = source_rule.extracted_data
    source_paths = set(p.lower() for p in source_data.get("exclusion_paths", []))
    source_processes = set(p.lower() for p in source_data.get("process_names", []))

    if not source_paths and not source_processes:
        return []

    # Get all other rules
    other_query = select(ASRRule).where(
        ASRRule.guid != guid,
        ASRRule.extracted_data.isnot(None)
    )
    other_result = await db.execute(other_query)
    other_rules = other_result.scalars().all()

    related = []

    for rule in other_rules:
        rule_data = rule.extracted_data or {}
        rule_paths = set(p.lower() for p in rule_data.get("exclusion_paths", []))
        rule_processes = set(p.lower() for p in rule_data.get("process_names", []))

        shared_paths = list(source_paths & rule_paths)
        shared_processes = list(source_processes & rule_processes)

        if shared_paths or shared_processes:
            related.append({
                "rule_guid": rule.guid,
                "rule_name": rule.name,
                "short_name": rule.short_name,
                "shared_exclusions": shared_paths,
                "shared_processes": shared_processes,
                "total_shared": len(shared_paths) + len(shared_processes),
            })

    # Sort by total shared
    related.sort(key=lambda x: x["total_shared"], reverse=True)

    return related


def analyze_all_exclusions(extracted_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze all exclusions from a rule's extracted data.

    Returns:
        Combined analysis with risk summary
    """
    path_analyses = []
    process_analyses = []

    # Analyze paths
    for path in extracted_data.get("exclusion_paths", []):
        path_analyses.append(analyze_exclusion(path))

    # Analyze processes
    for process in extracted_data.get("process_names", []):
        process_analyses.append(analyze_process_exclusion(process))

    # Calculate risk summary
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for analysis in path_analyses + process_analyses:
        risk_counts[analysis["risk_level"]] += 1

    # Determine overall risk
    if risk_counts["critical"] > 0:
        overall_risk = "critical"
    elif risk_counts["high"] > 0:
        overall_risk = "high"
    elif risk_counts["medium"] > 0:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    return {
        "path_analyses": path_analyses,
        "process_analyses": process_analyses,
        "risk_summary": {
            "overall_risk": overall_risk,
            "risk_counts": risk_counts,
            "total_exclusions": len(path_analyses) + len(process_analyses),
        },
    }
