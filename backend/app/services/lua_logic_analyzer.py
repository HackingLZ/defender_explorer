"""
Lua Logic Analyzer Service

Analyzes decompiled Lua scripts and generates human-readable summaries
of the detection logic flow.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from .lua_pattern_extractor import extract_lua_function_body


# Map ASR GUIDs to short names for readable output
ASR_GUID_NAMES = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "VulnerableDrivers",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "AdobeReaderChildProcess",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "OfficeChildProcess",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "LsassCredentialTheft",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "EmailExecutableContent",
    "01443614-cd74-433a-b99e-2ecdc07bfc25": "PrevalenceCheck",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "ObfuscatedScripts",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "ScriptDownloadedExe",
    "3b576869-a4ec-4529-8536-b80a7769e899": "OfficeExecutableContent",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "OfficeCodeInjection",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "OutlookChildProcess",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "WMIPersistence",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": "PSExecWMI",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "SafeModeReboot",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "USBUntrusted",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "ImpersonatedTools",
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": "WebshellCreation",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "OfficeMacroWin32API",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "RansomwareProtection",
    "1081f0b6-3e1e-4f44-acce-816d65112d99": "RMMTools",
}


@dataclass
class ScriptAnalysis:
    """Analysis of a single Lua script."""
    script_type: str = "unknown"  # "config", "detection", "helper"
    rule_name: Optional[str] = None
    rule_guid: Optional[str] = None
    entry_point: Optional[str] = None
    trigger_type: Optional[str] = None  # "process_create", "file_create", "image_load", etc.
    defined_functions: List[Dict] = field(default_factory=list)
    checks: List[str] = field(default_factory=list)
    outcomes: List[str] = field(default_factory=list)
    telemetry_attributes: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    referenced_asr_rules: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)


# Entry point names and their meanings
ENTRY_POINTS = {
    'OnBmHit': ('behavior_monitor', 'Behavior monitoring hit'),
    'OnCreatedProcess': ('process_create', 'Child process creation'),
    'OnImageLoad': ('image_load', 'DLL/image load'),
    'OnFileCreated': ('file_create', 'File creation'),
    'OnFileRenamed': ('file_rename', 'File rename'),
    'OnRegistryValueSet': ('registry_set', 'Registry modification'),
    'OnScriptContent': ('script_content', 'Script content analysis'),
}

# Config-only function names (no detection logic)
CONFIG_FUNCTIONS = {
    'GetRuleInfo', 'GetPathExclusions', 'GetMonitoredLocations',
    'GetPathInclusions', 'GetCommandLineRegExp', 'GetCommandLineExclusions',
    'GetCommandLineRegExpList', 'GetCommandLineInclusions',
    'GetMonitoredExtensions',
}

# Known function descriptions
FUNCTION_MEANINGS = {
    'GetRuleInfo': 'Returns rule metadata (name, GUID, description)',
    'GetPathExclusions': 'Returns paths where this rule does NOT apply',
    'GetMonitoredLocations': 'Returns paths/trigger types monitored by this rule',
    'GetPathInclusions': 'Returns specific executables to monitor',
    'GetCommandLineRegExp': 'Returns regex for command line detection',
    'GetCommandLineExclusions': 'Returns command patterns to exclude from detection',
    'GetCommandLineRegExpList': 'Returns list of command line regex patterns',
    'GetCommandLineInclusions': 'Returns command line patterns to detect',
    'GetMonitoredExtensions': 'Returns file extensions to monitor',
    'OnBmHit': 'Main entry — called on behavior monitoring hit',
    'OnCreatedProcess': 'Entry — called when a child process is created',
    'OnImageLoad': 'Entry — called when a DLL/image is loaded',
    'OnFileCreated': 'Entry — called when a file is created',
    'OnFileRenamed': 'Entry — called when a file is renamed',
    'OnRegistryValueSet': 'Entry — called when a registry value is modified',
    'OnScriptContent': 'Entry — called to analyze script content',
    'IsRmmToolFilePath': 'Checks if file path matches known RMM tool paths',
    'IsRmmToolVersionInfo': 'Checks if PE version info matches known RMM tools',
    'IsRmmToolOFN': 'Checks if original filename matches known RMM tools',
}


class LuaLogicAnalyzer:
    """Analyzes Lua scripts to extract readable logic summaries."""

    def analyze_script(self, source: str) -> ScriptAnalysis:
        """Analyze a single Lua script and return structured analysis."""
        analysis = ScriptAnalysis()
        if not source:
            return analysis

        self._classify_script(source, analysis)
        self._extract_rule_info(source, analysis)
        self._extract_functions(source, analysis)
        self._extract_checks(source, analysis)
        self._extract_outcomes(source, analysis)
        self._extract_telemetry(source, analysis)
        self._extract_mitre(source, analysis)
        self._extract_referenced_rules(source, analysis)
        self._extract_api_calls(source, analysis)

        return analysis

    def _classify_script(self, source: str, analysis: ScriptAnalysis) -> None:
        """Classify script as config, detection, or helper."""
        has_entry = any(f'{ep} = function' in source or f'{ep}=function' in source
                        for ep in ENTRY_POINTS)
        has_config = any(f'{fn} = function' in source for fn in CONFIG_FUNCTIONS)
        has_infected = 'mp.INFECTED' in source or 'return mp.INFECTED' in source
        has_clean = 'mp.CLEAN' in source
        has_return_bool = 'return true' in source or 'return false' in source

        if has_config and not has_entry and not has_infected:
            analysis.script_type = "config"
        elif has_entry or has_infected or has_clean:
            analysis.script_type = "detection"
        elif has_return_bool and not has_config:
            analysis.script_type = "helper"
        else:
            analysis.script_type = "detection"

        # Identify trigger type from entry point
        for ep, (trigger, _desc) in ENTRY_POINTS.items():
            if f'{ep} = function' in source or f'{ep}=function' in source:
                analysis.entry_point = ep
                analysis.trigger_type = trigger
                break

    def _extract_rule_info(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract rule name and GUID."""
        # Name from GetRuleInfo
        name_match = re.search(r"Name\s*=\s*['\"]([^'\"]+)['\"]", source)
        if name_match:
            analysis.rule_name = name_match.group(1)

        # GUID from IsHipsRuleEnabled
        guid_match = re.search(
            r'IsHipsRuleEnabled\s*\)?\s*\(\s*["\']([0-9a-fA-F-]{36})["\']',
            source
        )
        if guid_match:
            analysis.rule_guid = guid_match.group(1).lower()

    def _extract_functions(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract function definitions."""
        func_pattern = re.compile(r'(\w+)\s*=\s*function\s*\(([^)]*)\)')
        for match in func_pattern.finditer(source):
            name = match.group(1)
            params = match.group(2).strip()
            if name.startswith('l_') or name.startswith('_'):
                continue
            analysis.defined_functions.append({
                "name": name,
                "params": params,
                "description": FUNCTION_MEANINGS.get(name),
                "is_config": name in CONFIG_FUNCTIONS,
                "is_entry_point": name in ENTRY_POINTS,
            })

    def _extract_checks(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract detection checks/conditions from the script logic."""
        checks = []

        # IsHipsRuleEnabled — which rule is being checked
        for m in re.finditer(r'IsHipsRuleEnabled\s*\)?\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', source):
            guid = m.group(1).lower()
            name = ASR_GUID_NAMES.get(guid, guid)
            checks.append(f"Check ASR rule enabled: {name}")

        # Path exclusion check
        if 'GetPathExclusions' in source or 'IsPathExcluded' in source:
            checks.append("Check path against exclusion list")

        # GetTaintLevelHR — prevalence/trust check
        if 'GetTaintLevelHR' in source:
            # Try to extract the threshold
            taint_match = re.search(r'GetTaintLevelHR\s*\([^)]*\)\s*([<>=!]+)\s*(\d+)', source)
            if taint_match:
                checks.append(f"Check file trust level {taint_match.group(1)} {taint_match.group(2)} (low prevalence)")
            else:
                checks.append("Check file trust/prevalence level")

        # IsKnownFriendlyFile
        if 'IsKnownFriendlyFile' in source:
            checks.append("Check if file is on known-friendly list")

        # IsTrustedFile
        if 'IsTrustedFile' in source:
            checks.append("Check if file is trusted (signed/prevalent)")

        # Office process checks
        if 'IsOfficeProcess' in source:
            checks.append("Check if parent is a Microsoft Office process")
        if 'IsScriptInterpreter' in source:
            checks.append("Check if process is a script interpreter")

        # RMM tool checks
        rmm_checks = []
        if 'IsRmmToolFilePath' in source:
            rmm_checks.append("file path")
        if 'IsRmmToolVersionInfo' in source:
            rmm_checks.append("PE version info")
        if 'IsRmmToolOFN' in source:
            rmm_checks.append("original filename")
        if rmm_checks:
            checks.append(f"Check if file is a known RMM tool (via {', '.join(rmm_checks)})")

        # Scan source checks
        scan_sources = []
        if 'SCANSOURCE_IOAV_WEB' in source:
            scan_sources.append("web download")
        if 'SCANSOURCE_IOAV_FILE' in source:
            scan_sources.append("file download")
        if 'SCANSOURCE_RTP' in source:
            scan_sources.append("real-time protection")
        if scan_sources:
            checks.append(f"Check scan source: {', '.join(scan_sources)}")

        # OrgID / test mode gating
        if 'GetOrgID' in source or 'GetTestMode' in source:
            checks.append("Check organization ID / test mode gating")

        # Process name comparisons
        proc_names = set()
        for m in re.finditer(r'(?:processname|CONTEXT_DATA_PROCESSNAME)[^=]*==\s*["\']([^"\']+)["\']', source, re.I):
            proc_names.add(m.group(1).lower())
        # Also l_x_y == 'process.exe' patterns
        for m in re.finditer(r'(?:l_\d+_\d+|tmp\d*)\s*==\s*["\']([^"\']+\.exe)["\']', source, re.I):
            proc_names.add(m.group(1).lower())
        if proc_names:
            if len(proc_names) <= 5:
                checks.append(f"Check process name: {', '.join(sorted(proc_names))}")
            else:
                checks.append(f"Check process name against {len(proc_names)} known processes")

        # string.find path matching (detection vs exclusion)
        path_finds = re.findall(r"(?:string\.find|:find)\s*\([^,]+,\s*['\"]([^'\"]+)['\"]", source)
        path_finds = [p for p in path_finds if '\\' in p and len(p) > 5]
        if path_finds:
            checks.append(f"Match file path against {len(path_finds)} patterns")

        # Command line checks
        if 'commandline' in source.lower() or 'GetCommandLineRegExp' in source:
            # Try to extract the actual patterns
            cmd_body = extract_lua_function_body(source, 'GetCommandLineInclusions')
            if cmd_body:
                cmd_entries = re.findall(r"\['([^']+)'\]", cmd_body)
                if cmd_entries:
                    checks.append(f"Match command line against {len(cmd_entries)} regex patterns")
                else:
                    checks.append("Match command line against detection patterns")
            else:
                cmd_body = extract_lua_function_body(source, 'GetCommandLineRegExp')
                if cmd_body:
                    checks.append("Match command line against regex pattern")
                elif 'commandline' in source.lower():
                    checks.append("Inspect command line arguments")

        # Monitored locations
        monitored_body = extract_lua_function_body(source, 'GetMonitoredLocations')
        if monitored_body:
            if 'MONITOR_PROCESSCREATE' in monitored_body:
                checks.append("Trigger on: process creation")
            if 'MONITOR_IMAGELOAD' in monitored_body:
                checks.append("Trigger on: image/DLL load")
            if 'MONITOR_FILECREATE' in monitored_body:
                checks.append("Trigger on: file creation")

        # Monitored extensions
        if 'GetMonitoredExtensions' in source:
            checks.append("Check file extension against monitored list")

        # File extension inline checks
        ext_matches = set()
        for m in re.finditer(r'(?:extension|ext|l_\d+_\d+)\s*==\s*["\'](\w{2,5})["\']', source, re.I):
            ext_matches.add(m.group(1).lower())
        if ext_matches and len(ext_matches) <= 10:
            checks.append(f"Check file extension: {', '.join(sorted(ext_matches))}")
        elif ext_matches:
            checks.append(f"Check file extension ({len(ext_matches)} types)")

        # WMI event subscription
        if 'WmiPersistenceMonitor' in source or 'wmi' in source.lower() and 'event' in source.lower():
            checks.append("Monitor WMI event subscription persistence")

        analysis.checks = checks

    def _extract_outcomes(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract what the script does when conditions match."""
        outcomes = []

        if 'mp.INFECTED' in source or 'return mp.INFECTED' in source:
            outcomes.append("BLOCK execution (return INFECTED)")

        if 'mp.CLEAN' in source or 'return mp.CLEAN' in source:
            outcomes.append("ALLOW execution (return CLEAN)")

        if 'return true' in source and analysis.script_type != 'config':
            if 'mp.INFECTED' not in source and 'mp.CLEAN' not in source:
                outcomes.append("Return TRUE (match found)")

        if 'return false' in source and analysis.script_type != 'config':
            if 'mp.INFECTED' not in source and 'mp.CLEAN' not in source:
                outcomes.append("Return FALSE (no match)")

        if 'bm.add' in source:
            outcomes.append("Add to behavior monitoring watchlist")

        if 'bm.trigger_sig' in source or 'trigger_sig' in source:
            outcomes.append("Trigger signature detection alert")

        if 'SetHipsRule' in source:
            outcomes.append("Activate secondary ASR rule enforcement")

        analysis.outcomes = outcomes

    def _extract_telemetry(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract telemetry/logging attributes, filtering decompiler noise."""
        attrs = set()
        # Only match clean attribute strings: mp.set_mpattribute('AttrName')
        for m in re.finditer(r"mp\.set_mpattribute\s*\(\s*['\"]([A-Za-z0-9_]+)['\"]", source):
            attrs.add(m.group(1))
        analysis.telemetry_attributes = sorted(attrs)

    def _extract_mitre(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract MITRE ATT&CK technique references."""
        techniques = set()
        for m in re.finditer(r'["\']([Tt]\d{4}(?:\.\d{3})?)["\']', source):
            techniques.add(m.group(1).upper())
        analysis.mitre_techniques = sorted(techniques)

    def _extract_referenced_rules(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract references to other ASR rules."""
        refs = []
        for m in re.finditer(r'IsHipsRuleEnabled\s*\)?\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', source):
            guid = m.group(1).lower()
            name = ASR_GUID_NAMES.get(guid, guid)
            if guid != analysis.rule_guid:
                refs.append({"guid": guid, "name": name})
        analysis.referenced_asr_rules = refs

    def _extract_api_calls(self, source: str, analysis: ScriptAnalysis) -> None:
        """Extract notable Defender API calls."""
        notable_apis = {
            'mp.get_contextdata': 'Read process context data',
            'mp.getfilename': 'Get file path',
            'mp.GetScanSource': 'Get scan trigger source',
            'mp.IOAVGetProcessPath': 'Get download process path',
            'MpCommon.PathToWin32Path': 'Convert device path to Win32 path',
            'MpCommon.GetOriginalFileName': 'Get PE original filename',
            'MpCommon.QueryPersistContext': 'Query persisted context across scans',
            'MpCommon.IsSampled': 'Apply sampling rate gate',
            'sysio.GetPEVersionInfo': 'Read PE version information',
            'ImageConfig.GetImagePath': 'Get loaded image path',
        }
        calls = []
        for api, desc in notable_apis.items():
            if api in source:
                calls.append({"api": api, "description": desc})
        analysis.api_calls = calls


def analyze_lua_script(source: str) -> Dict:
    """Analyze a single Lua script."""
    analyzer = LuaLogicAnalyzer()
    result = analyzer.analyze_script(source)
    return {
        "script_type": result.script_type,
        "rule_name": result.rule_name,
        "rule_guid": result.rule_guid,
        "entry_point": result.entry_point,
        "trigger_type": result.trigger_type,
        "functions": result.defined_functions,
        "checks": result.checks,
        "outcomes": result.outcomes,
        "telemetry_attributes": result.telemetry_attributes,
        "mitre_techniques": result.mitre_techniques,
        "referenced_asr_rules": result.referenced_asr_rules,
        "api_calls": result.api_calls,
    }


def build_rule_logic_summary(
    rule_name: str,
    rule_guid: str,
    short_name: str,
    script_analyses: List[ScriptAnalysis],
    extracted_data: Dict,
) -> Dict:
    """
    Build a comprehensive logic summary for an ASR rule from all its script analyses.
    This replaces the previous endpoint-level merge logic.
    """
    # Classify scripts
    config_scripts = [s for s in script_analyses if s.script_type == "config"]
    detection_scripts = [s for s in script_analyses if s.script_type == "detection"]
    helper_scripts = [s for s in script_analyses if s.script_type == "helper"]

    # Collect all entry points and trigger types
    entry_points = set()
    trigger_types = set()
    for s in script_analyses:
        if s.entry_point:
            entry_points.add(s.entry_point)
        if s.trigger_type:
            trigger_types.add(s.trigger_type)

    # Collect all functions (deduplicated)
    all_functions = {}
    for s in script_analyses:
        for f in s.defined_functions:
            if f["name"] not in all_functions:
                all_functions[f["name"]] = f

    # Collect unique checks, outcomes, telemetry, MITRE, API calls
    all_checks = []
    seen_checks = set()
    for s in script_analyses:
        for c in s.checks:
            if c not in seen_checks:
                all_checks.append(c)
                seen_checks.add(c)

    all_outcomes = set()
    for s in script_analyses:
        all_outcomes.update(s.outcomes)

    all_telemetry = set()
    for s in script_analyses:
        all_telemetry.update(s.telemetry_attributes)

    all_mitre = set()
    for s in script_analyses:
        all_mitre.update(s.mitre_techniques)

    all_api_calls = {}
    for s in script_analyses:
        for api in s.api_calls:
            all_api_calls[api["api"]] = api["description"]

    # Referenced ASR rules (excluding self)
    referenced_rules = {}
    for s in script_analyses:
        for ref in s.referenced_asr_rules:
            if ref["guid"] != rule_guid:
                referenced_rules[ref["guid"]] = ref["name"]

    # Build detection flow
    ed = extracted_data or {}
    exclusions = ed.get("exclusion_paths", [])
    detections = ed.get("detection_paths", [])
    processes = ed.get("process_names", [])
    commands = ed.get("command_patterns", [])
    extensions = ed.get("file_extensions", [])
    mitre_list = ed.get("mitre_techniques", [])
    drivers = ed.get("vulnerable_drivers", [])
    rmm_fp = ed.get("rmm_file_paths", [])
    rmm_vi = ed.get("rmm_version_info", [])
    rmm_ofn = ed.get("rmm_original_filenames", [])

    # Determine if config-only
    is_config_only = len(detection_scripts) == 0 and len(config_scripts) > 0

    # Build flow
    flow = []
    step = 1

    # Trigger
    if trigger_types:
        trigger_desc = ", ".join(sorted(t.replace("_", " ") for t in trigger_types))
        flow.append(f"{step}. Trigger: Defender intercepts {trigger_desc} event")
    elif is_config_only:
        flow.append(f"{step}. Trigger: Engine-level interception (detection logic in native code)")
    else:
        flow.append(f"{step}. Trigger: Defender calls detection handler")
    step += 1

    # Rule enabled check
    flow.append(f"{step}. Gate: Check if '{short_name}' ASR rule is enabled in policy")
    step += 1

    # Exclusions
    if exclusions:
        flow.append(f"{step}. Exclusions: Match path against {len(exclusions)} exclusion patterns → SKIP if matched")
        step += 1

    # Core detection
    detection_steps = []
    if processes:
        detection_steps.append(f"Match process against {len(processes)} monitored executables")
    if detections:
        detection_steps.append(f"Match path against {len(detections)} detection patterns")
    if commands:
        detection_steps.append(f"Match command line against {len(commands)} regex patterns")
    if extensions:
        detection_steps.append(f"Check file extension ({len(extensions)} types)")
    if drivers:
        detection_steps.append(f"Match driver against {len(drivers)} known vulnerable drivers")
    if rmm_fp or rmm_vi or rmm_ofn:
        rmm_parts = []
        if rmm_fp:
            rmm_parts.append(f"{len(rmm_fp)} file paths")
        if rmm_vi:
            rmm_parts.append(f"{len(rmm_vi)} version strings")
        if rmm_ofn:
            rmm_parts.append(f"{len(rmm_ofn)} original filenames")
        detection_steps.append(f"Check against RMM tool database ({', '.join(rmm_parts)})")

    # Add script-level checks that aren't covered by pattern counts
    pattern_covered = {
        "Check path against exclusion list",
        "Check file extension against monitored list",
    }
    for check in all_checks:
        if check.startswith("Check ASR rule enabled"):
            continue
        if check in pattern_covered:
            continue
        # Avoid duplicating what we already have from extracted patterns
        if "process name" in check.lower() and processes:
            continue
        if "file path" in check.lower() and "pattern" in check.lower() and detections:
            continue
        if "command line" in check.lower() and "regex" in check.lower() and commands:
            continue
        detection_steps.append(check)

    if detection_steps:
        flow.append(f"{step}. Detection logic:")
        for i, ds in enumerate(detection_steps):
            flow.append(f"   {chr(97 + i)}. {ds}")
        step += 1

    # Telemetry
    if all_telemetry:
        flow.append(f"{step}. Telemetry: Log {len(all_telemetry)} attributes for threat intelligence")
        step += 1

    # MITRE tracking
    if all_mitre:
        flow.append(f"{step}. MITRE ATT&CK: Track techniques {', '.join(sorted(all_mitre))}")
        step += 1

    # Outcome
    has_block = "BLOCK execution (return INFECTED)" in all_outcomes
    has_allow = "ALLOW execution (return CLEAN)" in all_outcomes
    has_monitor = "Add to behavior monitoring watchlist" in all_outcomes
    has_alert = "Trigger signature detection alert" in all_outcomes

    outcome_parts = []
    if has_block:
        outcome_parts.append("BLOCK execution")
    if has_alert:
        outcome_parts.append("trigger detection alert")
    if has_monitor:
        outcome_parts.append("add to behavior watchlist")
    if has_allow:
        outcome_parts.append("ALLOW if no match")

    if outcome_parts:
        flow.append(f"{step}. Outcome: {' / '.join(outcome_parts)}")
    elif is_config_only:
        flow.append(f"{step}. Outcome: Engine decides BLOCK or ALLOW based on native logic")

    # Confidence assessment
    confidence_notes = []
    if is_config_only:
        confidence_notes.append(
            "This rule's detection logic runs in native code. "
            "Lua scripts only define configuration (monitored paths, command patterns, exclusions). "
            "The exact decision logic is not visible in the scripts."
        )
    if any(s.checks == [] and s.script_type == "detection" for s in detection_scripts):
        confidence_notes.append(
            "Some detection scripts have complex control flow that couldn't be fully summarized."
        )
    if referenced_rules:
        names = sorted(referenced_rules.values())
        confidence_notes.append(
            f"This rule cross-references {len(referenced_rules)} other ASR rule(s): {', '.join(names)}. "
            f"Detection may depend on those rules being enabled."
        )

    return {
        "rule_name": rule_name,
        "rule_guid": rule_guid,
        "short_name": short_name,
        "script_count": len(script_analyses),
        "script_breakdown": {
            "config": len(config_scripts),
            "detection": len(detection_scripts),
            "helper": len(helper_scripts),
        },
        "entry_points": sorted(entry_points),
        "trigger_types": sorted(trigger_types),
        "functions": list(all_functions.values()),
        "checks": all_checks,
        "outcomes": sorted(all_outcomes),
        "telemetry_attributes": sorted(all_telemetry),
        "mitre_techniques": sorted(all_mitre),
        "referenced_asr_rules": [
            {"guid": g, "name": n} for g, n in sorted(referenced_rules.items(), key=lambda x: x[1])
        ],
        "api_calls": [{"api": k, "description": v} for k, v in sorted(all_api_calls.items())],
        "flow": flow,
        "confidence_notes": confidence_notes,
        "patterns": {
            "exclusion_paths": exclusions,
            "detection_paths": detections,
            "process_names": processes,
            "command_patterns": commands,
            "file_extensions": extensions,
            "mitre_techniques": mitre_list,
            "registry_keys": ed.get("registry_keys", []),
            "native_functions": ed.get("native_functions", []),
            "vulnerable_drivers": drivers,
            "rmm_file_paths": rmm_fp,
            "rmm_version_info": rmm_vi,
            "rmm_original_filenames": rmm_ofn,
        },
    }
