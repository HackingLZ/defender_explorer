"""
Lua Pattern Extractor Service

Extracts detection patterns, exclusions, and metadata from decompiled Lua scripts.
This data is used to show what each ASR rule detects and excludes.
"""

import re
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field


def extract_lua_function_body(source: str, func_name: str) -> Optional[str]:
    """
    Extract the full body of a Lua function definition, correctly handling nested blocks.

    Matches: func_name = function(...)...end
    Tracks nesting depth for: function/do/then/repeat (increase) and end (decrease).
    Returns the body text between the opening function(...) and its matching end,
    or None if the function is not found.
    """
    # Find the function header
    pattern = re.compile(
        rf'{re.escape(func_name)}\s*=\s*function\s*\([^)]*\)',
        re.DOTALL
    )
    m = pattern.search(source)
    if not m:
        return None

    start = m.end()  # position right after function(...)
    # Tokenize to track nesting depth
    # Lua block openers: function, do, then, repeat  /  closer: end (also until for repeat)
    token_pattern = re.compile(
        r'\bfunction\b|\bdo\b|\bthen\b|\brepeat\b|\bend\b|\buntil\b'
    )
    depth = 1  # we're inside the function body
    pos = start
    while depth > 0:
        tok = token_pattern.search(source, pos)
        if not tok:
            # No more tokens; return everything to end of source
            return source[start:]
        keyword = tok.group()
        if keyword in ('function', 'do', 'then', 'repeat'):
            depth += 1
        elif keyword == 'end':
            depth -= 1
        elif keyword == 'until':
            # 'until' closes 'repeat' blocks
            depth -= 1
        pos = tok.end()
        if depth == 0:
            return source[start:tok.start()]
    return source[start:]


@dataclass
class ExtractedPatterns:
    """Patterns extracted from Lua scripts."""
    exclusion_paths: Set[str] = field(default_factory=set)
    detection_paths: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    file_extensions: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    registry_keys: Set[str] = field(default_factory=set)
    native_functions: Set[str] = field(default_factory=set)
    related_asr_guids: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    command_patterns: Set[str] = field(default_factory=set)
    vulnerable_drivers: Set[str] = field(default_factory=set)
    # RMM tool detection data (from IsRmmTool* functions)
    rmm_file_paths: Set[str] = field(default_factory=set)
    rmm_version_info: Set[str] = field(default_factory=set)
    rmm_original_filenames: Set[str] = field(default_factory=set)

    def merge(self, other: 'ExtractedPatterns') -> None:
        """Merge another ExtractedPatterns into this one."""
        self.exclusion_paths.update(other.exclusion_paths)
        self.detection_paths.update(other.detection_paths)
        self.process_names.update(other.process_names)
        self.file_extensions.update(other.file_extensions)
        self.mitre_techniques.update(other.mitre_techniques)
        self.registry_keys.update(other.registry_keys)
        self.native_functions.update(other.native_functions)
        self.related_asr_guids.update(other.related_asr_guids)
        self.domains.update(other.domains)
        self.command_patterns.update(other.command_patterns)
        self.vulnerable_drivers.update(other.vulnerable_drivers)
        self.rmm_file_paths.update(other.rmm_file_paths)
        self.rmm_version_info.update(other.rmm_version_info)
        self.rmm_original_filenames.update(other.rmm_original_filenames)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON storage."""
        return {
            "exclusion_paths": sorted(self.exclusion_paths),
            "detection_paths": sorted(self.detection_paths),
            "process_names": sorted(self.process_names),
            "file_extensions": sorted(self.file_extensions),
            "mitre_techniques": sorted(self.mitre_techniques),
            "registry_keys": sorted(self.registry_keys),
            "native_functions": sorted(self.native_functions),
            "related_asr_guids": sorted(self.related_asr_guids),
            "domains": sorted(self.domains),
            "command_patterns": sorted(self.command_patterns),
            "vulnerable_drivers": sorted(self.vulnerable_drivers),
            "rmm_file_paths": sorted(self.rmm_file_paths),
            "rmm_version_info": sorted(self.rmm_version_info),
            "rmm_original_filenames": sorted(self.rmm_original_filenames),
        }

    def is_empty(self) -> bool:
        """Check if no patterns were extracted."""
        return not any([
            self.exclusion_paths, self.detection_paths, self.process_names,
            self.file_extensions, self.mitre_techniques, self.registry_keys,
            self.native_functions, self.related_asr_guids, self.domains,
            self.command_patterns, self.vulnerable_drivers,
            self.rmm_file_paths, self.rmm_version_info, self.rmm_original_filenames
        ])


class LuaPatternExtractor:
    """Extracts patterns and metadata from decompiled Lua scripts."""

    # Regex patterns for extraction
    PATTERNS = {
        # string.find(path, "pattern", 1, true) - literal path patterns
        # Supports both (string.find)(...) and string.find(...) formats
        'string_find_literal': re.compile(
            r'(?:\(string\.find\)|string\.find)\s*\([^,]+,\s*["\']([^"\']+)["\'],\s*1,\s*true\)',
            re.IGNORECASE
        ),
        # string.find(path, "pattern") - regex path patterns
        'string_find_regex': re.compile(
            r'(?:\(string\.find\)|string\.find)\s*\([^,]+,\s*["\']([^"\']+)["\'](?:\s*\)|\s*~=)',
            re.IGNORECASE
        ),
        # :find("pattern", 1, true) - method call literal
        'find_method_literal': re.compile(
            r':find\s*\(\s*["\']([^"\']+)["\'],\s*1,\s*true\)',
            re.IGNORECASE
        ),
        # :find("pattern") - method call regex
        'find_method_regex': re.compile(
            r':find\s*\(\s*["\']([^"\']+)["\'](?:\s*\)|\s*~=)',
            re.IGNORECASE
        ),
        # Process name comparisons: == "process.exe"
        'process_name': re.compile(
            r'(?:processname|CONTEXT_DATA_PROCESSNAME)[^=]*==\s*["\']([^"\']+\.exe)["\']',
            re.IGNORECASE
        ),
        # MITRE techniques: "T1234" or "T1234.001"
        'mitre_technique': re.compile(
            r'["\']([Tt]\d{4}(?:\.\d{3})?)["\']'
        ),
        # ASR GUID references
        'asr_guid': re.compile(
            r'["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']'
        ),
        # Native function calls: IsRmmToolFilePath, IsRmmToolVersionInfo, etc.
        'native_function': re.compile(
            r'\b(Is[A-Z][a-zA-Z]+(?:FilePath|VersionInfo|OFN|Process|Path|File|Tool|Ext))\s*\('
        ),
        # Registry keys: HKLM\, HKCU\, etc.
        'registry_key': re.compile(
            r'["\']((HK[A-Z]{1,3}|HKEY_[A-Z_]+)\\[^"\']+)["\']',
            re.IGNORECASE
        ),
        # File extensions in checks
        'file_extension': re.compile(
            r'(?:l_\d+_\d+|ext|extension)\s*==\s*["\'](\w{2,5})["\']',
            re.IGNORECASE
        ),
        # Domains/URLs - must have valid structure with actual domain name + TLD
        'domain': re.compile(
            r'["\']([a-zA-Z0-9][-a-zA-Z0-9]{2,}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.(com|net|org|io|co|gov|edu|info|biz|us|uk|de|fr|ru|cn|jp|br|au|in|ca|es|it|nl|pl|se|ch|be|at))["\']',
            re.IGNORECASE
        ),
        # Environment variables
        'env_variable': re.compile(
            r'["\'](%[^%]+%)["\']'
        ),
    }

    # Known process names to look for
    KNOWN_PROCESSES = {
        'outlook.exe', 'olk.exe', 'msedgewebview2.exe', 'winword.exe',
        'excel.exe', 'powerpnt.exe', 'msaccess.exe', 'mspub.exe',
        'visio.exe', 'onenote.exe', 'acrord32.exe', 'acrobat.exe',
        'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
        'msiexec.exe', 'psexec.exe', 'wmiprvse.exe', 'lsass.exe',
    }

    # Known file extensions
    KNOWN_EXTENSIONS = {
        'exe', 'dll', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'com', 'scr',
        'pif', 'hta', 'wsf', 'jse', 'vbe', 'msi', 'msp', 'lnk', 'iso',
        'img', 'vhd', 'vhdx', 'zip', 'rar', '7z', 'cab', 'arj',
    }

    def __init__(self, primary_guid: Optional[str] = None):
        """
        Initialize extractor.

        Args:
            primary_guid: The primary ASR GUID for this script (to exclude from related GUIDs)
        """
        self.primary_guid = primary_guid.lower() if primary_guid else None

    def extract_from_source(self, source: str) -> ExtractedPatterns:
        """
        Extract all patterns from decompiled Lua source code.

        Args:
            source: Decompiled Lua source code

        Returns:
            ExtractedPatterns with all extracted data
        """
        patterns = ExtractedPatterns()

        if not source:
            return patterns

        # Extract path patterns (both exclusions and detections)
        self._extract_path_patterns(source, patterns)

        # Extract process names
        self._extract_process_names(source, patterns)

        # Extract MITRE techniques
        self._extract_mitre_techniques(source, patterns)

        # Extract related ASR GUIDs
        self._extract_asr_guids(source, patterns)

        # Extract native function calls
        self._extract_native_functions(source, patterns)

        # Extract registry keys
        self._extract_registry_keys(source, patterns)

        # Extract file extensions
        self._extract_file_extensions(source, patterns)

        # Extract domains
        self._extract_domains(source, patterns)

        # Extract vulnerable drivers (for VulnerableDrivers ASR rule)
        self._extract_vulnerable_drivers(source, patterns)

        # Extract RMM tool data (for RMMTools ASR rule)
        self._extract_rmm_data(source, patterns)

        return patterns

    def _extract_path_patterns(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract file path patterns from the source."""
        # First, look for structured function definitions (GetPathExclusions, GetMonitoredLocations)
        self._extract_structured_paths(source, patterns)

        # Extract paths from ExpandEnvironmentVariables calls
        # These are detection targets like %SystemDrive%\inetpub\wwwroot or exclusion bases
        env_path_pattern = re.compile(
            r'ExpandEnvironmentVariables\s*\(\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for match in env_path_pattern.finditer(source):
            path = match.group(1)
            if self._is_valid_path_pattern(path) and ('\\' in path or '%' in path):
                normalized = self._normalize_path(path)
                if not self._is_internal_logic_path(normalized):
                    # Look at context to determine if detection or exclusion
                    start_pos = match.start()
                    context = source[max(0, start_pos-100):start_pos+300]
                    if 'IsFileExists' in context or 'GetIisInstallPaths' in context:
                        patterns.detection_paths.add(normalized)
                    elif 'IsPathExcluded' in context or 'exclusion' in context.lower():
                        patterns.exclusion_paths.add(normalized)
                    else:
                        # Default: add as detection path for env variable paths with subpaths
                        patterns.detection_paths.add(normalized)

        # Extract paths from string concatenation patterns like: l_0_4 .. 'clientaccess\\oab\\temp\\'
        concat_path_pattern = re.compile(
            r'\.\.\s*["\']([^"\']*\\[^"\']+)["\']',
            re.IGNORECASE
        )
        for match in concat_path_pattern.finditer(source):
            path = match.group(1)
            if self._is_valid_path_pattern(path) and len(path) > 5:
                patterns.detection_paths.add(self._normalize_path(path))

        # Then extract from string.find patterns with line-level context
        lines = source.split('\n')
        path_contexts = []  # (path, is_exclusion)

        for i, line in enumerate(lines):
            # Look for string.find or :find with a path pattern
            for pattern in ['string_find_literal', 'string_find_regex',
                            'find_method_literal', 'find_method_regex']:
                for match in self.PATTERNS[pattern].finditer(line):
                    path = match.group(1)
                    if not self._is_valid_path_pattern(path):
                        continue

                    # Check if this is a "not ... find()" pattern
                    # "if not path:find('pattern')" means pattern is an exclusion
                    # (if pattern matches, execution skips to return CLEAN)
                    has_not_prefix = bool(re.search(
                        r'\bnot\b.*(?::find|string\.find)',
                        line, re.IGNORECASE
                    ))

                    # Look at surrounding lines to determine context
                    # Use wider window (8 lines) for nested if/else chains
                    context_lines = '\n'.join(lines[i:i+9])

                    # Exclusion: path match followed by "return mp.CLEAN" or "not" prefix
                    is_exclusion = has_not_prefix or bool(re.search(
                        r'(?:return\s+(?:false|1|true|mp\.CLEAN))',
                        context_lines, re.IGNORECASE
                    ))

                    # Detection: path match followed by attribute setting or INFECTED
                    is_detection = bool(re.search(
                        r'(?:mp\.set_mpattribute|bm\.add|mp\.INFECTED|return\s+0\b|ReportLowfi|trigger_sig)',
                        context_lines, re.IGNORECASE
                    ))

                    path_contexts.append((path, is_exclusion, is_detection))

        # Classify paths - exclusion wins if both match
        for path, is_exclusion, is_detection in path_contexts:
            normalized = self._normalize_path(path)
            # Skip if already classified by structured extraction
            if normalized in patterns.exclusion_paths or normalized in patterns.detection_paths:
                continue

            # Filter out broad internal logic patterns from detection paths
            if self._is_internal_logic_path(normalized):
                continue

            if is_exclusion and not is_detection:
                patterns.exclusion_paths.add(normalized)
            elif is_detection and not is_exclusion:
                patterns.detection_paths.add(normalized)
            elif is_exclusion:
                # Both match - default to exclusion (safer)
                patterns.exclusion_paths.add(normalized)
            else:
                # Neither clear context - default to detection
                patterns.detection_paths.add(normalized)

    def _extract_structured_paths(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract paths from structured Lua functions like GetPathExclusions and GetMonitoredLocations."""
        # Helper to extract table entries from a function body
        table_entry_re = re.compile(r'(?:l_\d+_\d+|\{\})\s*\[["\']([^"\']+)["\']\]\s*=')
        key_entry_re = re.compile(r'\[["\']([^"\']+)["\']\]\s*=')

        # GetPathExclusions - these are exclusions
        func_body = extract_lua_function_body(source, 'GetPathExclusions')
        if func_body:
            for match in table_entry_re.finditer(func_body):
                path = match.group(1)
                if self._is_valid_path_pattern(path):
                    patterns.exclusion_paths.add(self._normalize_path(path))

        # GetMonitoredLocations - these are detections
        monitored_body = extract_lua_function_body(source, 'GetMonitoredLocations')
        if monitored_body:
            for match in table_entry_re.finditer(monitored_body):
                path = match.group(1)
                normalized = self._normalize_path(path)
                if self._is_valid_path_pattern(path) and not self._is_internal_logic_path(normalized):
                    patterns.detection_paths.add(normalized)

        # GetCommandLineRegExp - single return value
        cmdline_body = extract_lua_function_body(source, 'GetCommandLineRegExp')
        if cmdline_body:
            ret_match = re.search(r'return\s*["\']([^"\']+)["\']', cmdline_body)
            if ret_match:
                patterns.command_patterns.add(ret_match.group(1))

        # GetCommandLineExclusions
        func_body = extract_lua_function_body(source, 'GetCommandLineExclusions')
        if func_body:
            for match in table_entry_re.finditer(func_body):
                pattern = match.group(1)
                if len(pattern) > 5:
                    patterns.command_patterns.add(f"EXCL: {pattern}")

        # GetCommandLineRegExpList
        func_body = extract_lua_function_body(source, 'GetCommandLineRegExpList')
        if func_body:
            for match in table_entry_re.finditer(func_body):
                pattern = match.group(1)
                if len(pattern) > 5:
                    patterns.command_patterns.add(pattern)

        # GetPathInclusions - detection targets
        func_body = extract_lua_function_body(source, 'GetPathInclusions')
        if func_body:
            for match in key_entry_re.finditer(func_body):
                path = match.group(1)
                normalized = self._normalize_path(path)
                if self._is_valid_path_pattern(path):
                    patterns.detection_paths.add(normalized)
                    exe_match = re.search(r'([^\\]+\.exe)$', path, re.IGNORECASE)
                    if exe_match:
                        patterns.process_names.add(exe_match.group(1).lower())

        # GetCommandLineInclusions
        func_body = extract_lua_function_body(source, 'GetCommandLineInclusions')
        if func_body:
            for match in key_entry_re.finditer(func_body):
                pattern = match.group(1)
                if len(pattern) > 5:
                    patterns.command_patterns.add(pattern)

        # Extract process names from GetMonitoredLocations paths
        if monitored_body:
            for match in re.finditer(r'\\([^\\]+\.exe)["\']', monitored_body, re.IGNORECASE):
                patterns.process_names.add(match.group(1).lower())

    def _extract_process_names(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract process names from the source."""
        # From explicit comparisons
        for match in self.PATTERNS['process_name'].finditer(source):
            proc = match.group(1).lower()
            patterns.process_names.add(proc)

        # Look for known processes in string literals
        source_lower = source.lower()
        for proc in self.KNOWN_PROCESSES:
            if f'"{proc}"' in source_lower or f"'{proc}'" in source_lower:
                patterns.process_names.add(proc)

        # Look for variable == 'process.exe' or ~= 'process.exe' patterns
        # This catches patterns like: l_0_2 == 'psexesvc.exe'
        var_proc_pattern = re.compile(
            r'(?:l_\d+_\d+|tmp\d*)\s*(?:==|~=)\s*["\']([^"\']+\.exe)["\']',
            re.IGNORECASE
        )
        for match in var_proc_pattern.finditer(source):
            proc = match.group(1).lower()
            if proc and len(proc) > 4:  # Filter very short names
                patterns.process_names.add(proc)

        # Extract from inline boolean tables: {['cmd.exe'] = true, ['powershell.exe'] = true, ...}
        proc_table_pattern = re.compile(
            r"\{(\['[^}]+\.exe[^}]*)\}",
            re.DOTALL
        )
        for match in proc_table_pattern.finditer(source):
            table_content = match.group(1)
            keys = re.findall(r"\['([^']+)'\]", table_content)
            for key in keys:
                key_lower = key.lower()
                if key_lower.endswith('.exe') or key_lower.endswith('.sys'):
                    patterns.process_names.add(key_lower)

        # Look for GetOriginalFileName comparisons
        ofn_pattern = re.compile(
            r'GetOriginalFileName\s*\([^)]*\)\s*(?:==|~=)\s*["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for match in ofn_pattern.finditer(source):
            filename = match.group(1).lower()
            if filename.endswith('.exe') or filename.endswith('.c') or '.' not in filename:
                patterns.process_names.add(filename)

    def _extract_mitre_techniques(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract MITRE ATT&CK technique IDs."""
        # Standard pattern: "T1234" or "T1234.001"
        for match in self.PATTERNS['mitre_technique'].finditer(source):
            technique = match.group(1).upper()
            patterns.mitre_techniques.add(technique)

        # Also look for TrackPidAndTechniqueBM calls which contain techniques
        track_pattern = re.compile(r'TrackPidAndTechnique[A-Z]*\s*\([^,]+,\s*["\']([Tt]\d{4}(?:\.\d{3})?)["\']')
        for match in track_pattern.finditer(source):
            patterns.mitre_techniques.add(match.group(1).upper())

        # Look for technique IDs in bm.trigger_sig or mp.set_mpattribute calls
        attr_pattern = re.compile(r'(?:bm\.trigger_sig|mp\.set_mpattribute)\s*\([^)]*([Tt]\d{4}(?:\.\d{3})?)')
        for match in attr_pattern.finditer(source):
            patterns.mitre_techniques.add(match.group(1).upper())

    def _extract_asr_guids(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract related ASR GUIDs (only known ASR rules, not org IDs or other GUIDs)."""
        # Known ASR rule GUIDs
        known_asr_guids = {
            "56a863a9-875e-4185-98a7-b882c64b5ce5",
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
            "01443614-cd74-433a-b99e-2ecdc07bfc25",
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
            "d3e037e1-3eb8-44c8-a917-57927947596d",
            "3b576869-a4ec-4529-8536-b80a7769e899",
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
            "26190899-1602-49e8-8b27-eb1d0a1ce869",
            "e6db77e5-3df2-4cf1-b95a-636979351e5b",
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",
            "33ddedf1-c6e0-47cb-833e-de6133960387",
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
            "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
            "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
            "c1db55ab-c21a-4637-bb3f-a12568109d35",
            "1081f0b6-3e1e-4f44-acce-816d65112d99",
        }

        for match in self.PATTERNS['asr_guid'].finditer(source):
            guid = match.group(1).lower()
            # Only include if it's a known ASR rule and not the primary GUID
            if guid != self.primary_guid and guid in known_asr_guids:
                patterns.related_asr_guids.add(guid)

    def _extract_native_functions(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract calls to native Defender functions."""
        for match in self.PATTERNS['native_function'].finditer(source):
            func = match.group(1)
            patterns.native_functions.add(func)

        # Also look for specific known functions
        known_natives = [
            'IsRmmToolFilePath', 'IsRmmToolVersionInfo', 'IsRmmToolOFN',
            'IsSuspiciousFileExt', 'IsArchiveFileExt', 'IsExecutableFileExt',
            'IsWebmailDownloadUrlIoavAndMotwV0', 'IsLnkPointingtoSuspFileExt',
            'GetTaintLevelHR', 'IsOfficeProcess', 'IsScriptInterpreter',
        ]
        for func in known_natives:
            if func in source:
                patterns.native_functions.add(func)

    def _extract_registry_keys(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract registry key patterns."""
        for match in self.PATTERNS['registry_key'].finditer(source):
            key = match.group(1)
            patterns.registry_keys.add(key)

    def _extract_file_extensions(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract file extensions."""
        # Only match clear extension checks with explicit variable names
        for match in self.PATTERNS['file_extension'].finditer(source):
            ext = match.group(1).lower()
            if ext in self.KNOWN_EXTENSIONS:
                patterns.file_extensions.add(ext)

        # Look for extension checks in context (e.g., :sub(-3) == "exe" or GetFileExtension patterns)
        # Require context that suggests extension check, not arbitrary string comparison
        ext_context_pattern = re.compile(
            r'(?:GetFileExtension|:sub\s*\(\s*-\d+\s*\)|fileext|file_ext|\.ext)\s*(?:==|~=)\s*["\']\.?(\w{2,5})["\']',
            re.IGNORECASE
        )
        for match in ext_context_pattern.finditer(source):
            ext = match.group(1).lower().lstrip('.')
            if ext in self.KNOWN_EXTENSIONS:
                patterns.file_extensions.add(ext)

        # Extract from inline boolean tables: {['.bat'] = true, ['.cmd'] = true, ...}
        # These are lookup tables used for extension checks
        bool_table_pattern = re.compile(
            r"\{(\['\.[^}]+)\}",
            re.DOTALL
        )
        for match in bool_table_pattern.finditer(source):
            table_content = match.group(1)
            keys = re.findall(r"\['(\.[^']+)'\]", table_content)
            if keys and all(k.startswith('.') for k in keys[:3]):
                for key in keys:
                    ext = key.lstrip('.').lower()
                    if ext and len(ext) <= 20:  # Allow longer extensions like settingcontent-ms
                        patterns.file_extensions.add(ext)

    def _extract_domains(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract domain names."""
        for match in self.PATTERNS['domain'].finditer(source):
            domain = match.group(1).lower()
            # Filter out common false positives
            if not self._is_false_positive_domain(domain):
                patterns.domains.add(domain)

    def _is_valid_path_pattern(self, path: str) -> bool:
        """Check if a string looks like a valid path pattern."""
        if not path or len(path) < 3:
            return False
        # Should contain backslash or look like a path
        if '\\' not in path and '/' not in path and '.' not in path:
            return False
        # Filter out very short patterns that are likely false positives
        if len(path) < 5 and '\\' not in path:
            return False
        # Filter out patterns that are just variable placeholders
        if path.startswith('%') and path.endswith('%'):
            return False
        return True

    def _normalize_path(self, path: str) -> str:
        """Normalize a path pattern for display."""
        # Convert Lua regex escapes to readable format
        path = path.replace('%.', '.')
        path = path.replace('%+', '+')
        path = path.replace('%-', '-')
        path = path.replace('%[', '[')
        path = path.replace('%]', ']')
        return path

    def _is_internal_logic_path(self, path: str) -> bool:
        """Check if a path pattern is internal scope logic rather than a specific detection target."""
        path_lower = path.lower()

        # Very broad system folder patterns - these are scope checks, not detection targets
        # These match patterns like: ^.:\windows\ or ^.:\\windows\\
        broad_patterns = [
            r'^\^?\.\s*:\\+\s*windows\\*$',
            r'^\^?\.\s*:\\+\s*program files\\*$',
            r'^\^?\.\s*:\\+\s*program files \(x86\)\\*$',
            r'^\^?\.\s*:\\+\s*programdata\\*$',
            r'^\^?\.\s*:\\+\s*users\\*$',
            r'^\^?\.\s*:\\+$',  # Just drive root like ^.:\
            r'^\^?\.\s*:$',     # Just drive letter
            r'^%systemroot%\\*$',
            r'^%programfiles%\\*$',
            r'^%programdata%\\*$',
            r'^%userprofile%\\*$',
        ]

        for pattern in broad_patterns:
            if re.match(pattern, path_lower):
                return True

        # Only filter specific known broad system folder names that are scope checks
        # Do NOT filter specific folder names like \doc\, \dell\, \adminarsenal\ etc.
        broad_folder_names = {
            'windows', 'users', 'program files', 'program files (x86)',
            'programdata', 'system32', 'syswow64', 'temp', 'tmp',
        }
        # Match \foldername\ or \foldername patterns at the start
        folder_match = re.match(r'^\\*([^\\]+)\\*$', path_lower)
        if folder_match and folder_match.group(1) in broad_folder_names:
            return True

        return False

    def _is_false_positive_domain(self, domain: str) -> bool:
        """Check if a domain is likely a false positive."""
        false_positives = {
            'mp.clean', 'mp.infected', 'string.find', 'string.lower',
            'string.match', 'string.len', 'table.insert', 'bm.get',
        }
        if domain in false_positives:
            return True
        if domain.endswith('.lua') or domain.endswith('.exe'):
            return True
        # Very short domains are likely false positives
        if len(domain) < 8:
            return True
        # Must have at least one dot with content on both sides
        parts = domain.split('.')
        if len(parts) < 2 or any(len(p) < 2 for p in parts):
            return True
        return False

    def _extract_vulnerable_drivers(self, source: str, patterns: ExtractedPatterns) -> None:
        """Extract vulnerable driver names from ASR VulnerableDrivers scripts."""
        # Only process scripts that are driver-related
        if '_asr_driver' not in source and 'isdriver' not in source.lower():
            return

        # Primary pattern: 'drivername_asr_driver' string markers
        # These appear as attribute names like mp.set_mpattribute('Drivername_asr_driver')
        # and are the most reliable/complete source of driver names
        asr_driver_pattern = re.compile(r"'([^']+)_asr_driver'", re.IGNORECASE)
        for match in asr_driver_pattern.finditer(source):
            driver_name = match.group(1).lower()
            if driver_name and len(driver_name) > 2:
                patterns.vulnerable_drivers.add(driver_name)

        # Secondary pattern: {key = 'DisplayName', ...} lookup tables
        # These map lowercase driver names to display names
        table_pattern = re.compile(
            r'\{(\w+\s*=\s*\'[^\']+\'(?:\s*,\s*\w+\s*=\s*\'[^\']+\')+)\}',
            re.DOTALL
        )
        for match in table_pattern.finditer(source):
            entries = re.findall(r"(\w+)\s*=\s*'([^']+)'", match.group(1))
            if len(entries) >= 5:  # Only large tables are driver lookup tables
                for driver_key, display_name in entries:
                    patterns.vulnerable_drivers.add(driver_key.lower())

    def _extract_rmm_data(self, source: str, patterns: ExtractedPatterns) -> None:
        """
        Extract RMM tool data from IsRmmTool* function definitions.

        This extracts data from function definitions like:
        IsRmmToolFilePath = function(...)
            {}[1] = "\\pdq\\pdqdeployrunner\\"
            {}[2] = "\\anydesk\\"
            ...
        end
        """
        # Data entry patterns
        array_entry_re = re.compile(r'\{\}\[\d+\]\s*=\s*["\']([^"\']+)["\']')
        ipairs_table_re = re.compile(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)')

        def _extract_entries(body: str) -> Set[str]:
            """Extract string entries from a function body (array or ipairs format)."""
            entries: Set[str] = set()
            for m in array_entry_re.finditer(body):
                entries.add(m.group(1))
            for m in ipairs_table_re.finditer(body):
                for val in re.findall(r'["\']([^"\']+)["\']', m.group(1)):
                    entries.add(val)
            return entries

        body = extract_lua_function_body(source, 'IsRmmToolFilePath')
        if body:
            patterns.rmm_file_paths.update(_extract_entries(body))

        body = extract_lua_function_body(source, 'IsRmmToolVersionInfo')
        if body:
            patterns.rmm_version_info.update(_extract_entries(body))

        body = extract_lua_function_body(source, 'IsRmmToolOFN')
        if body:
            patterns.rmm_original_filenames.update(_extract_entries(body))


def extract_patterns_from_scripts(scripts: List[str], primary_guid: Optional[str] = None) -> ExtractedPatterns:
    """
    Extract patterns from multiple Lua scripts and merge results.

    Args:
        scripts: List of decompiled Lua source code strings
        primary_guid: The primary ASR GUID (to exclude from related GUIDs)

    Returns:
        Merged ExtractedPatterns from all scripts
    """
    extractor = LuaPatternExtractor(primary_guid)
    merged = ExtractedPatterns()

    for source in scripts:
        if source:
            patterns = extractor.extract_from_source(source)
            merged.merge(patterns)

    return merged


def merge_external_function_data(patterns: ExtractedPatterns, external_data: Dict[str, List[str]]) -> None:
    """
    Merge external function data (from FunctionRegistry) into ExtractedPatterns.

    This links function calls to their definitions when they exist in separate scripts.

    Args:
        patterns: ExtractedPatterns to update
        external_data: Dictionary mapping function names to their data entries
                       e.g. {"IsRmmToolFilePath": ["\\pdq\\", "\\anydesk\\", ...]}
    """
    for func_name, data_entries in external_data.items():
        # RMM Tool functions
        if func_name == 'IsRmmToolFilePath':
            patterns.rmm_file_paths.update(data_entries)
        elif func_name == 'IsRmmToolVersionInfo':
            patterns.rmm_version_info.update(data_entries)
        elif func_name == 'IsRmmToolOFN':
            patterns.rmm_original_filenames.update(data_entries)
        # Path-related functions
        elif func_name == 'GetPathExclusions':
            patterns.exclusion_paths.update(data_entries)
        elif func_name == 'GetMonitoredLocations':
            patterns.detection_paths.update(data_entries)
        # File extension functions
        elif func_name in ('IsSuspiciousFileExt', 'IsArchiveFileExt', 'IsExecutableFileExt'):
            patterns.file_extensions.update(data_entries)
        # Process-related functions
        elif func_name in ('IsOfficeProcess', 'IsScriptInterpreter'):
            patterns.process_names.update(data_entries)
        # For any other discovered functions, add to detection_paths as a fallback
        # (these might contain indicators we want to capture)
