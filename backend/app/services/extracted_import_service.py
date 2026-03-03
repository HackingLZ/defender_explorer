"""Service for importing pre-extracted data (ASR scripts, IOCs, hashes, etc.)."""

import os
import re
import hashlib
import logging
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import select, update

logger = logging.getLogger(__name__)

from ..models import ASRRule, LuaScript, Threat, FunctionDefinition, FUNCTION_MAPPINGS
from ..database import async_session_maker
from .lua_pattern_extractor import extract_patterns_from_scripts, merge_external_function_data, ExtractedPatterns
from .function_registry_service import FunctionRegistryService


# Mapping of ASR rule names to GUIDs (for scripts that use GetRuleInfo)
ASR_RULE_NAME_TO_GUID = {
    "block abuse of exploited vulnerable signed drivers": "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "block adobe reader from creating child processes": "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "block all office applications from creating child processes": "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "block credential stealing from lsass.exe": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "block executable content from email client and webmail": "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "block executable files from running unless they meet a prevalence, age, or trusted list criterion": "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "block execution of potentially obfuscated scripts": "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "block javascript or vbscript from launching downloaded executable content": "d3e037e1-3eb8-44c8-a917-57927947596d",
    "block office applications from creating executable content": "3b576869-a4ec-4529-8536-b80a7769e899",
    "block office applications from injecting code into other processes": "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "block office communication application from creating child processes": "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "block persistence through wmi event subscription": "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "block process creations originating from psexec and wmi commands": "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    "block rebooting machine in safe mode": "33ddedf1-c6e0-47cb-833e-de6133960387",
    "block untrusted and unsigned processes that run from usb": "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "block use of copied or impersonated system tools": "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
    "block webshell creation for servers": "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
    "block win32 api calls from office macros": "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "use advanced protection against ransomware": "c1db55ab-c21a-4637-bb3f-a12568109d35",
    "block execution of files related to remote monitoring & management tools": "1081f0b6-3e1e-4f44-acce-816d65112d99",
}


@dataclass
class ExtractedImportStats:
    """Statistics from extracted data import."""
    asr_rules: int = 0
    lua_scripts: int = 0
    threats: int = 0
    errors: List[str] = field(default_factory=list)


class ExtractedImportService:
    """Service for importing pre-extracted data."""

    def __init__(self, db: AsyncSession, extracted_path: str = "/data/extracted"):
        self.db = db
        self.extracted_path = Path(extracted_path)

    async def import_all(self) -> ExtractedImportStats:
        """Import all extracted data."""
        stats = ExtractedImportStats()

        try:
            await self.import_threats(stats)
        except Exception as e:
            stats.errors.append(f"Threat import error: {e}")

        try:
            await self.import_lua_scripts(stats)
        except Exception as e:
            stats.errors.append(f"Lua import error: {e}")

        try:
            await self.import_asr_scripts(stats)
        except Exception as e:
            stats.errors.append(f"ASR import error: {e}")

        await self.db.commit()
        return stats

    async def import_threats(self, stats: ExtractedImportStats) -> None:
        """Import threats from extracted data."""
        threats_dir = self.extracted_path / "threats"
        if not threats_dir.exists():
            return

        batch = []
        batch_size = 500

        # Walk through category/family structure
        for category_dir in threats_dir.iterdir():
            if not category_dir.is_dir():
                continue
            category = category_dir.name

            for family_dir in category_dir.iterdir():
                if not family_dir.is_dir():
                    continue
                family = family_dir.name

                # Look for _combined.sig files
                sig_file = family_dir / "_combined.sig"
                if not sig_file.exists():
                    continue

                try:
                    content = sig_file.read_text(errors="replace")

                    # Parse signature ID from content
                    sig_id_match = re.search(r"Signature ID: (0x[0-9a-fA-F]+)", content)
                    sig_id = int(sig_id_match.group(1), 16) if sig_id_match else hash(f"{category}/{family}") & 0x7FFFFFFF

                    # Parse threat name from comment
                    threat_match = re.search(r"#ALF:([^\s]+)", content)
                    threat_name = threat_match.group(1) if threat_match else f"{category}:{family}"

                    # Parse signature count
                    sig_count_match = re.search(r"Signatures: (\d+)", content)
                    sig_count = int(sig_count_match.group(1)) if sig_count_match else 0

                    batch.append({
                        "signature_id": sig_id,
                        "threat_name": threat_name,
                        "category": category,
                        "family": family,
                        "signature_count": sig_count,
                    })

                    if len(batch) >= batch_size:
                        await self._insert_threats_batch(batch)
                        stats.threats += len(batch)
                        batch = []

                except Exception:
                    pass

        # Insert remaining batch
        if batch:
            await self._insert_threats_batch(batch)
            stats.threats += len(batch)

    async def _insert_threats_batch(self, batch: List[dict]) -> None:
        """Insert a batch of threats."""
        for item in batch:
            try:
                stmt = insert(Threat).values(**item).on_conflict_do_update(
                    index_elements=["signature_id"],
                    set_={
                        "threat_name": item["threat_name"],
                        "category": item["category"],
                        "family": item["family"],
                        "signature_count": item["signature_count"],
                    }
                )
                await self.db.execute(stmt)
            except Exception:
                await self.db.rollback()
        try:
            await self.db.commit()
        except Exception:
            await self.db.rollback()

    async def import_lua_scripts(self, stats: ExtractedImportStats) -> None:
        """Import Lua scripts from extracted lua/ directory."""
        lua_dir = self.extracted_path / "lua"
        if not lua_dir.exists():
            return

        batch = []
        batch_size = 500

        # Walk through all .lua files
        for lua_file in lua_dir.rglob("*.lua"):
            try:
                content = lua_file.read_text(errors="replace")
                # Remove null bytes and other problematic characters
                content = content.replace('\x00', '').replace('\x13', '').replace('\x0f', '')
                bytecode_hash = hashlib.sha256(content.encode()).hexdigest()

                # Extract ASR GUIDs using multiple patterns
                asr_guids = self._extract_asr_guids_from_content(content)

                batch.append({
                    "bytecode_hash": bytecode_hash,
                    "decompiled_source": content[:100000],  # Limit size
                    "asr_guids": asr_guids,
                })

                if len(batch) >= batch_size:
                    await self._insert_lua_batch(batch)
                    stats.lua_scripts += len(batch)
                    batch = []

            except Exception:
                pass

        # Insert remaining batch
        if batch:
            await self._insert_lua_batch(batch)
            stats.lua_scripts += len(batch)

    def _extract_asr_guids_from_content(self, content: str) -> List[str]:
        """Extract ASR GUIDs from Lua script content using multiple patterns."""
        asr_guids = set()

        # Pattern 1: "-- ASR Rule GUID: xxx"
        asr_match = re.search(r"-- ASR Rule GUID:\s*([0-9a-fA-F-]{36})", content)
        if asr_match:
            asr_guids.add(asr_match.group(1).lower())

        # Pattern 2: "-- ASR: xxx,yyy"
        asr_match = re.search(r"-- ASR:\s*(.+)", content)
        if asr_match:
            for g in asr_match.group(1).split(","):
                g = g.strip().lower()
                if re.match(r'^[0-9a-f-]{36}$', g):
                    asr_guids.add(g)

        # Pattern 3: Look for IsHipsRuleEnabled calls
        hips_matches = re.findall(r'IsHipsRuleEnabled\s*\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', content)
        for g in hips_matches:
            asr_guids.add(g.lower())

        # Pattern 4: Look for mp.IsHipsRuleEnabled calls
        hips_matches = re.findall(r'\(mp\.IsHipsRuleEnabled\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']', content)
        for g in hips_matches:
            asr_guids.add(g.lower())

        # Pattern 5: GetRuleInfo function with rule name (supports both .Name and {Name formats)
        rule_info_match = re.search(r'GetRuleInfo\s*=\s*function.*?(?:\.Name|\{Name)\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
        if rule_info_match:
            rule_name = rule_info_match.group(1).lower().strip()
            if rule_name in ASR_RULE_NAME_TO_GUID:
                asr_guids.add(ASR_RULE_NAME_TO_GUID[rule_name])

        # Pattern 6: l_x_y.Name = "rule name" (common pattern in decompiled scripts)
        name_matches = re.findall(r'l_\d+_\d+\.Name\s*=\s*["\']([^"\']+)["\']', content)
        for name in name_matches:
            name_lower = name.lower().strip()
            if name_lower in ASR_RULE_NAME_TO_GUID:
                asr_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

        # Pattern 7: Table literal with Name key: return {Name = "rule name", ...}
        name_matches = re.findall(r'return\s*\{[^}]*Name\s*=\s*["\']([^"\']+)["\']', content, re.DOTALL)
        for name in name_matches:
            name_lower = name.lower().strip()
            if name_lower in ASR_RULE_NAME_TO_GUID:
                asr_guids.add(ASR_RULE_NAME_TO_GUID[name_lower])

        return list(asr_guids)

    async def _insert_lua_batch(self, batch: List[dict]) -> None:
        """Insert a batch of Lua scripts."""
        for item in batch:
            try:
                # If script has ASR GUIDs, use upsert to update existing
                if item.get("asr_guids"):
                    stmt = insert(LuaScript).values(**item).on_conflict_do_update(
                        index_elements=["bytecode_hash"],
                        set_={
                            "asr_guids": item["asr_guids"],
                            "decompiled_source": item["decompiled_source"],
                        }
                    )
                else:
                    stmt = insert(LuaScript).values(**item).on_conflict_do_nothing()
                await self.db.execute(stmt)
            except Exception:
                await self.db.rollback()
        try:
            await self.db.commit()
        except Exception:
            await self.db.rollback()

    def _find_function_definition_scripts(self) -> Dict[str, List[str]]:
        """
        Find scripts that contain function definitions and extract their data.

        Searches all Lua scripts (not just ASR-associated ones) for function
        definitions that contain data tables.

        Supports multiple patterns:
        - {}[n] = "value" pattern
        - ipairs({'value1', 'value2', ...}) pattern
        - Table assignments: l_x_y["key"] = value pattern

        This auto-discovers ALL function definitions with data tables, including:
        - IsRmmToolFilePath, IsRmmToolVersionInfo, IsRmmToolOFN
        - Any other Is* functions with embedded data

        Returns:
            Dictionary mapping function names to their extracted data entries
        """
        function_data: Dict[str, List[str]] = {}
        lua_dir = self.extracted_path / "lua"

        # Pattern to extract data entries from function bodies - multiple formats
        # Pattern 1: {}[n] = "value" or {}[n] = 'value'
        data_entry_pattern1 = re.compile(r'\{\}\[\d+\]\s*=\s*["\']([^"\']+)["\']')
        # Pattern 2: ipairs({'value1', 'value2', ...}) - table literals in ipairs
        ipairs_table_pattern = re.compile(r'ipairs\s*\(\s*\{([^}]+)\}\s*\)')
        # Pattern 3: l_x_y["key"] = value (table key assignments)
        table_key_pattern = re.compile(r'(?:l_\d+_\d+|\{\})\s*\[["\']([^"\']+)["\']\]\s*=')

        # Generic pattern to find ALL function definitions
        # Matches: FuncName = function(...)...end where FuncName starts with Is or Get
        generic_func_pattern = re.compile(
            r'((?:Is|Get)[A-Za-z]+)\s*=\s*function\s*\([^)]*\)(.*?)(?:\nend|\bend\b)',
            re.DOTALL
        )

        # Known functions we specifically look for (prioritized)
        known_functions = [
            'IsRmmToolFilePath',
            'IsRmmToolVersionInfo',
            'IsRmmToolOFN',
            'IsSuspiciousFileExt',
            'IsArchiveFileExt',
            'IsExecutableFileExt',
            'IsOfficeProcess',
            'IsScriptInterpreter',
            'GetPathExclusions',
            'GetMonitoredLocations',
        ]

        # Search all lua directories
        search_dirs = [lua_dir]
        asr_dir = self.extracted_path / "asr"
        lolbin_dir = self.extracted_path / "lolbin"
        for d in [asr_dir, lolbin_dir]:
            if d.exists():
                search_dirs.append(d)

        discovered_functions = set()

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue

            for lua_file in search_dir.rglob("*.lua"):
                try:
                    content = lua_file.read_text(errors="replace")
                    content = content.replace('\x00', '').replace('\x13', '').replace('\x0f', '')

                    # Find all function definitions
                    for match in generic_func_pattern.finditer(content):
                        func_name = match.group(1)
                        body = match.group(2)
                        entries = []

                        # Pattern 1: {}[n] = "value"
                        entries.extend([m.group(1) for m in data_entry_pattern1.finditer(body)])

                        # Pattern 2: ipairs table literals - extract all string values
                        for ipairs_match in ipairs_table_pattern.finditer(body):
                            table_content = ipairs_match.group(1)
                            # Extract all quoted strings from the table
                            string_values = re.findall(r'["\']([^"\']+)["\']', table_content)
                            entries.extend(string_values)

                        # Pattern 3: Table key assignments
                        entries.extend([m.group(1) for m in table_key_pattern.finditer(body)])

                        if entries:
                            discovered_functions.add(func_name)
                            if func_name not in function_data:
                                function_data[func_name] = []
                            function_data[func_name].extend(entries)
                            logger.info(
                                f"Found {func_name} with {len(entries)} entries in {lua_file}"
                            )

                except Exception as e:
                    logger.debug(f"Error reading {lua_file}: {e}")

        # Deduplicate entries
        for func_name in function_data:
            function_data[func_name] = list(set(function_data[func_name]))

        # Log discovered functions that weren't in our known list (potential additions)
        unknown_funcs = discovered_functions - set(known_functions)
        if unknown_funcs:
            logger.warning(
                f"Discovered function definitions not in known list: {unknown_funcs}. "
                f"Consider adding these to the resolver."
            )

        return function_data

    def _check_calls_external_functions(self, content: str, known_functions: List[str] = None) -> List[str]:
        """
        Check if a script calls external functions that may have separate definitions.

        Args:
            content: Decompiled Lua source code
            known_functions: Optional list of function names to check for (defaults to RMM functions)

        Returns:
            List of external function names that are called
        """
        if known_functions is None:
            # Default to RMM-related functions
            known_functions = [
                'IsRmmToolFilePath',
                'IsRmmToolVersionInfo',
                'IsRmmToolOFN',
            ]

        called = []
        for func in known_functions:
            if f'{func}(' in content:
                called.append(func)
        return called

    async def import_asr_scripts(self, stats: ExtractedImportStats) -> None:
        """Import ASR scripts from extracted data with cross-script function resolution."""
        asr_dir = self.extracted_path / "asr"
        if not asr_dir.exists():
            return

        # Known ASR rules
        from defender_sig_extractor.output.asr_writer import ASR_RULES

        # STEP 1: Find function definitions across all scripts
        logger.info("Searching for function definitions across all scripts...")
        function_data = self._find_function_definition_scripts()
        if function_data:
            logger.info(f"Found function definitions: {list(function_data.keys())}")
            for func_name, entries in function_data.items():
                logger.info(f"  {func_name}: {len(entries)} entries")

        for guid_dir in asr_dir.iterdir():
            if not guid_dir.is_dir():
                continue

            guid = guid_dir.name.lower()
            if guid not in ASR_RULES:
                continue

            rule_info = ASR_RULES[guid]

            # Collect lua scripts and their content
            lua_files = list(guid_dir.glob("*.lua"))
            script_count = len(lua_files)
            script_contents = []
            calls_external_functions = False

            # Import lua scripts and collect content for pattern extraction
            for lua_file in lua_files:
                try:
                    content = lua_file.read_text(errors="replace")
                    # Remove null bytes and problematic characters
                    content = content.replace('\x00', '').replace('\x13', '').replace('\x0f', '')
                    script_contents.append(content)
                    bytecode_hash = hashlib.sha256(content.encode()).hexdigest()

                    # Check if this script calls any of the discovered external functions
                    discovered_func_names = list(function_data.keys()) if function_data else None
                    if self._check_calls_external_functions(content, discovered_func_names):
                        calls_external_functions = True

                    # Extract threat name from comment
                    threat_name = None
                    match = re.search(r"-- Threat: (.+)", content)
                    if match:
                        threat_name = match.group(1)

                    # Use upsert to update asr_guids if script already exists
                    stmt = insert(LuaScript).values(
                        bytecode_hash=bytecode_hash,
                        decompiled_source=content,
                        asr_guids=[guid],
                    ).on_conflict_do_update(
                        index_elements=["bytecode_hash"],
                        set_={
                            "asr_guids": [guid],
                            "decompiled_source": content,
                        }
                    )
                    await self.db.execute(stmt)
                    stats.lua_scripts += 1
                except Exception:
                    pass

            # Extract patterns from all scripts for this ASR rule
            patterns = ExtractedPatterns()
            if script_contents:
                try:
                    patterns = extract_patterns_from_scripts(script_contents, guid)
                except Exception:
                    pass

            # STEP 2: Merge external function data if this rule calls external functions
            if calls_external_functions and function_data:
                logger.info(f"ASR rule {guid} calls external functions, merging data...")
                merge_external_function_data(patterns, function_data)
                logger.info(
                    f"  After merge: {len(patterns.rmm_file_paths)} file paths, "
                    f"{len(patterns.rmm_version_info)} version info, "
                    f"{len(patterns.rmm_original_filenames)} original filenames"
                )

            extracted_data = patterns.to_dict()

            # Upsert ASR rule with extracted patterns
            stmt = insert(ASRRule).values(
                guid=guid,
                name=rule_info.get("name"),
                short_name=rule_info.get("short_name"),
                description=rule_info.get("description"),
                script_count=script_count,
                extracted_data=extracted_data,
            ).on_conflict_do_update(
                index_elements=["guid"],
                set_={
                    "name": rule_info.get("name"),
                    "short_name": rule_info.get("short_name"),
                    "description": rule_info.get("description"),
                    "script_count": script_count,
                    "extracted_data": extracted_data,
                }
            )
            await self.db.execute(stmt)
            stats.asr_rules += 1

async def import_extracted_data(extracted_path: str = "/data/extracted") -> ExtractedImportStats:
    """Import all extracted data from the specified path."""
    async with async_session_maker() as db:
        service = ExtractedImportService(db, extracted_path)
        return await service.import_all()
