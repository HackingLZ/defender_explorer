"""
ASR Resolver Service - Resolve ASR function dependencies across scripts.

This service:
1. For each known ASR GUID, finds all Lua scripts containing that GUID
2. Detects external function calls (IsRmmToolFilePath, etc.) in those scripts
3. Looks up function data from the function registry
4. Merges function data into asr_rules.extracted_data
"""

import logging
import re
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, any_

from ..models import LuaScript, ASRRule, FunctionDefinition, FUNCTION_MAPPINGS
from .lua_pattern_extractor import LuaPatternExtractor, ExtractedPatterns

logger = logging.getLogger(__name__)

# Known ASR GUIDs with their metadata
ASR_RULES_METADATA = {
    "01443614-cd74-433a-b99e-2ecdc07bfc25": {
        "name": "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
        "short_name": "PrevalenceCheck",
    },
    "1081f0b6-3e1e-4f44-acce-816d65112d99": {
        "name": "Block execution of files related to Remote Monitoring & Management tools",
        "short_name": "RMMTools",
    },
    "26190899-1602-49e8-8b27-eb1d0a1ce869": {
        "name": "Block Office communication application from creating child processes",
        "short_name": "OutlookChildProcess",
    },
    "3b576869-a4ec-4529-8536-b80a7769e899": {
        "name": "Block Office applications from creating executable content",
        "short_name": "OfficeExecutableContent",
    },
    "56a863a9-875e-4185-98a7-b882c64b5ce5": {
        "name": "Block abuse of exploited vulnerable signed drivers",
        "short_name": "VulnerableDrivers",
    },
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": {
        "name": "Block execution of potentially obfuscated scripts",
        "short_name": "ObfuscatedScripts",
    },
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": {
        "name": "Block Win32 API calls from Office macros",
        "short_name": "OfficeMacroWin32API",
    },
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": {
        "name": "Block credential stealing from the Windows local security authority subsystem",
        "short_name": "LsassCredentialTheft",
    },
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6": {
        "name": "Block webshell creation for servers",
        "short_name": "WebshellCreation",
    },
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": {
        "name": "Block untrusted and unsigned processes that run from USB",
        "short_name": "USBUntrusted",
    },
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": {
        "name": "Block executable content from email client and webmail",
        "short_name": "EmailExecutableContent",
    },
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": {
        "name": "Block use of copied or impersonated system tools",
        "short_name": "ImpersonatedTools",
    },
    "c1db55ab-c21a-4637-bb3f-a12568109d35": {
        "name": "Use advanced protection against ransomware",
        "short_name": "RansomwareProtection",
    },
    "d1e49aac-8f56-4280-b9ba-993a6d77406c": {
        "name": "Block process creations originating from PSExec and WMI commands",
        "short_name": "PSExecWMI",
    },
    "d3e037e1-3eb8-44c8-a917-57927947596d": {
        "name": "Block JavaScript or VBScript from launching downloaded executable content",
        "short_name": "ScriptDownloadedExe",
    },
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": {
        "name": "Block all Office applications from creating child processes",
        "short_name": "OfficeChildProcess",
    },
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": {
        "name": "Block persistence through WMI event subscription",
        "short_name": "WMIPersistence",
    },
}


@dataclass
class ASRResolverStats:
    """Statistics from ASR resolution."""
    rules_processed: int = 0
    rules_updated: int = 0
    functions_resolved: int = 0
    total_scripts_analyzed: int = 0
    errors: List[str] = field(default_factory=list)


class ASRResolverService:
    """
    Service for resolving ASR function dependencies.

    Links function calls in ASR scripts to their definitions in other scripts,
    merging the extracted data into the ASR rule's extracted_data field.
    """

    # Pattern to detect external function calls
    FUNC_CALL_PATTERN = re.compile(
        r'\b(Is[A-Z][a-zA-Z0-9]+|Get[A-Z][a-zA-Z0-9]+)\s*\('
    )

    def __init__(self, db: AsyncSession):
        self.db = db
        self.stats = ASRResolverStats()
        self.function_registry: Dict[str, List[str]] = {}

    async def resolve_all_asr_rules(self) -> ASRResolverStats:
        """
        Resolve function dependencies for all known ASR rules.

        Returns:
            Resolution statistics
        """
        # Load function registry from database
        await self._load_function_registry()
        logger.info(f"Loaded {len(self.function_registry)} functions into registry")

        # Ensure all known ASR rules exist in database
        await self._ensure_asr_rules_exist()

        # Process each ASR rule
        for guid, metadata in ASR_RULES_METADATA.items():
            await self._resolve_asr_rule(guid, metadata)
            self.stats.rules_processed += 1

        await self.db.commit()
        logger.info(
            f"ASR resolution complete: {self.stats.rules_updated} rules updated, "
            f"{self.stats.functions_resolved} functions resolved"
        )

        return self.stats

    async def resolve_single_asr_rule(self, guid: str) -> Optional[Dict]:
        """
        Resolve function dependencies for a single ASR rule.

        Args:
            guid: The ASR GUID to resolve

        Returns:
            The resolved extracted_data or None if not found
        """
        guid_lower = guid.lower()
        if guid_lower not in ASR_RULES_METADATA:
            return None

        await self._load_function_registry()
        await self._resolve_asr_rule(guid_lower, ASR_RULES_METADATA[guid_lower])
        await self.db.commit()

        # Return the updated data
        result = await self.db.execute(
            select(ASRRule.extracted_data).where(ASRRule.guid == guid_lower)
        )
        return result.scalar_one_or_none()

    async def _load_function_registry(self) -> None:
        """Load function definitions from database into registry."""
        result = await self.db.execute(
            select(FunctionDefinition.name, FunctionDefinition.data_entries)
            .where(FunctionDefinition.data_entries.isnot(None))
        )
        self.function_registry = {row[0]: row[1] for row in result.all() if row[1]}

    async def _ensure_asr_rules_exist(self) -> None:
        """Ensure all known ASR rules exist in the database."""
        from sqlalchemy.dialects.postgresql import insert

        for guid, metadata in ASR_RULES_METADATA.items():
            stmt = insert(ASRRule).values(
                guid=guid.lower(),
                name=metadata["name"],
                short_name=metadata["short_name"],
                script_count=0,
                extracted_data={},
            ).on_conflict_do_update(
                index_elements=["guid"],
                set_={
                    "name": metadata["name"],
                    "short_name": metadata["short_name"],
                }
            )
            await self.db.execute(stmt)

        await self.db.commit()

    async def _resolve_asr_rule(self, guid: str, metadata: Dict) -> None:
        """
        Resolve function dependencies for a single ASR rule.

        Args:
            guid: The ASR GUID
            metadata: Rule metadata (name, short_name)
        """
        try:
            # Find all scripts associated with this ASR rule
            result = await self.db.execute(
                select(LuaScript.id, LuaScript.decompiled_source)
                .where(guid == any_(LuaScript.asr_guids))
            )
            scripts = result.all()
            self.stats.total_scripts_analyzed += len(scripts)

            if not scripts:
                logger.debug(f"No scripts found for ASR rule {guid}")
                return

            # Extract patterns from all scripts using LuaPatternExtractor
            merged_patterns = ExtractedPatterns()
            extractor = LuaPatternExtractor(primary_guid=guid)

            for script_id, source in scripts:
                if not source:
                    continue

                # Extract patterns directly from script
                patterns = extractor.extract_from_source(source)
                merged_patterns.merge(patterns)

                # Detect external function calls
                external_funcs = self._detect_function_calls(source)

                # Resolve function data and merge
                for func_name in external_funcs:
                    if func_name in self.function_registry:
                        data_entries = self.function_registry[func_name]
                        self._merge_function_data(merged_patterns, func_name, data_entries)
                        self.stats.functions_resolved += 1

            # Update the ASR rule with merged extracted data
            extracted_data = merged_patterns.to_dict()

            await self.db.execute(
                update(ASRRule)
                .where(ASRRule.guid == guid)
                .values(
                    extracted_data=extracted_data,
                    script_count=len(scripts),
                )
            )
            self.stats.rules_updated += 1

            logger.debug(
                f"Resolved ASR rule {guid}: {len(scripts)} scripts, "
                f"extracted {sum(len(v) for v in extracted_data.values() if isinstance(v, list))} patterns"
            )

        except Exception as e:
            self.stats.errors.append(f"Error resolving ASR rule {guid}: {str(e)}")
            logger.error(f"Error resolving ASR rule {guid}: {e}")

    def _detect_function_calls(self, source: str) -> Set[str]:
        """
        Detect external function calls in source code.

        Returns set of function names that are called but may be defined elsewhere.
        """
        calls = set()
        for match in self.FUNC_CALL_PATTERN.finditer(source):
            func_name = match.group(1)
            calls.add(func_name)
        return calls

    def _merge_function_data(
        self,
        patterns: ExtractedPatterns,
        func_name: str,
        data_entries: List[str]
    ) -> None:
        """
        Merge function data into ExtractedPatterns.

        Maps function names to their target fields in ExtractedPatterns.
        """
        # Use FUNCTION_MAPPINGS for known functions
        if func_name in FUNCTION_MAPPINGS:
            target_field = FUNCTION_MAPPINGS[func_name]["mapped_field"]
        else:
            # Auto-infer for unknown functions
            target_field = self._infer_target_field(func_name)

        # Map to the appropriate field in ExtractedPatterns
        field_mapping = {
            "rmm_file_paths": patterns.rmm_file_paths,
            "rmm_version_info": patterns.rmm_version_info,
            "rmm_original_filenames": patterns.rmm_original_filenames,
            "exclusion_paths": patterns.exclusion_paths,
            "detection_paths": patterns.detection_paths,
            "process_names": patterns.process_names,
            "file_extensions": patterns.file_extensions,
            "vulnerable_drivers": patterns.vulnerable_drivers,
        }

        if target_field and target_field in field_mapping:
            field_mapping[target_field].update(data_entries)
        else:
            # For unknown mappings, add to detection_paths as a fallback
            # This ensures we don't lose data from newly discovered functions
            patterns.detection_paths.update(data_entries)

    def _infer_target_field(self, func_name: str) -> Optional[str]:
        """
        Infer the target field from function name.

        Examples:
            IsRmmToolFilePath -> rmm_file_paths
            IsRmmToolVersionInfo -> rmm_version_info
            GetPathExclusions -> exclusion_paths
        """
        name_lower = func_name.lower()

        # RMM tool functions
        if "rmmtool" in name_lower:
            if "filepath" in name_lower or "path" in name_lower:
                return "rmm_file_paths"
            elif "versioninfo" in name_lower or "version" in name_lower:
                return "rmm_version_info"
            elif "ofn" in name_lower or "originalfilename" in name_lower:
                return "rmm_original_filenames"

        # Path functions
        if "exclusion" in name_lower:
            return "exclusion_paths"
        if "monitored" in name_lower or "detection" in name_lower:
            return "detection_paths"

        # Extension functions
        if "ext" in name_lower and ("file" in name_lower or "suspicious" in name_lower):
            return "file_extensions"

        # Process functions
        if "process" in name_lower or "interpreter" in name_lower:
            return "process_names"

        # Driver functions
        if "driver" in name_lower:
            return "vulnerable_drivers"

        return None


async def refresh_asr_rule_counts(db: AsyncSession) -> Dict[str, int]:
    """
    Refresh script counts for all ASR rules.

    Returns:
        Dict mapping GUID to script count
    """
    from sqlalchemy import text

    # Aggregate counts in one pass
    result = await db.execute(
        text("""
            SELECT lower(guid) AS guid, COUNT(*) AS cnt
            FROM (
                SELECT unnest(asr_guids) AS guid
                FROM lua_scripts
                WHERE asr_guids IS NOT NULL
            ) AS s
            GROUP BY lower(guid)
        """)
    )
    counts = {row[0]: row[1] for row in result.all()}

    # Update all ASR rules
    for guid in ASR_RULES_METADATA.keys():
        guid_lower = guid.lower()
        count = counts.get(guid_lower, 0)
        await db.execute(
            update(ASRRule)
            .where(ASRRule.guid == guid_lower)
            .values(script_count=count)
        )

    await db.commit()
    return counts
