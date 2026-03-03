"""
Text Import Service - Parse decompiled Lua text files and build function registry.

This service parses the output from defender_sig_extractor and:
1. Imports Lua scripts to the database
2. Builds a registry of function definitions (Is*/Get* functions with data tables)
3. Extracts ASR GUIDs from scripts
"""

import hashlib
import logging
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from ..models import LuaScript, FunctionDefinition, FUNCTION_MAPPINGS

logger = logging.getLogger(__name__)

# Known ASR GUIDs (static list from Microsoft documentation)
KNOWN_ASR_GUIDS = {
    "01443614-cd74-433a-b99e-2ecdc07bfc25",  # PrevalenceCheck
    "1081f0b6-3e1e-4f44-acce-816d65112d99",  # RMMTools
    "26190899-1602-49e8-8b27-eb1d0a1ce869",  # OutlookChildProcess
    "3b576869-a4ec-4529-8536-b80a7769e899",  # OfficeExecutableContent
    "56a863a9-875e-4185-98a7-b882c64b5ce5",  # VulnerableDrivers
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",  # ObfuscatedScripts
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",  # OfficeMacroWin32API
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",  # LsassCredentialTheft
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6",  # WebshellCreation
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # USBUntrusted
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",  # EmailExecutableContent
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",  # ImpersonatedTools
    "c1db55ab-c21a-4637-bb3f-a12568109d35",  # RansomwareProtection
    "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # PSExecWMI
    "d3e037e1-3eb8-44c8-a917-57927947596d",  # ScriptDownloadedExe
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",  # OfficeChildProcess
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",  # WMIPersistence
    # Additional known GUIDs
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",  # AdobeReaderChildProcess
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",  # OfficeCommApp
    "33ddedf1-c6e0-47cb-833e-de6133960387",  # Removable storage
}


@dataclass
class FunctionDef:
    """Represents a discovered function definition."""
    name: str
    body: str
    data_entries: List[str]
    source_script: str
    category: str = "unknown"
    mapped_field: Optional[str] = None

    @property
    def entry_count(self) -> int:
        return len(self.data_entries)


@dataclass
class TextImportStats:
    """Statistics from text import operation."""
    lua_scripts_added: int = 0
    lua_scripts_updated: int = 0
    functions_discovered: int = 0
    functions_updated: int = 0
    asr_scripts_found: int = 0
    total_data_entries: int = 0
    errors: List[str] = field(default_factory=list)


class TextImportService:
    """
    Service for importing decompiled Lua text files and building function registry.
    """

    # Pattern to find function definition start positions
    FUNC_START_PATTERN = re.compile(
        r'(Is[A-Z][a-zA-Z0-9]+|Get[A-Z][a-zA-Z0-9]+)\s*=\s*function\s*\([^)]*\)'
    )

    # Pattern to extract string data from ipairs({...}) blocks
    IPAIRS_BLOCK_PATTERN = re.compile(
        r'ipairs\s*\(\s*\{([^}]+)\}',
        re.DOTALL
    )

    # Pattern to extract individual strings from within ipairs blocks
    IPAIRS_STRING_PATTERN = re.compile(
        r"'([^']+)'"
    )

    # Pattern to extract data entries: {}[n] = "value" or {}[n] = 'value'
    DATA_ENTRY_PATTERN = re.compile(
        r'\{\}\s*\[\d+\]\s*=\s*["\']([^"\']+)["\']'
    )

    # Pattern to extract data from table assignments: l_x_y["key"] = value
    TABLE_ENTRY_PATTERN = re.compile(
        r'(?:l_\d+_\d+|\{\})\s*\[["\']([^"\']+)["\']\]\s*='
    )

    # Pattern to extract ASR GUIDs from source
    GUID_PATTERN = re.compile(
        r'["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']'
    )

    # IsHipsRuleEnabled pattern for ASR detection
    HIPS_PATTERN = re.compile(
        r'IsHipsRuleEnabled\s*\)\s*\(\s*["\']([0-9a-fA-F-]{36})["\']',
        re.IGNORECASE
    )

    def __init__(self, db: AsyncSession):
        self.db = db
        self.stats = TextImportStats()
        self.function_registry: Dict[str, FunctionDef] = {}

    async def import_lua_directory(self, lua_dir: Path) -> TextImportStats:
        """
        Import all Lua scripts from a directory.

        Args:
            lua_dir: Path to directory containing .lua files

        Returns:
            Import statistics
        """
        if not lua_dir.exists():
            self.stats.errors.append(f"Directory not found: {lua_dir}")
            return self.stats

        lua_files = list(lua_dir.rglob("*.lua"))
        logger.info(f"Found {len(lua_files)} Lua files in {lua_dir}")

        # First pass: Read all scripts and build function registry
        scripts_data = []
        for lua_file in lua_files:
            try:
                content = lua_file.read_text(errors="replace")
                # Clean problematic characters
                content = content.replace('\x00', '').replace('\x13', '').replace('\x0f', '')

                if content.strip():
                    scripts_data.append((lua_file, content))
                    # Discover functions in this script
                    self._discover_functions(content, str(lua_file))
            except Exception as e:
                self.stats.errors.append(f"Error reading {lua_file.name}: {str(e)}")

        logger.info(f"Discovered {len(self.function_registry)} function definitions")

        # Save function definitions to database
        await self._save_function_registry()

        # Second pass: Import scripts to database
        await self._import_scripts(scripts_data)

        return self.stats

    def _discover_functions(self, source: str, script_path: str) -> None:
        """
        Discover function definitions in a script and add to registry.

        Looks for Is* and Get* function definitions with data tables.
        Splits the source into sections per function definition to correctly
        associate data entries with their parent function.
        """
        # Find all function definition start positions
        func_starts = []
        for match in self.FUNC_START_PATTERN.finditer(source):
            func_starts.append((match.group(1), match.start()))

        if not func_starts:
            return

        # For each function, extract the body as the section from its start
        # to the next function definition (or end of file)
        for i, (func_name, start_pos) in enumerate(func_starts):
            if i + 1 < len(func_starts):
                end_pos = func_starts[i + 1][1]
            else:
                end_pos = len(source)

            func_section = source[start_pos:end_pos]
            data_entries = []

            # Primary: Extract strings from ipairs({...}) blocks
            for block_match in self.IPAIRS_BLOCK_PATTERN.finditer(func_section):
                block_content = block_match.group(1)
                for str_match in self.IPAIRS_STRING_PATTERN.finditer(block_content):
                    value = str_match.group(1)
                    if value and len(value) > 1:  # Skip single chars
                        data_entries.append(value)

            # Fallback: Try {}[n] = "value" pattern
            if not data_entries:
                for entry_match in self.DATA_ENTRY_PATTERN.finditer(func_section):
                    value = entry_match.group(1)
                    if value and len(value) > 0:
                        data_entries.append(value)

            # Fallback: Try table assignment pattern
            if not data_entries:
                for entry_match in self.TABLE_ENTRY_PATTERN.finditer(func_section):
                    value = entry_match.group(1)
                    if value and len(value) > 0:
                        data_entries.append(value)

            # Only register functions with data entries
            if data_entries:
                if func_name in self.function_registry:
                    existing = self.function_registry[func_name]
                    if len(data_entries) > len(existing.data_entries):
                        self._register_function(func_name, func_section[:5000], data_entries, script_path)
                else:
                    self._register_function(func_name, func_section[:5000], data_entries, script_path)

    def _register_function(self, name: str, body: str, entries: List[str], source: str) -> None:
        """Register a function definition."""
        # Determine category and mapped field
        mapping = FUNCTION_MAPPINGS.get(name, {})
        category = mapping.get("category", self._infer_category(name))
        mapped_field = mapping.get("mapped_field", self._infer_mapped_field(name))

        self.function_registry[name] = FunctionDef(
            name=name,
            body=body[:5000],  # Truncate to reasonable size
            data_entries=entries,
            source_script=source,
            category=category,
            mapped_field=mapped_field,
        )
        self.stats.total_data_entries += len(entries)

    def _infer_category(self, func_name: str) -> str:
        """Infer function category from name."""
        name_lower = func_name.lower()
        if "rmm" in name_lower:
            return "rmm_tool"
        elif "path" in name_lower or "location" in name_lower:
            return "path"
        elif "ext" in name_lower:
            return "file_extension"
        elif "process" in name_lower:
            return "process"
        elif "driver" in name_lower:
            return "driver"
        return "unknown"

    def _infer_mapped_field(self, func_name: str) -> Optional[str]:
        """
        Infer the target field name from function name.

        Converts: IsRmmToolFilePath -> rmm_tool_file_path
                  GetPathExclusions -> path_exclusions
        """
        # Remove Is/Get prefix
        name = func_name
        if name.startswith("Is"):
            name = name[2:]
        elif name.startswith("Get"):
            name = name[3:]

        # Convert CamelCase to snake_case
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append('_')
            result.append(char.lower())

        return ''.join(result)

    async def _save_function_registry(self) -> None:
        """Save discovered functions to the database."""
        for func_name, func_def in self.function_registry.items():
            try:
                stmt = insert(FunctionDefinition).values(
                    name=func_name,
                    source_script=func_def.source_script[:512],
                    body=func_def.body,
                    data_entries=func_def.data_entries,
                    entry_count=func_def.entry_count,
                    category=func_def.category,
                    is_mapped="Y" if func_def.mapped_field else "N",
                    mapped_field=func_def.mapped_field,
                ).on_conflict_do_update(
                    index_elements=["name"],
                    set_={
                        "source_script": func_def.source_script[:512],
                        "body": func_def.body,
                        "data_entries": func_def.data_entries,
                        "entry_count": func_def.entry_count,
                        "category": func_def.category,
                        "is_mapped": "Y" if func_def.mapped_field else "N",
                        "mapped_field": func_def.mapped_field,
                    }
                )
                await self.db.execute(stmt)
                self.stats.functions_discovered += 1
            except Exception as e:
                self.stats.errors.append(f"Error saving function {func_name}: {str(e)}")

        await self.db.commit()
        logger.info(f"Saved {self.stats.functions_discovered} function definitions to database")

    async def _import_scripts(self, scripts_data: List[Tuple[Path, str]]) -> None:
        """Import scripts to database with ASR GUID extraction."""
        batch = []
        batch_size = 100

        for lua_file, content in scripts_data:
            try:
                bytecode_hash = hashlib.sha256(content.encode()).hexdigest()

                # Extract ASR GUIDs
                asr_guids = self._extract_asr_guids(content)
                is_asr_script = len(asr_guids) > 0

                if is_asr_script:
                    self.stats.asr_scripts_found += 1

                batch.append({
                    "bytecode_hash": bytecode_hash,
                    "decompiled_source": content[:100000],  # Truncate very large scripts
                    "decompilation_status": "completed",
                    "asr_guids": list(asr_guids),
                    "is_asr_script": is_asr_script,
                })

                if len(batch) >= batch_size:
                    await self._insert_script_batch(batch)
                    batch = []

            except Exception as e:
                self.stats.errors.append(f"Error processing {lua_file.name}: {str(e)}")

        # Insert remaining batch
        if batch:
            await self._insert_script_batch(batch)

        logger.info(f"Imported {self.stats.lua_scripts_added} Lua scripts ({self.stats.asr_scripts_found} ASR-related)")

    async def _insert_script_batch(self, batch: List[dict]) -> None:
        """Insert a batch of scripts using upsert."""
        for script_data in batch:
            try:
                stmt = insert(LuaScript).values(**script_data)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["bytecode_hash"],
                    set_={
                        "decompiled_source": script_data["decompiled_source"],
                        "decompilation_status": script_data["decompilation_status"],
                        "asr_guids": script_data["asr_guids"],
                        "is_asr_script": script_data["is_asr_script"],
                    }
                )
                await self.db.execute(stmt)
                self.stats.lua_scripts_added += 1
            except Exception as e:
                self.stats.errors.append(f"Error inserting script: {str(e)}")

        await self.db.commit()

    def _extract_asr_guids(self, source: str) -> Set[str]:
        """Extract ASR GUIDs from source code."""
        guids = set()

        # Pattern 1: IsHipsRuleEnabled calls
        for match in self.HIPS_PATTERN.finditer(source):
            guid = match.group(1).lower()
            if guid in KNOWN_ASR_GUIDS:
                guids.add(guid)

        # Pattern 2: General GUID pattern (filter to known ASR GUIDs)
        for match in self.GUID_PATTERN.finditer(source):
            guid = match.group(1).lower()
            if guid in KNOWN_ASR_GUIDS:
                guids.add(guid)

        return guids

    async def get_function_registry(self) -> Dict[str, List[str]]:
        """
        Get the function registry from database.

        Returns:
            Dict mapping function names to their data entries
        """
        result = await self.db.execute(
            select(FunctionDefinition.name, FunctionDefinition.data_entries)
        )
        return {row[0]: row[1] for row in result.all()}

    async def get_function_data(self, func_name: str) -> Optional[List[str]]:
        """Get data entries for a specific function."""
        result = await self.db.execute(
            select(FunctionDefinition.data_entries).where(FunctionDefinition.name == func_name)
        )
        row = result.scalar_one_or_none()
        return row if row else None


def camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case."""
    # Remove Is/Get prefix
    if name.startswith("Is"):
        name = name[2:]
    elif name.startswith("Get"):
        name = name[3:]

    # Convert
    result = []
    for i, char in enumerate(name):
        if char.isupper() and i > 0:
            result.append('_')
        result.append(char.lower())

    return ''.join(result)
