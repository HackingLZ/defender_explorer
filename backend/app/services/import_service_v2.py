"""
Import Service V2 - Improved import pipeline for Defender Explorer.

This service orchestrates the full import process:
1. Extract VDMs to text files (using defender_sig_extractor CLI)
2. Import Lua scripts to database
3. Build function registry (Is*/Get* functions with data tables)
4. Resolve ASR function dependencies

Key improvements over v1:
- Decompiles ALL scripts to text first (no blocking during import)
- Function registry enables cross-script resolution
- ASR GUIDs are resolved after all scripts are available
- Atomic import with proper error handling
"""

import asyncio
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from ..models import Threat, Signature, LuaScript, ASRRule, FunctionDefinition
from .text_import_service import TextImportService, TextImportStats
from .asr_resolver_service import ASRResolverService, ASRResolverStats

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_EXTRACTED_PATH = os.environ.get("EXTRACTED_PATH", "/data/extracted")
DEFAULT_VDM_PATH = os.environ.get("VDM_PATH", "/data/vdm")


@dataclass
class ImportV2Stats:
    """Statistics from the full import pipeline."""
    # Extraction phase
    extraction_started: Optional[datetime] = None
    extraction_completed: Optional[datetime] = None
    vdm_files_processed: int = 0

    # Text import phase
    text_import_stats: Optional[TextImportStats] = None

    # ASR resolution phase
    asr_resolver_stats: Optional[ASRResolverStats] = None

    # Summary
    total_lua_scripts: int = 0
    total_asr_scripts: int = 0
    total_functions: int = 0
    total_data_entries: int = 0

    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON response."""
        return {
            "extraction": {
                "started": self.extraction_started.isoformat() if self.extraction_started else None,
                "completed": self.extraction_completed.isoformat() if self.extraction_completed else None,
                "vdm_files_processed": self.vdm_files_processed,
            },
            "text_import": {
                "lua_scripts_added": self.text_import_stats.lua_scripts_added if self.text_import_stats else 0,
                "functions_discovered": self.text_import_stats.functions_discovered if self.text_import_stats else 0,
                "asr_scripts_found": self.text_import_stats.asr_scripts_found if self.text_import_stats else 0,
                "total_data_entries": self.text_import_stats.total_data_entries if self.text_import_stats else 0,
                "errors": self.text_import_stats.errors[:10] if self.text_import_stats else [],
            },
            "asr_resolution": {
                "rules_processed": self.asr_resolver_stats.rules_processed if self.asr_resolver_stats else 0,
                "rules_updated": self.asr_resolver_stats.rules_updated if self.asr_resolver_stats else 0,
                "functions_resolved": self.asr_resolver_stats.functions_resolved if self.asr_resolver_stats else 0,
                "scripts_analyzed": self.asr_resolver_stats.total_scripts_analyzed if self.asr_resolver_stats else 0,
                "errors": self.asr_resolver_stats.errors[:10] if self.asr_resolver_stats else [],
            },
            "summary": {
                "total_lua_scripts": self.total_lua_scripts,
                "total_asr_scripts": self.total_asr_scripts,
                "total_functions": self.total_functions,
                "total_data_entries": self.total_data_entries,
            },
            "errors": self.errors[:20],
        }


class ImportServiceV2:
    """
    Improved import service with full pipeline:
    1. Extract VDMs to text (using defender_sig_extractor)
    2. Import Lua scripts to database
    3. Build function registry
    4. Resolve ASR function dependencies
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.stats = ImportV2Stats()

    async def full_import(
        self,
        vdm_dir: Optional[str] = None,
        extracted_dir: Optional[str] = None,
        skip_extraction: bool = False,
    ) -> ImportV2Stats:
        """
        Run the full import pipeline.

        Args:
            vdm_dir: Directory containing VDM files (default: /data/vdm)
            extracted_dir: Directory for extracted data (default: /data/extracted)
            skip_extraction: If True, skip extraction and use existing extracted files

        Returns:
            Import statistics
        """
        vdm_path = Path(vdm_dir or DEFAULT_VDM_PATH)
        extracted_path = Path(extracted_dir or DEFAULT_EXTRACTED_PATH)
        lua_path = extracted_path / "lua"

        try:
            # Step 1: Extract VDMs to text files
            if not skip_extraction:
                await self._extract_vdms(vdm_path, extracted_path)
            else:
                logger.info("Skipping extraction, using existing files")
                if not lua_path.exists():
                    raise ValueError(f"Lua directory not found: {lua_path}")

            # Step 2: Import Lua scripts and build function registry
            await self._import_lua_scripts(lua_path)

            # Step 3: Resolve ASR function dependencies
            await self._resolve_asr_rules()

            # Update summary stats
            await self._compute_summary_stats()

            await self.db.commit()
            logger.info("Full import pipeline completed successfully")

        except Exception as e:
            self.stats.errors.append(f"Pipeline error: {str(e)}")
            logger.error(f"Import pipeline failed: {e}", exc_info=True)
            await self.db.rollback()
            raise

        return self.stats

    async def _extract_vdms(self, vdm_dir: Path, output_dir: Path) -> None:
        """
        Extract and decompile VDM files using defender_sig_extractor CLI.

        This runs the extractor in a subprocess to avoid blocking the event loop.
        """
        self.stats.extraction_started = datetime.utcnow()
        logger.info(f"Starting VDM extraction from {vdm_dir}")

        # Find VDM files
        vdm_files = list(vdm_dir.glob("*.vdm"))
        if not vdm_files:
            raise ValueError(f"No VDM files found in {vdm_dir}")

        logger.info(f"Found {len(vdm_files)} VDM files: {[f.name for f in vdm_files]}")

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        lua_dir = output_dir / "lua"
        lua_dir.mkdir(parents=True, exist_ok=True)

        # Run extraction for each VDM file
        for vdm_file in vdm_files:
            try:
                await self._extract_single_vdm(vdm_file, output_dir)
                self.stats.vdm_files_processed += 1
            except Exception as e:
                self.stats.errors.append(f"Error extracting {vdm_file.name}: {str(e)}")
                logger.error(f"Failed to extract {vdm_file}: {e}")

        self.stats.extraction_completed = datetime.utcnow()
        logger.info(
            f"Extraction completed: {self.stats.vdm_files_processed} VDM files processed"
        )

    async def _extract_single_vdm(self, vdm_file: Path, output_dir: Path) -> None:
        """Extract a single VDM file."""
        logger.info(f"Extracting {vdm_file.name}...")

        # Build command for defender_sig_extractor
        # The extractor should be available as a Python module
        cmd = [
            sys.executable,
            "-m", "defender_sig_extractor",
            "extract",
            "--vdm", str(vdm_file),
            "--output", str(output_dir),
            "--format", "lua",  # Output decompiled Lua
            "--decompile",  # Enable decompilation
        ]

        # Run in subprocess
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,  # 1 hour timeout for large VDMs
                )
            )

            if result.returncode != 0:
                logger.warning(f"Extractor warning for {vdm_file.name}: {result.stderr}")

            logger.info(f"Extracted {vdm_file.name}")

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Extraction timed out for {vdm_file.name}")
        except FileNotFoundError:
            # defender_sig_extractor not available as CLI, try direct import
            await self._extract_vdm_direct(vdm_file, output_dir)

    async def _extract_vdm_direct(self, vdm_file: Path, output_dir: Path) -> None:
        """
        Extract VDM file using direct Python import (fallback method).
        """
        logger.info(f"Using direct extraction for {vdm_file.name}")

        loop = asyncio.get_event_loop()

        def do_extract():
            # Add parent path for imports
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

            from defender_sig_extractor.vdm_parser import VDMParser
            from defender_sig_extractor.signature_extractor import extract_threats
            from defender_sig_extractor.output.asr_writer import (
                extract_lua_from_signature,
                decompile_lua_safe,
                extract_guids_from_bytecode,
            )
            from defender_sig_extractor.signature_types import is_lua_type

            # Parse VDM
            parser = VDMParser(str(vdm_file))
            decompressed = parser.decompress()
            threats = list(extract_threats(decompressed))

            lua_dir = output_dir / "lua"
            lua_dir.mkdir(parents=True, exist_ok=True)

            lua_count = 0
            for threat in threats:
                for sig in threat.signatures:
                    if is_lua_type(sig.sig_type):
                        bytecode = extract_lua_from_signature(sig.data)
                        if bytecode:
                            source = decompile_lua_safe(bytecode)
                            if source:
                                # Generate filename from threat name and hash
                                import hashlib
                                hash_prefix = hashlib.sha256(bytecode).hexdigest()[:8]
                                safe_name = "".join(
                                    c if c.isalnum() or c in "._-" else "_"
                                    for c in threat.threat_name
                                )[:50]
                                filename = f"{safe_name}_{hash_prefix}.lua"

                                # Write Lua file
                                (lua_dir / filename).write_text(source)
                                lua_count += 1

            return lua_count

        count = await loop.run_in_executor(None, do_extract)
        logger.info(f"Extracted {count} Lua scripts from {vdm_file.name}")

    async def _import_lua_scripts(self, lua_dir: Path) -> None:
        """Import Lua scripts and build function registry."""
        logger.info(f"Importing Lua scripts from {lua_dir}")

        text_service = TextImportService(self.db)
        self.stats.text_import_stats = await text_service.import_lua_directory(lua_dir)

        logger.info(
            f"Text import complete: {self.stats.text_import_stats.lua_scripts_added} scripts, "
            f"{self.stats.text_import_stats.functions_discovered} functions"
        )

    async def _resolve_asr_rules(self) -> None:
        """Resolve ASR function dependencies."""
        logger.info("Resolving ASR function dependencies")

        resolver = ASRResolverService(self.db)
        self.stats.asr_resolver_stats = await resolver.resolve_all_asr_rules()

        logger.info(
            f"ASR resolution complete: {self.stats.asr_resolver_stats.rules_updated} rules updated"
        )

    async def _compute_summary_stats(self) -> None:
        """Compute summary statistics from database."""
        # Count Lua scripts
        result = await self.db.execute(
            text("SELECT COUNT(*) FROM lua_scripts")
        )
        self.stats.total_lua_scripts = result.scalar() or 0

        # Count ASR scripts
        result = await self.db.execute(
            text("SELECT COUNT(*) FROM lua_scripts WHERE is_asr_script = true")
        )
        self.stats.total_asr_scripts = result.scalar() or 0

        # Count functions
        result = await self.db.execute(
            text("SELECT COUNT(*) FROM function_definitions")
        )
        self.stats.total_functions = result.scalar() or 0

        # Sum data entries
        result = await self.db.execute(
            text("SELECT COALESCE(SUM(entry_count), 0) FROM function_definitions")
        )
        self.stats.total_data_entries = result.scalar() or 0


async def run_full_import_v2(
    vdm_dir: Optional[str] = None,
    extracted_dir: Optional[str] = None,
    skip_extraction: bool = False,
) -> ImportV2Stats:
    """
    Run the full import pipeline (standalone function).

    This can be called from background tasks or CLI.
    """
    from ..database import async_session_maker

    async with async_session_maker() as db:
        service = ImportServiceV2(db)
        return await service.full_import(
            vdm_dir=vdm_dir,
            extracted_dir=extracted_dir,
            skip_extraction=skip_extraction,
        )


async def import_from_extracted_only(
    extracted_dir: Optional[str] = None,
) -> ImportV2Stats:
    """
    Import from pre-extracted Lua files (skip VDM extraction).

    Use this when defender_sig_extractor has already run.
    """
    return await run_full_import_v2(
        extracted_dir=extracted_dir,
        skip_extraction=True,
    )
