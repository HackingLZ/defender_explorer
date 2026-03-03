"""Service for syncing VDM data with delta updates."""

import asyncio
import hashlib
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Dict, List, Any
from dataclasses import dataclass, field

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import async_session_maker
from ..models import Threat, Signature, LuaScript, VDMVersion, SyncStatus
from .import_service import ImportService, ImportStats, import_asr_rules

logger = logging.getLogger(__name__)

# Thread pool for blocking I/O operations (downloads, file parsing)
_sync_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sync_worker")


@dataclass
class DeltaResult:
    """Result of delta computation."""
    added: Set[int] = field(default_factory=set)
    removed: Set[int] = field(default_factory=set)
    potentially_modified: Set[int] = field(default_factory=set)


@dataclass
class VDMFileHashes:
    """Hashes for individual VDM files."""
    av_base: Optional[str] = None
    av_delta: Optional[str] = None
    as_base: Optional[str] = None
    as_delta: Optional[str] = None

    @property
    def combined_hash(self) -> str:
        """Compute combined hash for all files."""
        combined = hashlib.sha256()
        for h in [self.av_base, self.av_delta, self.as_base, self.as_delta]:
            if h:
                combined.update(h.encode())
        return combined.hexdigest()


class SyncService:
    """Service for syncing VDM data with delta updates."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def compute_delta(self, new_threats: list) -> DeltaResult:
        """
        Compute delta between new VDM data and existing database.

        Args:
            new_threats: List of ThreatDefinition objects from VDM

        Returns:
            DeltaResult with sets of added, removed, and modified signature IDs
        """
        # Get existing signature IDs
        result = await self.db.execute(select(Threat.signature_id))
        existing_ids = set(row[0] for row in result.all())

        # Get new signature IDs
        new_ids = {t.signature_id for t in new_threats}

        return DeltaResult(
            added=new_ids - existing_ids,
            removed=existing_ids - new_ids,
            potentially_modified=new_ids & existing_ids,
        )

    async def apply_incremental_update(
        self,
        delta: DeltaResult,
        threats_by_id: Dict[int, Any],
    ) -> ImportStats:
        """
        Apply incremental updates to the database.

        Args:
            delta: Delta result showing what changed
            threats_by_id: Dict mapping signature_id to ThreatDefinition

        Returns:
            ImportStats with counts of changes
        """
        stats = ImportStats()
        import_service = ImportService(self.db)

        # DELETE removed threats
        if delta.removed:
            logger.info(f"Removing {len(delta.removed)} threats...")
            for sig_id in delta.removed:
                # Get threat ID first
                result = await self.db.execute(
                    select(Threat.id).where(Threat.signature_id == sig_id)
                )
                threat_row = result.first()
                if threat_row:
                    threat_id = threat_row[0]
                    # Delete related records first (cascading should handle this, but be explicit)
                    await self.db.execute(delete(LuaScript).where(LuaScript.threat_id == threat_id))
                    await self.db.execute(delete(Signature).where(Signature.threat_id == threat_id))
                    await self.db.execute(delete(Threat).where(Threat.id == threat_id))

        # INSERT new threats
        if delta.added:
            logger.info(f"Adding {len(delta.added)} new threats...")
            for i, sig_id in enumerate(delta.added):
                if sig_id in threats_by_id:
                    await import_service._import_threat(threats_by_id[sig_id], stats)
                    if (i + 1) % 1000 == 0:
                        await self.db.commit()
                        logger.info(f"Added {i + 1}/{len(delta.added)} threats...")

        # UPDATE modified threats (only if content actually changed)
        if delta.potentially_modified:
            logger.info(f"Checking {len(delta.potentially_modified)} potentially modified threats...")
            modified_count = 0
            for i, sig_id in enumerate(delta.potentially_modified):
                if sig_id in threats_by_id:
                    new_threat = threats_by_id[sig_id]
                    if await self._threat_changed(sig_id, new_threat):
                        await import_service.update_threat(sig_id, new_threat, stats)
                        modified_count += 1

                if (i + 1) % 10000 == 0:
                    logger.info(f"Checked {i + 1}/{len(delta.potentially_modified)} threats, {modified_count} modified...")

            logger.info(f"Updated {modified_count} modified threats")

        await self.db.commit()
        return stats

    async def _threat_changed(self, sig_id: int, new_threat) -> bool:
        """
        Check if a threat has actually changed.

        Quick check: compare signature count first, then content hash if needed.
        """
        result = await self.db.execute(
            select(Threat.signature_count, Threat.content_hash)
            .where(Threat.signature_id == sig_id)
        )
        row = result.first()
        if not row:
            return True

        existing_sig_count, existing_hash = row

        # Quick check: signature count changed
        if existing_sig_count != len(new_threat.signatures):
            return True

        # Compute new content hash if existing has one
        if existing_hash:
            new_hash = self._compute_threat_hash(new_threat)
            return existing_hash != new_hash

        # No existing hash, assume changed for safety
        return True

    def _compute_threat_hash(self, threat_def) -> str:
        """Compute a content hash for a threat definition."""
        h = hashlib.sha256()
        h.update(threat_def.threat_name.encode())
        h.update(str(threat_def.signature_id).encode())
        for sig in sorted(threat_def.signatures, key=lambda s: (s.sig_type, s.size)):
            h.update(bytes([sig.sig_type]))
            h.update(sig.data or b'')
        return h.hexdigest()


@dataclass
class VDMDownloadResult:
    """Result of VDM download and extraction."""
    vdm_files: Dict[str, str]  # type -> path
    temp_dir: str  # temp directory to clean up
    mpam_path: str  # downloaded MPAM path to clean up


def _download_and_extract_vdm() -> VDMDownloadResult:
    """
    Synchronous helper to download MPAM and extract VDM files.

    Runs in a thread pool to avoid blocking the async event loop.

    Returns:
        VDMDownloadResult with file paths and temp directories for cleanup
    """
    from defender_sig_extractor.downloader import download_mpam_to_temp
    from defender_sig_extractor.pe_extractor import PEExtractor, get_vdm_files
    import sys

    print("Starting MPAM download from Microsoft...", flush=True)
    logger.info("Starting MPAM download from Microsoft...")
    mpam_path = download_mpam_to_temp()
    print(f"Download complete: {mpam_path}", flush=True)
    logger.info(f"Download complete: {mpam_path}")

    # Create temp directory for extraction
    temp_dir = tempfile.mkdtemp(prefix="vdm_extract_")

    logger.info("Extracting VDM files from MPAM...")
    pe_extractor = PEExtractor(mpam_path)
    pe_extractor.extract_vdm_files(temp_dir)

    # Use get_vdm_files to properly categorize (av_base, av_delta, as_base, as_delta)
    vdm_files = get_vdm_files(temp_dir)

    if not vdm_files:
        raise ValueError("No VDM files found in MPAM")

    for key, path in vdm_files.items():
        logger.info(f"Found VDM file: {key} -> {Path(path).name}")

    return VDMDownloadResult(
        vdm_files=vdm_files,
        temp_dir=temp_dir,
        mpam_path=mpam_path,
    )


def _cleanup_temp_files(result: VDMDownloadResult) -> None:
    """Clean up temporary files from download/extraction."""
    import shutil
    import os

    try:
        if result.temp_dir and Path(result.temp_dir).exists():
            shutil.rmtree(result.temp_dir)
            logger.info(f"Cleaned up temp directory: {result.temp_dir}")
    except Exception as e:
        logger.warning(f"Failed to clean up temp directory {result.temp_dir}: {e}")

    try:
        if result.mpam_path and Path(result.mpam_path).exists():
            os.remove(result.mpam_path)
            logger.info(f"Cleaned up MPAM file: {result.mpam_path}")
    except Exception as e:
        logger.warning(f"Failed to clean up MPAM file {result.mpam_path}: {e}")


async def run_sync(sync_id: int) -> None:
    """
    Run a sync operation in the background.

    Args:
        sync_id: ID of the SyncStatus record
    """
    download_result = None
    async with async_session_maker() as db:
        try:
            from defender_sig_extractor.downloader import download_mpam_to_temp
            from defender_sig_extractor.vdm_parser import VDMParser
            from defender_sig_extractor.signature_extractor import extract_threats
            from defender_sig_extractor.pe_extractor import PEExtractor
        except ImportError as e:
            # Update status with error
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="failed",
                    completed_at=datetime.utcnow(),
                    error_message=f"Import error: {e}",
                )
            )
            await db.commit()
            return

        try:
            # Run download and extraction in thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()
            print(f"Sync {sync_id}: Starting download in background thread...", flush=True)
            logger.info(f"Sync {sync_id}: Starting download in background thread...")
            download_result = await loop.run_in_executor(_sync_executor, _download_and_extract_vdm)
            print(f"Sync {sync_id}: Download complete, got {len(download_result.vdm_files)} files", flush=True)

            logger.info(f"Sync {sync_id}: Importing {len(download_result.vdm_files)} VDM files...")
            await _import_vdm_files(db, sync_id, download_result.vdm_files)
            logger.info(f"Sync {sync_id}: Import complete")

        except Exception as e:
            logger.exception(f"Sync {sync_id} failed: {e}")
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="failed",
                    completed_at=datetime.utcnow(),
                    error_message="Sync failed. Check server logs for details.",
                )
            )
            await db.commit()
        finally:
            # Clean up temp files
            if download_result:
                _cleanup_temp_files(download_result)


async def run_local_import(sync_id: int, vdm_path: str) -> None:
    """
    Run import from a local VDM file.

    Args:
        sync_id: ID of the SyncStatus record
        vdm_path: Path to local VDM file
    """
    logger.info(f"Local import {sync_id}: Starting import from {vdm_path}")
    async with async_session_maker() as db:
        try:
            await _import_vdm_file(db, sync_id, vdm_path)
            logger.info(f"Local import {sync_id}: Complete")
        except Exception as e:
            logger.exception(f"Local import {sync_id} failed: {e}")
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="failed",
                    completed_at=datetime.utcnow(),
                    error_message="Import failed. Check server logs for details.",
                )
            )
            await db.commit()


def _parse_vdm_sync(vdm_path: str) -> tuple[bytes, str]:
    """
    Synchronous helper to parse VDM file and compute hash.

    Runs in a thread pool to avoid blocking the async event loop.

    Returns:
        Tuple of (decompressed_data, content_hash)
    """
    from defender_sig_extractor.vdm_parser import VDMParser

    print(f"Parsing VDM file: {vdm_path}", flush=True)
    parser = VDMParser(vdm_path)
    decompressed = parser.decompress()
    content_hash = hashlib.sha256(decompressed).hexdigest()
    print(f"VDM decompressed: {len(decompressed)} bytes, hash: {content_hash[:16]}...", flush=True)
    return decompressed, content_hash


def _extract_threats_from_vdm(vdm_path: str) -> List[Any]:
    """
    Extract threats from a single VDM file.

    Args:
        vdm_path: Path to VDM file

    Returns:
        List of ThreatDefinitions
    """
    from defender_sig_extractor.vdm_parser import VDMParser
    from defender_sig_extractor.signature_extractor import extract_threats

    logger.info(f"Parsing VDM: {Path(vdm_path).name}")
    parser = VDMParser(vdm_path)
    data = parser.decompress()
    logger.info(f"Decompressed: {len(data)} bytes")

    threats = list(extract_threats(data))
    logger.info(f"Extracted {len(threats)} threats from {Path(vdm_path).name}")

    return threats


async def _import_vdm_files(db: AsyncSession, sync_id: int, vdm_files: dict) -> None:
    """Internal function to import multiple VDM files with incremental sync support.

    Args:
        db: Database session
        sync_id: Sync status record ID
        vdm_files: Dict mapping VDM type to path (av_base, av_delta, as_base, as_delta)
    """
    print(f"_import_vdm_files called with {len(vdm_files)} files: {list(vdm_files.keys())}", flush=True)

    try:
        from defender_sig_extractor.vdm_parser import VDMParser
        from defender_sig_extractor.signature_extractor import extract_threats
    except ImportError as e:
        raise ImportError(f"defender_sig_extractor not available: {e}")

    loop = asyncio.get_event_loop()

    # Compute hashes for individual VDM files
    print("Computing file hashes...", flush=True)
    file_hashes = VDMFileHashes()
    for key in ['av_base', 'av_delta', 'as_base', 'as_delta']:
        if key in vdm_files:
            print(f"Hashing {key}...", flush=True)
            _, content_hash = await loop.run_in_executor(
                _sync_executor, _parse_vdm_sync, vdm_files[key]
            )
            setattr(file_hashes, key.replace('-', '_'), content_hash)
            print(f"Done hashing {key}: {content_hash[:16]}...", flush=True)

    version_hash = file_hashes.combined_hash
    print(f"Combined version hash: {version_hash[:16]}...", flush=True)

    # Check if we already have this exact version
    print("Checking for existing version...", flush=True)
    existing = await db.execute(
        select(VDMVersion).where(VDMVersion.version_hash == version_hash)
    )
    if existing.scalar_one_or_none():
        print("Version already imported, skipping", flush=True)
        await db.execute(
            update(SyncStatus)
            .where(SyncStatus.id == sync_id)
            .values(
                status="completed",
                completed_at=datetime.utcnow(),
                error_message="No changes - version already imported",
            )
        )
        await db.commit()
        return

    print("New version, proceeding with import...", flush=True)

    # Check if we have existing data and can do incremental sync
    current_version = await db.execute(
        select(VDMVersion).where(VDMVersion.is_current == True)
    )
    current = current_version.scalar_one_or_none()

    # Determine if we can do incremental sync
    # Incremental sync is possible if:
    # 1. We have existing data (current version exists)
    # 2. Base files haven't changed (only deltas changed)
    can_do_incremental = False
    if current:
        base_unchanged = (
            current.av_base_hash == file_hashes.av_base and
            current.as_base_hash == file_hashes.as_base
        )
        if base_unchanged:
            can_do_incremental = True
            print("Base files unchanged - using incremental sync", flush=True)
        else:
            print("Base files changed - doing full import", flush=True)
    else:
        print("No current version - doing full import", flush=True)

    # Import ASR rules first
    print("Importing ASR rules...", flush=True)
    await import_asr_rules(db)
    print("ASR rules imported", flush=True)

    # Extract threats from all VDM files
    # Process each file separately (base and delta files both contain signatures)
    print("Starting threat extraction from VDM files...", flush=True)
    file_order = ['av_base', 'av_delta', 'as_base', 'as_delta']

    # Perform sync (incremental or full)
    sync_service = SyncService(db)
    import_service = ImportService(db)

    total_threats_added = 0
    total_threats_updated = 0
    total_threats_removed = 0
    total_signatures_added = 0

    if can_do_incremental:
        # Incremental sync: compute delta and apply changes
        all_threats = []
        for vdm_key in file_order:
            vdm_path = vdm_files.get(vdm_key)
            if vdm_path:
                print(f"Extracting threats from {vdm_key}...", flush=True)
                threats = await loop.run_in_executor(
                    _sync_executor,
                    _extract_threats_from_vdm,
                    vdm_path,
                )
                all_threats.extend(threats)
                print(f"Processed {vdm_key}: {len(threats)} threats", flush=True)

        threats_by_id = {t.signature_id: t for t in all_threats}
        logger.info(f"Total threats to sync: {len(threats_by_id)}")

        if len(threats_by_id) == 0:
            logger.error("No threats extracted from VDM files - aborting sync")
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="failed",
                    completed_at=datetime.utcnow(),
                    error_message="No threats extracted from VDM files",
                )
            )
            await db.commit()
            return

        logger.info("Computing delta between new VDM and database...")
        delta = await sync_service.compute_delta(all_threats)

        logger.info(f"Delta: +{len(delta.added)} added, -{len(delta.removed)} removed, ~{len(delta.potentially_modified)} to check")

        if not delta.added and not delta.removed and not delta.potentially_modified:
            logger.info("No changes detected")
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="completed",
                    completed_at=datetime.utcnow(),
                    error_message="No changes detected",
                )
            )
            await db.commit()
            return

        stats = await sync_service.apply_incremental_update(delta, threats_by_id)
        total_threats_added = stats.threats_added
        total_threats_updated = stats.threats_updated
        total_threats_removed = len(delta.removed)
        total_signatures_added = stats.signatures_added

    else:
        # Full import: stream each VDM file and import without building a combined list
        logger.info("Performing full import (streamed)...")
        stats = ImportStats()

        # Disable decompilation during import to reduce memory pressure
        import_service = ImportService(db, decompile_during_import=False)

        total_threats = 0
        processed = 0
        batch_size = 100

        for vdm_key in file_order:
            vdm_path = vdm_files.get(vdm_key)
            if not vdm_path:
                continue
            print(f"Extracting threats from {vdm_key}...", flush=True)
            threats = await loop.run_in_executor(
                _sync_executor,
                _extract_threats_from_vdm,
                vdm_path,
            )
            print(f"Processed {vdm_key}: {len(threats)} threats", flush=True)

            total_threats += len(threats)
            for threat_def in threats:
                await import_service._import_threat(threat_def, stats)
                processed += 1
                if processed % batch_size == 0:
                    await asyncio.sleep(0)
                    if processed % 1000 == 0:
                        # Persist progress so UI can reflect forward motion.
                        await db.execute(
                            update(SyncStatus)
                            .where(SyncStatus.id == sync_id)
                            .values(
                                threats_added=stats.threats_added,
                                threats_updated=stats.threats_updated,
                            )
                        )
                        await db.commit()
                        if total_threats:
                            logger.info(f"Import progress: {processed}/{total_threats} threats ({processed * 100 // total_threats}%)")
                            print(f"Import progress: {processed}/{total_threats} threats ({processed * 100 // total_threats}%)", flush=True)

        total_threats_added = stats.threats_added
        total_threats_updated = stats.threats_updated
        total_signatures_added = stats.signatures_added
        logger.info(
            f"Import loop finished: processed={processed}, "
            f"threats_added={total_threats_added}, threats_updated={total_threats_updated}, "
            f"signatures_added={total_signatures_added}"
        )
        print("Import loop finished, committing...", flush=True)
        await db.commit()
        print("Import commit done.", flush=True)

    # If we skipped decompilation during import, complete it now (bounded batches)
    if isinstance(import_service, ImportService) and not import_service.decompile_during_import:
        from .decompilation_service import decompile_all_pending
        logger.info("Starting post-import decompilation to finalize ASR resolution...")
        print("Starting post-import decompilation...", flush=True)
        total_decompiled = await decompile_all_pending(batch_size=20)
        logger.info(f"Post-import decompilation complete: {total_decompiled} scripts")
        print(f"Post-import decompilation complete: {total_decompiled} scripts", flush=True)

    # Finalize ASR resolution (backfill GUIDs and update counts)
    print("Finalizing ASR resolution...", flush=True)
    await import_service._finalize_asr_resolution()
    print("ASR resolution finalized.", flush=True)

    # Run V2 ASR function resolution to build function registry and resolve cross-script dependencies
    print("Building function registry and resolving ASR dependencies...", flush=True)
    try:
        from .text_import_service import TextImportService
        from .asr_resolver_service import ASRResolverService

        # Build function registry from all Lua scripts in database
        text_service = TextImportService(db)

        # Scan all decompiled sources for function definitions
        from sqlalchemy import select as sql_select
        result = await db.execute(
            sql_select(LuaScript.decompiled_source).where(LuaScript.decompiled_source.isnot(None))
        )
        sources = [row[0] for row in result.all() if row[0]]
        logger.info(f"Scanning {len(sources)} Lua scripts for function definitions...")

        for source in sources:
            text_service._discover_functions(source, "database")

        logger.info(f"Discovered {len(text_service.function_registry)} function definitions")

        # Save function definitions to database
        await text_service._save_function_registry()

        # Resolve ASR function dependencies
        resolver = ASRResolverService(db)
        resolver_stats = await resolver.resolve_all_asr_rules()
        logger.info(
            f"ASR V2 resolution complete: {resolver_stats.rules_updated} rules updated, "
            f"{resolver_stats.functions_resolved} functions resolved"
        )
        print(f"ASR V2 resolution complete: {resolver_stats.rules_updated} rules, {resolver_stats.functions_resolved} functions", flush=True)
    except Exception as e:
        logger.warning(f"V2 ASR resolution failed (non-fatal): {e}")
        print(f"Warning: V2 ASR resolution failed: {e}", flush=True)

    # Create version record with individual file hashes
    version = VDMVersion(
        version_hash=version_hash,
        threat_count=total_threats_added + total_threats_updated,
        signature_count=total_signatures_added,
        is_current=True,
        av_base_hash=file_hashes.av_base,
        av_delta_hash=file_hashes.av_delta,
        as_base_hash=file_hashes.as_base,
        as_delta_hash=file_hashes.as_delta,
    )

    # Mark previous versions as not current
    await db.execute(
        update(VDMVersion).values(is_current=False)
    )

    db.add(version)

    # Update sync status
    await db.execute(
        update(SyncStatus)
        .where(SyncStatus.id == sync_id)
        .values(
            status="completed",
            completed_at=datetime.utcnow(),
            threats_added=total_threats_added,
            threats_updated=total_threats_updated,
            threats_removed=total_threats_removed,
        )
    )

    await db.commit()
    logger.info(f"Sync complete: +{total_threats_added} added, ~{total_threats_updated} updated, -{total_threats_removed} removed")


async def _import_vdm_file(db: AsyncSession, sync_id: int, vdm_path: str) -> None:
    """Internal function to import a single VDM file (for backwards compatibility)."""
    await _import_vdm_files(db, sync_id, {'av_base': vdm_path})
