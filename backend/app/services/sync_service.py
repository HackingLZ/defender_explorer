"""Service for syncing VDM data with delta updates."""

import asyncio
import gc
import hashlib
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Dict, List, Any
from dataclasses import dataclass, field

from sqlalchemy import select, update, delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import async_session_maker
from ..models import Threat, Signature, LuaScript, VDMVersion, SyncStatus
from .import_service import ImportService, ImportStats, import_asr_rules
from .vdm_service import decompress_vdm, hash_vdm, merge_vdm
from .sync_lifecycle import exclusive_sync, set_progress

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
        combined = hashlib.sha256(b"verified-delta-v1:")
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

    print("Starting MPAM download from Microsoft...", flush=True)
    logger.info("Starting MPAM download from Microsoft...")
    mpam_path = download_mpam_to_temp()
    print(f"Download complete: {mpam_path}", flush=True)
    logger.info(f"Download complete: {mpam_path}")

    # Create temp directory for extraction
    temp_dir = tempfile.mkdtemp(prefix="vdm_extract_")

    result = VDMDownloadResult({}, temp_dir, mpam_path)
    try:
        logger.info("Extracting VDM files from MPAM...")
        PEExtractor(mpam_path).extract_vdm_files(temp_dir)
        result.vdm_files = get_vdm_files(temp_dir)
        if not result.vdm_files:
            raise ValueError("No VDM files found in MPAM")
        return result
    except BaseException:
        _cleanup_temp_files(result)
        raise


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


@exclusive_sync
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
                    phase="failed",
                    completed_at=datetime.utcnow(),
                    error_message=f"Import error: {e}",
                )
            )
            await db.commit()
            return

        try:
            # Run download and extraction in thread pool to avoid blocking event loop
            await set_progress(db, sync_id, "downloading")
            loop = asyncio.get_event_loop()
            print(f"Sync {sync_id}: Starting download in background thread...", flush=True)
            logger.info(f"Sync {sync_id}: Starting download in background thread...")
            download_future = loop.run_in_executor(_sync_executor, _download_and_extract_vdm)
            try:
                download_result = await asyncio.shield(download_future)
            except asyncio.CancelledError:
                # Thread cancellation cannot stop a download. Reap its temporary
                # files when it finishes, without letting it start an import.
                def cleanup_finished(future):
                    try:
                        _cleanup_temp_files(future.result())
                    except Exception:
                        logger.exception("Cancelled sync download failed")
                download_future.add_done_callback(cleanup_finished)
                raise
            print(f"Sync {sync_id}: Download complete, got {len(download_result.vdm_files)} files", flush=True)

            logger.info(f"Sync {sync_id}: Importing {len(download_result.vdm_files)} VDM files...")
            await _import_vdm_files(db, sync_id, download_result.vdm_files, authoritative=True)
            logger.info(f"Sync {sync_id}: Import complete")

        except Exception as e:
            logger.exception(f"Sync {sync_id} failed: {e}")
            # A database error aborts the transaction. Roll it back before
            # recording failure, or this update fails too and leaves it running.
            await db.rollback()
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="failed",
                    phase="failed",
                    completed_at=datetime.utcnow(),
                    error_message="Sync failed. Check server logs for details.",
                )
            )
            await db.commit()
        finally:
            # Clean up temp files
            if download_result:
                _cleanup_temp_files(download_result)


@exclusive_sync
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
            await db.rollback()
            await db.execute(
                update(SyncStatus)
                .where(SyncStatus.id == sync_id)
                .values(
                    status="failed",
                    phase="failed",
                    completed_at=datetime.utcnow(),
                    error_message="Import failed. Check server logs for details.",
                )
            )
            await db.commit()


def _extract_threats_from_data(data: bytes) -> List[Any]:
    """Extract threats from data already bounded by the VDM worker."""
    from defender_sig_extractor.signature_extractor import extract_threats

    from defender_sig_extractor.delta_patcher import records
    in_threat = False
    for kind, payload in records(data):
        if kind in (0x73, 0x74):
            raise ValueError("Unapplied delta records in snapshot")
        if kind == 0x5c:
            if in_threat or len(payload) < 13:
                raise ValueError("Malformed threat record")
            in_threat = True
        elif kind == 0x5d:
            in_threat = False
    if in_threat:
        raise ValueError("Unterminated threat record")
    threats = list(extract_threats(data))
    logger.info(f"Extracted {len(threats)} threats")

    return threats


async def _extract_threats_from_vdm(vdm_path: str) -> List[Any]:
    data = await decompress_vdm(vdm_path)
    return await asyncio.get_running_loop().run_in_executor(
        _sync_executor, _extract_threats_from_data, data
    )


async def _import_vdm_files(db: AsyncSession, sync_id: int, vdm_files: dict, *, authoritative=False) -> None:
    """Reconstruct snapshots, reuse unchanged threats, then reconcile removals.

    Only a complete downloaded AV/AS snapshot can remove absent records.
    A single-file local import is additive and never deletes unrelated data.
    Failed batches can be retried: stored hashes skip already committed work.
    """
    if authoritative and set(vdm_files) != {"av_base", "av_delta", "as_base", "as_delta"}:
        raise ValueError("A complete AV/AS base and delta snapshot is required")
    for family in ("av", "as"):
        if f"{family}_delta" in vdm_files and f"{family}_base" not in vdm_files:
            raise ValueError("A delta requires its matching base")

    file_hashes = VDMFileHashes()
    for key in ('av_base', 'av_delta', 'as_base', 'as_delta'):
        if key in vdm_files:
            setattr(file_hashes, key, await hash_vdm(vdm_files[key]))
    version_hash = file_hashes.combined_hash
    existing = await db.scalar(select(VDMVersion).where(VDMVersion.version_hash == version_hash))
    # A failed newer update may have committed batches. Reconcile even when
    # returning to the current/previous snapshot instead of blindly skipping.
    failed_since = None
    if existing is not None:
        failed_since = await db.scalar(select(SyncStatus.id).where(
            SyncStatus.status == "failed", SyncStatus.started_at >= existing.download_timestamp,
        ).limit(1))
    if existing is not None and existing.is_current and not failed_since:
        from .decompilation_service import get_decompilation_stats
        lua = await get_decompilation_stats()
        await db.execute(update(SyncStatus).where(SyncStatus.id == sync_id).values(
            status="completed", phase="completed", completed_at=datetime.utcnow(),
            error_message="No changes - version already imported",
            lua_completed=lua.get("completed", 0), lua_failed=lua.get("failed", 0), lua_pending=lua.get("pending", 0),
        ))
        await db.commit()
        return

    db.info["vdm_version_hash"] = version_hash
    # after_begin propagates provenance to subsequent batch transactions.
    await db.execute(text("SELECT set_config('app.vdm_version_hash', :version_hash, true)"),
                     {"version_hash": version_hash})
    await import_asr_rules(db)
    await set_progress(db, sync_id, "parsing")
    stored = dict((await db.execute(select(Threat.signature_id, Threat.content_hash))).all())
    import_service = ImportService(db, decompile_during_import=False)
    stats = ImportStats()
    seen = set()
    processed = signatures = 0
    for family in ("av", "as"):
        base = vdm_files.get(f"{family}_base")
        if not base:
            continue
        await set_progress(db, sync_id, "parsing")
        delta = vdm_files.get(f"{family}_delta")
        data = await merge_vdm(base, delta) if delta else await decompress_vdm(base)
        threats = await asyncio.get_running_loop().run_in_executor(
            _sync_executor, _extract_threats_from_data, data,
        )
        del data
        if not threats:
            raise ValueError("No threats extracted from VDM files")
        total = processed + len(threats)
        await set_progress(db, sync_id, "importing", threats_total=total)
        for index, threat in enumerate(threats):
            sig_id = threat.signature_id
            if sig_id in seen:
                raise ValueError("Duplicate threat ID in snapshot")
            seen.add(sig_id)
            content_hash = import_service._compute_threat_hash(threat)
            if stored.get(sig_id) != content_hash:
                await import_service._import_threat(threat, stats)
            signatures += len(threat.signatures)
            processed += 1
            threats[index] = None
            if processed % 1000 == 0:
                await set_progress(db, sync_id, "importing", threats_processed=processed,
                                   threats_added=stats.threats_added, threats_updated=stats.threats_updated)
                db.sync_session.expunge_all()
                await asyncio.sleep(0)
        del threats
        gc.collect()

    if not seen:
        raise ValueError("No threats extracted from VDM files")
    removed = list(set(stored) - seen) if authoritative else []
    # Defer removal until both families have parsed/imported successfully.
    for offset in range(0, len(removed), 1000):
        await db.execute(delete(Threat).where(Threat.signature_id.in_(removed[offset:offset + 1000])))
    await set_progress(db, sync_id, "decompiling", threats_processed=processed, threats_total=processed,
                       threats_added=stats.threats_added, threats_updated=stats.threats_updated,
                       threats_removed=len(removed))

    from .decompilation_service import decompile_all_pending, get_decompilation_stats
    await decompile_all_pending(batch_size=20)
    lua = await get_decompilation_stats()
    warning = f"{lua.get('failed', 0)} Lua scripts failed; see admin decompilation diagnostics." if lua.get("failed") else None
    # Finalize ASR resolution (backfill GUIDs and update counts)
    await set_progress(db, sync_id, "resolving_asr")
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
        await db.rollback()
        warning = "ASR dependency resolution failed; check server logs."
        logger.warning(f"V2 ASR resolution failed (non-fatal): {e}")
        print(f"Warning: V2 ASR resolution failed: {e}", flush=True)

    # Reuse historical version rows when reverting/retrying a snapshot.
    await db.execute(update(VDMVersion).values(is_current=False))
    version = await db.scalar(select(VDMVersion).where(VDMVersion.version_hash == version_hash))
    if version is None:
        version = VDMVersion(version_hash=version_hash)
        db.add(version)
    version.is_current = True
    version.download_timestamp = datetime.utcnow()
    version.threat_count = len(seen)
    version.signature_count = signatures
    for key in ('av_base', 'av_delta', 'as_base', 'as_delta'):
        setattr(version, key + "_hash", getattr(file_hashes, key))
    await db.execute(update(SyncStatus).where(SyncStatus.id == sync_id).values(
        status="completed", phase="completed", completed_at=datetime.utcnow(),
        heartbeat_at=datetime.utcnow(), error_message=warning,
        threats_added=stats.threats_added, threats_updated=stats.threats_updated,
        threats_removed=len(removed), lua_completed=lua.get("completed", 0),
        lua_failed=lua.get("failed", 0), lua_pending=lua.get("pending", 0),
    ))
    await db.commit()


async def _import_vdm_file(db: AsyncSession, sync_id: int, vdm_path: str) -> None:
    """Internal function to import a single VDM file (for backwards compatibility)."""
    await _import_vdm_files(db, sync_id, {'av_base': vdm_path})
