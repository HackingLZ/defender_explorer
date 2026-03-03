"""Service for importing VDM data into the database."""

import asyncio
import hashlib
import logging
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional, Callable, List, Any
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func, update
from sqlalchemy.dialects.postgresql import insert

# Add the parent directory to path for defender_sig_extractor imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from ..models import Threat, Signature, LuaScript, ASRRule
from ..database import async_session_maker
from .signature_classifier import classify_signature, extract_searchable_text

logger = logging.getLogger(__name__)

# Thread pool for CPU-intensive VDM parsing
_import_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="import_worker")
_lua_decompile_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="lua_import_worker")


def _parse_and_extract_threats(vdm_path: str) -> List[Any]:
    """
    Parse VDM file and extract threats (runs in thread pool).

    This is CPU-intensive work that should not block the event loop.
    """
    from defender_sig_extractor.vdm_parser import VDMParser
    from defender_sig_extractor.signature_extractor import extract_threats

    logger.info(f"Thread: Decompressing VDM file...")
    parser = VDMParser(vdm_path)
    decompressed = parser.decompress()
    logger.info(f"Thread: Decompressed {len(decompressed)} bytes, extracting threats...")

    threats = list(extract_threats(decompressed))
    logger.info(f"Thread: Extracted {len(threats)} threats")
    return threats


def _get_rss_mb() -> Optional[float]:
    """Best-effort RSS in MB for logging (Linux containers)."""
    try:
        with open("/proc/self/statm", "r", encoding="utf-8") as f:
            parts = f.readline().split()
        if len(parts) < 2:
            return None
        rss_pages = int(parts[1])
        page_size = os.sysconf("SC_PAGE_SIZE")
        return (rss_pages * page_size) / (1024 * 1024)
    except Exception:
        return None


@dataclass
class ImportStats:
    """Statistics from an import operation."""
    threats_added: int = 0
    threats_updated: int = 0
    signatures_added: int = 0
    lua_scripts_added: int = 0
    hashes_added: int = 0
    iocs_added: int = 0


class ImportService:
    """Service for importing VDM data into the database."""

    def __init__(self, db: AsyncSession, decompile_during_import: bool = True):
        self.db = db
        self.decompile_during_import = decompile_during_import

    async def import_from_vdm(
        self,
        vdm_path: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> ImportStats:
        """
        Import threats from a VDM file using bulk inserts for performance.

        Args:
            vdm_path: Path to VDM file
            progress_callback: Optional callback(current, total)

        Returns:
            Import statistics
        """
        stats = ImportStats()

        # Run VDM parsing and threat extraction in thread pool (CPU-intensive)
        loop = asyncio.get_event_loop()
        logger.info(f"Parsing VDM file in background thread: {vdm_path}")
        threats = await loop.run_in_executor(
            _import_executor, _parse_and_extract_threats, vdm_path
        )
        total = len(threats)
        logger.info(f"Extracted {total} threats, starting bulk database import...")

        # Use bulk import for better performance
        await self._bulk_import_threats(threats, stats, progress_callback)

        logger.info(f"Import complete: {stats.threats_added} added, {stats.threats_updated} updated, {stats.signatures_added} signatures")

        # Finalize ASR resolution (backfill missing GUIDs and update counts)
        await self._finalize_asr_resolution()

        return stats

    async def _bulk_import_threats(
        self,
        threats: List[Any],
        stats: ImportStats,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """
        Bulk import threats using batched INSERT statements.

        This is ~5-10x faster than individual ORM inserts.
        """
        try:
            from defender_sig_extractor.signature_types import get_type_name, is_lua_type
            from defender_sig_extractor.output.asr_writer import (
                extract_guids_from_bytecode,
                decompile_lua_safe,
                extract_lua_from_signature,
            )
        except ImportError:
            get_type_name = lambda x: f"UNKNOWN_0x{x:02X}"
            is_lua_type = lambda x: x in (0x4C, 0xBD)
            extract_guids_from_bytecode = lambda x: set()
            decompile_lua_safe = lambda x: None
            extract_lua_from_signature = lambda x: None

        total = len(threats)
        batch_size = 500  # Process 500 threats at a time

        for batch_start in range(0, total, batch_size):
            batch_end = min(batch_start + batch_size, total)
            batch = threats[batch_start:batch_end]

            if progress_callback:
                progress_callback(batch_start, total)

            # Prepare threat data for bulk insert
            threat_rows = []
            threat_defs_map = {}  # signature_id -> threat_def

            for threat_def in batch:
                fixed_name = Threat.fix_threat_name(threat_def.threat_name)
                parsed = Threat.parse_threat_name(threat_def.threat_name)
                content_hash = self._compute_threat_hash(threat_def)

                threat_rows.append({
                    "signature_id": threat_def.signature_id,
                    "threat_name": fixed_name,
                    "category": parsed["category"],
                    "family": parsed["family"],
                    "signature_count": len(threat_def.signatures),
                    "content_hash": content_hash,
                })
                threat_defs_map[threat_def.signature_id] = threat_def

            # Bulk upsert threats and get their IDs
            if threat_rows:
                stmt = insert(Threat).values(threat_rows)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["signature_id"],
                    set_={
                        "threat_name": stmt.excluded.threat_name,
                        "category": stmt.excluded.category,
                        "family": stmt.excluded.family,
                        "signature_count": stmt.excluded.signature_count,
                        "content_hash": stmt.excluded.content_hash,
                    }
                ).returning(Threat.id, Threat.signature_id)

                result = await self.db.execute(stmt)
                threat_id_map = {row.signature_id: row.id for row in result.fetchall()}
                stats.threats_added += len(threat_rows)

            # Delete old signatures for these threats (for re-imports)
            threat_ids = list(threat_id_map.values())
            if threat_ids:
                await self.db.execute(
                    delete(Signature).where(Signature.threat_id.in_(threat_ids))
                )
                await self.db.execute(
                    delete(LuaScript).where(LuaScript.threat_id.in_(threat_ids))
                )

            # Prepare signature data for bulk insert
            signature_rows = []
            lua_pending = []  # (sig_data, threat_id, sig_type) for Lua processing

            for vdm_sig_id, threat_id in threat_id_map.items():
                threat_def = threat_defs_map[vdm_sig_id]

                for sig_entry in threat_def.signatures:
                    data_hash = hashlib.sha256(sig_entry.data).hexdigest() if sig_entry.data else None
                    sig_type_name = get_type_name(sig_entry.sig_type)
                    category, subcategory = classify_signature(sig_type_name, sig_entry.data)
                    extracted_text = extract_searchable_text(sig_entry.data, sig_type_name)

                    signature_rows.append({
                        "threat_id": threat_id,
                        "sig_type": sig_entry.sig_type,
                        "sig_type_name": sig_type_name,
                        "size": sig_entry.size,
                        "data_hash": data_hash,
                        "data": sig_entry.data,
                        "category": category,
                        "subcategory": subcategory,
                        "extracted_text": extracted_text if extracted_text else None,
                    })

                    # Track Lua signatures for later processing
                    if is_lua_type(sig_entry.sig_type):
                        lua_pending.append((sig_entry.data, threat_id, len(signature_rows) - 1))

            # Bulk insert signatures
            if signature_rows:
                # Insert in sub-batches of 1000 to avoid query size limits
                sig_batch_size = 1000
                sig_id_list = []

                for sig_start in range(0, len(signature_rows), sig_batch_size):
                    sig_end = min(sig_start + sig_batch_size, len(signature_rows))
                    sig_batch = signature_rows[sig_start:sig_end]

                    stmt = insert(Signature).values(sig_batch).returning(Signature.id)
                    result = await self.db.execute(stmt)
                    sig_id_list.extend([row.id for row in result.fetchall()])

                stats.signatures_added += len(signature_rows)

                # Process Lua scripts (need signature IDs)
                for sig_data, threat_id, sig_idx in lua_pending:
                    if sig_idx < len(sig_id_list):
                        signature_id = sig_id_list[sig_idx]
                        await self._import_lua_script(
                            sig_data, signature_id, threat_id, stats,
                            extract_lua_from_signature, extract_guids_from_bytecode, decompile_lua_safe
                        )

            # Commit this batch
            await self.db.commit()

            # Log progress
            if batch_start % 2000 == 0:
                logger.info(f"Bulk import progress: {batch_end}/{total} threats ({batch_end*100//total}%)")

            # Yield to event loop
            await asyncio.sleep(0)

    async def _finalize_asr_resolution(self) -> None:
        """Ensure ASR GUIDs are resolved and counts are accurate after import."""
        try:
            from defender_sig_extractor.output.asr_writer import extract_guids_from_source, ASR_RULES

            start = time.monotonic()
            logger.info("ASR finalize: backfill starting")

            # Backfill missing ASR GUIDs from decompiled source when available.
            result = await self.db.execute(
                select(LuaScript.id, LuaScript.decompiled_source)
                .where(LuaScript.decompiled_source.isnot(None))
                .where(
                    (LuaScript.asr_guids == None) |
                    (func.array_length(LuaScript.asr_guids, 1) == 0)
                )
            )
            rows = result.all()
            updated = 0
            for script_id, source in rows:
                if not source:
                    continue
                guids = extract_guids_from_source(source)
                filtered = [g.lower() for g in guids if g and g.lower() in ASR_RULES]
                if filtered:
                    await self.db.execute(
                        update(LuaScript)
                        .where(LuaScript.id == script_id)
                        .values(
                            asr_guids=filtered,
                            is_asr_script=True,
                        )
                    )
                    updated += 1

            await self.db.commit()
            elapsed = time.monotonic() - start
            logger.info(
                f"ASR finalize: backfill completed (rows={len(rows)}, updated={updated}, {elapsed:.1f}s)"
            )
        except Exception as e:
            logger.error(f"Failed to backfill ASR GUIDs: {e}")
            await self.db.rollback()

        await self._update_asr_rule_counts()

    async def _update_asr_rule_counts(self) -> None:
        """Update script counts for all ASR rules based on linked Lua scripts."""
        try:
            from defender_sig_extractor.output.asr_writer import ASR_RULES
            from sqlalchemy import text

            start = time.monotonic()
            logger.info("ASR count update: starting")

            # Aggregate counts in one pass for speed and consistency.
            result = await self.db.execute(
                text(
                    """
                    SELECT lower(guid) AS guid, COUNT(*) AS cnt
                    FROM (
                        SELECT unnest(asr_guids) AS guid
                        FROM lua_scripts
                        WHERE asr_guids IS NOT NULL
                    ) AS s
                    GROUP BY lower(guid)
                    """
                )
            )
            counts = {row[0]: row[1] for row in result.all()}

            for guid in ASR_RULES.keys():
                guid_lower = guid.lower()
                count = counts.get(guid_lower, 0)
                await self.db.execute(
                    update(ASRRule)
                    .where(ASRRule.guid == guid_lower)
                    .values(script_count=count)
                )

            await self.db.commit()
            elapsed = time.monotonic() - start
            logger.info(
                f"ASR count update: completed ({len(ASR_RULES)} rules, {len(counts)} guids, {elapsed:.1f}s)"
            )
        except Exception as e:
            logger.error(f"Failed to update ASR rule counts: {e}")
            await self.db.rollback()  # Rollback to clear failed transaction

    async def _import_threat(self, threat_def, stats: ImportStats) -> None:
        """Import a single threat definition."""
        try:
            from defender_sig_extractor.signature_types import get_type_name, is_lua_type
            from defender_sig_extractor.output.asr_writer import (
                extract_guids_from_bytecode,
                decompile_lua_safe,
                extract_lua_from_signature,
            )
        except ImportError:
            get_type_name = lambda x: f"UNKNOWN_0x{x:02X}"
            is_lua_type = lambda x: x in (0x4C, 0xBD)
            extract_guids_from_bytecode = lambda x: set()
            decompile_lua_safe = lambda x: None
            extract_lua_from_signature = lambda x: None

        # Fix and parse threat name for category and family
        fixed_threat_name = Threat.fix_threat_name(threat_def.threat_name)
        parsed = Threat.parse_threat_name(threat_def.threat_name)

        # Check if threat exists
        existing = await self.db.execute(
            select(Threat).where(Threat.signature_id == threat_def.signature_id)
        )
        existing_threat = existing.scalar_one_or_none()

        if existing_threat:
            # Update existing threat
            # Clear existing signatures/Lua scripts to avoid duplication on re-import
            await self.db.execute(
                delete(LuaScript).where(LuaScript.threat_id == existing_threat.id)
            )
            await self.db.execute(
                delete(Signature).where(Signature.threat_id == existing_threat.id)
            )
            existing_threat.threat_name = fixed_threat_name
            existing_threat.category = parsed["category"]
            existing_threat.family = parsed["family"]
            existing_threat.signature_count = len(threat_def.signatures)
            existing_threat.content_hash = self._compute_threat_hash(threat_def)
            stats.threats_updated += 1
            threat = existing_threat
        else:
            # Create new threat
            threat = Threat(
                signature_id=threat_def.signature_id,
                threat_name=fixed_threat_name,
                category=parsed["category"],
                family=parsed["family"],
                signature_count=len(threat_def.signatures),
                content_hash=self._compute_threat_hash(threat_def),
            )
            self.db.add(threat)
            await self.db.flush()
            stats.threats_added += 1

        # Import signatures
        lua_entries = []
        non_lua_batch = []
        for sig_entry in threat_def.signatures:
            data_hash = hashlib.sha256(sig_entry.data).hexdigest() if sig_entry.data else None
            sig_type_name = get_type_name(sig_entry.sig_type)

            # Classify signature for browsing
            category, subcategory = classify_signature(sig_type_name, sig_entry.data)
            extracted_text = extract_searchable_text(sig_entry.data, sig_type_name)

            # Process Lua scripts
            if is_lua_type(sig_entry.sig_type):
                signature = Signature(
                    threat_id=threat.id,
                    sig_type=sig_entry.sig_type,
                    sig_type_name=sig_type_name,
                    size=sig_entry.size,
                    data_hash=data_hash,
                    data=sig_entry.data,
                    category=category,
                    subcategory=subcategory,
                    extracted_text=extracted_text if extracted_text else None,
                )
                self.db.add(signature)
                await self.db.flush()
                stats.signatures_added += 1
                lua_entries.append((sig_entry.data, signature.id))
            else:
                non_lua_batch.append(
                    {
                        "threat_id": threat.id,
                        "sig_type": sig_entry.sig_type,
                        "sig_type_name": sig_type_name,
                        "size": sig_entry.size,
                        "data_hash": data_hash,
                        "data": sig_entry.data,
                        "category": category,
                        "subcategory": subcategory,
                        "extracted_text": extracted_text if extracted_text else None,
                    }
                )

        if non_lua_batch:
            await self.db.execute(insert(Signature), non_lua_batch)
            stats.signatures_added += len(non_lua_batch)

        if lua_entries:
            await self._import_lua_scripts_batch(
                lua_entries, threat.id, stats,
                extract_lua_from_signature,
                extract_guids_from_bytecode,
                decompile_lua_safe if self.decompile_during_import else None
            )

    def _compute_threat_hash(self, threat_def) -> str:
        """Compute a content hash for a threat definition."""
        h = hashlib.sha256()
        h.update(threat_def.threat_name.encode())
        h.update(str(threat_def.signature_id).encode())
        for sig in sorted(threat_def.signatures, key=lambda s: (s.sig_type, s.size)):
            h.update(bytes([sig.sig_type]))
            h.update(sig.data or b'')
        return h.hexdigest()

    async def update_threat(self, sig_id: int, threat_def, stats: ImportStats) -> None:
        """
        Update an existing threat with new definition.

        Args:
            sig_id: The signature_id of the threat to update
            threat_def: New ThreatDefinition
            stats: Import stats to update
        """
        try:
            from defender_sig_extractor.signature_types import get_type_name, is_lua_type
            from defender_sig_extractor.output.asr_writer import (
                extract_guids_from_bytecode,
                decompile_lua_safe,
                extract_lua_from_signature,
            )
        except ImportError:
            get_type_name = lambda x: f"UNKNOWN_0x{x:02X}"
            is_lua_type = lambda x: x in (0x4C, 0xBD)
            extract_guids_from_bytecode = lambda x: set()
            decompile_lua_safe = lambda x: None
            extract_lua_from_signature = lambda x: None

        # Get existing threat
        result = await self.db.execute(
            select(Threat).where(Threat.signature_id == sig_id)
        )
        threat = result.scalar_one_or_none()
        if not threat:
            # Threat not found, import as new
            await self._import_threat(threat_def, stats)
            return

        # Fix and parse threat name
        fixed_threat_name = Threat.fix_threat_name(threat_def.threat_name)
        parsed = Threat.parse_threat_name(threat_def.threat_name)

        # Delete old signatures and Lua scripts
        await self.db.execute(delete(LuaScript).where(LuaScript.threat_id == threat.id))
        await self.db.execute(delete(Signature).where(Signature.threat_id == threat.id))

        # Update threat metadata
        threat.threat_name = fixed_threat_name
        threat.category = parsed["category"]
        threat.family = parsed["family"]
        threat.signature_count = len(threat_def.signatures)
        threat.content_hash = self._compute_threat_hash(threat_def)
        stats.threats_updated += 1

        # Import new signatures
        lua_entries = []
        non_lua_batch = []
        for sig_entry in threat_def.signatures:
            data_hash = hashlib.sha256(sig_entry.data).hexdigest() if sig_entry.data else None
            sig_type_name = get_type_name(sig_entry.sig_type)

            # Classify signature for browsing
            category, subcategory = classify_signature(sig_type_name, sig_entry.data)
            extracted_text = extract_searchable_text(sig_entry.data, sig_type_name)

            # Process Lua scripts
            if is_lua_type(sig_entry.sig_type):
                signature = Signature(
                    threat_id=threat.id,
                    sig_type=sig_entry.sig_type,
                    sig_type_name=sig_type_name,
                    size=sig_entry.size,
                    data_hash=data_hash,
                    data=sig_entry.data,
                    category=category,
                    subcategory=subcategory,
                    extracted_text=extracted_text if extracted_text else None,
                )
                self.db.add(signature)
                await self.db.flush()
                stats.signatures_added += 1
                lua_entries.append((sig_entry.data, signature.id))
            else:
                non_lua_batch.append(
                    {
                        "threat_id": threat.id,
                        "sig_type": sig_entry.sig_type,
                        "sig_type_name": sig_type_name,
                        "size": sig_entry.size,
                        "data_hash": data_hash,
                        "data": sig_entry.data,
                        "category": category,
                        "subcategory": subcategory,
                        "extracted_text": extracted_text if extracted_text else None,
                    }
                )

        if non_lua_batch:
            await self.db.execute(insert(Signature), non_lua_batch)
            stats.signatures_added += len(non_lua_batch)

        if lua_entries:
            await self._import_lua_scripts_batch(
                lua_entries, threat.id, stats,
                extract_lua_from_signature,
                extract_guids_from_bytecode,
                decompile_lua_safe if self.decompile_during_import else None
            )

    async def _import_lua_script(
        self,
        sig_data: bytes,
        signature_id: int,
        threat_id: int,
        stats: ImportStats,
        extract_lua_from_signature,
        extract_guids_from_bytecode,
        decompile_lua_safe,
    ) -> None:
        """Import a Lua script from signature data.

        Decompiles during import to extract ASR GUIDs from source.
        """
        # Extract Lua bytecode
        bytecode = extract_lua_from_signature(sig_data) if extract_lua_from_signature else None
        if not bytecode:
            bytecode = sig_data

        bytecode_hash = hashlib.sha256(bytecode).hexdigest()

        # Check if script already exists
        existing = await self.db.execute(
            select(LuaScript).where(LuaScript.bytecode_hash == bytecode_hash)
        )
        existing_script = existing.scalar_one_or_none()
        if existing_script:
            # If GUIDs were not resolved previously, re-extract to ensure correctness.
            if not existing_script.asr_guids:
                decompiled_source = existing_script.decompiled_source
                decompilation_status = existing_script.decompilation_status

                if decompile_lua_safe and not decompiled_source:
                    decompiled_source = decompile_lua_safe(bytecode)
                    decompilation_status = "completed" if decompiled_source else "failed"

                asr_guids = list(extract_guids_from_bytecode(bytecode)) if extract_guids_from_bytecode else []

                if decompiled_source:
                    try:
                        from defender_sig_extractor.output.asr_writer import extract_guids_from_source
                        source_guids = extract_guids_from_source(decompiled_source)
                        asr_guids = list(set(asr_guids) | source_guids)
                    except ImportError:
                        pass

                try:
                    from defender_sig_extractor.output.asr_writer import ASR_RULES
                    asr_guids = [g.lower() for g in asr_guids if g and g.lower() in ASR_RULES]
                    is_asr_script = len(asr_guids) > 0
                    await self.db.execute(
                        update(LuaScript)
                        .where(LuaScript.id == existing_script.id)
                        .values(
                            asr_guids=asr_guids,
                            is_asr_script=is_asr_script,
                            decompiled_source=decompiled_source,
                            decompilation_status=decompilation_status,
                        )
                    )
                except ImportError:
                    pass
            return

        # Decompile the Lua bytecode
        decompiled_source = None
        decompilation_status = "pending"
        if decompile_lua_safe:
            decompiled_source = decompile_lua_safe(bytecode)
            decompilation_status = "completed" if decompiled_source else "failed"

        # Extract ASR GUIDs from bytecode first
        asr_guids = list(extract_guids_from_bytecode(bytecode)) if extract_guids_from_bytecode else []

        # Also extract from decompiled source (more reliable)
        if decompiled_source:
            try:
                from defender_sig_extractor.output.asr_writer import extract_guids_from_source
                source_guids = extract_guids_from_source(decompiled_source)
                asr_guids = list(set(asr_guids) | source_guids)
            except ImportError:
                pass

        # Normalize and filter to known ASR GUIDs
        is_asr_script = False
        try:
            from defender_sig_extractor.output.asr_writer import ASR_RULES
            asr_guids = [g.lower() for g in asr_guids if g and g.lower() in ASR_RULES]
            is_asr_script = len(asr_guids) > 0
        except ImportError:
            pass

        lua_script = LuaScript(
            signature_id=signature_id,
            threat_id=threat_id,
            bytecode_hash=bytecode_hash,
            bytecode=bytecode,
            decompiled_source=decompiled_source,
            decompilation_status=decompilation_status,
            is_asr_script=is_asr_script,
            asr_guids=asr_guids,
        )
        self.db.add(lua_script)
        stats.lua_scripts_added += 1

    async def _import_lua_scripts_batch(
        self,
        entries: list[tuple[bytes, int]],
        threat_id: int,
        stats: ImportStats,
        extract_lua_from_signature,
        extract_guids_from_bytecode,
        decompile_lua_safe,
    ) -> None:
        """Import multiple Lua scripts with bounded parallel decompilation."""
        if not entries:
            return

        try:
            from defender_sig_extractor.output.asr_writer import ASR_RULES, extract_guids_from_source
        except ImportError:
            ASR_RULES = {}
            extract_guids_from_source = None

        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(1)

        async def decompile_one(bytecode: bytes) -> tuple[Optional[str], str]:
            if not decompile_lua_safe:
                return None, "pending"
            async with semaphore:
                source = await loop.run_in_executor(_lua_decompile_executor, decompile_lua_safe, bytecode)
            status = "completed" if source else "failed"
            return source, status

        chunk_size = 50
        for chunk_start in range(0, len(entries), chunk_size):
            chunk = entries[chunk_start:chunk_start + chunk_size]

            # Precompute bytecode + hashes for chunk
            prepared = []
            total_bytes = 0
            for sig_data, signature_id in chunk:
                bytecode = extract_lua_from_signature(sig_data) if extract_lua_from_signature else None
                if not bytecode:
                    bytecode = sig_data
                bytecode_hash = hashlib.sha256(bytecode).hexdigest()
                total_bytes += len(bytecode)
                prepared.append((signature_id, bytecode, bytecode_hash))

            rss_mb = _get_rss_mb()
            logger.info(
                f"Lua import chunk: threat_id={threat_id} items={len(prepared)} "
                f"bytes={total_bytes} rss_mb={rss_mb:.1f}" if rss_mb else
                f"Lua import chunk: threat_id={threat_id} items={len(prepared)} bytes={total_bytes}"
            )

            # Load existing scripts by hash
            hashes = [h for _, _, h in prepared]
            existing_rows = await self.db.execute(
                select(
                    LuaScript.id,
                    LuaScript.bytecode_hash,
                    LuaScript.asr_guids,
                    LuaScript.decompiled_source,
                    LuaScript.decompilation_status,
                ).where(LuaScript.bytecode_hash.in_(hashes))
            )
            existing_by_hash = {row[1]: row for row in existing_rows.all()}

            new_items = []
            new_rows = []
            for signature_id, bytecode, bytecode_hash in prepared:
                existing = existing_by_hash.get(bytecode_hash)
                if existing:
                    # Re-extract ASR GUIDs if missing
                    existing_id, _, asr_guids, decompiled_source, decomp_status = existing
                    if not asr_guids:
                        if not decompiled_source:
                            decompiled_source, decomp_status = await decompile_one(bytecode)
                        guids = list(extract_guids_from_bytecode(bytecode)) if extract_guids_from_bytecode else []
                        if decompiled_source and extract_guids_from_source:
                            source_guids = extract_guids_from_source(decompiled_source)
                            guids = list(set(guids) | source_guids)
                        if ASR_RULES:
                            guids = [g.lower() for g in guids if g and g.lower() in ASR_RULES]
                        is_asr_script = len(guids) > 0
                        await self.db.execute(
                            update(LuaScript)
                            .where(LuaScript.id == existing_id)
                            .values(
                                asr_guids=guids,
                                is_asr_script=is_asr_script,
                                decompiled_source=decompiled_source,
                                decompilation_status=decomp_status,
                            )
                        )
                    continue

                new_items.append((signature_id, bytecode, bytecode_hash))

            if new_items:
                decomp_tasks = [asyncio.create_task(decompile_one(bytecode)) for _, bytecode, _ in new_items]
                decomp_results = await asyncio.gather(*decomp_tasks)
                for (signature_id, bytecode, bytecode_hash), (decompiled_source, decomp_status) in zip(new_items, decomp_results):
                    asr_guids = list(extract_guids_from_bytecode(bytecode)) if extract_guids_from_bytecode else []
                    if decompiled_source and extract_guids_from_source:
                        source_guids = extract_guids_from_source(decompiled_source)
                        asr_guids = list(set(asr_guids) | source_guids)
                    if ASR_RULES:
                        asr_guids = [g.lower() for g in asr_guids if g and g.lower() in ASR_RULES]
                    is_asr_script = len(asr_guids) > 0

                    new_rows.append(
                        {
                            "signature_id": signature_id,
                            "threat_id": threat_id,
                            "bytecode_hash": bytecode_hash,
                            "bytecode": bytecode,
                            "decompiled_source": decompiled_source,
                            "decompilation_status": decomp_status,
                            "is_asr_script": is_asr_script,
                            "asr_guids": asr_guids,
                        }
                    )

            if new_rows:
                # Use upsert to handle duplicate bytecode_hash (shared Lua scripts across threats)
                for row in new_rows:
                    stmt = insert(LuaScript).values(**row)
                    stmt = stmt.on_conflict_do_update(
                        index_elements=["bytecode_hash"],
                        set_={
                            "decompiled_source": row["decompiled_source"],
                            "decompilation_status": row["decompilation_status"],
                            "asr_guids": row["asr_guids"],
                            "is_asr_script": row["is_asr_script"],
                        }
                    )
                    await self.db.execute(stmt)
                stats.lua_scripts_added += len(new_rows)


async def import_asr_rules(db: AsyncSession) -> int:
    """Import known ASR rules into the database."""
    try:
        from defender_sig_extractor.output.asr_writer import ASR_RULES
    except ImportError:
        print("Warning: defender_sig_extractor not found, cannot import ASR rules")
        return 0

    count = 0
    for guid, info in ASR_RULES.items():
        try:
            # Use upsert
            stmt = insert(ASRRule).values(
                guid=guid.lower(),
                name=info.get("name"),
                short_name=info.get("short_name"),
                description=info.get("description"),
                script_count=0,
                extracted_data={},
            ).on_conflict_do_update(
                index_elements=["guid"],
                set_={
                    "name": info.get("name"),
                    "short_name": info.get("short_name"),
                    "description": info.get("description"),
                }
            )
            await db.execute(stmt)
            count += 1
        except Exception as e:
            print(f"Error importing ASR rule {guid}: {e}")

    await db.commit()
    return count
