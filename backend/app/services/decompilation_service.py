"""Background Lua decompilation service.

Handles:
1. On-demand decompilation when viewing scripts
2. Background worker that continuously decompiles pending scripts
3. Prioritizes ASR scripts for decompilation
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import async_session_maker
from ..models import LuaScript

logger = logging.getLogger(__name__)

# Thread pool for CPU-intensive decompilation
_decompile_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="decompile_worker")

# Background task handle
_background_task: Optional[asyncio.Task] = None
_shutdown_event: Optional[asyncio.Event] = None


def _decompile_bytecode_sync(bytecode: bytes) -> tuple[Optional[str], str, list[str]]:
    """
    Synchronously decompile Lua bytecode (runs in thread pool).

    Returns:
        Tuple of (decompiled_source, status, asr_guids)
    """
    try:
        from defender_sig_extractor.lua_decompiler import decompile_bytecode
        from defender_sig_extractor.output.asr_writer import extract_guids_from_source, ASR_RULES

        source = decompile_bytecode(bytecode)

        # Extract ASR GUIDs from decompiled source
        asr_guids = []
        if source:
            all_guids = extract_guids_from_source(source)
            asr_guids = [g.lower() for g in all_guids if g and g.lower() in ASR_RULES]

        return source, "completed", asr_guids
    except Exception as e:
        logger.debug(f"Decompilation failed: {e}")
        return None, "failed", []


async def decompile_on_demand(db: AsyncSession, script_id: int) -> Optional[str]:
    """
    Decompile a script on-demand when viewing.

    If already decompiled, returns cached source.
    If pending, decompiles and caches result.

    Args:
        db: Database session
        script_id: LuaScript ID

    Returns:
        Decompiled source or None if failed
    """
    # Get the script
    result = await db.execute(
        select(LuaScript).where(LuaScript.id == script_id)
    )
    script = result.scalar_one_or_none()

    if not script:
        return None

    # Already decompiled
    if script.decompilation_status == "completed" and script.decompiled_source:
        return script.decompiled_source

    # No bytecode to decompile
    if not script.bytecode:
        return script.decompiled_source  # Return whatever we have

    # Decompile in thread pool
    loop = asyncio.get_running_loop()
    source, status, asr_guids = await loop.run_in_executor(
        _decompile_executor, _decompile_bytecode_sync, script.bytecode
    )

    # Update database
    is_asr = len(asr_guids) > 0
    await db.execute(
        update(LuaScript)
        .where(LuaScript.id == script_id)
        .values(
            decompiled_source=source,
            decompilation_status=status,
            asr_guids=asr_guids,
            is_asr_script=is_asr
        )
    )
    await db.commit()

    # Update ASR rule script counts
    if asr_guids:
        await _update_asr_rule_counts(db, asr_guids)

    return source


async def get_decompilation_stats() -> dict:
    """Get statistics about decompilation progress."""
    async with async_session_maker() as db:
        # Count by status
        result = await db.execute(
            select(
                LuaScript.decompilation_status,
                func.count(LuaScript.id)
            ).group_by(LuaScript.decompilation_status)
        )
        stats = {row[0]: row[1] for row in result.all()}

        # Count ASR scripts
        asr_result = await db.execute(
            select(func.count(LuaScript.id)).where(LuaScript.is_asr_script == True)
        )
        stats["asr_scripts"] = asr_result.scalar() or 0

        return stats


async def _update_asr_rule_counts(db: AsyncSession, guids: list[str]) -> None:
    """Update script counts for ASR rules."""
    from ..models import ASRRule

    for guid in guids:
        guid = guid.lower()
        # Count scripts with this GUID using any_() to avoid type mismatch
        from sqlalchemy import any_
        result = await db.execute(
            select(func.count(LuaScript.id))
            .where(guid == any_(LuaScript.asr_guids))
        )
        count = result.scalar() or 0

        # Update ASR rule
        await db.execute(
            update(ASRRule)
            .where(ASRRule.guid == guid.lower())
            .values(script_count=count)
        )

    await db.commit()


async def _decompile_batch(batch_size: int = 10) -> int:
    """
    Decompile a batch of pending scripts.

    Prioritizes ASR scripts.

    Returns:
        Number of scripts processed
    """
    async with async_session_maker() as db:
        # Get pending scripts, prioritize ASR scripts
        result = await db.execute(
            select(LuaScript)
            .where(LuaScript.decompilation_status == "pending")
            .where(LuaScript.bytecode.isnot(None))
            .order_by(LuaScript.is_asr_script.desc())  # ASR first
            .limit(batch_size)
        )
        scripts = result.scalars().all()

        if not scripts:
            return 0

        loop = asyncio.get_running_loop()
        processed = 0

        all_asr_guids = set()

        for script in scripts:
            # Decompile in thread pool
            source, status, asr_guids = await loop.run_in_executor(
                _decompile_executor, _decompile_bytecode_sync, script.bytecode
            )

            # Track ASR GUIDs for batch update
            all_asr_guids.update(asr_guids)
            is_asr = len(asr_guids) > 0

            # Update database
            await db.execute(
                update(LuaScript)
                .where(LuaScript.id == script.id)
                .values(
                    decompiled_source=source,
                    decompilation_status=status,
                    asr_guids=asr_guids,
                    is_asr_script=is_asr
                )
            )
            processed += 1

            # Yield control periodically
            if processed % 5 == 0:
                await asyncio.sleep(0)

        await db.commit()

        # Update ASR rule script counts
        if all_asr_guids:
            await _update_asr_rule_counts(db, list(all_asr_guids))

        return processed


async def decompile_all_pending(batch_size: int = 20, max_batches: Optional[int] = None) -> int:
    """
    Decompile all pending scripts in batches.

    Returns:
        Total number of scripts processed.
    """
    total = 0
    batches = 0
    while True:
        processed = await _decompile_batch(batch_size=batch_size)
        if processed == 0:
            break
        total += processed
        batches += 1
        if max_batches is not None and batches >= max_batches:
            break
        await asyncio.sleep(0)
    return total


async def _background_decompilation_loop():
    """Background loop that continuously decompiles pending scripts."""
    global _shutdown_event
    if _shutdown_event is None:
        _shutdown_event = asyncio.Event()
    logger.info("Background decompilation worker started")

    while not _shutdown_event.is_set():
        try:
            processed = await _decompile_batch(batch_size=20)

            if processed > 0:
                logger.debug(f"Decompiled {processed} scripts")
                # Small delay between batches
                await asyncio.sleep(0.5)
            else:
                # No pending scripts, wait longer
                await asyncio.sleep(10)

        except asyncio.CancelledError:
            logger.info("Background decompilation worker cancelled")
            break
        except Exception as e:
            logger.error(f"Background decompilation error: {e}")
            await asyncio.sleep(5)

    logger.info("Background decompilation worker stopped")


def start_background_worker():
    """Start the background decompilation worker."""
    global _background_task, _shutdown_event

    if _background_task is not None and not _background_task.done():
        logger.warning("Background worker already running")
        return

    _shutdown_event = asyncio.Event()
    _background_task = asyncio.create_task(_background_decompilation_loop())
    logger.info("Background decompilation worker scheduled")


async def stop_background_worker():
    """Stop the background decompilation worker."""
    global _background_task, _shutdown_event

    if _background_task is None:
        return

    if _shutdown_event is not None:
        _shutdown_event.set()
    _background_task.cancel()

    try:
        await _background_task
    except asyncio.CancelledError:
        pass

    _background_task = None
    logger.info("Background decompilation worker stopped")
