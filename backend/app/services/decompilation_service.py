"""Background Lua decompilation service.

Handles:
1. On-demand decompilation when viewing scripts
2. Background worker that continuously decompiles pending scripts
3. Prioritizes ASR scripts for decompilation
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import async_session_maker
from ..models import LuaScript
from .process_worker import run_worker

logger = logging.getLogger(__name__)

# Jobs are shared by public requests and the background worker. Each owns its
# database session and process, so request cancellation cannot abandon results.
_DECOMPILE_CONCURRENCY = 2
_DECOMPILE_TIMEOUT = 30
_DECOMPILE_MAX_BYTES = 8 * 1024 * 1024
_decompile_jobs: dict[int, asyncio.Task] = {}

# Background task handle
_background_task: Optional[asyncio.Task] = None
_shutdown_event: Optional[asyncio.Event] = None


def _decompile_bytecode_sync(bytecode: bytes) -> tuple[Optional[str], str, list[str]]:
    """
    Synchronously decompile Lua bytecode (runs in a disposable process).

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

        return source, "completed" if source else "failed", asr_guids
    except Exception as e:
        logger.debug(f"Decompilation failed: {e}")
        return None, "failed", []


def _decompile_worker(bytecode: bytes, output_path: str) -> None:
    result = json.dumps(_decompile_bytecode_sync(bytecode)).encode("utf-8")
    if len(result) > _DECOMPILE_MAX_BYTES:
        raise ValueError("Decompiler output exceeds its limit")
    Path(output_path).write_bytes(result)


async def _run_decompilation(script_id: int) -> Optional[str]:
    try:
        async with async_session_maker() as db:
            result = await db.execute(select(LuaScript).where(LuaScript.id == script_id))
            script = result.scalar_one_or_none()
            if not script:
                return None
            if script.decompilation_status != "pending" or not script.bytecode:
                return script.decompiled_source
            bytecode = script.bytecode
            previous_guids = script.asr_guids or []

        # Release the connection while CPU work runs.
        try:
            if len(bytecode) > _DECOMPILE_MAX_BYTES:
                raise ValueError("Decompiler input exceeds its limit")
            result = await run_worker(
                _decompile_worker, (bytecode,), timeout=_DECOMPILE_TIMEOUT,
                max_output=_DECOMPILE_MAX_BYTES,
            )
            source, status, asr_guids = json.loads(result)
            if status == "failed":
                asr_guids = previous_guids
        except Exception as exc:
            logger.warning("Decompilation failed for script %s: %s", script_id, exc)
            source, status, asr_guids = None, "failed", previous_guids

        async with async_session_maker() as db:
            # An import may replace the bytecode while this process is running.
            # Persist only if this is still the same pending input.
            result = await db.execute(
                update(LuaScript)
                .where(
                    LuaScript.id == script_id,
                    LuaScript.bytecode == bytecode,
                    LuaScript.decompilation_status == "pending",
                )
                .values(
                    decompiled_source=source,
                    decompilation_status=status,
                    asr_guids=asr_guids,
                    is_asr_script=bool(asr_guids),
                )
                .returning(LuaScript.id)
            )
            updated = result.scalar_one_or_none() is not None
            await db.commit()
            if updated and (previous_guids or asr_guids):
                await _update_asr_rule_counts(db, list(set(previous_guids) | set(asr_guids)))
            return source if updated else None
    finally:
        _decompile_jobs.pop(script_id, None)


def _observe_decompilation(task: asyncio.Task) -> None:
    if not task.cancelled():
        error = task.exception()
        if error:
            logger.error("Decompilation job failed: %s", error)


def _get_or_start_job(script_id: int) -> Optional[asyncio.Task]:
    task = _decompile_jobs.get(script_id)
    if task is None:
        if (_shutdown_event is not None and _shutdown_event.is_set()) or len(_decompile_jobs) >= _DECOMPILE_CONCURRENCY:
            return None
        task = asyncio.create_task(_run_decompilation(script_id))
        _decompile_jobs[script_id] = task
        task.add_done_callback(_observe_decompilation)
    return task


async def decompile_on_demand(db: AsyncSession, script_id: int) -> Optional[str]:
    """Share bounded work; its independent session survives request cancellation.

    ``db`` is retained for caller compatibility and is never passed to the job.
    At capacity, return pending immediately so browsing stays responsive.
    """
    task = _get_or_start_job(script_id)
    return await asyncio.shield(task) if task is not None else None


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
            select(LuaScript.id)
            .where(LuaScript.decompilation_status == "pending")
            .where(LuaScript.bytecode.isnot(None))
            .order_by(LuaScript.is_asr_script.desc())  # ASR first
            .limit(batch_size)
        )
        script_ids = result.scalars().all()

    processed = 0
    for script_id in script_ids:
        task = _get_or_start_job(script_id)
        if task is None and _decompile_jobs:
            await asyncio.wait(list(_decompile_jobs.values()), return_when=asyncio.FIRST_COMPLETED)
            task = _get_or_start_job(script_id)
        if task is not None:
            await asyncio.shield(task)
            processed += 1
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

    if _shutdown_event is not None:
        _shutdown_event.set()
    if _background_task is not None:
        _background_task.cancel()
        await asyncio.gather(_background_task, return_exceptions=True)

    jobs = list(_decompile_jobs.values())
    for task in jobs:
        task.cancel()
    await asyncio.gather(*jobs, return_exceptions=True)

    _background_task = None
    logger.info("Background decompilation worker stopped")
