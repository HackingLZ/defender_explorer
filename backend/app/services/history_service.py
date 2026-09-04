"""History service for tracking entity changes over time."""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from ..models import EntityHistory, VDMVersion


@dataclass
class ChangeDetails:
    """Details about a specific change."""
    field: str
    old_value: Any
    new_value: Any


def compute_diff(previous: Dict[str, Any], current: Dict[str, Any]) -> List[str]:
    """
    Compute a human-readable diff between two data snapshots.

    Returns:
        List of change descriptions
    """
    changes = []

    all_keys = set(previous.keys()) | set(current.keys())

    for key in all_keys:
        old_val = previous.get(key)
        new_val = current.get(key)

        if old_val != new_val:
            if old_val is None:
                changes.append(f"Added {key}")
            elif new_val is None:
                changes.append(f"Removed {key}")
            elif isinstance(old_val, list) and isinstance(new_val, list):
                added = len(new_val) - len(old_val)
                if added > 0:
                    changes.append(f"{key}: added {added} items")
                elif added < 0:
                    changes.append(f"{key}: removed {-added} items")
                else:
                    changes.append(f"{key}: modified")
            elif isinstance(old_val, dict) and isinstance(new_val, dict):
                changes.append(f"{key}: modified")
            else:
                # Truncate long values
                old_str = str(old_val)[:50]
                new_str = str(new_val)[:50]
                changes.append(f"{key}: '{old_str}' → '{new_str}'")

    return changes


async def record_history(
    db: AsyncSession,
    entity_type: str,
    entity_id: str,
    change_type: str,
    previous_data: Dict[str, Any],
    current_data: Dict[str, Any],
    vdm_version_id: Optional[int] = None,
) -> EntityHistory:
    """
    Record a history entry for an entity change.

    Args:
        db: Database session
        entity_type: Type of entity ('threat', 'asr_rule', 'signature')
        entity_id: ID of the entity
        change_type: Type of change ('created', 'updated', 'deleted')
        previous_data: Snapshot before change
        current_data: Snapshot after change
        vdm_version_id: Optional VDM version ID

    Returns:
        Created EntityHistory record
    """
    # Compute diff summary
    if change_type == "created":
        diff_summary = "Entity created"
    elif change_type == "deleted":
        diff_summary = "Entity deleted"
    else:
        changes = compute_diff(previous_data, current_data)
        diff_summary = "; ".join(changes[:5])
        if len(changes) > 5:
            diff_summary += f" (+{len(changes) - 5} more)"

    history = EntityHistory(
        entity_type=entity_type,
        entity_id=entity_id,
        change_type=change_type,
        vdm_version_id=vdm_version_id,
        previous_data=previous_data,
        current_data=current_data,
        diff_summary=diff_summary,
    )

    db.add(history)
    # History participates in its caller's transaction, including rollback.
    await db.flush()

    return history


async def get_entity_timeline(
    db: AsyncSession,
    entity_type: str,
    entity_id: str,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Get the timeline of changes for an entity.

    Args:
        db: Database session
        entity_type: Type of entity
        entity_id: ID of the entity
        limit: Maximum events to return

    Returns:
        Timeline with events list
    """
    # Get history entries
    query = (
        select(EntityHistory)
        .where(
            EntityHistory.entity_type == entity_type,
            EntityHistory.entity_id == entity_id
        )
        .order_by(desc(EntityHistory.changed_at))
        .limit(limit)
    )

    result = await db.execute(query)
    history_entries = result.scalars().all()

    # Get VDM versions for context
    vdm_ids = [h.vdm_version_id for h in history_entries if h.vdm_version_id]
    vdm_versions = {}

    if vdm_ids:
        vdm_query = select(VDMVersion).where(VDMVersion.id.in_(vdm_ids))
        vdm_result = await db.execute(vdm_query)
        for v in vdm_result.scalars().all():
            vdm_versions[v.id] = v.version_hash

    # Build timeline events
    events = []
    for entry in history_entries:
        vdm_version = entry.vdm_version_hash
        if entry.vdm_version_id:
            vdm_version = vdm_versions.get(entry.vdm_version_id) or vdm_version

        # Parse changes from diff
        changes = []
        if entry.diff_summary:
            changes = [c.strip() for c in entry.diff_summary.split(";")]

        events.append({
            "date": entry.changed_at.isoformat(),
            "type": entry.change_type,
            "vdm_version": vdm_version,
            "changes": changes,
            "details": {
                "previous_data": entry.previous_data,
                "current_data": entry.current_data,
            }
        })

    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "events": events,
        "total_events": len(events),
    }


async def get_recent_changes(
    db: AsyncSession,
    entity_type: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Get recent changes across all entities.

    Args:
        db: Database session
        entity_type: Optional filter by entity type
        limit: Maximum events to return

    Returns:
        List of recent change events
    """
    query = select(EntityHistory).order_by(desc(EntityHistory.changed_at)).limit(limit)

    if entity_type:
        query = query.where(EntityHistory.entity_type == entity_type)

    result = await db.execute(query)
    entries = result.scalars().all()

    return [
        {
            "id": entry.id,
            "entity_type": entry.entity_type,
            "entity_id": entry.entity_id,
            "change_type": entry.change_type,
            "changed_at": entry.changed_at.isoformat(),
            "diff_summary": entry.diff_summary,
        }
        for entry in entries
    ]


def snapshot_threat(threat) -> Dict[str, Any]:
    """Create a snapshot of a threat for history tracking."""
    return {
        "signature_id": threat.signature_id,
        "threat_name": threat.threat_name,
        "category": threat.category,
        "family": threat.family,
        "signature_count": threat.signature_count,
        "content_hash": threat.content_hash,
    }


def snapshot_asr_rule(rule) -> Dict[str, Any]:
    """Create a snapshot of an ASR rule for history tracking."""
    return {
        "guid": rule.guid,
        "name": rule.name,
        "short_name": rule.short_name,
        "description": rule.description,
        "script_count": rule.script_count,
        "extracted_data": rule.extracted_data,
    }


def snapshot_signature(sig) -> Dict[str, Any]:
    """Create a snapshot of a signature for history tracking."""
    return {
        "sig_type": sig.sig_type,
        "sig_type_name": sig.sig_type_name,
        "size": sig.size,
        "data_hash": sig.data_hash,
    }
