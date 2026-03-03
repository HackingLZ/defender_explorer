"""Signature similarity service for finding related threats."""

import hashlib
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

from ..models import Threat, Signature, SignatureSimilarity


@dataclass
class SimilarityResult:
    """Result of similarity analysis."""
    threat_id: int
    signature_id: int
    threat_name: str
    category: str
    family: str
    similarity_score: float
    similarity_types: List[str]
    shared_strings: List[str]
    matching_bytes: int


def extract_strings_set(data: bytes, min_len: int = 4) -> Set[str]:
    """Extract readable strings as a set."""
    strings = set()
    current = []

    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.add(''.join(current))
            current = []

    if len(current) >= min_len:
        strings.add(''.join(current))

    return strings


def jaccard_similarity(set1: Set[str], set2: Set[str]) -> float:
    """Calculate Jaccard similarity between two sets."""
    if not set1 and not set2:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


def substring_overlap(data1: bytes, data2: bytes, min_match: int = 8) -> Tuple[float, int]:
    """
    Calculate substring overlap between two byte sequences.
    Returns (similarity_score, matching_bytes)
    """
    if not data1 or not data2:
        return 0.0, 0

    # Use sliding window to find matching substrings
    shorter, longer = (data1, data2) if len(data1) <= len(data2) else (data2, data1)

    if len(shorter) < min_match:
        return 0.0, 0

    # Build hash table of substrings in shorter sequence
    substring_hashes = {}
    for i in range(len(shorter) - min_match + 1):
        h = hashlib.md5(shorter[i:i + min_match]).digest()
        substring_hashes[h] = i

    # Look for matches in longer sequence
    matching_bytes = 0
    matched_positions = set()

    for i in range(len(longer) - min_match + 1):
        h = hashlib.md5(longer[i:i + min_match]).digest()
        if h in substring_hashes:
            # Extend match as far as possible
            short_pos = substring_hashes[h]
            match_len = min_match

            # Extend forward
            while (short_pos + match_len < len(shorter) and
                   i + match_len < len(longer) and
                   shorter[short_pos + match_len] == longer[i + match_len]):
                match_len += 1

            # Track matched bytes (avoid double counting)
            for j in range(short_pos, short_pos + match_len):
                if j not in matched_positions:
                    matched_positions.add(j)
                    matching_bytes += 1

    similarity = matching_bytes / len(shorter) if len(shorter) > 0 else 0.0
    return similarity, matching_bytes


async def find_similar_by_hash(
    db: AsyncSession,
    data_hash: str,
    exclude_threat_id: int
) -> List[Dict[str, Any]]:
    """Find signatures with exact hash match."""
    query = (
        select(Signature)
        .options(selectinload(Signature.threat))
        .where(
            Signature.data_hash == data_hash,
            Signature.threat_id != exclude_threat_id
        )
    )

    result = await db.execute(query)
    signatures = result.scalars().all()

    similar = []
    for sig in signatures:
        if sig.threat:
            similar.append({
                "threat_id": sig.threat.id,
                "signature_id": sig.threat.signature_id,
                "threat_name": sig.threat.threat_name,
                "category": sig.threat.category,
                "family": sig.threat.family,
                "similarity_score": 1.0,
                "similarity_types": ["exact_hash"],
                "shared_strings": [],
                "matching_bytes": sig.size or 0,
            })

    return similar


async def compute_similarity(
    db: AsyncSession,
    threat_id: int,
    limit: int = 20,
    min_score: float = 0.3
) -> List[Dict[str, Any]]:
    """
    Compute similarity between a threat and all others.
    Uses multiple similarity metrics and combines scores.
    """
    # Get the source threat (no selectinload - load sigs separately with cap)
    threat_result = await db.execute(select(Threat).where(Threat.id == threat_id))
    source_threat = threat_result.scalar_one_or_none()

    if not source_threat:
        return []

    # Load source signatures with a cap to avoid OOM on mega-threats
    source_sigs_result = await db.execute(
        select(Signature).where(Signature.threat_id == threat_id).limit(500)
    )
    source_sigs = source_sigs_result.scalars().all()

    similar_threats = {}

    # Collect all strings and hashes from source signatures
    source_strings: Set[str] = set()
    source_hashes: Set[str] = set()
    source_data: List[bytes] = []

    for sig in source_sigs:
        if sig.data:
            source_strings |= extract_strings_set(sig.data)
            source_data.append(sig.data)
        if sig.data_hash:
            source_hashes.add(sig.data_hash)

    # 1. Find exact hash matches
    for data_hash in source_hashes:
        matches = await find_similar_by_hash(db, data_hash, threat_id)
        for match in matches:
            tid = match["threat_id"]
            if tid not in similar_threats:
                similar_threats[tid] = match
            else:
                # Merge similarity types
                for st in match["similarity_types"]:
                    if st not in similar_threats[tid]["similarity_types"]:
                        similar_threats[tid]["similarity_types"].append(st)
                similar_threats[tid]["similarity_score"] = max(
                    similar_threats[tid]["similarity_score"],
                    match["similarity_score"]
                )

    # 2. Find similar by family (same malware family often has related signatures)
    if source_threat.family:
        family_query = (
            select(Threat)
            .where(
                Threat.family == source_threat.family,
                Threat.id != threat_id
            )
            .limit(100)
        )
        family_result = await db.execute(family_query)
        family_threats = family_result.scalars().all()

        for candidate in family_threats:
            if candidate.id in similar_threats:
                continue

            # Load candidate signatures with a cap to avoid OOM on mega-threats
            candidate_sigs_result = await db.execute(
                select(Signature)
                .where(Signature.threat_id == candidate.id)
                .limit(500)
            )
            candidate_sigs = candidate_sigs_result.scalars().all()

            # Compute string similarity
            candidate_strings: Set[str] = set()
            for sig in candidate_sigs:
                if sig.data:
                    candidate_strings |= extract_strings_set(sig.data)

            string_sim = jaccard_similarity(source_strings, candidate_strings)
            shared = list(source_strings & candidate_strings)[:10]

            if string_sim >= min_score:
                similar_threats[candidate.id] = {
                    "threat_id": candidate.id,
                    "signature_id": candidate.signature_id,
                    "threat_name": candidate.threat_name,
                    "category": candidate.category,
                    "family": candidate.family,
                    "similarity_score": string_sim,
                    "similarity_types": ["string_overlap", "same_family"],
                    "shared_strings": shared,
                    "matching_bytes": 0,
                }

    # 3. Check for substring overlap with signatures that have similar sizes
    for source_sig in source_sigs:
        if not source_sig.data or len(source_sig.data) < 16:
            continue

        size = len(source_sig.data)
        size_range = (int(size * 0.5), int(size * 2))

        size_query = (
            select(Signature)
            .options(selectinload(Signature.threat))
            .where(
                Signature.size.between(size_range[0], size_range[1]),
                Signature.threat_id != threat_id
            )
            .limit(200)
        )
        size_result = await db.execute(size_query)
        candidates = size_result.scalars().all()

        for candidate in candidates:
            if not candidate.threat or candidate.threat.id in similar_threats:
                continue
            if not candidate.data:
                continue

            sub_sim, match_bytes = substring_overlap(source_sig.data, candidate.data)

            if sub_sim >= min_score:
                # Also compute string similarity
                candidate_strings = extract_strings_set(candidate.data)
                string_sim = jaccard_similarity(source_strings, candidate_strings)
                shared = list(source_strings & candidate_strings)[:10]

                combined_score = (sub_sim + string_sim) / 2

                if combined_score >= min_score:
                    similar_threats[candidate.threat.id] = {
                        "threat_id": candidate.threat.id,
                        "signature_id": candidate.threat.signature_id,
                        "threat_name": candidate.threat.threat_name,
                        "category": candidate.threat.category,
                        "family": candidate.threat.family,
                        "similarity_score": combined_score,
                        "similarity_types": ["substring_overlap", "string_overlap"],
                        "shared_strings": shared,
                        "matching_bytes": match_bytes,
                    }

    # Sort by similarity score and return top results
    sorted_results = sorted(
        similar_threats.values(),
        key=lambda x: x["similarity_score"],
        reverse=True
    )

    return sorted_results[:limit]


async def store_similarity(
    db: AsyncSession,
    sig_id_1: int,
    sig_id_2: int,
    score: float,
    sim_type: str
) -> None:
    """Store a computed similarity score."""
    # Ensure consistent ordering
    if sig_id_1 > sig_id_2:
        sig_id_1, sig_id_2 = sig_id_2, sig_id_1

    similarity = SignatureSimilarity(
        signature_id_1=sig_id_1,
        signature_id_2=sig_id_2,
        similarity_score=score,
        similarity_type=sim_type,
    )

    db.add(similarity)
    try:
        await db.commit()
    except Exception:
        await db.rollback()  # Already exists
