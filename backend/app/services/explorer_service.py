"""Validated search predicates and bounded, complete threat exports."""

import json
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field, TypeAdapter, ValidationError
from sqlalchemy import func, or_, select

from ..models import Signature, Threat
from ..schemas.threat import ThreatResponse


class SearchFilter(BaseModel):
    field: Literal["threat_name", "category", "family", "signature_type"]
    operator: Literal["contains", "equals", "starts_with", "ends_with", "not_contains"]
    value: str = Field(min_length=1, max_length=255)


class ExportRequest(BaseModel):
    threat_ids: list[Annotated[int, Field(ge=0, le=2**63 - 1)]] = Field(min_length=1, max_length=500)
    include_signatures: bool = False


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_filters(raw: str | None) -> list[SearchFilter]:
    if not raw:
        return []
    try:
        filters = TypeAdapter(list[SearchFilter]).validate_json(raw)
    except ValidationError:
        raise HTTPException(422, "Invalid search filters") from None
    if len(filters) > 20:
        raise HTTPException(422, "Maximum 20 search filters allowed")
    return filters


def _text_predicate(column, condition: SearchFilter):
    value = escape_like(condition.value)
    patterns = {
        "contains": f"%{value}%",
        "not_contains": f"%{value}%",
        "equals": value,
        "starts_with": f"{value}%",
        "ends_with": f"%{value}",
    }
    match = func.coalesce(column, "").ilike(patterns[condition.operator], escape="\\")
    return ~match if condition.operator == "not_contains" else match


def threat_predicates(q: str, category: str | None, family: str | None,
                      filters: list[SearchFilter]) -> list:
    predicates = []
    if q.strip():
        name = Threat.threat_name.ilike(f"%{escape_like(q.strip())}%", escape="\\")
        try:
            number = int(q.strip(), 16 if q.strip().lower().startswith("0x") else 10)
        except ValueError:
            number = -1
        predicates.append(or_(name, Threat.signature_id == number) if 0 <= number < 2**63 else name)
    if category:
        predicates.append(Threat.category == category)
    if family:
        predicates.append(Threat.family == family)
    for condition in filters:
        if condition.field == "signature_type":
            # A negative type condition means that no signature has that type.
            positive = condition.model_copy(update={"operator": "contains"}) if condition.operator == "not_contains" else condition
            match = select(Signature.id).where(
                Signature.threat_id == Threat.id,
                _text_predicate(Signature.sig_type_name, positive),
            ).exists()
            predicates.append(~match if condition.operator == "not_contains" else match)
        else:
            predicates.append(_text_predicate(getattr(Threat, condition.field), condition))
    return predicates


async def export_threats(db, request: ExportRequest) -> dict:
    ids = list(dict.fromkeys(request.threat_ids))
    threats = (await db.execute(select(Threat).where(Threat.signature_id.in_(ids)))).scalars().all()
    by_id = {t.signature_id: t for t in threats}
    if len(by_id) != len(ids):
        raise HTTPException(409, "Some selected threats no longer exist. Refresh your selection and retry.")
    items = [ThreatResponse.model_validate(by_id[sig_id]).model_dump(mode="json") for sig_id in ids]
    if request.include_signatures:
        internal_ids = [t.id for t in threats]
        count, byte_count = (await db.execute(
            select(func.count(Signature.id), func.coalesce(func.sum(func.octet_length(Signature.data)), 0))
            .where(Signature.threat_id.in_(internal_ids))
        )).one()
        if count > 5000 or byte_count * 2 + count * 512 > 16 * 1024 * 1024:
            raise HTTPException(413, "Export exceeds 5,000 signatures or 16 MiB. Select fewer threats or turn off Include signatures.")
        grouped = {t.id: [] for t in threats}
        result = await db.stream(select(Signature).where(Signature.threat_id.in_(internal_ids)).order_by(Signature.id))
        loaded = 0
        loaded_bytes = 0
        async for sig in result.scalars():
            loaded += 1
            loaded_bytes += len(sig.data or b"") * 2 + 512
            if loaded > 5000:
                raise HTTPException(409, "Signatures changed during export. Retry with a smaller selection.")
            if loaded_bytes > 16 * 1024 * 1024:
                raise HTTPException(413, "Export exceeds 16 MiB. Select fewer threats or turn off Include signatures.")
            grouped[sig.threat_id].append({
                "id": sig.id, "sig_type": sig.sig_type, "sig_type_name": sig.sig_type_name,
                "size": sig.size, "data_hex": (sig.data or b"").hex(),
            })
        for item in items:
            item["signatures"] = grouped[by_id[item["signature_id"]].id]
    result = {"items": items, "total": len(items)}
    if len(json.dumps(result).encode()) > 16 * 1024 * 1024:
        raise HTTPException(413, "Export exceeds 16 MiB. Select fewer threats or turn off Include signatures.")
    return result
