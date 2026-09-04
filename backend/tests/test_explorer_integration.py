"""Run against a disposable database: TEST_DATABASE_URL=.../defender_test.

These tests never start the app lifespan or download definitions.
"""

import json
import os
import unittest
from datetime import datetime
from unittest.mock import AsyncMock, patch

import httpx
from sqlalchemy import func, select, text, update
from sqlalchemy.engine import make_url

TEST_URL = os.environ.get("TEST_DATABASE_URL")
if TEST_URL:
    url = make_url(TEST_URL)
    if url.database != "defender_test" or url.host not in ("127.0.0.1", "localhost"):
        raise RuntimeError("Integration tests require the disposable localhost defender_test database")
    os.environ["DATABASE_URL"] = TEST_URL

from app.database import async_session_maker, engine, init_db
from app.main import app
from app.models import ASRRule, EntityHistory, Signature, SyncStatus, Threat, VDMVersion
from app.rate_limit import limiter
from app.services import scheduler_service

if TEST_URL and engine.url != make_url(TEST_URL):
    raise RuntimeError("App engine was initialized with a different database; refusing to run destructive test setup")


@unittest.skipUnless(TEST_URL, "Set TEST_DATABASE_URL to a disposable defender_test database")
class ExplorerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        await init_db()
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE threats, signatures, lua_scripts, asr_rules, entity_history, vdm_versions, sync_status RESTART IDENTITY CASCADE"))
        limiter.reset()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def asyncTearDown(self):
        await self.client.aclose()
        await engine.dispose()

    async def seed(self):
        async with async_session_maker() as db:
            a = Threat(signature_id=1001, threat_name="Demo:Alpha", category="Demo", family="Alpha", signature_count=1)
            b = Threat(signature_id=1002, threat_name="Demo:Beta", category="Other", family="Beta", signature_count=1)
            db.add_all([a, b])
            await db.flush()
            db.add_all([
                Signature(threat_id=a.id, sig_type=1, sig_type_name="STRING", size=5, data=b"alpha"),
                Signature(threat_id=b.id, sig_type=2, sig_type_name="BINARY", size=4, data=b"beta"),
            ])
            await db.commit()
            return a.id, b.id

    async def test_advanced_filters_combine_with_query_and_operators(self):
        await self.seed()
        cases = [
            ([{"field": "category", "operator": "equals", "value": "Other"}], [1002]),
            ([{"field": "threat_name", "operator": "not_contains", "value": "Alpha"}], [1002]),
            ([{"field": "family", "operator": "starts_with", "value": "Al"}], [1001]),
            ([{"field": "family", "operator": "ends_with", "value": "ta"}], [1002]),
            ([{"field": "signature_type", "operator": "equals", "value": "STRING"}], [1001]),
            ([{"field": "signature_type", "operator": "not_contains", "value": "STRING"}], [1002]),
        ]
        for filters, expected in cases:
            response = await self.client.get("/api/threats/search", params={"q": "Demo", "filters": json.dumps(filters)})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual([x["signature_id"] for x in response.json()["items"]], expected)
        response = await self.client.get("/api/threats/search", params={"q": "Alpha", "category": "Other"})
        self.assertEqual(response.json()["total"], 0)
        response = await self.client.get("/api/threats/search", params={"filters": "invalid"})
        self.assertEqual(response.status_code, 422)

    async def test_exports_preserve_selection_order_and_include_bytes(self):
        await self.seed()
        response = await self.client.post("/api/threats/export", json={"threat_ids": [1002, 1001], "include_signatures": True})
        self.assertEqual(response.status_code, 200, response.text)
        items = response.json()["items"]
        self.assertEqual([x["signature_id"] for x in items], [1002, 1001])
        self.assertEqual(items[0]["signatures"][0]["data_hex"], b"beta".hex())
        response = await self.client.post("/api/threats/export", json={"threat_ids": [1001], "include_signatures": False})
        self.assertNotIn("signatures", response.json()["items"][0])
        response = await self.client.post("/api/threats/export", json={"threat_ids": [9999]})
        self.assertEqual(response.status_code, 409)

    async def test_export_rejects_oversize_without_partial_results(self):
        a, _ = await self.seed()
        async with async_session_maker() as db:
            await db.execute(Signature.__table__.insert(), [
                {"threat_id": a, "sig_type": 1, "data": b"demo", "size": 4} for _ in range(5000)
            ])
            await db.commit()
        response = await self.client.post("/api/threats/export", json={"threat_ids": [1001], "include_signatures": True})
        self.assertEqual(response.status_code, 413)
        self.assertNotIn("items", response.json())

    async def test_family_pagination_can_reach_small_families(self):
        async with async_session_maker() as db:
            db.add_all([Threat(signature_id=i + 2000, threat_name=f"Demo:{i}", category="Demo", family=f"Family{i:03d}", signature_count=0) for i in range(105)])
            await db.commit()
        response = await self.client.get("/api/threats/families/list", params={"category": "Demo", "page": 5, "page_size": 25})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total"], 105)
        self.assertEqual(len(response.json()["items"]), 5)
        response = await self.client.get("/api/threats/families/list", params={"q": "104"})
        self.assertEqual(response.json()["items"][0]["family"], "Family104")

    async def test_yara_samples_each_selected_threat(self):
        a, b = await self.seed()
        async with async_session_maker() as db:
            db.add_all([Signature(threat_id=a, sig_type=1, data=f"first_pattern_{i}".encode(), size=16) for i in range(45)])
            db.add(Signature(threat_id=b, sig_type=1, data=b"last_selected_pattern", size=21))
            await db.commit()
        response = await self.client.post("/api/yara/build", json={"threat_ids": [1001, 1002], "rule_name": "demo_selection"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("last_selected_pattern", response.json()["rule_content"])

    async def test_yara_output_cap_keeps_every_selected_threat(self):
        async with async_session_maker() as db:
            threats = [Threat(signature_id=3000 + i, threat_name=f"Demo:{i}", category="Demo", family="Test", signature_count=20) for i in range(30)]
            db.add_all(threats)
            await db.flush()
            for threat in threats:
                db.add_all([Signature(threat_id=threat.id, sig_type=1, data=f"sample_{threat.signature_id}_{i}\n".encode(), size=20) for i in range(20)])
            await db.commit()
        response = await self.client.post("/api/yara/build", json={"threat_ids": list(range(3000, 3030)), "rule_name": "demo_cap"})
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        represented = {name for sources in result["pattern_map"].values() for name in sources}
        self.assertEqual(represented, {f"Demo:{i}" for i in range(30)})
        self.assertEqual(result["pattern_count"], 500)
        import yara
        yara.compile(source=result["rule_content"], includes=False)

    async def test_history_is_transactional_compact_and_versioned(self):
        a, _ = await self.seed()
        async with async_session_maker() as db:
            original = (await db.execute(select(func.count(EntityHistory.id)))).scalar()
            await db.execute(update(Threat).where(Threat.id == a).values(family="RolledBack"))
            await db.rollback()
            self.assertEqual((await db.execute(select(func.count(EntityHistory.id)))).scalar(), original)
            await db.rollback()
            db.info["vdm_version_hash"] = "a" * 64
            await db.execute(update(Threat).where(Threat.id == a).values(family="Changed"))
            await db.commit()
            await db.execute(update(Threat).where(Threat.id == a).values(family="Changed"))
            await db.commit()
            self.assertEqual((await db.execute(select(func.count(EntityHistory.id)))).scalar(), original + 1)
            db.add(ASRRule(guid="demo-rule", name="Demo", extracted_data={"paths": ["example"]}))
            await db.commit()
            event = (await db.execute(select(EntityHistory).where(EntityHistory.entity_type == "asr_rule"))).scalar_one()
            self.assertNotIn("extracted_data", event.current_data)
            self.assertIn("extracted_data_hash", event.current_data)
        response = await self.client.get("/api/threats/1001/timeline")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["events"][0]["vdm_version"], "a" * 64)
        response = await self.client.get("/api/activity")
        self.assertEqual(sum(x["count"] for x in response.json()["items"]), 3)
        self.assertTrue(response.json()["tracked_since"])

    async def test_status_reports_failure_without_private_diagnostics(self):
        async with async_session_maker() as db:
            db.add(VDMVersion(version_hash="b" * 64, is_current=True))
            db.add(SyncStatus(status="failed", started_at=datetime.utcnow(), error_message="private diagnostic"))
            await db.commit()
        response = await self.client.get("/api/status")
        self.assertEqual(response.json()["status"], "failed")
        self.assertEqual(response.json()["current_version"], "b" * 64)
        self.assertNotIn("private diagnostic", response.text)

    async def test_scheduler_restores_disabled_setting(self):
        with patch.object(scheduler_service, "_load_schedule_from_db", AsyncMock(return_value={"enabled": False, "time": "11:30"})), patch.object(scheduler_service, "set_schedule", AsyncMock()) as restore:
            await scheduler_service.start_scheduler_on_startup()
            restore.assert_awaited_once_with(False, "11:30")


if __name__ == "__main__":
    unittest.main()
