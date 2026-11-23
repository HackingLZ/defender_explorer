"""Run against a disposable database: TEST_DATABASE_URL=.../defender_test.

These tests never start the app lifespan or download definitions.
"""

import json
import asyncio
import os
import struct
import tempfile
import unittest
import zlib
from datetime import datetime, timedelta
from pathlib import Path
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
from app.models import LuaScript, ASRRule, EntityHistory, Signature, SyncStatus, Threat, VDMVersion
from app.rate_limit import limiter
from app.services import scheduler_service, sync_service

if TEST_URL and engine.url != make_url(TEST_URL):
    raise RuntimeError("App engine was initialized with a different database; refusing to run destructive test setup")


@unittest.skipUnless(TEST_URL, "Set TEST_DATABASE_URL to a disposable defender_test database")
class ExplorerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
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

    @staticmethod
    def write_vdm(path, threats):
        """Build a small compressed RMDX/TLV fixture for the real VDM parser."""
        def tlv(type_, data):
            return struct.pack("<BBH", type_, len(data) & 255, len(data) >> 8) + data

        records = []
        for signature_id, name, pattern in threats:
            encoded_name = name.encode("ascii")
            begin = struct.pack("<I", signature_id) + bytes(6) + bytes([len(encoded_name)]) + bytes(2) + encoded_name
            records.extend([
                tlv(0x5C, begin),
                tlv(0xA0, pattern),
                tlv(0x5D, struct.pack("<I", signature_id)),
            ])
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(b"".join(records)) + compressor.flush()
        header = bytearray(40)
        header[:4] = b"RMDX"
        struct.pack_into("<II", header, 24, 32, len(compressed))
        Path(path).write_bytes(header + compressed)
        return str(path)

    @staticmethod
    def write_delta(path, base_path, output_path):
        from defender_sig_extractor.vdm_parser import VDMParser
        from test_delta_patcher import blob, literal, tlv
        base = VDMParser(base_path).decompress()
        output = VDMParser(output_path).decompress()
        # Copy common base bytes when possible; literal commands supply changes.
        common = 0
        while common < min(len(base), len(output)) and base[common] == output[common]:
            common += 1
        commands = b""
        offset = 0
        while common - offset >= 6:
            size = min(common - offset, 0x8005)
            commands += struct.pack("<HI", 0x8000 | (size - 6), offset)
            offset += size
        commands += literal(output[offset:])
        payload = tlv(0x74, b"fixture metadata") + tlv(0x73, blob(output, commands))
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(payload) + compressor.flush()
        header = bytearray(40)
        header[:4] = b"RMDX"
        struct.pack_into("<II", header, 24, 32, len(payload))
        Path(path).write_bytes(header + compressed)
        return str(path)

    def snapshot(self, directory, threats):
        base = self.write_vdm(Path(directory) / "mpavbase.vdm", threats)
        as_base = self.write_vdm(Path(directory) / "mpasbase.vdm", [(9001, "Spyware:Win32/Fixture.A", b"as fixture")])
        return {"av_base": base, "av_delta": self.write_delta(Path(directory)/"mpavdlta.vdm", base, base),
                "as_base": as_base, "as_delta": self.write_delta(Path(directory)/"mpasdlta.vdm", as_base, as_base)}

    async def import_snapshot(self, paths):
        sync_id = await self.create_sync()
        async with async_session_maker() as db:
            await sync_service._import_vdm_files(db, sync_id, paths, authoritative=True)
        return sync_id

    async def create_sync(self):
        async with async_session_maker() as db:
            status = SyncStatus(status="running")
            db.add(status)
            await db.commit()
            return status.id

    async def test_local_vdm_import_is_searchable_and_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_vdm(Path(directory) / "mpavbase.vdm", [
                (1001, "Trojan:Win32/IngestionTest.A", b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\fixture"),
            ])
            for attempt in range(2):
                sync_id = await self.create_sync()
                await sync_service.run_local_import(sync_id, path)
                async with async_session_maker() as db:
                    status = await db.get(SyncStatus, sync_id)
                    self.assertEqual(status.status, "completed", status.error_message)
                    self.assertEqual(status.threats_added, 1 if attempt == 0 else 0)
                    self.assertEqual((await db.execute(select(func.count(Threat.id)))).scalar(), 1)
                    self.assertEqual((await db.execute(select(func.count(Signature.id)))).scalar(), 1)
                    self.assertEqual((await db.execute(select(func.count(VDMVersion.id)))).scalar(), 1)

            response = await self.client.get("/api/signatures/search", params={"q": "fixture", "category": "Persistence/Registry", "subcategory": "Run"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["total"], 1)
            self.assertEqual(response.json()["items"][0]["threat_name"], "Trojan:Win32/IngestionTest.A")
            async with async_session_maker() as db:
                version = (await db.execute(select(VDMVersion))).scalar_one()
                history = (await db.execute(select(EntityHistory).where(EntityHistory.entity_type == "threat"))).scalars().all()
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0].vdm_version_hash, version.version_hash)

    async def test_sync_endpoint_applies_real_delta_format_changes(self):
        from app.api.admin import settings as admin_settings
        with tempfile.TemporaryDirectory() as directory:
            paths = self.snapshot(directory, [(1001, "Trojan:Win32/Base.A", b"base fixture")])
            output = Path(directory)/"merged.vdm"
            for attempt in range(2):
                self.write_vdm(output, [
                    (1001, "Trojan:Win32/Base.A", b"base fixture"),
                    (1002, "Trojan:Win32/Updated.A", b"new pattern" if attempt else b"old pattern"),
                    (1004 if attempt else 1003, "Trojan:Win32/Changed.A", b"added" if attempt else b"removed"),
                ])
                self.write_delta(paths["av_delta"], paths["av_base"], output)
                download = sync_service.VDMDownloadResult(paths, "", "")
                with patch.object(admin_settings, "admin_api_key", "ingestion-test-key"), patch.object(sync_service, "_download_and_extract_vdm", return_value=download):
                    response = await self.client.post("/api/admin/sync", headers={"X-API-Key": "ingestion-test-key"})
                self.assertEqual(response.status_code, 200, response.text)
                async with async_session_maker() as db:
                    status = await db.get(SyncStatus, response.json()["id"])
                    self.assertEqual(status.status, "completed", status.error_message)
                    self.assertEqual(status.threats_added, 1 if attempt else 4)
                    self.assertEqual(status.threats_updated, attempt)
                    self.assertEqual(status.threats_removed, attempt)
                    self.assertEqual(status.threats_processed, 4)
            async with async_session_maker() as db:
                ids = (await db.execute(select(Threat.signature_id).order_by(Threat.signature_id))).scalars().all()
                self.assertEqual(ids, [1001, 1002, 1004, 9001])
                version = await db.scalar(select(VDMVersion).where(VDMVersion.is_current.is_(True)))
                self.assertEqual(version.threat_count, 4)
                self.assertEqual(version.signature_count, 4)

    async def test_full_refresh_removes_absent_threats_and_reuses_unchanged_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            initial = [(1, "Trojan:Win32/Keep.A", b"keep"), (2, "Trojan:Win32/Remove.A", b"remove")]
            paths = self.snapshot(directory, initial)
            await self.import_snapshot(paths)
            async with async_session_maker() as db:
                original = (await db.execute(select(Signature.id).join(Threat).where(Threat.signature_id == 1))).scalar_one()
            paths = self.snapshot(directory, [initial[0], (3, "Trojan:Win32/Add.A", b"new")])
            sync_id = await self.import_snapshot(paths)
            async with async_session_maker() as db:
                status = await db.get(SyncStatus, sync_id)
                self.assertEqual((status.threats_added,status.threats_updated,status.threats_removed), (1,0,1))
                self.assertIsNone(await db.scalar(select(Threat.id).where(Threat.signature_id == 2)))
                self.assertEqual(await db.scalar(select(Signature.id).join(Threat).where(Threat.signature_id == 1)), original)
            # Reverting to a historical snapshot reuses its version row safely.
            paths = self.snapshot(directory, initial)
            await self.import_snapshot(paths)
            async with async_session_maker() as db:
                self.assertIsNotNone(await db.scalar(select(Threat.id).where(Threat.signature_id == 2)))
                self.assertIsNone(await db.scalar(select(Threat.id).where(Threat.signature_id == 3)))
                self.assertEqual(await db.scalar(select(func.count(VDMVersion.id))), 2)

    async def test_local_import_preserves_unrelated_threats(self):
        await self.seed()
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_vdm(Path(directory)/"local.vdm", [(77, "Trojan:Win32/Local.A", b"local")])
            await sync_service.run_local_import(await self.create_sync(), path)
            async with async_session_maker() as db:
                self.assertEqual(await db.scalar(select(func.count(Threat.id))), 3)

    async def test_concurrent_reservations_and_active_worker_recovery(self):
        from app.services.sync_lifecycle import reserve_sync, SyncBusy, exclusive_sync, recover_interrupted_syncs
        async def reserve():
            async with async_session_maker() as db:
                try:
                    return await reserve_sync(db)
                except SyncBusy:
                    return None
        attempts = await asyncio.gather(reserve(), reserve())
        winners = [s for s in attempts if s is not None]
        self.assertEqual(len(winners), 1)
        started = asyncio.Event()
        @exclusive_sync
        async def job(sync_id):
            started.set()
            await asyncio.Event().wait()
        task = asyncio.create_task(job(winners[0].id))
        try:
            await asyncio.wait_for(started.wait(), 5)
            self.assertIsNone(await reserve())
            async with async_session_maker() as db:
                self.assertEqual(await recover_interrupted_syncs(db), 0)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        async with async_session_maker() as db:
            self.assertEqual((await db.get(SyncStatus, winners[0].id)).status, "failed")
        self.assertIsNotNone(await reserve())

    async def test_stale_update_recovers_even_with_current_version(self):
        from app.services.sync_lifecycle import recover_interrupted_syncs, reserve_sync
        async with async_session_maker() as db:
            db.add(VDMVersion(version_hash="old", is_current=True))
            stale = SyncStatus(status="running", phase="importing", started_at=datetime.utcnow()-timedelta(hours=2))
            db.add(stale)
            await db.commit()
            self.assertEqual(await recover_interrupted_syncs(db), 1)
            await db.refresh(stale)
            self.assertEqual(stale.status, "failed")
            self.assertEqual((await reserve_sync(db)).status, "running")

    async def test_changed_threat_preserves_lua_results_by_bytecode_and_removes_old_scripts(self):
        from app.services.import_service import ImportService, ImportStats
        from defender_sig_extractor.signature_extractor import ThreatDefinition, TLVEntry
        def definition(include_second=True):
            entries = [TLVEntry(0xBD, len(payload), payload, 0) for payload in
                       ([b"benign cached lua A", b"benign cached lua B"] if include_second else [b"benign cached lua A"])]
            return ThreatDefinition(123, "Trojan:Win32/Cached.A", entries)
        async with async_session_maker() as db:
            service = ImportService(db, decompile_during_import=False)
            await service._import_threat(definition(), ImportStats())
            await db.commit()
            scripts = (await db.execute(select(LuaScript).order_by(LuaScript.id))).scalars().all()
            self.assertEqual(len(scripts), 2)
            first_id, second_id = [script.id for script in scripts]
            scripts[0].decompiled_source = "return true"
            scripts[0].decompilation_status = "completed"
            scripts[0].decompilation_attempts = 1
            scripts[1].decompilation_status = "failed"
            scripts[1].decompilation_error = "no_source"
            scripts[1].decompilation_attempts = 2
            await db.commit()
            old_signature_id = scripts[0].signature_id
            # Force a changed parent with identical bytecode payloads.
            changed = definition()
            changed.signatures.append(TLVEntry(0xA0, 3, b"new", 0))
            await service._import_threat(changed, ImportStats())
            await db.commit()
            db.expire_all()
            first, second = await db.get(LuaScript,first_id), await db.get(LuaScript,second_id)
            self.assertEqual((first.decompiled_source, first.decompilation_status, first.decompilation_attempts), ("return true", "completed", 1))
            self.assertNotEqual(first.signature_id, old_signature_id)
            self.assertIsNotNone(first.threat_id)
            self.assertEqual((second.decompilation_status, second.decompilation_error, second.decompilation_attempts), ("failed", "no_source", 2))
            await service._import_threat(definition(False), ImportStats())
            await db.rollback()
            self.assertIsNotNone(await db.get(LuaScript,second_id))
            self.assertEqual((await db.get(LuaScript,first_id)).decompiled_source, "return true")
            await service._import_threat(definition(False), ImportStats())
            await db.commit()
            db.expire_all()
            self.assertIsNone(await db.get(LuaScript,second_id))
            self.assertEqual((await db.get(LuaScript,first_id)).decompiled_source, "return true")

    async def test_cancellation_records_interruption_and_cleans_late_download(self):
        import threading
        started, release = threading.Event(), threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            extracted = Path(directory)/"extracted"
            extracted.mkdir()
            package = Path(directory)/"package.exe"
            package.write_bytes(b"fixture")
            def download():
                started.set()
                if not release.wait(5):
                    raise RuntimeError("Test did not release download")
                return sync_service.VDMDownloadResult({}, str(extracted), str(package))
            sync_id = await self.create_sync()
            with patch.object(sync_service, "_download_and_extract_vdm", side_effect=download):
                task = asyncio.create_task(sync_service.run_sync(sync_id))
                try:
                    self.assertTrue(await asyncio.to_thread(started.wait, 5))
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                finally:
                    release.set()
                for _ in range(100):
                    if not package.exists():
                        break
                    await asyncio.sleep(0.01)
            self.assertFalse(package.exists())
            self.assertFalse(extracted.exists())
            async with async_session_maker() as db:
                status = await db.get(SyncStatus, sync_id)
                self.assertEqual((status.status,status.phase), ("failed","interrupted"))
                self.assertEqual(await db.scalar(select(func.count(VDMVersion.id))), 0)

    async def test_startup_retries_interrupted_update_with_existing_version(self):
        from app.services.sync_lifecycle import resume_startup_sync
        async with async_session_maker() as db:
            db.add(VDMVersion(version_hash="existing", is_current=True))
            db.add(SyncStatus(status="running", phase="decompiling", started_at=datetime.utcnow()-timedelta(hours=2)))
            await db.commit()
        with patch.object(sync_service, "run_sync", new_callable=AsyncMock) as run:
            await resume_startup_sync()
            run.assert_awaited_once()
        async with async_session_maker() as db:
            rows = (await db.execute(select(SyncStatus).order_by(SyncStatus.id))).scalars().all()
            self.assertEqual([s.status for s in rows], ["failed", "running"])

    async def test_failed_partial_update_can_restore_the_current_version(self):
        from app.services.import_service import ImportService
        original_import = ImportService._import_threat
        async def interrupted(service, threat, stats):
            await original_import(service, threat, stats)
            await service.db.commit()
            raise RuntimeError("Simulated interruption after a committed batch")
        initial = [(1, "Trojan:Win32/Keep.A", b"original")]
        with tempfile.TemporaryDirectory() as directory:
            await self.import_snapshot(self.snapshot(directory, initial))
            changed = self.snapshot(directory, [(1, "Trojan:Win32/Keep.A", b"partial update")])
            download = sync_service.VDMDownloadResult(changed, "", "")
            sync_id = await self.create_sync()
            with patch.object(sync_service, "_download_and_extract_vdm", return_value=download), patch.object(ImportService, "_import_threat", interrupted):
                await sync_service.run_sync(sync_id)
            async with async_session_maker() as db:
                self.assertEqual((await db.get(SyncStatus, sync_id)).status, "failed")
                self.assertEqual(await db.scalar(select(Signature.data).join(Threat).where(Threat.signature_id == 1)), b"partial update")
            # The same version hash is still current, but must not skip repair.
            await self.import_snapshot(self.snapshot(directory, initial))
            async with async_session_maker() as db:
                self.assertEqual(await db.scalar(select(Signature.data).join(Threat).where(Threat.signature_id == 1)), b"original")
                self.assertEqual(await db.scalar(select(func.count(VDMVersion.id))), 1)

    async def test_invalid_delta_and_missing_snapshot_do_not_publish_or_remove(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.snapshot(directory, [(1, "Trojan:Win32/Keep.A", b"original")])
            await self.import_snapshot(paths)
            self.write_vdm(paths["av_delta"], [(2, "Trojan:Win32/InvalidDelta.A", b"plain records are not a patch")])
            for files in [paths, {"av_base":paths["av_base"]}]:
                sync_id = await self.create_sync()
                with patch.object(sync_service, "_download_and_extract_vdm", return_value=sync_service.VDMDownloadResult(files,"","")):
                    await sync_service.run_sync(sync_id)
                async with async_session_maker() as db:
                    self.assertEqual((await db.get(SyncStatus,sync_id)).status, "failed")
                    self.assertEqual(await db.scalar(select(func.count(Threat.id))), 2)
                    self.assertEqual(await db.scalar(select(func.count(VDMVersion.id))), 1)

    async def test_readiness_checks_database_and_reports_unavailability(self):
        import importlib
        main = importlib.import_module("app.main")
        self.assertEqual((await self.client.get("/ready")).status_code, 200)
        with patch.object(main, "async_session_maker", side_effect=RuntimeError("private database detail")):
            response = await self.client.get("/ready")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private", response.text)

    async def test_lua_failure_retry_is_authenticated_and_only_requeues_failures(self):
        from app.api.admin import settings as admin_settings
        async with async_session_maker() as db:
            db.add_all([LuaScript(id=1, bytecode=b"fixture", decompilation_status="failed", decompilation_error="timeout", decompilation_attempts=1),
                        LuaScript(id=2, bytecode=b"fixture", decompilation_status="completed", decompiled_source="return true")])
            await db.commit()
        with patch.object(admin_settings, "admin_api_key", "test-key"):
            response = await self.client.post("/api/admin/decompilation/retry", json={})
            self.assertNotEqual(response.status_code, 200)
            response = await self.client.get("/api/admin/decompilation/failures", headers={"X-API-Key":"test-key"})
            self.assertEqual(response.json()[0]["decompilation_error"], "timeout")
            response = await self.client.post("/api/admin/decompilation/retry", json={"script_ids":[1,2]}, headers={"X-API-Key":"test-key"})
            self.assertEqual(response.json()["script_ids"], [1])
        public = (await self.client.get("/api/status")).json()
        self.assertEqual((public["lua_pending"], public["lua_completed"], public["lua_failed"]), (1, 1, 0))
        async with async_session_maker() as db:
            self.assertEqual((await db.get(LuaScript,1)).decompilation_status, "pending")
            self.assertEqual((await db.get(LuaScript,2)).decompilation_status, "completed")

    async def test_empty_vdm_does_not_publish_a_successful_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_vdm(Path(directory) / "empty.vdm", [])
            sync_id = await self.create_sync()
            await sync_service.run_local_import(sync_id, path)
            async with async_session_maker() as db:
                self.assertEqual((await db.get(SyncStatus, sync_id)).status, "failed")
                self.assertEqual((await db.execute(select(func.count(VDMVersion.id)))).scalar(), 0)

    async def test_ingestion_database_failure_records_failed_status(self):
        async def fail_write(db, *args, **kwargs):
            # PostgreSQL leaves the transaction aborted after a write/query error.
            await db.execute(text("SELECT CAST('invalid' AS INTEGER)"))

        for operation in ("local", "download"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                sync_id = await self.create_sync()
                extracted = Path(directory) / "extracted"
                extracted.mkdir()
                package = Path(directory) / "mpam-fe.exe"
                package.write_bytes(b"test package")
                download = sync_service.VDMDownloadResult(vdm_files={}, temp_dir=str(extracted), mpam_path=str(package))
                with patch.object(sync_service, "_import_vdm_files", side_effect=fail_write), patch.object(sync_service, "_download_and_extract_vdm", return_value=download):
                    if operation == "local":
                        await sync_service.run_local_import(sync_id, "/unused.vdm")
                    else:
                        await sync_service.run_sync(sync_id)
                        self.assertFalse(extracted.exists())
                        self.assertFalse(package.exists())
                async with async_session_maker() as db:
                    status = await db.get(SyncStatus, sync_id)
                    self.assertEqual(status.status, "failed")
                    self.assertIsNotNone(status.completed_at)

    async def test_signature_search_combines_category_and_subcategory(self):
        async with async_session_maker() as db:
            db.add_all([
                Signature(id=40, sig_type=1, category="Persistence/Registry", subcategory="Run", extracted_text="powershell.exe 100%_literal"),
                Signature(id=10, sig_type=1, category="Persistence/Registry", subcategory="Run", extracted_text="powershell.exe"),
                Signature(id=30, sig_type=1, category="Persistence/Registry", subcategory="Services", extracted_text="powershell.exe"),
                Signature(id=20, sig_type=1, category="Script/PowerShell", subcategory="Run", extracted_text="powershell.exe"),
            ])
            await db.commit()

        cases = [
            ({"category": "Persistence/Registry", "subcategory": "Run"}, [10, 40]),
            ({"category": "Persistence/Registry"}, [10, 30, 40]),
            ({"subcategory": "Run"}, [10, 20, 40]),
            ({"category": "Script/PowerShell", "subcategory": "Services"}, []),
            ({"q": "100%_literal"}, [40]),
        ]
        for filters, expected in cases:
            with self.subTest(filters=filters):
                response = await self.client.get("/api/signatures/search", params={"q": "powershell", **filters})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual([item["id"] for item in response.json()["items"]], expected)
                self.assertEqual(response.json()["total"], len(expected))

    async def test_signature_pagination_has_stable_order_and_filtered_totals(self):
        async with async_session_maker() as db:
            # Insert out of ID order to catch reliance on physical row ordering.
            db.add_all([
                Signature(id=id_, sig_type=1, category="Persistence/Registry", subcategory="Run", extracted_text="powershell.exe")
                for id_ in (40, 10, 30, 20, 50)
            ])
            db.add(Signature(id=60, sig_type=1, category="Persistence/Registry", subcategory="Services", extracted_text="powershell.exe"))
            await db.commit()

        for endpoint in ("browse", "search"):
            for page, expected in ((1, [10, 20]), (2, [30, 40]), (3, [50]), (4, [])):
                with self.subTest(endpoint=endpoint, page=page):
                    params = {"category": "Persistence/Registry", "subcategory": "Run", "page_size": 2, "page": page}
                    if endpoint == "search":
                        params["q"] = "powershell"
                    response = await self.client.get(f"/api/signatures/{endpoint}", params=params)
                    self.assertEqual(response.status_code, 200, response.text)
                    payload = response.json()
                    self.assertEqual([item["id"] for item in payload["items"]], expected)
                    self.assertEqual(payload["total"], 5)
                    self.assertEqual(payload["pages"], 3)
                    self.assertEqual(payload["page"], page)

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
