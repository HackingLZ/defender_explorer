"""Real spawned VDM workers; database effects are observed with test doubles."""

import asyncio
import hashlib
from datetime import datetime
from types import SimpleNamespace
import multiprocessing
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from app.database import get_db
from app.main import app
from app.services import sync_service, vdm_service
from app.services.import_service import ImportService
from app.services.process_worker import WorkerTimeoutError
from test_security_vdm import LAYOUTS, make_vdm


def threat_stream():
    def tlv(kind, data):
        return struct.pack("<BBH", kind, len(data) & 255, len(data) >> 8) + data

    name = b"Trojan:Win32/VDMTest.A"
    begin = struct.pack("<I", 1001) + bytes(6) + bytes([len(name)]) + bytes(2) + name
    return tlv(0x5C, begin) + tlv(0xA0, b"legitimate signature") + tlv(0x5D, struct.pack("<I", 1001))


class VDMWorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "fixture.vdm"
        # Exercise the same limits with small fixtures instead of an OOM test.
        for name, value in (("MAX_VDM_DECOMPRESSED_SIZE", 1024 * 1024),
                            ("MAX_VDM_FILE_SIZE", 1024 * 1024),
                            ("_vdm_slot", asyncio.Semaphore(1))):
            patcher = patch.object(vdm_service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    async def test_valid_layouts_keep_bytes_hashes_and_threats(self):
        payload = threat_stream()
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                self.path.write_bytes(make_vdm(payload, layout))
                self.assertEqual(await vdm_service.decompress_vdm(str(self.path)), payload)
                self.assertEqual(await vdm_service.hash_vdm(str(self.path)), hashlib.sha256(payload).hexdigest())
                threats = await sync_service._extract_threats_from_vdm(str(self.path))
                self.assertEqual([(t.signature_id, t.threat_name) for t in threats],
                                 [(1001, "Trojan:Win32/VDMTest.A")])
                self.assertEqual(threats[0].signatures[0].data, b"legitimate signature")

    async def test_bombs_fail_in_hashing_and_extraction_then_next_job_succeeds(self):
        before = {child.pid for child in multiprocessing.active_children()}
        for layout in LAYOUTS:
            self.path.write_bytes(make_vdm(b"A" * (2 * 1024 * 1024), layout))
            for operation in (vdm_service.hash_vdm, sync_service._extract_threats_from_vdm):
                with self.subTest(layout=layout, operation=operation.__name__):
                    with self.assertRaisesRegex(RuntimeError, "Worker failed"):
                        await operation(str(self.path))
                    self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)
        self.path.write_bytes(make_vdm(threat_stream()))
        self.assertEqual(await vdm_service.decompress_vdm(str(self.path)), threat_stream())

    async def test_worker_deadline_and_cancellation_release_slot_and_reap_child(self):
        before = {child.pid for child in multiprocessing.active_children()}
        self.path.write_bytes(make_vdm(threat_stream()))
        with patch.object(vdm_service, "VDM_TIMEOUT", 0):
            with self.assertRaises(WorkerTimeoutError):
                await vdm_service.hash_vdm(str(self.path))
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)
        task = asyncio.create_task(vdm_service.hash_vdm(str(self.path)))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)
        self.assertEqual(await vdm_service.decompress_vdm(str(self.path)), threat_stream())

    async def test_failed_local_import_records_failure_while_api_responds(self):
        self.path.write_bytes(make_vdm(b"A" * (16 * 1024 * 1024)))
        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        db.rollback = AsyncMock()
        session = MagicMock()
        session.return_value.__aenter__.return_value = db
        read_result = MagicMock()
        read_result.scalar.return_value = 0
        read_result.scalars.return_value.all.return_value = []
        read_db = MagicMock(execute=AsyncMock(return_value=read_result))

        async def browsing_db():
            yield read_db

        app.dependency_overrides[get_db] = browsing_db
        self.addCleanup(app.dependency_overrides.pop, get_db)
        with patch.object(sync_service, "async_session_maker", session):
            task = asyncio.create_task(sync_service.run_local_import.__wrapped__(42, str(self.path)))
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                for route in ("/health", "/api/threats"):
                    response = await asyncio.wait_for(client.get(route), timeout=1)
                    self.assertEqual(response.status_code, 200, response.text)
            await task
        db.rollback.assert_awaited_once()
        db.commit.assert_awaited_once()
        db.execute.assert_awaited_once()
        self.assertEqual(db.execute.call_args.args[0].compile().params["status"], "failed")

    async def test_duplicate_import_hash_and_legacy_import_remain_compatible(self):
        payload = threat_stream()
        self.path.write_bytes(make_vdm(payload))
        existing = MagicMock()
        existing.scalar_one_or_none.return_value = object()
        db = MagicMock(execute=AsyncMock(return_value=existing), commit=AsyncMock(),
                       scalar=AsyncMock(side_effect=[SimpleNamespace(is_current=True, download_timestamp=datetime.utcnow()), None]))
        with patch("app.services.decompilation_service.get_decompilation_stats", return_value={}):
            await sync_service._import_vdm_files(db, 7, {"av_base": str(self.path)})
        content_hash = hashlib.sha256(payload).hexdigest()
        combined = hashlib.sha256(b"verified-delta-v1:" + content_hash.encode()).hexdigest()
        params = db.scalar.call_args_list[0].args[0].compile().params
        self.assertIn(combined, params.values())
        self.assertEqual(db.execute.call_args_list[0].args[0].compile().params["status"], "completed")
        service = ImportService(db)
        service._bulk_import_threats = AsyncMock()
        await service.import_from_vdm(str(self.path))
        imported = service._bulk_import_threats.call_args.args[0]
        self.assertEqual(imported[0].signature_id, 1001)
        self.assertEqual(imported[0].signatures[0].data, b"legitimate signature")


if __name__ == "__main__":
    unittest.main()
