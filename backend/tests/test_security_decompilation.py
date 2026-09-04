"""Decompilation lifecycle tests with benign mocked worker results and DB."""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.services import decompilation_service as service
from app.services.process_worker import WorkerTimeoutError


class DecompilationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.previous_shutdown = service._shutdown_event
        service._shutdown_event = None

    async def asyncTearDown(self):
        await service.stop_background_worker()
        service._decompile_jobs.clear()
        service._shutdown_event = self.previous_shutdown

    def database(self, updated=True):
        script = SimpleNamespace(bytecode=b"benign fixture", decompilation_status="pending", decompiled_source=None, asr_guids=[])
        read_result = MagicMock()
        read_result.scalar_one_or_none.return_value = script
        write_result = MagicMock()
        write_result.scalar_one_or_none.return_value = 7 if updated else None
        read_session = SimpleNamespace(execute=AsyncMock(return_value=read_result))
        write_session = SimpleNamespace(execute=AsyncMock(return_value=write_result), commit=AsyncMock())
        sessions = iter([read_session, write_session])

        @asynccontextmanager
        async def factory():
            yield next(sessions)

        return factory, read_session, write_session

    async def test_cancelled_request_does_not_abandon_shared_job_or_commit(self):
        factory, read, write = self.database()
        started, release = asyncio.Event(), asyncio.Event()

        async def worker(*args, **kwargs):
            started.set()
            await release.wait()
            return b'["return true", "completed", []]'

        with patch.object(service, "async_session_maker", factory), patch.object(service, "run_worker", side_effect=worker) as run:
            first = asyncio.create_task(service.decompile_on_demand(None, 7))
            await started.wait()
            second = asyncio.create_task(service.decompile_on_demand(None, 7))
            await asyncio.sleep(0)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            release.set()
            self.assertEqual(await second, "return true")
            self.assertEqual(run.call_count, 1)
            write.commit.assert_awaited_once()
            self.assertFalse(service._decompile_jobs)

    async def test_deadline_persists_failed_status(self):
        factory, read, write = self.database()
        with patch.object(service, "async_session_maker", factory), patch.object(service, "run_worker", side_effect=WorkerTimeoutError("deadline")):
            self.assertIsNone(await service.decompile_on_demand(None, 7))
        statement = write.execute.call_args.args[0]
        self.assertEqual(statement.compile().params["decompilation_status"], "failed")
        write.commit.assert_awaited_once()

    async def test_stale_input_is_not_published(self):
        factory, read, write = self.database(updated=False)
        with patch.object(service, "async_session_maker", factory), patch.object(service, "run_worker", return_value=b'["return true", "completed", []]'):
            self.assertIsNone(await service.decompile_on_demand(None, 7))
        statement = str(write.execute.call_args.args[0])
        self.assertIn("lua_scripts.bytecode =", statement)
        self.assertIn("lua_scripts.decompilation_status =", statement)


if __name__ == "__main__":
    unittest.main()
