"""Benign lifecycle tests for bounded report and process workers."""

import asyncio
import multiprocessing
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from app.services.process_worker import run_worker, WorkerTimeoutError
from app.services import report_service as reports


def write_result(value: bytes, delay: float, output_path: str) -> None:
    time.sleep(delay)
    Path(output_path).write_bytes(value)


class ProcessWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_result_and_event_loop_responsiveness(self):
        task = asyncio.create_task(run_worker(write_result, (b"report", 0.15), timeout=5, max_output=1024))
        await asyncio.sleep(0.03)
        self.assertFalse(task.done())
        self.assertEqual(await task, b"report")

    async def test_deadline_reaps_child(self):
        before = {child.pid for child in multiprocessing.active_children()}
        with self.assertRaises(WorkerTimeoutError):
            await run_worker(write_result, (b"report", 1), timeout=0.15, max_output=1024)
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)

    async def test_cancellation_reaps_child(self):
        before = {child.pid for child in multiprocessing.active_children()}
        task = asyncio.create_task(run_worker(write_result, (b"report", 1), timeout=5, max_output=1024))
        await asyncio.sleep(0.15)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)


class ReportJobTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await reports.stop_report_workers()

    async def test_duplicate_requests_share_work_and_cache(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def render(*args, **kwargs):
            started.set()
            await release.wait()
            return b"pdf"

        with patch.object(reports, "run_worker", side_effect=render) as worker:
            first = asyncio.create_task(reports.generate_pdf_from_html("<p>report</p>"))
            await started.wait()
            second = asyncio.create_task(reports.generate_pdf_from_html("<p>report</p>"))
            await asyncio.sleep(0)
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            release.set()
            self.assertEqual(await second, b"pdf")
            self.assertEqual(await reports.generate_pdf_from_html("<p>report</p>"), b"pdf")
            self.assertEqual(worker.call_count, 1)

    async def test_admission_is_bounded(self):
        release = asyncio.Event()

        async def render(*args, **kwargs):
            await release.wait()
            return b"pdf"

        with patch.object(reports, "run_worker", side_effect=render):
            jobs = [asyncio.create_task(reports.generate_pdf_from_html(f"<p>{i}</p>")) for i in range(2)]
            await asyncio.sleep(0)
            with self.assertRaises(reports.ReportBusyError):
                await reports.generate_pdf_from_html("<p>third</p>")
            release.set()
            await asyncio.gather(*jobs)

    async def test_timeout_has_specific_error_and_releases_slot(self):
        with patch.object(reports, "run_worker", side_effect=WorkerTimeoutError("deadline")):
            with self.assertRaises(reports.ReportTimeoutError):
                await reports.generate_pdf_from_html("<p>report</p>")
        self.assertFalse(reports._pdf_jobs)


if __name__ == "__main__":
    unittest.main()
