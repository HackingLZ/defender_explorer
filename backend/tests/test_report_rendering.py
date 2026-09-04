"""Optional real renderer smoke test; requires WeasyPrint system libraries."""

import os
import unittest

from app.services.report_service import generate_pdf_from_html, stop_report_workers


@unittest.skipUnless(os.getenv("TEST_PDF_RENDER") == "1", "Set TEST_PDF_RENDER=1 with WeasyPrint system libraries installed")
class ReportRenderingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await stop_report_workers()

    async def test_report_is_rendered_in_worker(self):
        pdf = await generate_pdf_from_html("<!doctype html><html><body><h1>Definition report</h1><p>Local test data.</p></body></html>")
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 100)


if __name__ == "__main__":
    unittest.main()
