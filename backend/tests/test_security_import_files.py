"""Import containment regressions using synthetic files and a mocked database."""

import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
import httpx
from sqlalchemy.sql.dml import Insert

from app.api import admin, lua
from app.database import get_db
from app.services import import_files
from app.services.extracted_import_service import ExtractedImportService, ExtractedImportStats
from app.services.function_registry_service import discover_functions_from_directory
from app.services.import_service_v2 import ImportServiceV2


GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5"
SOURCE = f'-- ASR Rule GUID: {GUID}\n(mp.IsHipsRuleEnabled)("{GUID}")\nreturn true\n'
SECRET = "SYNTHETIC_BACKEND_SECRET=do-not-publish\x00"


class ImportFileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "dataset"
        self.root.mkdir()
        self.outside = self.base / "outside.lua"
        self.outside.write_text(SECRET)

    def test_regular_nested_file_preserves_text_decoding(self):
        nested = self.root / "nested"
        nested.mkdir()
        path = nested / "normal.lua"
        path.write_bytes(b'return "hello"\r\n-- \xff\x00')
        self.assertEqual(import_files.read_import_text(self.root, path), path.read_text(errors="replace"))

    def test_links_traversal_and_nonregular_entries_are_rejected(self):
        nested = self.root / "nested"
        nested.mkdir()
        regular = nested / "normal.lua"
        regular.write_text(SOURCE)
        outside_link = self.root / "outside.lua"
        outside_link.symlink_to(self.outside)
        inside_link = self.root / "inside.lua"
        inside_link.symlink_to(regular)
        broken = self.root / "broken.lua"
        broken.symlink_to(self.base / "missing")
        parent_link = self.root / "linked"
        parent_link.symlink_to(self.base, target_is_directory=True)
        fifo = self.root / "fifo.lua"
        os.mkfifo(fifo)
        for path in (outside_link, inside_link, broken, parent_link / "outside.lua",
                     self.outside, self.root / ".." / "outside.lua", nested, fifo):
            with self.subTest(path=path), self.assertRaises(import_files.UnsafeImportFileError):
                import_files.read_import_text(self.root, path)

    def test_symlinked_root_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        (self.root / "normal.lua").write_text(SOURCE)
        with self.assertRaises(import_files.UnsafeImportFileError):
            import_files.read_import_text(alias, alias / "normal.lua")

    def test_replacement_before_open_cannot_redirect_read(self):
        real_open = os.open
        (self.base / "normal.lua").write_text(SECRET)
        for replace_directory in (False, True):
            with self.subTest(directory=replace_directory):
                root = self.root / str(replace_directory)
                root.mkdir()
                nested = root / "nested"
                nested.mkdir()
                path = nested / "normal.lua"
                path.write_text(SOURCE)
                trigger = "nested" if replace_directory else "normal.lua"
                replaced = False

                def racing_open(name, flags, *args, **kwargs):
                    nonlocal replaced
                    if name == trigger and not replaced:
                        replaced = True
                        if replace_directory:
                            nested.rename(root / "original")
                            nested.symlink_to(self.base, target_is_directory=True)
                        else:
                            path.unlink()
                            path.symlink_to(self.outside)
                    return real_open(name, flags, *args, **kwargs)

                with patch.object(import_files.os, "open", side_effect=racing_open) as opened:
                    with patch.object(import_files.os, "supports_dir_fd", os.supports_dir_fd | {opened}):
                        with self.assertRaises(import_files.UnsafeImportFileError):
                            import_files.read_import_text(root, path)
                self.assertTrue(replaced)

    def test_open_directory_stays_pinned_after_replacement(self):
        nested = self.root / "nested"
        nested.mkdir()
        path = nested / "normal.lua"
        path.write_text(SOURCE)
        (self.base / "normal.lua").write_text(SECRET)
        real_open = os.open

        def racing_open(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if name == "nested":
                nested.rename(self.root / "original")
                nested.symlink_to(self.base, target_is_directory=True)
            return fd

        with patch.object(import_files.os, "open", side_effect=racing_open) as opened:
            with patch.object(import_files.os, "supports_dir_fd", os.supports_dir_fd | {opened}):
                self.assertEqual(import_files.read_import_text(self.root, path), SOURCE)

    def test_unsupported_platform_fails_closed(self):
        path = self.root / "normal.lua"
        path.write_text(SOURCE)
        with patch.object(import_files.os, "supports_dir_fd", set()):
            with self.assertRaises(import_files.UnsafeImportFileError):
                import_files.read_import_text(self.root, path)


class ImportPublicationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.outside = self.base / "secret.txt"
        self.outside.write_text(SECRET)

    def database(self):
        writes = []

        def execute(statement):
            if isinstance(statement, Insert):
                writes.append((statement.table.name, statement.compile().params))
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            result.all.return_value = []
            return result

        db = SimpleNamespace(execute=AsyncMock(side_effect=execute), commit=AsyncMock(), rollback=AsyncMock())
        return db, writes

    async def run_import(self, kind, root, db):
        if kind == "direct":
            with patch.object(admin, "ALLOWED_IMPORT_ROOTS", [root]), patch.object(admin.settings, "admin_imports_enabled", True):
                result = await admin.import_lua_scripts_from_path(admin.LuaImportRequest(lua_path=str(root / "lua")), db)
            return result["errors"]
        if kind == "v2":
            pipeline = ImportServiceV2(db)
            await pipeline._import_lua_scripts(root / "lua")
            return pipeline.stats.text_import_stats.errors
        service = ExtractedImportService(db, str(root))
        stats = ExtractedImportStats()
        if kind == "asr":
            await service.import_asr_scripts(stats)
        else:
            await service.import_lua_scripts(stats)
        return stats.errors

    def directory(self, root, kind):
        directory = root / "asr" / GUID if kind == "asr" else root / "lua"
        directory.mkdir(parents=True)
        return directory

    async def public_source(self, row):
        script = SimpleNamespace(id=1, signature_id=None, threat_id=None, threat=None, bytecode=None,
                                 decompilation_status="completed", mitre_techniques=[], **row)
        result = MagicMock()
        result.scalar_one_or_none.return_value = script
        db = SimpleNamespace(execute=AsyncMock(return_value=result))
        app = FastAPI()
        app.include_router(lua.router, prefix="/api/lua")
        app.dependency_overrides[get_db] = lambda: db
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/lua/1")
        self.assertEqual(response.status_code, 200)
        return response.json()["decompiled_source"]

    async def test_all_importers_reject_outside_links_and_publish_regular_files(self):
        for kind in ("direct", "extracted", "asr", "v2"):
            with self.subTest(importer=kind):
                root = self.base / kind
                directory = self.directory(root, kind)
                (directory / "leak.lua").symlink_to(self.outside)
                db, writes = self.database()
                errors = await self.run_import(kind, root, db)
                self.assertEqual([row for table, row in writes if table == "lua_scripts"], [])
                self.assertTrue(errors)

                # A rejected file must not prevent a valid neighboring script from importing.
                (directory / "normal.lua").write_text(SOURCE + "\x00\x13\x0f")
                db, writes = self.database()
                await self.run_import(kind, root, db)
                scripts = [row for table, row in writes if table == "lua_scripts"]
                self.assertEqual(len(scripts), 1)
                row = scripts[0]
                self.assertEqual(row["decompiled_source"], SOURCE)
                self.assertEqual(row["bytecode_hash"], hashlib.sha256(SOURCE.encode()).hexdigest())
                self.assertIn(GUID, row["asr_guids"])
                public_row = {key: row[key] for key in ("bytecode_hash", "decompiled_source", "asr_guids")}
                self.assertEqual(await self.public_source(public_row), SOURCE)
                self.assertNotIn("SYNTHETIC_BACKEND_SECRET", repr(writes))
                if kind == "asr":
                    self.assertEqual([row["script_count"] for table, row in writes if table == "asr_rules"], [1])

    async def test_all_importers_reject_intermediate_directory_links(self):
        outside_dir = self.base / "outside"
        outside_dir.mkdir()
        (outside_dir / "leak.lua").write_text(SECRET)
        for kind in ("direct", "extracted", "asr", "v2"):
            with self.subTest(importer=kind):
                root = self.base / kind
                directory = self.directory(root, kind)
                if kind == "asr":
                    directory.rmdir()
                    directory.symlink_to(outside_dir, target_is_directory=True)
                elif kind in ("extracted", "v2"):
                    directory.rmdir()
                    directory.symlink_to(outside_dir, target_is_directory=True)
                else:
                    (directory / "nested").symlink_to(outside_dir, target_is_directory=True)
                db, writes = self.database()
                await self.run_import(kind, root, db)
                self.assertEqual([row for table, row in writes if table == "lua_scripts"], [])
                self.assertNotIn("SYNTHETIC_BACKEND_SECRET", repr(writes))

    async def test_function_discovery_rejects_links_in_every_search_directory(self):
        function = 'IsRmmToolFilePath = function()\nreturn ipairs({"SAFE_ENTRY"})\nend\n'
        self.outside.write_text(function.replace("SAFE_ENTRY", "SYNTHETIC_BACKEND_SECRET"))
        root = self.base / "dataset"
        for name in ("lua", "asr", "lolbin"):
            directory = root / name
            directory.mkdir(parents=True)
            (directory / "leak.lua").symlink_to(self.outside)
            (directory / "normal.lua").write_text(function)
        db, _ = self.database()
        found = ExtractedImportService(db, str(root))._find_function_definition_scripts()
        self.assertEqual(found, {"IsRmmToolFilePath": ["SAFE_ENTRY"]})

    async def test_threat_metadata_uses_the_same_containment_boundary(self):
        self.outside.write_text("Signature ID: 0x123\n#ALF:SYNTHETIC_BACKEND_SECRET\n")
        root = self.base / "dataset"
        family = root / "threats" / "Example" / "Family"
        family.mkdir(parents=True)
        entry = family / "_combined.sig"
        entry.symlink_to(self.outside)
        db, writes = self.database()
        service = ExtractedImportService(db, str(root))
        stats = ExtractedImportStats()
        await service.import_threats(stats)
        self.assertEqual(writes, [])
        self.assertTrue(stats.errors)
        entry.unlink()
        entry.write_text("Signature ID: 0x123\n#ALF:Example:Family\nSignatures: 2\n")
        await service.import_threats(stats)
        self.assertEqual(writes[0][1]["threat_name"], "Example:Family")

    async def test_persistent_function_discovery_rejects_outside_links(self):
        function = 'IsRmmToolFilePath = function()\n{}[1] = "SAFE_ENTRY"\nend\n'
        self.outside.write_text(function.replace("SAFE_ENTRY", "SYNTHETIC_BACKEND_SECRET"))
        directory = self.base / "lua"
        directory.mkdir()
        (directory / "leak.lua").symlink_to(self.outside)
        db, writes = self.database()
        stats = await discover_functions_from_directory(db, directory)
        self.assertEqual(writes, [])
        self.assertEqual(stats, {"files_scanned": 0, "functions_found": 0, "errors": 1})
        (directory / "normal.lua").write_text(function)
        stats = await discover_functions_from_directory(db, directory)
        self.assertEqual(stats, {"files_scanned": 1, "functions_found": 1, "errors": 1})
        self.assertEqual(writes[0][1]["data_entries"], ["SAFE_ENTRY"])
        self.assertNotIn("SYNTHETIC_BACKEND_SECRET", repr(writes))


if __name__ == "__main__":
    unittest.main()
