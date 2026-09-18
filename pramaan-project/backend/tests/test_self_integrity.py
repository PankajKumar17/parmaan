import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.core import self_integrity as integrity
from scripts.record_checksums import main as record_checksums


class SelfIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.baseline = self.root / "backend/checksums.json"
        self.source = self.root / "backend/app/core/detector.py"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("VALUE = 1\n", encoding="utf-8")
        self.config = self.root / "requirements.txt"
        self.config.write_text("numpy\n", encoding="utf-8")
        self.schema = self.root / "backend/app/manifests/schema.json"
        self.schema.parent.mkdir(parents=True)
        self.schema.write_text('{"type":"object"}\n', encoding="utf-8")
        self.addCleanup(self.reset_status)

    def reset_status(self):
        integrity._report = integrity.IntegrityReport()
        integrity.SELF_INTEGRITY_DEGRADED = True
        integrity.SELF_INTEGRITY_VERIFIED = False

    def record(self, *extra):
        with contextlib.redirect_stdout(io.StringIO()):
            return record_checksums(["--record", "--root", str(self.root), *extra])

    def check(self, require=False):
        return integrity.check_self_integrity(self.root, require=require)

    def write_document(self, document):
        self.baseline.write_text(json.dumps(document), encoding="utf-8")

    def test_missing_baseline_fails_closed_without_creating_one(self):
        self.assertTrue(self.check().degraded)
        with self.assertRaises(integrity.SelfIntegrityError) as caught:
            self.check(require=True)
        self.assertIs(caught.exception.report, integrity.get_integrity_status())
        self.assertTrue(integrity.SELF_INTEGRITY_DEGRADED)
        self.assertFalse(integrity.SELF_INTEGRITY_VERIFIED)
        self.assertFalse(self.baseline.exists())

    def test_explicit_cli_then_tampering_end_to_end(self):
        self.assertEqual(self.record(), 0)
        self.assertTrue(self.check(require=True).verified)
        self.assertFalse(integrity.SELF_INTEGRITY_DEGRADED)
        self.source.write_text("VALUE = 2\n", encoding="utf-8")
        with self.assertRaises(integrity.SelfIntegrityError) as caught:
            self.check(require=True)
        self.assertEqual(caught.exception.report.changed, ("backend/app/core/detector.py",))
        self.assertTrue(integrity.SELF_INTEGRITY_DEGRADED)
        self.assertFalse(integrity.SELF_INTEGRITY_VERIFIED)

    def test_source_schema_config_added_changed_and_deleted(self):
        self.record()
        self.config.write_text("numpy==2\n", encoding="utf-8")
        self.schema.unlink()
        (self.source.parent / "new.py").write_text("VALUE = 3\n", encoding="utf-8")
        report = self.check()
        self.assertEqual(report.changed, ("requirements.txt",))
        self.assertEqual(report.missing, ("backend/app/manifests/schema.json",))
        self.assertEqual(report.added, ("backend/app/core/new.py",))
        self.assertEqual(report.status, "DEGRADED/UNVERIFIED")

    def test_malformed_snapshots_never_verify(self):
        self.record()
        document = json.loads(self.baseline.read_text(encoding="utf-8"))
        malformed = [
            "", "{", "null", "[]", "42", '"text"',
            '{"version":1,"version":1,"algorithm":"sha256","files":{}}',
            json.dumps({**document, "version": True}),
            json.dumps({**document, "version": 2}),
            json.dumps({**document, "algorithm": "md5"}),
            json.dumps({**document, "files": {}}),
            json.dumps({**document, "files": []}),
            json.dumps({**document, "files": {"requirements.txt": None}}),
            json.dumps({**document, "files": {"requirements.txt": "x" * 64}}),
            json.dumps({**document, "extra": 1}),
            '{"version":1,"algorithm":"sha256","files":{"requirements.txt":"' + "0" * 64 + '","requirements.txt":"' + "0" * 64 + '"}}',
            "[" * 2000,
        ]
        for value in malformed:
            with self.subTest(value=value[:100]):
                self.baseline.write_text(value, encoding="utf-8")
                self.assertTrue(self.check().errors)
                with self.assertRaises(integrity.SelfIntegrityError):
                    self.check(require=True)
        self.baseline.write_bytes(b"\xff\xfe")
        self.assertTrue(self.check().errors)

    def test_unsafe_baseline_entries_are_rejected(self):
        paths = [
            "../outside.py", "/outside.py", "C:/outside.py", "C:outside.py",
            "backend/../../outside.py", "backend\\app\\core\\detector.py",
            "backend//app/core/detector.py", "./requirements.txt", "requirements.txt:stream",
            "backend/app/core/../core/detector.py", "bad\x00.py", "backend/checksums.json",
            "backend/tests/test.py", "backend./app/core/detector.py",
        ]
        for name in paths:
            with self.subTest(name=name):
                self.write_document({"version": 1, "algorithm": "sha256", "files": {name: "0" * 64}})
                self.assertTrue(self.check().errors)
                with self.assertRaises(integrity.SelfIntegrityError):
                    self.check(require=True)

    def test_environment_enforcement_and_invalid_boolean(self):
        for value in ["true", "TRUE", "1", " yes ", "on", "invalid"]:
            with self.subTest(value=value), patch.dict(os.environ, {"REQUIRE_SELF_INTEGRITY": value}):
                with self.assertRaises(integrity.SelfIntegrityError):
                    integrity.check_self_integrity(self.root)
        with patch.dict(os.environ, {"REQUIRE_SELF_INTEGRITY": "false"}):
            self.assertTrue(integrity.check_self_integrity(self.root).degraded)
        with self.assertRaises(integrity.SelfIntegrityError):
            integrity.check_self_integrity(self.root, require="false")

    def test_helper_is_deterministic_and_requires_explicit_overwrite(self):
        self.record()
        first = self.baseline.read_bytes()
        self.record("--force")
        self.assertEqual(first, self.baseline.read_bytes())
        document = json.loads(first)
        self.assertEqual(list(document["files"]), sorted(document["files"]))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            self.record()
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(first, self.baseline.read_bytes())
        self.baseline.unlink()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            record_checksums(["--root", str(self.root)])
        self.assertFalse(self.baseline.exists())

    def test_runtime_and_test_files_are_excluded_but_configuration_is_tracked(self):
        self.record()
        for relative in ["backend/artifacts/output.json", "backend/keys/key.json", "backend/tests/test.py", "backend/app/__pycache__/cached.py", ".venv/lib/package.py"]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("ignored", encoding="utf-8")
        self.assertTrue(self.check().verified)
        for relative in ["backend/.env", "backend/config/settings.yaml", "pyproject.toml", "backend/app/db/schema.sql", "backend/scripts/helper.py"]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("configuration", encoding="utf-8")
        self.assertEqual(len(self.check().added), 5)

    def test_unreadable_source_and_baseline_are_unverified(self):
        self.record()
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            self.assertTrue(self.check().errors)
        with patch.object(integrity, "collect_checksums", side_effect=PermissionError("denied")):
            with self.assertRaises(integrity.SelfIntegrityError):
                self.check(require=True)

    def test_invalid_root_and_empty_application_are_unverified(self):
        self.assertTrue(integrity.check_self_integrity(self.root / "missing", require=False).degraded)
        self.record()
        self.source.unlink()
        self.config.unlink()
        self.schema.unlink()
        self.assertTrue(self.check().degraded)

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.py"
            target.write_text("VALUE = 1\n", encoding="utf-8")
            link = self.source.parent / "linked.py"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic links unavailable")
            self.write_document({"version": 1, "algorithm": "sha256", "files": {"backend/app/core/linked.py": "0" * 64}})
            self.assertTrue(self.check().errors)
            with self.assertRaises(ValueError):
                integrity.collect_checksums(self.root)

    def test_cli_runs_from_unrelated_working_directory(self):
        script = Path(__file__).resolve().parents[1] / "scripts/record_checksums.py"
        result = subprocess.run(
            [sys.executable, "-B", str(script), "--record", "--root", str(self.root)],
            cwd=self.root, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.check(require=True).verified)


if __name__ == "__main__":
    unittest.main()
