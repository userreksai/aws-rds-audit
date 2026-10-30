"""Publish complete web assets under index/ without exposing raw archives."""
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

import rds_audit as audit
from test_report_pages import Links


class IndexPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.project = Path(self.temporary.name) / "project"
        self.project.mkdir()
        self.source = self.project / "reports/private"
        shutil.copytree(Path(__file__).parent / "examples/daily-sample", self.source)
        self.web = self.project / "index"
        self.root_patch = patch.object(audit, "PROJECT_ROOT", self.project)
        self.default_patch = patch.object(audit, "DEFAULT_PUBLISH_DIR", self.web)
        self.root_patch.start()
        self.default_patch.start()

    def tearDown(self):
        self.default_patch.stop()
        self.root_patch.stop()
        self.temporary.cleanup()

    def run_offline(self, *extra):
        with patch.object(audit, "aws_session", side_effect=AssertionError("offline publication must not query AWS")), redirect_stdout(io.StringIO()):
            result = audit.main(["--input-dir", str(self.source), *extra])
        self.assertIn(result, (0, 2))

    def test_default_site_contains_index_and_all_working_page_assets(self):
        raw = (self.source / "report.json").read_bytes()
        self.run_offline()
        report = json.loads((self.source / "daily-report.json").read_text(encoding="utf-8"))
        self.assertEqual((self.web / "index.html").read_bytes(), (self.web / report["metadata"]["report_filename"]).read_bytes())
        self.assertFalse((self.web / "index.htm").exists())
        for relative in report["artifacts"]["manifest"]:
            self.assertTrue((self.web / relative).is_file(), relative)
        for page in self.web.rglob("*.html"):
            parsed = Links()
            parsed.feed(page.read_text(encoding="utf-8"))
            for link in parsed.hrefs:
                target = (page.parent / unquote(urlsplit(link).path)).resolve()
                self.assertTrue(target.exists(), (page.name, link))
        self.assertFalse(list(self.web.rglob("*.json")))
        self.assertFalse(list(self.web.rglob("*.jsonl")))
        self.assertEqual((self.source / "report.json").read_bytes(), raw)

    @unittest.skipUnless(os.name == "posix", "Linux directory permission check")
    def test_private_service_umask_does_not_block_nginx_site(self):
        self.project.chmod(0o750)
        self.source.chmod(0o750)
        (self.source / "report.json").chmod(0o600)
        previous = os.umask(0o027)
        try:
            self.run_offline()
        finally:
            os.umask(previous)
        self.assertTrue(stat.S_IMODE(self.project.stat().st_mode) & 0o001)
        self.assertEqual(stat.S_IMODE(self.web.stat().st_mode), 0o755)
        for path in self.web.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755 if path.is_dir() else 0o644)
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.source / "report.json").stat().st_mode), 0o600)

    def test_no_publish_keeps_a_manual_report_private(self):
        self.run_offline("--no-publish")
        self.assertFalse(self.web.exists())
        self.assertTrue(list(self.source.glob("*.html")))

    def test_preflight_has_no_publication_side_effect(self):
        with patch.object(audit, "check_configuration", return_value=0):
            self.assertEqual(audit.main(["--check-config"]), 0)
        self.assertFalse(self.web.exists())

    def test_default_query_window_still_works_with_default_publication(self):
        now = datetime(2026, 10, 30, 3, tzinfo=timezone.utc)
        options = audit.build_parser().parse_args([])
        kind, _, start, end = audit.resolve_report_window(options, now)
        self.assertEqual((kind, end - start, end), ("custom", timedelta(days=7), now))
        self.assertEqual(options.publish_dir, self.web)


if __name__ == "__main__":
    unittest.main()
