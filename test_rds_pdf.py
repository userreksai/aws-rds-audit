from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from rds_pdf import render_account_pdf


def account_report(account="123456789012", rows=2):
    actors = []
    for number in range(rows):
        actors.append({"source_kind": "sql", "source_ip": f"2001:db8::{number + 1:x}",
                       "actor_type": "来源 IP", "counts": {"新增": 12, "删除": 1, "修改": 7, "其他操作": 0},
                       "failed": 2, "total": 22,
                       "sql": "MUST-NOT-RENDER SQL TEXT", "private": "AUTH-CODE-SECRET"})
    actors.append({"source_kind": "management", "source_ip": "203.0.113.25",
                   "counts": {"新增": 1, "删除": 0, "修改": 2, "其他操作": 0},
                   "failed": 0, "total": 3})
    return {"account_id": account, "account_name": "生产环境（离线示例）", "date": "2026-11-03",
            "timezone": "Asia/Shanghai", "generated_at": "2026-11-03T01:00:00Z", "demo": True,
            "window": {"start_inclusive": "2026-11-02T16:00:00Z", "end_exclusive": "2026-11-03T16:00:00Z"},
            "actors": actors, "complete": True, "coverage": {"unparsed_records": 0}, "errors": [],
            "SMTP_AUTH_CODE": "AUTH-CODE-SECRET", "events": [{"sql": "MUST-NOT-RENDER SQL TEXT"}]}


class PdfTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def extract(self, path):
        try:
            from pypdf import PdfReader
        except ImportError:
            self.skipTest("Optional PDF text QA requires pypdf")
        reader = PdfReader(path)
        return reader, "\n".join(page.extract_text() or "" for page in reader.pages)

    def test_account_summary_no_execution_or_secret_fields(self):
        path = render_account_pdf(account_report(), self.directory / "账号报告.pdf")
        self.assertTrue(path.read_bytes().startswith(b"%PDF-"))
        reader, text = self.extract(path)
        self.assertGreaterEqual(len(reader.pages), 1)
        for expected in ("123456789012", "2001:db8::1", "203.0.113.25", "SQL", "API", "语句次数", "事务最终提交"):
            self.assertIn(expected, text)
        self.assertNotIn("MUST-NOT-RENDER", text)
        self.assertNotIn("AUTH-CODE-SECRET", text)

    def test_accounts_do_not_mix_and_long_table_repeats_headers(self):
        report = account_report(account="210987654321", rows=90)
        report["actors"][0]["source_ip"] = "very-long-client-host-" * 10 + ".example.internal"
        report["actors"][0]["actor_type"] = "来源主机"
        path = render_account_pdf(report, self.directory / "many-ips.pdf")
        reader, text = self.extract(path)
        self.assertGreaterEqual(len(reader.pages), 4)
        self.assertNotIn("123456789012", text)
        self.assertIn("210987654321", text)
        for page in reader.pages[:-1]:
            self.assertIn("来源 IP / 主机", page.extract_text())

    def test_empty_incomplete_explains_missing_coverage(self):
        report = account_report()
        report.update(actors=[], complete=False, errors=[{"message": "SECRET-ERROR-SQL"}],
                      coverage={"unparsed_records": 3})
        path = render_account_pdf(report, self.directory / "incomplete.pdf")
        _, text = self.extract(path)
        self.assertIn("采集或解析不完整", text)
        self.assertIn("不能直接认定没有操作", text)
        self.assertNotIn("SECRET-ERROR-SQL", text)

    def test_bad_counts_and_missing_font_refused(self):
        report = account_report()
        report["actors"][0]["total"] = 999
        with self.assertRaises(ValueError):
            render_account_pdf(report, self.directory / "invalid.pdf")
        with self.assertRaises(ValueError):
            render_account_pdf(account_report(), self.directory / "invalid.pdf", str(self.directory / "missing.ttf"))
        self.assertFalse((self.directory / "invalid.pdf").exists())


if __name__ == "__main__":
    unittest.main()
