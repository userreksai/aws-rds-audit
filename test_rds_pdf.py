from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from rds_pdf import FRESH_LOG_NOTE, render_account_pdf


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

    def test_yesterday_to_now_range_has_explicit_label_real_window_and_fixed_delay_note(self):
        report = account_report()
        report.update(report_kind="since_yesterday", date="2026-11-03",
                      generated_at="2026-11-03T05:17:29Z",
                      fresh_log_note="DO-NOT-RENDER SQL-ERROR-CONTENT")
        report["window"] = {"start_inclusive": "2026-11-01T16:00:00Z",
                            "end_exclusive": "2026-11-03T05:17:29Z"}
        path = render_account_pdf(report, self.directory / "yesterday-to-now.pdf")
        _, text = self.extract(path)
        self.assertIn("昨日到当前", text)
        self.assertIn("截止日期 2026-11-03", text)
        self.assertIn("2026-11-02 00:00:00", text)
        self.assertIn("2026-11-03 13:17:29", text)
        self.assertIn(FRESH_LOG_NOTE, text)
        self.assertNotIn("DO-NOT-RENDER", text)
        self.assertNotIn("MUST-NOT-RENDER", text)
        self.assertNotIn("AUTH-CODE-SECRET", text)

    def test_yesterday_to_now_keeps_incomplete_status_and_ordinary_daily_pdf_unchanged(self):
        report = account_report()
        report.update(report_kind="since_yesterday", complete=False,
                      errors=[{"message": "UNSAFE-PROVIDER-TEXT"}])
        _, ranged_text = self.extract(render_account_pdf(report, self.directory / "range-incomplete.pdf"))
        self.assertIn("采集或解析不完整", ranged_text)
        self.assertNotIn("UNSAFE-PROVIDER-TEXT", ranged_text)
        _, daily_text = self.extract(render_account_pdf(account_report(), self.directory / "daily.pdf"))
        self.assertIn("AWS RDS 来源 IP 审计汇总", daily_text)
        self.assertIn("报表日期 2026-11-03", daily_text)
        self.assertNotIn("昨日到当前", daily_text)
        self.assertNotIn(FRESH_LOG_NOTE, daily_text)
        self.assertNotIn("仅统计有效来源", daily_text)

    def test_ip_only_scope_explains_filtered_sources_and_keeps_quality_failure(self):
        for selector in ({"schema_version": 3}, {"scope": {"source_filter": "ip_only"}}):
            with self.subTest(selector=selector):
                report = account_report()
                report.update(selector)
                report.update(report_kind="since_yesterday", complete=False,
                              coverage={"unparsed_records": 2, "filtered_no_ip_records": 17,
                                        "source_unreadable_records": 2},
                              errors=[{"message": "DO-NOT-RENDER-PROVIDER-ERROR"}])
                path = render_account_pdf(report, self.directory / "ip-only.pdf")
                _, text = self.extract(path)
                self.assertIn("仅统计有效来源 IPv4/IPv6", text)
                self.assertIn("无 IP 已排除 17 条", text)
                self.assertIn("无法读取来源 2 条仍属质量问题", text)
                self.assertNotIn("来源 IP / 主机", text)
                self.assertNotIn("非 IP 主机名及未知来源单独标识", text)
                self.assertIn("采集或解析不完整", text)
                self.assertIn("未解析 / 未分类记录 2 条", text)
                self.assertNotIn("DO-NOT-RENDER", text)


if __name__ == "__main__":
    unittest.main()
