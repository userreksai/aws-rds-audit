"""Mail body contract, escaped metadata and SQL/API source-IP separation."""
from copy import deepcopy
from html import unescape
import re
import unittest

from rds_mail_summary import message_body, message_body_html


def row(source="sql", ip="192.0.2.10", *, added=2, deleted=1, modified=3, failed=1, other=0):
    return {"source_kind": source, "source_ip": ip, "actor": "PRIVATE RAW SQL ACTOR",
            "counts": {"新增": added, "删除": deleted, "修改": modified, "其他操作": other},
            "failed": failed, "total": added + deleted + modified + other + failed,
            "sql": "PRIVATE SQL MUST NOT RENDER"}


class MailSummaryTests(unittest.TestCase):
    def setUp(self):
        self.config = {"TIMEZONE": "Asia/Shanghai", "ACCOUNTS": [
            {"NAME": "test", "ACCOUNT_ID": "796973492024", "TAG": "测试账号"}]}
        self.report = {"account_id": "796973492024", "account_name": "test", "complete": True,
                       "window": {"start_inclusive": "2026-11-05T02:00:00Z", "end_exclusive": "2026-11-06T02:00:00Z"},
                       "actors": [row(), row("management", "2001:db8::22", added=0, deleted=0, modified=2, failed=0)],
                       "errors": [{"message": "PRIVATE ERROR MUST NOT RENDER"}],
                       "secret": "PRIVATE SECRET MUST NOT RENDER"}

    def test_requested_intro_and_separate_source_tables_are_in_plain_and_html(self):
        intro = ("各位领导和同事好：\nRDS 来源 IP 审计汇总\n查询范围（北京时间，结束时刻不含）：\n"
                 "2026-11-05 10:00:00 至 2026-11-06 10:00:00\n账号总数：1\n账号信息：测试账号-796973492024")
        text = message_body(self.config, [self.report])
        html = message_body_html(self.config, [self.report])
        self.assertTrue(text.startswith(intro))
        self.assertIn(intro.replace("\n", "<br>\n"), html)
        self.assertIn("192.0.2.10 | 2 | 1 | 3 | 1 | 0 | 7", text)
        self.assertIn("2001:db8::22 | 0 | 0 | 2 | 0 | 0 | 2", text)
        self.assertEqual(html.count("<table "), 2)
        self.assertIn("数据库内部 SQL（语句次数）", html)
        self.assertIn("RDS 管理 API（调用次数）", html)
        self.assertNotIn("PRIVATE", text + html)

    def test_blank_tag_falls_back_to_existing_name_and_all_accounts_keep_their_status(self):
        self.config["ACCOUNTS"][0]["TAG"] = ""
        second = deepcopy(self.report)
        second.update(account_id="000000000002", account_name="staging", complete=False, actors=[])
        text = message_body(self.config, [self.report, second])
        html = message_body_html(self.config, [self.report, second])
        self.assertIn("账号总数：2\n账号信息：test-796973492024\nstaging-000000000002", text)
        self.assertIn("staging-000000000002：数据不完整", text)
        self.assertIn("本窗口未取得可计数记录", html)
        self.assertNotIn("无操作", text)

    def test_tags_are_escaped_and_mail_tables_use_no_raw_actor_or_error(self):
        self.config["ACCOUNTS"][0]["TAG"] = '<测试 & "标签">|'
        html = message_body_html(self.config, [self.report])
        text = message_body(self.config, [self.report])
        self.assertIn('&lt;测试 &amp; &quot;标签&quot;&gt;|', html)
        self.assertNotIn('<测试', html)
        self.assertIn('<测试 & "标签">|-796973492024', text)
        self.assertNotIn("PRIVATE", text + html)

    def test_beijing_display_is_independent_of_configured_or_host_timezone(self):
        self.config["TIMEZONE"] = "UTC"
        self.assertIn("2026-11-05 10:00:00 至 2026-11-06 10:00:00", message_body(self.config, [self.report]))

    def test_invalid_or_mismatched_windows_are_rejected(self):
        for replacement in ({}, {"start_inclusive": "invalid", "end_exclusive": "invalid"},
                            {"start_inclusive": "2026-11-05T10:00:00", "end_exclusive": "2026-11-06T10:00:00"},
                            {"start_inclusive": "2026-11-06T02:00:00Z", "end_exclusive": "2026-11-05T02:00:00Z"}):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                message_body(self.config, [{**self.report, "window": replacement}])
        other = deepcopy(self.report)
        other["window"]["end_exclusive"] = "2026-11-07T02:00:00Z"
        with self.assertRaisesRegex(ValueError, "相同统计窗口"):
            message_body_html(self.config, [self.report, other])

    def test_invalid_counts_or_non_ip_sources_are_rejected(self):
        for changes in ({"source_ip": "database.internal"}, {"source_kind": "unexpected"},
                        {"failed": True}, {"total": -1}, {"total": 100}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                message_body(self.config, [{**self.report, "actors": [{**row(), **changes}]}])

    def test_sorted_rows_and_other_column_do_not_mix_failures_into_changes(self):
        report = {**self.report, "actors": [row(added=0, deleted=0, modified=0, failed=1),
                                            row(ip="2001:db8::1", added=0, deleted=0, modified=0, failed=0, other=9)]}
        text = message_body(self.config, [report])
        self.assertIn("192.0.2.10 | 0 | 0 | 0 | 1 | 0 | 1", text)
        self.assertIn("2001:db8::1 | 0 | 0 | 0 | 0 | 9 | 9", text)
        self.assertLess(text.index("2001:db8::1"), text.index("192.0.2.10"))

    def test_html_and_plain_tables_contain_identical_summary_numbers(self):
        text = message_body(self.config, [self.report])
        html = message_body_html(self.config, [self.report])
        plain_rows = [line.split(" | ") for line in text.splitlines() if re.match(r"(?:[0-9]+\.|2001:)", line)]
        html_rows = [re.findall(r"<td[^>]*>(.*?)</td>", match) for match in re.findall(r"<tr>(.*?)</tr>", html)]
        html_rows = [[unescape(value) for value in values] for values in html_rows if values]
        self.assertEqual(plain_rows, html_rows)


if __name__ == "__main__":
    unittest.main()
