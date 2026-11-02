"""Bounded static-page checks; no AWS, browser, or network is needed."""
from collections import defaultdict
from copy import deepcopy
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import unquote, urlsplit
from zipfile import ZipFile

import rds_report_pages as pages


def fixture(count=251, actor_count=7):
    events, actors = [], {}
    counts = {key: 0 for key in ("新增", "删除", "修改", "其他操作")}
    failed = 0
    for index in range(count):
        key = "sql:instance-" + str(index % actor_count)
        category = ("新增", "删除", "修改")[index % 3]
        failure = index % 17 == 0
        failed += failure
        if not failure:
            counts[category] += 1
        actor = actors.setdefault(key, {"actor": "user-" + str(index % actor_count), "actor_key": key, "actor_type": "数据库账号", "source_kind": "sql", "counts": {key: 0 for key in counts}, "failed": 0, "total": 0})
        actor["total"] += 1
        actor["failed"] += failure
        if not failure:
            actor["counts"][category] += 1
        events.append({
            "event_id": f"EVT-{index:06d}", "source_kind": "sql", "source": "mysql.audit", "actor_key": key,
            "actor": actor["actor"], "actor_type": "数据库账号", "category": category,
            "status": "failed" if failure else "success", "counted": not failure,
            "time_utc": "2026-10-29T01:00:00Z", "time_local": "2026-10-29 09:00:00",
            "event_name": "QUERY", "description": f"UPDATE example SET value=1 WHERE id={index}",
            "sql": f"UPDATE example SET value=1 WHERE id={index}", "source_ip": "203.0.113.10", "region": "ap-east-1",
            "resources": ["test-instance", "数据库：example"], "result": "失败：权限不足" if failure else "返回码 0（不证明事务提交）",
            "identity": {"username": actor["actor"], "query_id": str(index)}, "parameters": None, "response": None,
        })
    return {
        "metadata": {"audit_date": "2026-10-29", "account_id": "123456789012", "generated_at": "2026-10-29T02:00:00Z", "window_start_utc": "2026-10-28T00:00:00Z", "window_end_utc_exclusive": "2026-10-29T02:00:00Z", "period_kind": "custom", "period_label": "自定义时间窗口", "report_filename": "2026-10-29-rds操作审计-自定义窗口.html", "complete": True, "offline": True, "counts": counts, "total": count, "counted_total": sum(counts.values()), "failed_or_partial": failed, "errors": []},
        "events": events, "actors": list(actors.values()),
        "by_source": {"management": {"label": "RDS 管理 API", "counts": dict.fromkeys(counts, 0), "failed": 0, "total": 0}, "sql": {"label": "数据库 SQL 审计", "counts": counts, "failed": failed, "total": count}},
        "coverage": {"notes": ["仅显示增删改；失败请求单独标识。"], "unparsed_records": 0}, "unparsed": [],
    }


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.ids = []
        self.records = 0

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if "href" in attributes:
            self.hrefs.append(attributes["href"])
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if "record" in attributes.get("class", "").split():
            self.records += 1


class ReportMarkup(HTMLParser):
    """Inspect related header/cell semantics and native expandable content."""
    def __init__(self):
        super().__init__()
        self.tables = []
        self.details = []
        self._table = self._row = self._cell = None
        self._open_details = []

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "table":
            self._table = {"classes": attributes.get("class", "").split(), "rows": []}
            self.tables.append(self._table)
        elif tag == "tr" and self._table is not None:
            self._row = []
            self._table["rows"].append(self._row)
        elif tag in {"th", "td"} and self._row is not None:
            self._cell = {"tag": tag, "classes": attributes.get("class", "").split(), "text": ""}
            self._row.append(self._cell)
        elif tag == "details":
            detail = {"classes": attributes.get("class", "").split(), "text": ""}
            self.details.append(detail)
            self._open_details.append(detail)

    def handle_endtag(self, tag):
        if tag == "table":
            self._table = self._row = self._cell = None
        elif tag == "tr":
            self._row = self._cell = None
        elif tag in {"th", "td"}:
            self._cell = None
        elif tag == "details":
            self._open_details.pop()

    def handle_data(self, data):
        if self._cell is not None:
            self._cell["text"] += data
        for detail in self._open_details:
            detail["text"] += data


class LightweightPagesTests(unittest.TestCase):
    def test_overview_size_depends_on_users_not_statement_volume(self):
        small, large = fixture(25), fixture(5000)
        markup = pages.generate_overview(large)
        self.assertLess(len(markup.encode()), 30000)
        self.assertLess(abs(len(markup) - len(pages.generate_overview(small))), 2000)
        for forbidden in ("data-event-index=", "EVT-004999", "UPDATE example", "operation-details", "更多记录", "增删改操作明细", "<script"):
            self.assertNotIn(forbidden, markup)
        self.assertIn("按来源汇总", markup)
        self.assertIn("按操作者汇总", markup)
        self.assertIn("<style>", markup)

    def test_only_user_totals_are_exported_even_for_legacy_models(self):
        report = fixture(1)
        report["events"][0].update(sql="SECRET_SQL_TEXT", parameters={"password": "NEVER_EXPORT"})
        report["actors"][0]["contexts"] = [{"database": "PRIVATE_DATABASE"}]
        report["metadata"]["errors"] = [{"message": "PRIVATE_ERROR_SQL"}]
        report["unparsed"] = [{"raw": "UNKNOWN_RAW_SQL"}]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            main = pages.write_paginated_report(report, directory)
            stored = json.loads((directory / "daily-report.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["events"], [])
            self.assertEqual(stored["unparsed"], [])
            self.assertNotIn("contexts", stored["actors"][0])
            for path in directory.glob("*"):
                if path.suffix in {".json", ".html"}:
                    text = path.read_text(encoding="utf-8")
                    for value in ("SECRET_SQL_TEXT", "NEVER_EXPORT", "PRIVATE_DATABASE", "PRIVATE_ERROR_SQL", "UNKNOWN_RAW_SQL"):
                        self.assertNotIn(value, text)
            self.assertEqual(report["artifacts"]["detail_pages"], 0)
            self.assertEqual(len(list(directory.glob("*.html"))), 1)
            with ZipFile(directory / report["artifacts"]["bundle_filename"]) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(set(archive.namelist()), {main.name, "rds-report.css"})

    def test_summary_numeric_headers_align_with_their_cells(self):
        parsed = ReportMarkup()
        parsed.feed(pages.generate_overview(fixture(3)))
        for table_class, first_numeric in (("source-summary", 1), ("actor-summary", 2)):
            table = next(item for item in parsed.tables if table_class in item["classes"])
            headings = table["rows"][0]
            for row in table["rows"]:
                self.assertEqual(len(row), len(headings))
                for cell in row[first_numeric:]:
                    self.assertIn("number", cell["classes"])
        self.assertEqual(parsed.details, [])

    def test_more_actor_navigation_only_appears_when_overview_is_truncated(self):
        self.assertNotIn("更多操作者", pages.generate_overview(fixture(20, actor_count=20)))
        self.assertIn("更多操作者", pages.generate_overview(fixture(101, actor_count=101)))

    def test_user_pages_are_bounded_and_all_local_links_resolve(self):
        report = fixture(251, actor_count=251)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            main = pages.write_paginated_report(report, directory)
            detail = directory / report["artifacts"]["detail_directory"]
            children = sorted(detail.glob("*.html"))
            self.assertEqual(len(children), 3)
            for path in [main, *children]:
                markup = path.read_text(encoding="utf-8")
                parsed = Links()
                parsed.feed(markup)
                self.assertEqual(parsed.records, 0)
                for forbidden in ("UPDATE example", "EVT-", "operation-details", "events-", "failed-", "unparsed-"):
                    self.assertNotIn(forbidden, markup)
                tables = ReportMarkup()
                tables.feed(markup)
                users = next(table for table in tables.tables if "actor-summary" in table["classes"])
                self.assertLessEqual(len(users["rows"])-1, pages.PAGE_SIZE)
                for link in parsed.hrefs:
                    parts = urlsplit(link)
                    self.assertFalse(parts.scheme)
                    target = (path.parent / unquote(parts.path)).resolve()
                    self.assertTrue(target.is_relative_to(directory.resolve()))
                    self.assertTrue(target.is_file(), (path.name, link))

    def test_actor_xss_is_escaped_and_operation_fields_are_absent(self):
        report = fixture(1)
        report["actors"][0]["actor"] = "<script>attack()</script>"
        report["events"][0].update(description="q" * 200000, source_ip="<img src=x onerror=attack()>")
        markup = pages.generate_overview(report)
        self.assertIn("&lt;script&gt;", markup)
        self.assertNotIn("<script>", markup)
        self.assertNotIn("<img ", markup)
        self.assertNotIn("q" * 1000, markup)
        self.assertLess(len(markup.encode()), 30000)

    def test_incomplete_summary_shows_quality_counter_without_raw_evidence(self):
        report = fixture(0)
        report["metadata"]["complete"] = False
        report["coverage"]["unparsed_records"] = 100000000
        report["metadata"]["errors"] = [{"message": "PRIVATE_SQL"}]
        report["unparsed"] = [{"raw": "RAW_SQL"}]
        markup = pages.generate_overview(report)
        self.assertIn("当前汇总不完整", markup)
        self.assertIn("100000000", markup)
        self.assertNotIn("PRIVATE_SQL", markup)
        self.assertNotIn("RAW_SQL", markup)

    def test_same_summary_reuses_asset_directory_despite_new_timestamp(self):
        report = fixture(101, actor_count=101)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            pages.write_paginated_report(report, directory)
            original = report["artifacts"]["detail_directory"]
            report["metadata"]["generated_at"] = "2026-10-29T03:00:00Z"
            pages.write_paginated_report(report, directory)
            self.assertEqual(report["artifacts"]["detail_directory"], original)
            self.assertEqual([path.name for path in directory.iterdir() if path.is_dir()], [original])


if __name__ == "__main__":
    unittest.main()
