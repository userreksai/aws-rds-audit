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
    def test_overview_size_stays_bounded_and_contains_no_eager_dataset(self):
        small, large = fixture(25), fixture(5000)
        markup = pages.generate_overview(large)
        self.assertLess(len(markup.encode()), 100000)
        self.assertLess(abs(len(markup) - len(pages.generate_overview(small))), 2000)
        self.assertEqual(markup.count("data-event-index="), pages.PREVIEW_SIZE)
        self.assertNotIn("EVT-004999", markup)
        self.assertNotIn("daily-report.json\"", markup)
        self.assertNotIn("<script", markup)
        self.assertIn("<style>", markup)
        self.assertIn('href="rds-report.css?v=', markup)
        self.assertIn("更多记录（共 5000 条）", markup)

    def test_overview_removes_requested_copy_and_top_navigation(self):
        markup = pages.generate_overview(fixture(1851))
        for removed in ("统计全量已识别的增删改记录", "全部增删改明细", "失败请求</a>", "全部操作者</a>", "下载完整报告包 ZIP", "本页为轻量总览", "原始 JSON/SQL 归档不会自动加载到浏览器"):
            self.assertNotIn(removed, markup)
        self.assertNotIn('class="report-nav"', markup)
        self.assertIn("更多记录（共 1851 条）", markup)
        self.assertIn("按来源汇总", markup)
        self.assertIn("按操作者汇总", markup)

    def test_current_record_sql_and_identity_expand_without_another_file(self):
        report = fixture(1)
        statement = "UPDATE example SET value='" + "v" * 300 + "' WHERE id=71829"
        report["events"][0].update(description=statement, sql=statement,
                                   identity={"username": "audit-operator", "connection_id": "connection-71829"},
                                   parameters={"schema": "business-schema"})
        markup = pages.generate_overview(report)
        parsed = ReportMarkup()
        parsed.feed(markup)
        operation = [item for item in parsed.details if "operation-details" in item["classes"]]
        self.assertEqual(len(operation), 1)
        self.assertIn(statement, operation[0]["text"])
        self.assertIn("audit-operator", operation[0]["text"])
        self.assertIn("connection-71829", operation[0]["text"])
        self.assertIn("business-schema", operation[0]["text"])
        self.assertNotIn("查看该条完整展示", markup)
        self.assertNotIn("events-000001.html#event-", markup)

    def test_summary_numeric_headers_align_with_their_cells_and_actor_context_is_collapsible(self):
        report = fixture(1)
        actor_key = "sql:/aws/rds/cluster/example/audit:" + "very-long-instance-context-" * 15
        report["actors"][0]["actor_key"] = actor_key
        markup = pages.generate_overview(report)
        parsed = ReportMarkup()
        parsed.feed(markup)
        expected = (("source-summary", 1), ("actor-summary", 2))
        for table_class, first_numeric in expected:
            table = next(item for item in parsed.tables if table_class in item["classes"])
            self.assertIn("summary-table", table["classes"])
            headings = table["rows"][0]
            self.assertEqual(len(headings) - first_numeric, 5)
            for column in range(first_numeric, len(headings)):
                self.assertEqual(headings[column]["tag"], "th")
                self.assertIn("number", headings[column]["classes"])
                for row in table["rows"][1:]:
                    self.assertEqual(len(row), len(headings))
                    self.assertIn("number", row[column]["classes"])
        contexts = [item for item in parsed.details if "actor-details" in item["classes"]]
        self.assertEqual(len(contexts), 1)
        self.assertIn("sql:/aws/rds/cluster/example/audit:", contexts[0]["text"])
        self.assertIn("<colgroup>", markup)

    def test_more_actor_navigation_only_appears_when_overview_is_truncated(self):
        self.assertNotIn("更多操作者", pages.generate_overview(fixture(20, actor_count=20)))
        self.assertIn("更多操作者", pages.generate_overview(fixture(101, actor_count=101)))

    def test_every_event_has_one_canonical_record_and_all_local_links_resolve(self):
        report = fixture(251)
        expected_counts = deepcopy(report["metadata"]["counts"])
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            main = pages.write_paginated_report(report, directory)
            artifacts = report["artifacts"]
            self.assertEqual(artifacts["detail_pages"], 3)
            detail = directory / artifacts["detail_directory"]
            ids = []
            for path in sorted(detail.glob("events-*.html")):
                parsed = Links()
                parsed.feed(path.read_text(encoding="utf-8"))
                self.assertLessEqual(parsed.records, pages.PAGE_SIZE)
                ids += [value for value in parsed.ids if value.startswith("event-")]
            self.assertEqual(ids, [f"event-{index + 1:06d}" for index in range(251)])
            for path in [main, *detail.glob("*.html")]:
                parsed = Links()
                parsed.feed(path.read_text(encoding="utf-8"))
                for link in parsed.hrefs:
                    parts = urlsplit(link)
                    self.assertFalse(parts.scheme)
                    target = (path.parent / unquote(parts.path)).resolve()
                    self.assertTrue(target.is_relative_to(directory.resolve()))
                    self.assertTrue(target.exists(), (path.name, link))
                    if parts.fragment:
                        target_html = target.read_text(encoding="utf-8")
                        self.assertIn(f'id="{parts.fragment}"', target_html)
            self.assertEqual(report["metadata"]["counts"], expected_counts)
            normalized = json.loads((directory / "daily-report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(normalized["events"]), 251)
            with ZipFile(directory / artifacts["bundle_filename"]) as archive:
                self.assertIsNone(archive.testzip())
                self.assertIn(main.name, archive.namelist())
                self.assertNotIn("daily-report.json", archive.namelist())
                self.assertFalse(any(name.endswith(".jsonl") for name in archive.namelist()))

    def test_xss_is_escaped_and_very_large_fields_do_not_expand_pages_without_limit(self):
        report = fixture(1)
        row = report["events"][0]
        row["description"] = "UPDATE t SET value='<script>attack()</script>' " + "x" * 200000
        row["source_ip"] = "<img src=x onerror=attack()>"
        row["parameters"] = {"password": "DO-NOT-SHOW", "large": "p" * 200000}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            main = pages.write_paginated_report(report, directory)
            child = directory / report["artifacts"]["detail_directory"] / "events-000001.html"
            for path in (main, child):
                markup = path.read_text(encoding="utf-8")
                self.assertNotIn("<script>", markup)
                self.assertNotIn("<img ", markup)
                self.assertNotIn("DO-NOT-SHOW", markup)
                self.assertIn("&lt;script&gt;", markup)
                self.assertIn("展示已截断", markup)
                self.assertLess(path.stat().st_size, 100000)
            self.assertIn("x" * 50000, (directory / "daily-report.json").read_text(encoding="utf-8"))

    def test_large_issue_lists_are_paginated_and_absent_from_overview(self):
        report = fixture(0)
        report["metadata"]["complete"] = False
        report["metadata"]["errors"] = [{"message": f"ISSUE-{index:04d}"} for index in range(201)]
        report["unparsed"] = [{"raw": f"UNKNOWN-RAW-{index:04d}"} for index in range(201)]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            main = pages.write_paginated_report(report, directory)
            overview = main.read_text(encoding="utf-8")
            self.assertNotIn("UNKNOWN-RAW-0200", overview)
            self.assertNotIn("ISSUE-0200", overview)
            detail = directory / report["artifacts"]["detail_directory"]
            for prefix, marker in (("errors", "ISSUE-0200"), ("unparsed", "UNKNOWN-RAW-0200")):
                files = sorted(detail.glob(prefix + "-*.html"))
                self.assertEqual(len(files), 3)
                self.assertTrue(all(path.read_text(encoding="utf-8").count('class="error-item"') <= 100 for path in files))
                self.assertIn(marker, files[-1].read_text(encoding="utf-8"))

    def test_same_data_reuses_asset_directory_despite_new_generated_timestamp(self):
        report = fixture(2)
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
