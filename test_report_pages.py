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
        self.assertIn("共 5000 条明细", markup)

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
