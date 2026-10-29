"""Offline evidence/counting/security checks for the RDS HTML report."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import rds_report as report

UTC = timezone.utc
START = datetime(2026, 10, 27, 23, tzinfo=UTC)  # Beijing yesterday 07:00.
END = START + timedelta(hours=25)
WHEN = START + timedelta(hours=1)


def management(event_id="m1", name="CreateDBInstance", **extra):
    event = {
        "eventID": event_id, "eventName": name, "eventTime": report.iso(WHEN),
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/ops/session-123", "principalId": "role:session-123"},
        "requestParameters": {"dBInstanceIdentifier": "db-prod", "masterUserPassword": "NEVER_SHOW"},
        "sourceIPAddress": "192.0.2.10", "awsRegion": "ap-southeast-1",
    }
    event.update(extra)
    return {"region": "ap-southeast-1", "event": event, "lookup": {}}


def audit_event(sql="UPDATE users SET enabled=1 WHERE id=2", *, event_id="s1", stream="db-writer", operation="QUERY", code=0, aurora=True, connection_type=None, when=WHEN):
    stamp = str(int(when.timestamp() * 1000000)) if aurora else when.strftime("%Y%m%d %H:%M:%S")
    message = f"{stamp},db-writer,app_user,192.0.2.22,99,23,{operation},app,'{sql}',{code}"
    if connection_type:
        message += "," + connection_type
    return {"region": "ap-southeast-1", "logGroupName": "/aws/rds/cluster/prod/audit", "logStreamName": stream, "timestamp": int(when.timestamp() * 1000), "eventId": event_id, "message": message}


class ReportFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        (self.directory / "cloudwatch").mkdir()
        self.collection = {"identity": {"Account": "123456789012"}, "checks": [], "collection_status": "ok", "sql_log_download_requested": True}
        self.save([], [])

    def tearDown(self):
        self.temporary.cleanup()

    def save(self, management_rows, sql_rows):
        (self.directory / "report.json").write_text(json.dumps(self.collection), encoding="utf-8")
        for filename, rows in (("management-events.jsonl", management_rows), ("cloudwatch/audit.jsonl", sql_rows)):
            (self.directory / filename).write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")

    def build(self):
        return report.build_daily_report(self.directory, audit_date="2026-10-29", start=START, end=END)

    def test_successful_changes_and_failed_attempts_have_distinct_counts(self):
        self.save([
            management("a", "CreateDBInstance"),
            management("b", "DeleteDBInstance", errorCode="AccessDenied", errorMessage="denied"),
            management("c", "ModifyDBInstance"),
        ], [audit_event("INSERT INTO t VALUES (1)"), audit_event("DELETE FROM t", event_id="s2", code=1142)])
        result = self.build()
        meta = result["metadata"]
        self.assertEqual(meta["counts"], {"新增": 2, "删除": 0, "修改": 1, "其他操作": 0})
        self.assertEqual(meta["source_counts"]["management"]["新增"], 1)
        self.assertEqual(meta["source_counts"]["sql"]["新增"], 1)
        self.assertEqual(meta["total"], 5)
        self.assertEqual(meta["failed_or_partial"], 2)
        self.assertEqual(meta["counted_total"], 3)
        self.assertEqual(meta["attempted_counts"]["删除"], 2)
        self.assertEqual(sum(item["total"] for item in result["actors"]), 5)
        self.assertTrue(all("COMMIT" not in row["result"] for row in result["events"]))
        sql_row = next(row for row in result["events"] if row["source_kind"] == "sql" and row["event_id"] == "s1:0")
        self.assertIn("不证明事务提交", sql_row["result"])

    def test_management_event_id_deduplicates_across_envelopes_and_keeps_read_calls(self):
        event = management("same", "DescribeDBInstances", readOnly=True)
        self.save([event, {**event, "region": "us-east-1"}], [])
        result = self.build()
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["metadata"]["counts"]["其他操作"], 1)
        self.assertEqual(result["metadata"]["counts"]["新增"], 0)
        self.assertEqual(result["events"][0]["actor"], "ops/session-123")

    def test_sql_event_id_dedup_does_not_merge_different_streams(self):
        event = audit_event()
        self.save([], [event, event, {**event, "logStreamName": "db-reader"}])
        result = self.build()
        self.assertEqual(result["metadata"]["counts"]["修改"], 2)
        self.assertEqual(result["coverage"]["duplicate_cloudwatch_events"], 1)
        self.assertEqual(len(result["actors"]), 2)

    def test_general_log_is_preserved_in_collection_but_not_double_counted(self):
        audit = audit_event()
        general = {**audit, "logGroupName": "/aws/rds/cluster/prod/general", "eventId": "g1", "message": "42 Query UPDATE users SET enabled=1"}
        self.save([], [audit, general])
        result = self.build()
        self.assertEqual(result["metadata"]["counts"]["修改"], 1)
        self.assertEqual(result["coverage"]["general_log_events_not_counted"], 1)

    def test_half_open_window_applies_to_management_and_audit_record_timestamp(self):
        self.save([management("at-end", eventTime=report.iso(END))], [audit_event(when=START), audit_event(event_id="end", when=END)])
        result = self.build()
        self.assertEqual(result["metadata"]["total"], 1)
        self.assertEqual(result["events"][0]["time_utc"], report.iso(START))

    def test_multiline_sql_commas_and_escaped_quotes_survive(self):
        sql = "UPDATE users\nSET name=\\'a,b\\', note=\\'it\\\\s ok\\' WHERE id=1"
        self.save([], [audit_event(sql)])
        row = self.build()["events"][0]
        self.assertEqual(row["sql"], sql)
        self.assertEqual(row["category"], "修改")

    def test_rds_mysql_connection_type_and_cloudwatch_timestamp_are_supported(self):
        event = audit_event("DELETE FROM t", aurora=False, connection_type="SSL/TLS")
        event["message"] = event["message"].replace(WHEN.strftime("%Y%m%d %H:%M:%S"), "20261028 13:45:22")
        row = report.parse_audit_record(event["message"], event)
        self.assertEqual(row["category"], "删除")
        self.assertEqual(row["timestamp_raw"], "20261028 13:45:22")
        self.assertEqual(row["time_utc"], report.iso(WHEN))
        self.assertIn("CloudWatch", row["timestamp_source"])

    def test_auxiliary_table_events_are_not_counted_as_query_modifications(self):
        self.save([], [audit_event("UPDATE users SET enabled=1"), audit_event("users", operation="WRITE", event_id="table")])
        result = self.build()
        self.assertEqual(result["metadata"]["counts"]["修改"], 1)
        self.assertEqual(result["metadata"]["total"], 2)
        self.assertEqual(result["metadata"]["counted_total"], 1)

    def test_multiple_records_in_one_cloudwatch_message(self):
        first, second = audit_event("INSERT INTO t VALUES (1)"), audit_event("DROP TABLE t")
        first["message"] += "\n" + second["message"] + "\n"
        self.save([], [first])
        result = self.build()
        self.assertEqual(result["metadata"]["counts"]["新增"], 1)
        self.assertEqual(result["metadata"]["counts"]["删除"], 1)
        self.assertEqual(result["coverage"]["audit_cloudwatch_events"], 1)

    def test_truncated_sql_remains_evidence_and_marks_report_partial(self):
        event = audit_event()
        event["message"] = event["message"][:-3]  # Remove closing SQL quote and return code.
        self.save([], [event])
        result = self.build()
        self.assertFalse(result["metadata"]["complete"])
        self.assertEqual(result["metadata"]["total"], 0)
        self.assertEqual(result["coverage"]["unparsed_records"], 1)
        self.assertIn("UPDATE users", result["unparsed"][0]["raw"])
        self.assertIn("未解析审计记录", report.generate_html(result))

    def test_collection_errors_and_invalid_json_never_become_no_activity(self):
        self.collection["checks"] = [{"scope": "eu-north-1:cloudtrail", "status": "error", "message": "AccessDenied"}]
        self.collection["collection_status"] = "partial"
        self.save([], [])
        (self.directory / "management-events.jsonl").write_text("{bad JSON}\n", encoding="utf-8")
        result = self.build()
        self.assertFalse(result["metadata"]["complete"])
        self.assertEqual(len(result["metadata"]["errors"]), 2)
        self.assertIn("没有可解析", " ".join(result["coverage"]["notes"]))

    def test_xss_escape_and_secret_redaction_in_html_and_normalized_json(self):
        sql = "CREATE USER 'eve' IDENTIFIED BY 'SENSITIVE_PASSWORD'"
        event = management("m", sourceIPAddress="<script>alert(1)</script>")
        event["event"]["requestParameters"]["nested"] = {"sessionToken": "PRIVATE_SESSION"}
        self.save([event], [audit_event(sql)])
        result = self.build()
        markup = report.generate_html(result)
        stored = json.dumps(result)
        for secret in ("NEVER_SHOW", "SENSITIVE_PASSWORD", "PRIVATE_SESSION"):
            self.assertNotIn(secret, markup)
            self.assertNotIn(secret, stored)
        self.assertNotIn("<script>", markup)
        self.assertIn("&lt;script&gt;", markup)
        self.assertNotIn("<style", markup)
        self.assertIn('href="rds-report.css?v=', markup)

    def test_static_html_json_and_css_are_written_together(self):
        self.save([management()], [audit_event()])
        result = self.build()
        target = report.write_report(result, self.directory)
        self.assertEqual(target.name, "2026-10-29-rds操作审计.html")
        self.assertTrue((self.directory / "rds-report.css").is_file())
        saved = json.loads((self.directory / "daily-report.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["metadata"]["counts"], result["metadata"]["counts"])
        self.assertIn("2026-10-28 07:00:00", target.read_text(encoding="utf-8"))

    def test_custom_24_hour_window_keeps_exact_boundaries_and_custom_report_identity(self):
        start = datetime(2026, 10, 28, 9, 32, 55, tzinfo=UTC)
        end = start + timedelta(hours=24)
        self.save([
            management("start", eventTime=report.iso(start)),
            management("end", eventTime=report.iso(end)),
        ], [
            audit_event("UPDATE t SET x=1", when=start, event_id="sql-start"),
            audit_event("DELETE FROM t", when=end, event_id="sql-end"),
        ])
        result = report.build_daily_report(self.directory, audit_date="2026-10-29", start=start, end=end, offline=True, period_kind="custom")
        meta = result["metadata"]
        self.assertEqual(meta["period_kind"], "custom")
        self.assertEqual(meta["period_label"], "自定义时间窗口")
        self.assertEqual(meta["window_start_utc"], report.iso(start))
        self.assertEqual(meta["window_end_utc_exclusive"], report.iso(end))
        self.assertEqual(meta["total"], 2)
        self.assertEqual(meta["counts"], {"新增": 1, "删除": 0, "修改": 1, "其他操作": 0})
        self.assertEqual(meta["report_filename"], "2026-10-29-rds操作审计-自定义窗口.html")
        target = report.write_report(result, self.directory)
        markup = target.read_text(encoding="utf-8")
        self.assertIn("<h1>RDS 操作审计报告</h1>", markup)
        self.assertIn("自定义时间窗口", markup)
        self.assertIn("2026-10-28 17:32:55 至 2026-10-29 17:32:55", markup)
        self.assertNotIn("相邻日报", markup)
        self.assertNotIn("重叠 1 小时", markup)
        self.assertNotIn("RDS 操作审计日报", markup)

    def test_default_daily_report_retains_title_filename_and_overlap_note(self):
        result = self.build()
        markup = report.generate_html(result)
        self.assertEqual(result["metadata"]["period_kind"], "daily")
        self.assertEqual(result["metadata"]["report_filename"], "2026-10-29-rds操作审计.html")
        self.assertIn("<h1>RDS 操作审计日报</h1>", markup)
        self.assertIn("重叠 1 小时", markup)

    def test_unsupported_period_kind_cannot_silently_select_a_report_window(self):
        with self.assertRaisesRegex(ValueError, "period_kind"):
            report.build_daily_report(self.directory, audit_date="2026-10-29", start=START, end=END, period_kind="weekly")

    def test_real_offline_archive_is_not_mislabelled_as_fictional_example(self):
        result = report.build_daily_report(self.directory, audit_date="2026-10-29", start=START, end=END, offline=True)
        markup = report.generate_html(result)
        self.assertTrue(result["metadata"]["offline"])
        self.assertFalse(result["metadata"]["example_data"])
        self.assertIn("离线输入，未向 AWS 验证", markup)
        self.assertNotIn("非真实账号数据", markup)

    def test_example_marker_is_explicit_and_separate_from_offline_flag(self):
        self.collection["example_data"] = True
        self.save([], [])
        result = report.build_daily_report(self.directory, audit_date="2026-10-29", start=START, end=END, offline=True)
        self.assertTrue(result["metadata"]["example_data"])
        self.assertIn("虚构示例，非真实账号数据", report.generate_html(result))


class StatementClassificationTests(unittest.TestCase):
    def test_comments_are_skipped_but_dynamic_sql_and_cte_are_not_guessed(self):
        self.assertEqual(report.classify_sql("/* note */\n-- note\nUPDATE t SET x=1"), "修改")
        self.assertEqual(report.classify_sql("# note\nINSERT INTO t VALUES (1)"), "新增")
        for sql in ("CALL alter_balance(1)", "EXECUTE stmt", "PREPARE stmt FROM 'DELETE FROM t'", "WITH ids AS (SELECT 1) DELETE FROM t", "/*!80000 DELETE FROM t */"):
            with self.subTest(sql=sql):
                self.assertEqual(report.classify_sql(sql), "其他操作")

    def test_ambiguous_multi_statement_records_are_not_classified_by_first_verb(self):
        self.assertEqual(report.classify_sql("UPDATE t SET x=1;"), "修改")
        self.assertEqual(report.classify_sql("INSERT INTO t VALUES (1); DELETE FROM t"), "其他操作")
        self.assertEqual(report.classify_sql("INSERT INTO t VALUES ('ambiguous;literal')"), "其他操作")


if __name__ == "__main__":
    unittest.main()
