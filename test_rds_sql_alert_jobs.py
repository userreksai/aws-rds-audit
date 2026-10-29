"""Actual job orchestration with synthetic SQL and a fake Lark transport."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import lark_notify
import rds_audit as audit
import rds_jobs as jobs
from rds_cache import CacheStore

NOW = datetime(2026, 10, 29, 13, 5, tzinfo=timezone.utc)
ACCOUNT = "123456789012"


def collect_snapshot(instance, *, partial=False):
    when = instance.start + timedelta(minutes=1)
    events = []
    for index, sql in enumerate(("UPDATE qa_table SET x=1", "SELECT * FROM qa_table")):
        events.append({"eventId": str(int(instance.start.timestamp())) + str(index), "timestamp": int(when.timestamp()*1000),
                       "region": "ap-east-1", "logGroupName": "/aws/rds/cluster/qa/audit", "logStreamName": "writer",
                       "message": f"{int(when.timestamp()*1000000)},qa-server,qa-admin,203.0.113.1,1,1,QUERY,qa,'{sql}',0"})
    (instance.directory / "cloudwatch").mkdir()
    (instance.directory / "cloudwatch/events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    (instance.directory / "management-events.jsonl").write_text("", encoding="utf-8")
    errors = [{"scope": "another-region", "status": "error", "error_type": "AccessDenied", "message": "test read failure"}] if partial else []
    instance.report.update(collection_status="partial" if partial else "ok", checks=errors)
    (instance.directory / "report.json").write_text(json.dumps(instance.report, default=audit.json_default), encoding="utf-8")
    return 2 if partial else 0


class SqlAlertJobTests(unittest.TestCase):
    def run_job(self, root, notices, *, at=NOW, partial=False, disabled=False):
        options = audit.build_parser().parse_args([
            "--collect-incremental", "--profile", "audit", "--regions", "ap-east-1", "--send-lark",
            "--cache-dir", str(root / "cache"), "--output-dir", str(root / "reports"), "--max-buckets-per-run", "2",
            *( ["--no-sql-alerts"] if disabled else []),
        ])
        original = CacheStore.run_due

        def immediate(store, now, collect, notify, **kwargs):
            return original(store, now, collect, notify, sleep=lambda _: None, **kwargs)

        with patch.object(audit, "lark_configuration", return_value={}), \
                patch.object(jobs, "_notifier", return_value=notices.append), \
                patch.object(audit, "aws_session", return_value=(Mock(), None, {"Account": ACCOUNT, "Arn": "TEST"})), \
                patch.object(audit.Collector, "run", lambda instance: collect_snapshot(instance, partial=partial)), \
                patch.object(CacheStore, "run_due", immediate), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return jobs.run_incremental(options, api=audit, now=at)

    def test_latest_sql_alerts_once_and_initial_historical_backfill_is_quiet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, notices = Path(temporary), []
            self.assertEqual(self.run_job(root, notices), 0)
            self.assertEqual(self.run_job(root, notices, at=NOW + timedelta(minutes=5)), 0)
            sql = [item for item in notices if item["kind"] == "sql_change"]
            self.assertEqual(len(sql), 1)
            self.assertEqual(sql[0]["operation_count"], 1)
            self.assertIn("qa-admin", sql[0]["message"])
            self.assertIn("UPDATE qa_table", sql[0]["message"])
            self.assertNotIn("SELECT", sql[0]["message"])

    def test_other_region_failure_and_retries_do_not_hide_or_repeat_valid_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            notices = []
            self.assertEqual(self.run_job(Path(temporary), notices, partial=True), 2)
            sql = [item for item in notices if item["kind"] == "sql_change"]
            self.assertEqual(len(sql), 1)
            self.assertEqual(sql[0]["operation_count"], 1)

    def test_sql_alerts_can_be_disabled_without_disabling_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            notices = []
            self.assertEqual(self.run_job(Path(temporary), notices, disabled=True), 0)
            self.assertFalse(any(item["kind"] == "sql_change" for item in notices))
            self.assertTrue(list((Path(temporary) / "cache").rglob("management-events.jsonl")))


class SqlLarkPayloadTests(unittest.TestCase):
    config = {"webhook_url": "https://open.larksuite.com/open-apis/bot/v2/hook/TEST-ONLY", "signing_secret": "TEST-ONLY"}

    def test_sql_payload_keeps_all_batch_lines_and_uses_existing_signed_transport(self):
        message = "\n".join(["账号：qa-admin", *["SQL行 " + str(index) for index in range(100)], "SQL：DELETE FROM qa_table WHERE x=2"])
        with patch.object(lark_notify, "_send_payload", return_value={"code": 0}) as send:
            lark_notify.send_lark_alert({"kind": "sql_change", "event_id": "TEST-ID", "message": message}, self.config, now=NOW)
        payload = send.call_args.args[0]
        self.assertIn("sign", payload)
        self.assertIn("SQL行 99", payload["content"]["text"])
        self.assertIn("DELETE FROM qa_table", payload["content"]["text"])
        self.assertIn("RDS采集告警", payload["content"]["text"])

    def test_oversized_sql_notification_is_rejected_before_network(self):
        with patch.object(lark_notify, "_send_payload") as send, self.assertRaises(lark_notify.LarkNotificationError):
            lark_notify.send_lark_alert({"kind": "sql_change", "message": ("中" * 100 + "\n") * 200}, self.config, now=NOW)
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
