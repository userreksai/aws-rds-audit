"""Summary jobs never revive SQL-detail notifications or persist raw statements."""
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
from rds_sql_alerts import SqlChangeAlerts
from rds_summary import SummaryAccumulator

NOW = datetime(2026, 10, 29, 13, 5, tzinfo=timezone.utc)
ACCOUNT = "123456789012"


def collect_snapshot(instance, *, partial=False):
    """Emulate the new collector output, using the real streaming summarizer."""
    when = instance.start + timedelta(minutes=1)
    with SummaryAccumulator(instance.directory, instance.start, instance.end) as summary:
        for index, sql in enumerate(("UPDATE qa_table SET x=1", "SELECT * FROM qa_table")):
            summary.process_audit({
                "eventId": str(int(instance.start.timestamp())) + str(index),
                "timestamp": int(when.timestamp() * 1000), "region": "ap-east-1",
                "logGroupName": "/aws/rds/cluster/qa/audit", "logStreamName": "writer",
                "message": f"{int(when.timestamp()*1000000)},qa-server,qa-admin,203.0.113.1,1,1,QUERY,qa,'{sql}',0",
            })
        summary.finish()
    errors = [{"scope": "another-region", "status": "error", "error_type": "AccessDenied", "message": "test read failure"}] if partial else []
    instance.report.update(collection_status="partial" if partial else "ok", checks=errors)
    (instance.directory / "report.json").write_text(json.dumps(instance.report, default=audit.json_default), encoding="utf-8")
    return 2 if partial else 0


class SummaryOnlySqlJobTests(unittest.TestCase):
    def options(self, root, *, disabled=False):
        return audit.build_parser().parse_args([
            "--collect-incremental", "--profile", "audit", "--regions", "ap-east-1", "--send-lark",
            "--cache-dir", str(root / "cache"), "--output-dir", str(root / "reports"), "--max-buckets-per-run", "2",
            *(["--no-sql-alerts"] if disabled else []),
        ])

    def run_job(self, root, notices, *, at=NOW, partial=False, disabled=False):
        options = self.options(root, disabled=disabled)
        original = CacheStore.run_due

        def immediate(store, now, collect, notify, **kwargs):
            return original(store, now, collect, notify, sleep=lambda _: None, **kwargs)

        with patch.object(audit, "lark_configuration", return_value={}), \
                patch.object(jobs, "_notifier", return_value=notices.append), \
                patch.object(audit, "aws_session", return_value=(Mock(), None, {"Account": ACCOUNT, "Arn": "TEST"})), \
                patch.object(audit.Collector, "run", lambda instance: collect_snapshot(instance, partial=partial)), \
                patch("rds_sql_alerts.SqlChangeAlerts", side_effect=AssertionError("summary jobs must not open the legacy SQL outbox")) as legacy, \
                patch.object(CacheStore, "run_due", immediate), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            status = jobs.run_incremental(options, api=audit, now=at)
        legacy.assert_not_called()
        return status

    def assert_summary_artifacts(self, root):
        snapshots = list((root / "cache").rglob("operation-summary.json"))
        self.assertTrue(snapshots)
        for file in snapshots:
            payload = json.loads(file.read_text(encoding="utf-8"))
            self.assertTrue(payload["summary_only"])
            actor = payload["actors"][0]
            self.assertEqual(actor["actor"], "qa-admin")
            self.assertEqual(actor["counts"]["修改"], 1)
            self.assertEqual(actor["total"], 1)
        for pattern in ("*.jsonl", ".summary-identities-*.sqlite3"):
            self.assertFalse(list((root / "cache").rglob(pattern)))
        for file in (root / "cache").rglob("*.json"):
            text = file.read_text(encoding="utf-8")
            for secret_detail in ("UPDATE qa_table", "SELECT * FROM qa_table", "203.0.113.1"):
                self.assertNotIn(secret_detail, text)

    def test_success_and_later_incremental_rounds_save_only_user_counts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, notices = Path(temporary), []
            self.assertEqual(self.run_job(root, notices), 0)
            self.assertEqual(self.run_job(root, notices, at=NOW + timedelta(minutes=5)), 0)
            self.assertFalse(any(item.get("kind") == "sql_change" for item in notices))
            self.assert_summary_artifacts(root)

    def test_other_region_failure_retries_keep_operational_alerts_without_sql(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, notices = Path(temporary), []
            self.assertEqual(self.run_job(root, notices, partial=True), 2)
            self.assertGreaterEqual(len(list((root / "cache").rglob("operation-summary.json"))), 3)
            self.assertTrue(notices)
            self.assertFalse(any(item.get("kind") == "sql_change" for item in notices))
            self.assertNotIn("UPDATE qa_table", json.dumps(notices))
            self.assert_summary_artifacts(root)

    def test_legacy_disable_argument_preserves_summary_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, notices = Path(temporary), []
            self.assertEqual(self.run_job(root, notices, disabled=True), 0)
            self.assertFalse(any(item.get("kind") == "sql_change" for item in notices))
            self.assert_summary_artifacts(root)

    def test_pending_legacy_sql_outbox_is_not_scanned_instantiated_or_flushed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, notices = Path(temporary), []
            options = self.options(root)
            store = CacheStore(options.cache_dir, ACCOUNT, jobs.cache_scope(options))
            try:
                SqlChangeAlerts(store, NOW)
                with store.connection:
                    store.connection.execute(
                        "INSERT INTO sql_change_batches(id,payload) VALUES(?,?)",
                        ("legacy-pending", json.dumps({"kind": "sql_change", "message": "DELETE FROM qa_table WHERE private=1"})),
                    )
            finally:
                store.close()
            with patch.object(SqlChangeAlerts, "scan_committed", side_effect=AssertionError("must not scan legacy raw evidence")) as scan, \
                    patch.object(SqlChangeAlerts, "flush", side_effect=AssertionError("must not send legacy pending SQL")) as flush:
                self.assertEqual(self.run_job(root, notices), 0)
            scan.assert_not_called()
            flush.assert_not_called()
            store = CacheStore(options.cache_dir, ACCOUNT, jobs.cache_scope(options))
            try:
                pending = store.connection.execute("SELECT status,attempts FROM sql_change_batches WHERE id='legacy-pending'").fetchone()
                self.assertEqual((pending["status"], pending["attempts"]), ("pending", 0))
            finally:
                store.close()
            self.assertNotIn("DELETE FROM qa_table", json.dumps(notices))


class SummaryOnlyBoundaryTests(unittest.TestCase):
    def test_detail_options_are_rejected_before_credential_or_notification_loading(self):
        for option in ("--sql-alerts", "--download-instance-logs"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "must-not-be-created"
                with patch.object(audit, "aws_session") as credentials, \
                        patch.object(audit, "lark_configuration") as config, \
                        patch.object(audit, "check_configuration") as check, \
                        redirect_stderr(io.StringIO()):
                    self.assertEqual(audit.main([option, "--check-config", "--output-dir", str(destination), "--no-publish"]), 1)
                credentials.assert_not_called()
                config.assert_not_called()
                check.assert_not_called()
                self.assertFalse(destination.exists())


class SqlLarkPayloadTests(unittest.TestCase):
    config = {"webhook_url": "https://open.larksuite.com/open-apis/bot/v2/hook/TEST-ONLY", "signing_secret": "TEST-ONLY"}

    def test_legacy_sql_notifications_are_rejected_before_signing_or_network(self):
        for message in ("SQL：DELETE FROM qa_table WHERE x=2", "中" * 30000):
            with self.subTest(length=len(message)), \
                    patch.object(lark_notify, "_signed_payload") as sign, \
                    patch.object(lark_notify, "_send_payload") as send, \
                    self.assertRaisesRegex(ValueError, "仅汇总模式"):
                lark_notify.send_lark_alert({"kind": "sql_change", "event_id": "TEST-ID", "message": message}, self.config, now=NOW)
            sign.assert_not_called()
            send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
