"""Job integration checks use fake collectors/transports and real local ledgers."""
from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

import rds_audit as audit
import rds_jobs as jobs
from rds_cache import CacheStore

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 0, 10, tzinfo=UTC)
ACCOUNT = "123456789012"


def args(root, *extra):
    return audit.build_parser().parse_args(["--profile", "audit", "--regions", "ap-east-1", "--cache-dir", str(root / "cache"), "--output-dir", str(root / "reports"), "--no-publish", *extra])


def make_snapshot(start, end, target, marker="one"):
    source = {"identity": {"Account": ACCOUNT}, "window": {"start_inclusive": audit.iso(start), "end_exclusive": audit.iso(end)}, "collection_status": "ok", "checks": [], "regions": {}, "sql_log_download_requested": True}
    (target / "report.json").write_text(json.dumps(source), encoding="utf-8")
    (target / "management-events.jsonl").write_text("", encoding="utf-8")
    (target / "cloudwatch").mkdir()
    when = start + timedelta(seconds=1)
    record = {"region": "ap-east-1", "eventId": str(int(start.timestamp())) + marker, "timestamp": int(when.timestamp()*1000), "logGroupName": "/aws/rds/cluster/example/audit", "logStreamName": "example", "message": f"{int(when.timestamp()*1000000)},server,user,203.0.113.1,1,1,QUERY,db,'UPDATE example SET x=1',0"}
    (target / "cloudwatch/events.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    return 0


class AlertOutboxTests(unittest.TestCase):
    def test_failure_is_durable_throttled_and_recovery_is_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            box = jobs.OpsOutbox(root, jobs.cache_scope(args(root)))
            failure = {"kind": "failed", "message": "temporary outage"}
            box.failure("one", failure, NOW)
            box.failure("one", failure, NOW + timedelta(minutes=5))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(box.flush(Mock(side_effect=OSError("private webhook")), NOW), 1)
            box.close()
            box = jobs.OpsOutbox(root, jobs.cache_scope(args(root)))
            delivered = []
            self.assertEqual(box.flush(delivered.append, NOW + timedelta(minutes=2)), 0)
            self.assertEqual(len(delivered), 1)
            box.failure("one", failure, NOW + timedelta(minutes=10))
            self.assertEqual(box.flush(delivered.append, NOW + timedelta(minutes=10)), 0)
            box.recovery("one", {"message": "recovered"}, NOW + timedelta(minutes=15))
            box.recovery("one", {"message": "recovered"}, NOW + timedelta(minutes=16))
            box.flush(delivered.append, NOW + timedelta(minutes=16))
            self.assertEqual([row["kind"] for row in delivered], ["failed", "recovered"])
            box.close()

    def test_signed_operational_alert_does_not_include_sql(self):
        import lark_notify
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 200
        response.read.return_value = b'{"code":0}'
        opener = Mock(return_value=response)
        lark_notify.send_lark_alert({"kind": "failed", "message": "AccessDenied", "sql": "PRIVATE-SQL", "bucket_start": audit.iso(NOW)}, {"webhook_url": "https://open.larksuite.com/open-apis/bot/v2/hook/TEST-ONLY", "signing_secret": "TEST-ONLY"}, opener=opener, now=NOW)
        sent = json.loads(opener.call_args.args[0].data)
        self.assertIn("sign", sent)
        self.assertNotIn("PRIVATE-SQL", json.dumps(sent))


class JobIntegrationTests(unittest.TestCase):
    def test_cached_daily_uses_fifty_local_segments_and_never_calls_aws(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = args(root, "--daily", "--from-cache", "--date", "2026-10-29")
            store = CacheStore(options.cache_dir, ACCOUNT, jobs.cache_scope(options))
            store.run_due(NOW, make_snapshot, max_buckets=100, lookback_hours=26)
            store.close()
            with patch.object(audit, "aws_session", side_effect=AssertionError("daily must not contact AWS")), redirect_stdout(io.StringIO()):
                self.assertEqual(jobs.run_cached_daily(options, api=audit, now=NOW), 0)
            report_path = next((root / "reports").rglob("daily-report.json"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["metadata"]["source_cache"]["selected_segments"], 50)
            self.assertEqual(report["metadata"]["source_cache"]["expected_segments"], 50)
            self.assertEqual(report["metadata"]["counts"]["修改"], 50)
            self.assertTrue(report["metadata"]["complete"])

    def test_missing_daily_segments_are_partial_queued_and_alerted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = args(root, "--daily", "--from-cache", "--date", "2026-10-29")
            store = CacheStore(options.cache_dir, ACCOUNT, jobs.cache_scope(options))
            store.close()
            notices = []
            with patch.object(jobs, "_notifier", return_value=notices.append), patch.object(audit, "aws_session", side_effect=AssertionError("no AWS")), redirect_stdout(io.StringIO()):
                self.assertEqual(jobs.run_cached_daily(options, api=audit, now=NOW), 2)
            report = json.loads(next((root / "reports").rglob("daily-report.json")).read_text(encoding="utf-8"))
            self.assertFalse(report["metadata"]["complete"])
            self.assertEqual(len(report["metadata"]["source_cache"]["missing_segments"]), 50)
            self.assertTrue(any(item["kind"] == "daily_missing_segments" for item in notices))
            store = CacheStore.discover(options.cache_dir, jobs.cache_scope(options))
            self.assertEqual(store.connection.execute("SELECT count(*) FROM buckets WHERE status='pending'").fetchone()[0], 50)
            store.close()

    def test_incremental_callback_is_lightweight_and_does_not_render_each_bucket(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = args(root, "--collect-incremental", "--max-buckets-per-run", "1", "--cache-lookback-hours", "1")
            observed = []

            def collect(instance):
                observed.append(instance.args.metadata_light)
                make_snapshot(instance.start, instance.end, instance.directory)
                instance.report.update(collection_status="ok", checks=[])
                return 0

            with patch.object(audit, "aws_session", return_value=(Mock(), None, {"Account": ACCOUNT, "Arn": "EXAMPLE"})), patch.object(audit.Collector, "run", collect), patch.object(audit, "finish_daily") as render, redirect_stdout(io.StringIO()):
                self.assertEqual(jobs.run_incremental(options, api=audit, now=NOW), 0)
            self.assertEqual(observed, [True])
            render.assert_not_called()
            store = CacheStore.discover(options.cache_dir, jobs.cache_scope(options))
            self.assertEqual(store.connection.execute("SELECT count(*) FROM buckets WHERE status='succeeded'").fetchone()[0], 1)
            store.close()

    def test_bootstrap_identity_failure_has_a_persistent_alert(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = args(root, "--collect-incremental")
            with patch.object(audit, "aws_session", side_effect=RuntimeError("No credentials")), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(jobs.run_incremental(options, api=audit, now=NOW), 2)
            box = jobs.OpsOutbox(options.cache_dir, jobs.cache_scope(options))
            delivered = []
            self.assertEqual(box.flush(delivered.append, NOW), 0)
            self.assertEqual(delivered[0]["kind"], "collection_start_failure")
            box.close()

    def test_service_failure_hook_does_not_start_aws_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            options = args(Path(temporary), "--notify-service-failure", "--source-service", "aws-rds-audit-collect.service")
            delivered = []
            with patch.object(jobs, "_notifier", return_value=delivered.append), patch.object(audit, "aws_session") as aws:
                self.assertEqual(jobs.notify_service_failure(options, api=audit, now=NOW), 0)
            aws.assert_not_called()
            self.assertEqual(delivered[0]["source_service"], "aws-rds-audit-collect.service")

    def test_paged_publication_copies_assets_and_excludes_raw_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, web = root / "raw", root / "web"
            shutil.copytree(Path(__file__).parent / "examples/daily-sample", source)
            with patch.object(audit, "aws_session", side_effect=AssertionError("offline")), redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main(["--input-dir", str(source), "--publish-dir", str(web)]), 2)
            report = json.loads((source / "daily-report.json").read_text(encoding="utf-8"))
            for name in report["artifacts"]["manifest"]:
                self.assertTrue((web / name).is_file())
            self.assertTrue((web / "index.html").is_file())
            self.assertFalse((web / "daily-report.json").exists())
            self.assertFalse((web / "cloudwatch").exists())


if __name__ == "__main__":
    unittest.main()
