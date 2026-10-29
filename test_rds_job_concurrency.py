"""Local regressions for queued daily jobs and snapshot repair; no AWS or Lark."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import rds_audit as audit
import rds_jobs as jobs
from rds_cache import CacheStore, _exclusive

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 0, 10, tzinfo=UTC)
DAY = "2026-10-29"
ACCOUNT = "123456789012"


def options(root, *extra):
    return audit.build_parser().parse_args([
        "--profile", "audit", "--regions", "ap-east-1", "--cache-dir", str(root / "cache"),
        "--output-dir", str(root / "reports"), "--max-buckets-per-run", "100", *extra,
    ])


def snapshot(start, end, target):
    source = {
        "identity": {"Account": ACCOUNT},
        "window": {"start_inclusive": audit.iso(start), "end_exclusive": audit.iso(end)},
        "collection_status": "ok", "checks": [], "regions": {},
    }
    (target / "report.json").write_text(json.dumps(source), encoding="utf-8")
    (target / "management-events.jsonl").write_text("", encoding="utf-8")
    return 0


def collect(instance):
    snapshot(instance.start, instance.end, instance.directory)
    instance.report.update(collection_status="ok", checks=[])
    return 0


class JobConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.daily = options(self.root, "--daily", "--from-cache", "--date", DAY)
        self.incremental = options(self.root, "--collect-incremental")
        self.notices = []
        self.silence = io.StringIO()

    def tearDown(self):
        self.temporary.cleanup()

    def seed(self):
        store = CacheStore(self.daily.cache_dir, ACCOUNT, jobs.cache_scope(self.daily))
        store.run_due(NOW, snapshot, max_buckets=100, lookback_hours=26)
        return store

    def pending(self):
        box = jobs.OpsOutbox(self.daily.cache_dir, jobs.cache_scope(self.daily))
        try:
            return box.daily_pending(DAY)
        finally:
            box.close()

    def increment(self, finish):
        with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                patch.object(audit, "aws_session", return_value=(Mock(), None, {"Account": ACCOUNT, "Arn": "TEST"})), \
                patch.object(audit.Collector, "run", collect), \
                patch.object(audit, "finish_daily", finish), \
                redirect_stdout(self.silence), redirect_stderr(self.silence):
            return jobs.run_incremental(self.incremental, api=audit, now=NOW + timedelta(minutes=5))

    def test_busy_daily_is_durable_and_next_collection_produces_report(self):
        store = self.seed()
        try:
            with _exclusive(store.directory / ".job.lock") as locked:
                self.assertTrue(locked)
                with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                        patch.object(audit, "aws_session", side_effect=AssertionError("daily must not use AWS")), \
                        patch.object(audit, "finish_daily") as finish, redirect_stdout(self.silence):
                    self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW), 0)
                finish.assert_not_called()
                self.assertTrue(self.pending())
            finish = Mock(return_value=0)
            self.assertEqual(self.increment(finish), 0)
            finish.assert_called_once()
            self.assertFalse(self.pending())
            state = jobs._load_state(store)[DAY]
            self.assertEqual(state["status"], 0)
            source = json.loads((Path(state["path"]) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(source["source_cache"]["selected_segments"], 50)
        finally:
            store.close()

    def test_first_render_failure_is_retried_by_next_collection(self):
        store = self.seed()
        try:
            with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                    patch.object(audit, "finish_daily", side_effect=OSError("temporary report write error")), \
                    redirect_stdout(self.silence), redirect_stderr(self.silence):
                self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW), 2)
            self.assertTrue(self.pending())
            self.assertTrue(jobs._load_state(store)[DAY]["delivery_pending"])
            finish = Mock(return_value=0)
            self.assertEqual(self.increment(finish), 0)
            finish.assert_called_once()
            self.assertFalse(self.pending())
            self.assertFalse(jobs._load_state(store)[DAY]["delivery_pending"])
            self.assertTrue(any(notice["kind"] == "recovered" for notice in self.notices))
        finally:
            store.close()

    def test_daily_requested_before_first_cache_is_retried_after_collection(self):
        with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                patch.object(audit, "aws_session", side_effect=AssertionError("daily must not use AWS")), \
                redirect_stdout(self.silence), redirect_stderr(self.silence):
            self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW), 2)
        self.assertTrue(self.pending())
        finish = Mock(return_value=0)
        self.assertEqual(self.increment(finish), 0)
        finish.assert_called_once()
        self.assertFalse(self.pending())

    def test_changed_segment_inside_issued_daily_window_generates_revision(self):
        store = self.seed()
        try:
            with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                    patch.object(audit, "finish_daily", return_value=0), redirect_stdout(self.silence):
                self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW), 0)
            original = jobs._load_state(store)[DAY]
            start = NOW.replace(hour=23, minute=30) - timedelta(days=1)
            end = start + timedelta(minutes=30)
            # Simulate a new, independently committed immutable late-arrival snapshot.
            target = store.directory / "segments" / "late-arrival-version"
            target.mkdir()
            snapshot(start, end, target)
            (target / "management-events.jsonl").write_text('{"late_arrival":true}\n', encoding="utf-8")
            _, digest = store._validate_snapshot(target, int(start.timestamp()), int(end.timestamp()), False)
            store.connection.execute("UPDATE buckets SET active_path=?,active_digest=? WHERE start=?", (store._relative_snapshot(target), digest, int(start.timestamp())))
            store.connection.commit()
            stats = {"succeeded": 1, "changed_starts": [audit.iso(start)], "failed": 0, "pending_alerts": 0}
            finish = Mock(return_value=0)
            with patch.object(CacheStore, "run_due", return_value=stats):
                self.assertEqual(self.increment(finish), 0)
            finish.assert_called_once()
            revised = jobs._load_state(store)[DAY]
            self.assertNotEqual(original["fingerprint"], revised["fingerprint"])
            source = json.loads((Path(revised["path"]) / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(source["source_cache"]["revision"])
        finally:
            store.close()

    def test_changed_segment_at_or_after_daily_end_does_not_repeat_report(self):
        store = self.seed()
        try:
            with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                    patch.object(audit, "finish_daily", return_value=0), redirect_stdout(self.silence):
                self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW), 0)
            original = jobs._load_state(store)
            stats = {"succeeded": 1, "changed_starts": [audit.iso(NOW.replace(minute=0)), audit.iso(NOW.replace(minute=30))], "failed": 0, "pending_alerts": 0}
            finish = Mock(return_value=0)
            with patch.object(CacheStore, "run_due", return_value=stats):
                self.assertEqual(self.increment(finish), 0)
            finish.assert_not_called()
            self.assertEqual(jobs._load_state(store), original)
        finally:
            store.close()

    def test_collector_process_recovery_alert_is_sent_once(self):
        store = self.seed()
        store.close()
        failure = options(self.root, "--notify-service-failure", "--source-service", "aws-rds-audit-collect.service")
        with patch.object(jobs, "_notifier", return_value=self.notices.append):
            self.assertEqual(jobs.notify_service_failure(failure, api=audit, now=NOW), 0)
        self.assertEqual(self.increment(Mock(return_value=0)), 0)
        self.assertEqual(self.increment(Mock(return_value=0)), 0)
        relevant = [row for row in self.notices if "service:aws-rds-audit-collect.service" in row["event_id"]]
        self.assertEqual([row["kind"] for row in relevant], ["service_process_failure", "recovered"])

    def test_daily_process_recovery_alert_is_sent_once(self):
        store = self.seed()
        store.close()
        failure = options(self.root, "--notify-service-failure", "--source-service", "aws-rds-audit.service")
        with patch.object(jobs, "_notifier", return_value=self.notices.append):
            self.assertEqual(jobs.notify_service_failure(failure, api=audit, now=NOW), 0)
        with patch.object(jobs, "_notifier", return_value=self.notices.append), \
                patch.object(audit, "finish_daily", return_value=0), redirect_stdout(self.silence):
            self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW), 0)
            self.assertEqual(jobs.run_cached_daily(self.daily, api=audit, now=NOW + timedelta(minutes=5)), 0)
        relevant = [row for row in self.notices if "service:aws-rds-audit.service" in row["event_id"]]
        self.assertEqual([row["kind"] for row in relevant], ["service_process_failure", "recovered"])


class SnapshotRepairTests(unittest.TestCase):
    def test_corrupt_committed_snapshot_is_excluded_and_recollected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = options(root)
            store = CacheStore(args.cache_dir, ACCOUNT, jobs.cache_scope(args))
            try:
                store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
                start, end = NOW.replace(hour=23, minute=30) - timedelta(days=1), NOW.replace(minute=0)
                bucket = store.bucket(start)
                (store.directory / bucket["active_path"] / "management-events.jsonl").write_text("altered\n", encoding="utf-8")
                damaged = store.assemble_window(start, end, root / "damaged")
                self.assertEqual(damaged["source_cache"]["selected_segments"], 0)
                self.assertEqual(damaged["checks"][0]["error_type"], "InvalidCacheSnapshot")
                repaired = store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
                self.assertEqual(repaired["succeeded"], 1)
                self.assertIn(audit.iso(start), repaired["changed_starts"])
                result = store.assemble_window(start, end, root / "repaired")
                self.assertEqual(result["collection_status"], "ok")
                self.assertEqual(result["source_cache"]["selected_segments"], 1)
            finally:
                store.close()

    def test_requested_old_daily_gap_is_repaired_outside_normal_lookback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = options(root)
            store = CacheStore(args.cache_dir, ACCOUNT, jobs.cache_scope(args))
            try:
                end = NOW.replace(minute=0) - timedelta(days=3)
                start = end - timedelta(minutes=30)
                missing = store.assemble_window(start, end, root / "missing")
                self.assertEqual(len(missing["source_cache"]["missing_segments"]), 1)
                observed = []

                def record(a, b, target):
                    observed.append(a)
                    return snapshot(a, b, target)

                store.run_due(NOW, record, max_buckets=2, lookback_hours=1)
                self.assertIn(start, observed)
                complete = store.assemble_window(start, end, root / "complete")
                self.assertEqual(complete["collection_status"], "ok")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
