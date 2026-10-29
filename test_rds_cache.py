"""Offline interval ledger/retry/outbox/assembly checks; no AWS or Lark I/O."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from rds_cache import CacheStore, _exclusive

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 9, 5, tzinfo=UTC)
ACCOUNT = "123456789012"
SCOPE = {"profile": "audit", "regions": "ap-east-1", "interval_minutes": 30, "filter_version": "changes-v1"}


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def snapshot(start, end, directory, marker="one", *, status="ok", checks=None):
    source = {"identity": {"Account": ACCOUNT}, "window": {"start_inclusive": stamp(start), "end_exclusive": stamp(end)}, "collection_status": status, "checks": checks or [], "regions": {"ap-east-1": {"filtered_management_event_count": 2, "sql_log_groups": []}}}
    (directory / "report.json").write_text(json.dumps(source), encoding="utf-8")
    (directory / "management-events.jsonl").write_text(json.dumps({"marker": marker}) + "\n", encoding="utf-8")
    (directory / "rds-events.jsonl").write_text("", encoding="utf-8")
    return 0


class CacheFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = CacheStore(self.root / "cache", ACCOUNT, SCOPE)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def test_latest_first_bounded_backfill_and_success_is_not_recollected(self):
        windows = []

        def collect(start, end, target):
            windows.append((start, end))
            return snapshot(start, end, target)

        first = self.store.run_due(NOW, collect, max_buckets=1, lookback_hours=1)
        self.assertEqual(first["succeeded"], 1)
        self.assertEqual(windows[0][1], datetime(2026, 10, 29, 9, tzinfo=UTC))
        self.assertLessEqual(windows[0][1] + timedelta(minutes=5), NOW)
        second = self.store.run_due(NOW, collect, max_buckets=1, lookback_hours=1)
        self.assertEqual(second["succeeded"], 1)
        self.assertLess(windows[1][0], windows[0][0])
        third = self.store.run_due(NOW, collect, max_buckets=1, lookback_hours=1)
        self.assertEqual(third["attempts"], 0)
        self.assertEqual(len(set(windows)), 2)

    def test_three_attempts_then_failure_alert_recovery_and_checkpoint(self):
        attempts, notices, pauses = [], [], []

        def fail(start, end, target):
            attempts.append(target)
            raise ConnectionError("AWS temporarily unavailable")

        failed = self.store.run_due(NOW, fail, notices.append, max_buckets=1, lookback_hours=1, sleep=pauses.append)
        self.assertEqual(failed["attempts"], 3)
        self.assertEqual(pauses, [2, 4])
        self.assertEqual(len(set(attempts)), 3)
        self.assertTrue(all(path.is_dir() for path in attempts))
        latest = datetime(2026, 10, 29, 8, 30, tzinfo=UTC)
        row = self.store.bucket(latest)
        self.assertEqual(row["status"], "failed")
        self.assertIsNone(row["active_path"])
        self.assertEqual(notices[0]["kind"], "failed")
        recovered = self.store.run_due(NOW + timedelta(minutes=5), snapshot, notices.append, max_buckets=1, lookback_hours=1)
        self.assertEqual(recovered["succeeded"], 1)
        self.assertEqual([notice["kind"] for notice in notices], ["failed", "recovered"])
        self.assertEqual(self.store.bucket(latest)["attempts"], 4)
        self.assertEqual(self.store.bucket(latest)["status"], "succeeded")

    def test_notification_failure_stays_pending_and_is_retried_without_new_failure_alert(self):
        def fail(*args):
            return {"status": 2, "error": "AccessDenied", "retryable": False}

        def broken_notice(payload):
            raise OSError("PRIVATE-WEBHOOK-URL")

        first = self.store.run_due(NOW, fail, broken_notice, max_buckets=1, lookback_hours=1)
        self.assertEqual(first["pending_alerts"], 1)
        self.assertNotIn("PRIVATE", self.store.pending_alerts()[0]["last_error"])
        delivered = []
        # No segment is eligible before next_retry; old missing data may still collect.
        self.store.run_due(NOW + timedelta(minutes=2), fail, delivered.append, max_buckets=1, lookback_hours=1)
        self.assertTrue(any(item["window_start_utc"].endswith("08:30:00Z") for item in delivered))
        recent = list(self.store.connection.execute("SELECT * FROM alerts WHERE bucket_start=?", (int(datetime(2026, 10, 29, 8, 30, tzinfo=UTC).timestamp()),)))
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["status"], "sent")

    def test_process_restart_recovers_uncommitted_running_segment(self):
        self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        start = int(datetime(2026, 10, 29, 8, tzinfo=UTC).timestamp())
        self.store.connection.execute("UPDATE buckets SET status='running' WHERE start=?", (start,))
        self.store.connection.commit()
        self.store.close()
        self.store = CacheStore(self.root / "cache", ACCOUNT, SCOPE)
        result = self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        self.assertEqual(result["succeeded"], 1)
        self.assertEqual(self.store.connection.execute("SELECT status FROM buckets WHERE start=?", (start,)).fetchone()[0], "succeeded")

    def test_missing_segment_is_partial_and_zero_event_success_is_coverage(self):
        self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        start, end = datetime(2026, 10, 29, 8, tzinfo=UTC), datetime(2026, 10, 29, 9, tzinfo=UTC)
        report = self.store.assemble_window(start, end, self.root / "partial")
        self.assertEqual(report["collection_status"], "partial")
        self.assertEqual(report["source_cache"]["expected_segments"], 2)
        self.assertEqual(report["source_cache"]["selected_segments"], 1)
        self.assertEqual(len(report["source_cache"]["missing_segments"]), 1)
        self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        full = self.store.assemble_window(start, end, self.root / "full")
        self.assertEqual(full["collection_status"], "ok")
        self.assertEqual(len((self.root / "full/management-events.jsonl").read_text().splitlines()), 2)

    def test_late_refresh_replaces_snapshot_and_content_fingerprint_is_stable(self):
        self.store.run_due(NOW, snapshot, max_buckets=2, lookback_hours=1)
        start, end = datetime(2026, 10, 29, 8, tzinfo=UTC), datetime(2026, 10, 29, 9, tzinfo=UTC)
        original = self.store.assemble_window(start, end, self.root / "before")
        # Newer pending segments consume the first two slots; refresh gets the rest.
        def refreshed(a, b, target):
            return snapshot(a, b, target, marker="newest")

        result = self.store.run_due(NOW + timedelta(hours=1), refreshed, max_buckets=6, lookback_hours=2)
        self.assertGreaterEqual(result["changed"], 1)
        after = self.store.assemble_window(start, end, self.root / "after")
        rows = (self.root / "after/management-events.jsonl").read_text().splitlines()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(json.loads(row)["marker"] == "newest" for row in rows))
        self.assertNotEqual(original["source_cache"]["fingerprint"], after["source_cache"]["fingerprint"])
        same = self.store.assemble_window(start, end, self.root / "same")
        self.assertEqual(after["source_cache"]["fingerprint"], same["source_cache"]["fingerprint"])

    def test_only_explicit_limited_quality_partial_can_commit(self):
        def quality(a, b, target):
            snapshot(a, b, target, status="partial", checks=[{"scope": "sql", "status": "error", "error_type": "UnclassifiedSqlRecords", "message": "1 record quarantined"}])
            return {"status": 0, "success": True, "quality_partial": True, "directory": str(target)}

        result = self.store.run_due(NOW, quality, max_buckets=1, lookback_hours=1)
        self.assertEqual(result["succeeded"], 1)
        self.assertEqual(result["quality_partial"], 1)
        report = self.store.assemble_window(datetime(2026, 10, 29, 8, 30, tzinfo=UTC), datetime(2026, 10, 29, 9, tzinfo=UTC), self.root / "quality")
        self.assertEqual(report["collection_status"], "partial")
        self.assertEqual(report["checks"][0]["error_type"], "UnclassifiedSqlRecords")
        def invalid(a, b, target):
            snapshot(a, b, target, status="partial", checks=[{"status": "error", "error_type": "AccessDenied"}])
            return {"status": 0, "success": True, "quality_partial": True}
        failed = self.store.run_due(NOW, invalid, max_buckets=1, lookback_hours=1, sleep=lambda _: None)
        self.assertEqual(failed["failed"], 1)

    def test_scope_and_account_isolation_and_ambiguous_discovery(self):
        self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        same = CacheStore.discover(self.root / "cache", SCOPE)
        self.assertEqual(same.directory, self.store.directory)
        same.close()
        other = CacheStore(self.root / "cache", "999999999999", SCOPE)
        try:
            self.assertNotEqual(other.directory, self.store.directory)
            self.assertEqual(other.connection.execute("SELECT COUNT(*) FROM buckets").fetchone()[0], 0)
            with self.assertRaisesRegex(ValueError, "多个AWS账号"):
                CacheStore.discover(self.root / "cache", SCOPE)
            explicit = CacheStore.discover(self.root / "cache", SCOPE, ACCOUNT)
            explicit.close()
        finally:
            other.close()
        changed = CacheStore(self.root / "cache", ACCOUNT, {**SCOPE, "interval_minutes": 60})
        self.assertNotEqual(changed.directory, self.store.directory)
        changed.close()

    def test_overlapping_invocation_does_not_collect_twice(self):
        with _exclusive(self.store.directory / ".collect.lock") as locked:
            self.assertTrue(locked)
            def never(*args):
                self.fail("Another collection must not start while its OS lock is held")
            result = self.store.run_due(NOW, never, max_buckets=1)
        self.assertTrue(result["busy"])

    def test_failed_segment_older_than_lookback_is_recovered_with_bounded_work(self):
        def fail(*args):
            return {"status": 2, "retryable": False, "error": "temporary outage"}

        self.store.run_due(NOW, fail, max_buckets=1, lookback_hours=26)
        original = datetime(2026, 10, 29, 8, 30, tzinfo=UTC)
        self.assertEqual(self.store.bucket(original)["status"], "failed")
        windows = []
        def recover(start, end, target):
            windows.append((start, end))
            return snapshot(start, end, target)

        later = NOW + timedelta(hours=28)
        stats = self.store.run_due(later, recover, max_buckets=2, lookback_hours=26)
        self.assertEqual(stats["attempted_buckets"], 2)
        self.assertEqual(windows[1][0], original)
        self.assertEqual(self.store.bucket(original)["status"], "succeeded")

    def test_expired_failed_segment_is_retained_but_not_retried_forever(self):
        old = int((NOW - timedelta(days=91)).timestamp()) // 1800 * 1800
        self.store.connection.execute("INSERT INTO buckets(start,end,status,next_retry) VALUES(?,?,?,0)", (old, old + 1800, "failed"))
        self.store.connection.commit()
        called = []
        def collect(start, end, target):
            called.append(int(start.timestamp()))
            return snapshot(start, end, target)
        self.store.run_due(NOW, collect, max_buckets=6, lookback_hours=1)
        self.assertNotIn(old, called)
        self.assertEqual(self.store.connection.execute("SELECT status FROM buckets WHERE start=?", (old,)).fetchone()[0], "failed")


if __name__ == "__main__":
    unittest.main()
