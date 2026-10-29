"""Committed quality state survives empty rounds, failures and process restarts."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rds_cache import CacheStore

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 9, 5, tzinfo=UTC)
ACCOUNT = "123456789012"
SCOPE = {"profile": "audit", "regions": "ap-east-1", "interval_minutes": 30, "filter_version": "changes-v1"}


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def snapshot(start, end, directory, *, problem=False, account=ACCOUNT):
    errors = [{"status": "error", "error_type": "UnclassifiedSqlRecords", "message": "unclassified record"}] if problem else []
    report = {"identity": {"Account": account}, "window": {"start_inclusive": iso(start), "end_exclusive": iso(end)}, "collection_status": "partial" if problem else "ok", "checks": errors, "regions": {}}
    (directory / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (directory / "management-events.jsonl").write_text("", encoding="utf-8")
    return {"status": 0, "success": True, "quality_partial": problem}


def quality_snapshot(start, end, target):
    return snapshot(start, end, target, problem=True)


class QualityCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = CacheStore(self.root / "cache", ACCOUNT, SCOPE)

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def commit_problem(self):
        stats = self.store.run_due(NOW, quality_snapshot, max_buckets=1, lookback_hours=1)
        self.assertEqual(stats["succeeded"], 1)
        start = NOW.replace(hour=8, minute=30)
        return start, self.store.bucket(start)

    def test_problem_is_persistent_and_other_empty_segment_does_not_clear_it(self):
        self.commit_problem()
        initial = self.store.quality_status()
        self.assertEqual(initial["problem_segments"], 1)
        self.assertEqual(initial["unknown_segments"], 0)
        self.store.close()
        self.store = CacheStore(self.root / "cache", ACCOUNT, SCOPE)
        self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        after = self.store.quality_status()
        self.assertEqual(after, initial)
        self.assertEqual(after["segments"][0]["start"], "2026-10-29T08:30:00Z")

    def test_only_healthy_success_for_same_problem_window_clears_problem(self):
        self.commit_problem()
        self.store.run_due(NOW, snapshot, max_buckets=1, lookback_hours=1)
        self.assertEqual(self.store.quality_status()["problem_segments"], 1)
        self.store.run_due(NOW + timedelta(hours=1), snapshot, max_buckets=6, lookback_hours=2)
        status = self.store.quality_status()
        self.assertEqual(status["problem_segments"], 0)
        self.assertEqual(status["unknown_segments"], 0)
        self.assertEqual(status["segments"], [])
        self.assertEqual(status["fingerprint"], self.store.quality_status()["fingerprint"])

    def test_failed_refresh_cannot_overwrite_committed_quality(self):
        start, old = self.commit_problem()
        self.store.connection.execute("UPDATE buckets SET status='failed',next_retry=0 WHERE start=?", (int(start.timestamp()),))
        self.store.connection.commit()

        def fail(a, b, target):
            snapshot(a, b, target)
            return {"status": 2, "retryable": False, "error": "network response incomplete"}

        self.store.run_due(NOW, fail, max_buckets=1, lookback_hours=1, sleep=lambda _: None)
        self.assertEqual(self.store.bucket(start)["active_path"], old["active_path"])
        self.assertEqual(self.store.quality_status()["problem_segments"], 1)

    def test_legacy_metadata_backfill_is_cached_and_never_reads_sql_archive(self):
        self.commit_problem()
        self.store.connection.execute("DELETE FROM quality_snapshots")
        self.store.connection.commit()
        original = Path.read_bytes
        observed = []

        def guarded(path):
            observed.append(path.name)
            self.assertEqual(path.name, "report.json")
            return original(path)

        with patch.object(Path, "read_bytes", guarded):
            self.assertEqual(self.store.quality_status()["problem_segments"], 1)
            self.assertEqual(self.store.quality_status()["problem_segments"], 1)
        self.assertEqual(observed, ["report.json"])

    def test_missing_or_changed_metadata_is_unknown_and_cannot_report_recovery(self):
        start, bucket = self.commit_problem()
        self.assertEqual(self.store.quality_status()["problem_segments"], 1)
        report_path = self.store.directory / bucket["active_path"] / "report.json"
        raw = report_path.read_bytes()
        report_path.unlink()
        self.assertEqual(self.store.quality_status()["unknown_segments"], 1)
        report_path.write_bytes(raw)
        self.assertEqual(self.store.quality_status()["problem_segments"], 1)
        source = json.loads(raw)
        source.update(checks=[], collection_status="ok")
        report_path.write_text(json.dumps(source), encoding="utf-8")
        self.assertEqual(self.store.quality_status()["unknown_segments"], 1)

    def test_corrupt_legacy_metadata_and_missing_ledger_are_not_clean(self):
        start, bucket = self.commit_problem()
        self.store.connection.execute("DELETE FROM quality_snapshots")
        self.store.connection.commit()
        (self.store.directory / bucket["active_path"] / "report.json").write_text("{broken", encoding="utf-8")
        self.assertEqual(self.store.quality_status()["unknown_segments"], 1)
        self.store.connection.execute("DELETE FROM buckets WHERE start=?", (int(start.timestamp()),))
        self.store.connection.commit()
        self.assertEqual(self.store.quality_status()["unknown_segments"], 1)

    def test_historical_problem_does_not_expire_with_collection_lookback(self):
        self.commit_problem()
        previous = self.store.quality_status()
        self.store.run_due(NOW + timedelta(days=3), snapshot, max_buckets=1, lookback_hours=1)
        self.assertEqual(self.store.quality_status(), previous)

    def test_accounts_and_scopes_do_not_share_quality_problems(self):
        self.commit_problem()
        other = CacheStore(self.root / "cache", "999999999999", SCOPE)
        changed = CacheStore(self.root / "cache", ACCOUNT, {**SCOPE, "regions": "all"})
        try:
            self.assertEqual(other.quality_status()["problem_segments"], 0)
            self.assertEqual(changed.quality_status()["problem_segments"], 0)
            self.assertEqual(self.store.quality_status()["problem_segments"], 1)
        finally:
            other.close()
            changed.close()

    def test_repeated_same_problem_content_has_stable_fingerprint_despite_new_path(self):
        start, old = self.commit_problem()
        initial = self.store.quality_status()
        self.store.connection.execute("UPDATE buckets SET status='failed',next_retry=0 WHERE start=?", (int(start.timestamp()),))
        self.store.connection.commit()
        self.store.run_due(NOW, quality_snapshot, max_buckets=1, lookback_hours=1)
        self.assertNotEqual(self.store.bucket(start)["active_path"], old["active_path"])
        self.assertEqual(self.store.quality_status(), initial)


if __name__ == "__main__":
    unittest.main()
