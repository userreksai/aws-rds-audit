"""Quality incidents follow committed problem segments, never unrelated success."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import rds_audit as audit
import rds_jobs as jobs

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 13, 5, tzinfo=UTC)
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "999999999999"
SCOPE = {"profile": "audit", "regions": "ap-east-1", "interval_minutes": 30, "filter_version": "changes-v1"}


def quality_status(*problems, unknown=()):
    segments = []
    for state, values in (("problem", problems), ("unknown", unknown)):
        for offset in values:
            start = NOW.replace(minute=0) - timedelta(minutes=30 * (offset + 1))
            segments.append({"start": audit.iso(start), "end": audit.iso(start + timedelta(minutes=30)), "state": state, "digest": "digest-" + str(offset)})
    segments.sort(key=lambda row: row["start"])
    fingerprint = hashlib.sha256(json.dumps(segments, sort_keys=True).encode()).hexdigest()
    return {"problem_segments": len(problems), "unknown_segments": len(unknown), "segments": segments, "fingerprint": fingerprint}


class QualityIncidentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.box = jobs.OpsOutbox(self.root, SCOPE)
        self.store = SimpleNamespace(account_id=ACCOUNT, directory=self.root / ACCOUNT, quality_status=Mock(return_value=quality_status()))
        self.notices = []

    def tearDown(self):
        self.box.close()
        self.temporary.cleanup()

    def sync(self, status, *, at=NOW, store=None):
        target = store or self.store
        target.quality_status.return_value = status
        self.box.sync_quality(target, at)
        self.box.flush(self.notices.append, at)

    def incident(self, account=ACCOUNT):
        return self.box.db.execute("SELECT * FROM incidents WHERE key=?", (self.box.scope_id + ":quality:" + account,)).fetchone()

    def test_problem_empty_round_new_problem_do_not_flap_or_reset_generation(self):
        self.sync(quality_status(0))
        # A later round may only collect unrelated empty buckets. The committed
        # problem set still contains the first bad segment.
        self.sync(quality_status(0), at=NOW + timedelta(minutes=5))
        self.sync(quality_status(0, 1), at=NOW + timedelta(minutes=10))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial"])
        self.assertTrue(self.incident()["is_open"])
        self.assertEqual(self.incident()["generation"], 1)
        # A changed set suppressed inside the hour is delivered on a later wake.
        self.sync(quality_status(0, 1), at=NOW + timedelta(minutes=61))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial", "quality_partial"])
        self.assertEqual(self.incident()["generation"], 1)
        self.assertNotEqual(self.notices[0]["event_id"], self.notices[1]["event_id"])

    def test_unchanged_historical_problem_does_not_repeat_hourly_after_restart(self):
        self.sync(quality_status(0))
        self.box.close()
        self.box = jobs.OpsOutbox(self.root, SCOPE)
        self.sync(quality_status(0), at=NOW + timedelta(hours=2))
        self.sync(quality_status(0), at=NOW + timedelta(days=3))
        self.assertEqual(len(self.notices), 1)
        self.assertEqual(self.incident()["generation"], 1)
        self.assertTrue(self.incident()["is_open"])

    def test_unknown_state_blocks_recovery_and_all_healthy_recovers_once(self):
        self.sync(quality_status(0))
        self.sync(quality_status(unknown=(0,)), at=NOW + timedelta(minutes=5))
        self.assertFalse(any(row["kind"] == "recovered" for row in self.notices))
        self.assertTrue(self.incident()["is_open"])
        self.sync(quality_status(), at=NOW + timedelta(minutes=10))
        self.sync(quality_status(), at=NOW + timedelta(minutes=15))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial", "recovered"])
        self.assertFalse(self.incident()["is_open"])

    def test_pending_legacy_false_recovery_is_cancelled_and_throttle_is_preserved(self):
        self.box.failure("quality", {"kind": "quality_partial", "account_id": ACCOUNT, "message": "old quality problem"}, NOW)
        self.box.flush(self.notices.append, NOW)
        self.box.recovery("quality", {"account_id": ACCOUNT, "message": "old unrelated empty round"}, NOW + timedelta(minutes=5))
        self.box.close()
        self.box = jobs.OpsOutbox(self.root, SCOPE)
        self.sync(quality_status(0), at=NOW + timedelta(minutes=10))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial"])
        self.assertTrue(self.incident()["is_open"])
        self.assertEqual(self.incident()["generation"], 1)
        self.assertEqual(self.incident()["last_notice"], int(NOW.timestamp()))

    def test_healthy_other_account_cannot_close_existing_quality_incident(self):
        self.sync(quality_status(0))
        other = SimpleNamespace(account_id=OTHER_ACCOUNT, directory=self.root / OTHER_ACCOUNT, quality_status=Mock())
        self.sync(quality_status(), at=NOW + timedelta(minutes=5), store=other)
        self.assertTrue(self.incident()["is_open"])
        self.assertFalse(any(row["kind"] == "recovered" for row in self.notices))
        self.sync(quality_status(0), at=NOW + timedelta(minutes=10), store=other)
        self.assertEqual([row["account_id"] for row in self.notices], [ACCOUNT, OTHER_ACCOUNT])
        self.assertTrue(self.incident(OTHER_ACCOUNT)["is_open"])

    def test_legacy_older_sent_generation_cannot_hide_current_pending_failure(self):
        self.box.failure("quality", {"kind": "quality_partial", "account_id": ACCOUNT, "message": "old"}, NOW)
        self.box.flush(self.notices.append, NOW)
        self.box.recovery("quality", {"account_id": ACCOUNT}, NOW + timedelta(minutes=1))
        self.box.flush(self.notices.append, NOW + timedelta(minutes=1))
        self.box.failure("quality", {"kind": "quality_partial", "account_id": ACCOUNT, "message": "new still pending"}, NOW + timedelta(minutes=2))
        self.sync(quality_status(0), at=NOW + timedelta(minutes=3))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial", "recovered", "quality_partial"])
        self.assertEqual(self.incident()["generation"], 2)

    def test_deferred_quality_notices_do_not_starve_operational_alerts(self):
        for index in range(35):
            self.box.failure("quality:" + str(index), {"kind": "quality_partial"}, NOW)
        self.box.failure("identity", {"kind": "collection_start_failure"}, NOW)
        self.assertEqual(self.box.flush(self.notices.append, NOW, include_quality=False), 0)
        self.assertEqual([row["kind"] for row in self.notices], ["collection_start_failure"])
        self.assertEqual(self.box.db.execute("SELECT count(*) FROM notices WHERE status='pending'").fetchone()[0], 35)

    def test_failed_quality_delivery_is_retried_without_new_incident(self):
        self.store.quality_status.return_value = quality_status(0)
        self.box.sync_quality(self.store, NOW)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(self.box.flush(Mock(side_effect=OSError("test transport outage")), NOW), 1)
        self.sync(quality_status(0), at=NOW + timedelta(minutes=5))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial"])
        self.assertEqual(self.incident()["generation"], 1)
        self.assertEqual(self.box.db.execute("SELECT count(*) FROM notices WHERE status='pending'").fetchone()[0], 0)

    def test_new_problem_cancels_recovery_that_was_still_waiting_for_delivery(self):
        self.sync(quality_status(0))
        self.store.quality_status.return_value = quality_status()
        self.box.sync_quality(self.store, NOW + timedelta(minutes=5))
        # A true recovery was queued, but never delivered. Before its retry a
        # different committed segment has another problem.
        self.store.quality_status.return_value = quality_status(1)
        self.box.sync_quality(self.store, NOW + timedelta(minutes=10))
        self.box.flush(self.notices.append, NOW + timedelta(minutes=10))
        self.assertEqual([row["kind"] for row in self.notices], ["quality_partial", "quality_partial"])
        self.assertTrue(self.incident()["is_open"])
        self.assertEqual(self.incident()["generation"], 2)
        pending_recoveries = self.box.db.execute("SELECT count(*) FROM notices WHERE status='pending' AND id LIKE '%:recovered'").fetchone()[0]
        self.assertEqual(pending_recoveries, 0)


class IncrementalQualityIntegrationTests(unittest.TestCase):
    def test_actual_jobs_bad_then_empty_then_bad_keep_one_quality_incident(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = audit.build_parser().parse_args([
                "--collect-incremental", "--profile", "audit", "--regions", "ap-east-1",
                "--cache-dir", str(root / "cache"), "--output-dir", str(root / "reports"),
                "--max-buckets-per-run", "1", "--cache-lookback-hours", "1",
            ])
            notices = []
            outcomes = iter((True, False, True, False))

            def collect(instance):
                bad = next(outcomes)
                errors = [{"scope": "sql", "status": "error", "error_type": "UnclassifiedSqlRecords", "message": "1 isolated test record"}] if bad else []
                source = {
                    "identity": {"Account": ACCOUNT},
                    "window": {"start_inclusive": audit.iso(instance.start), "end_exclusive": audit.iso(instance.end)},
                    "collection_status": "partial" if bad else "ok", "checks": errors, "regions": {},
                }
                (instance.directory / "report.json").write_text(json.dumps(source), encoding="utf-8")
                (instance.directory / "management-events.jsonl").write_text("", encoding="utf-8")
                if bad:
                    quarantine = instance.directory / "quarantine"
                    quarantine.mkdir()
                    (quarantine / "sql-unclassified.jsonl").write_text(json.dumps({"reason": "unclassified_sql", "raw": "TEST-ONLY UNKNOWN"}) + "\n", encoding="utf-8")
                instance.report.update(collection_status=source["collection_status"], checks=errors)
                return 2 if bad else 0

            with patch.object(audit, "aws_session", return_value=(Mock(), None, {"Account": ACCOUNT, "Arn": "TEST"})), \
                    patch.object(audit.Collector, "run", collect), patch.object(jobs, "_notifier", return_value=notices.append), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                for minutes in (0, 5, 30):
                    self.assertEqual(jobs.run_incremental(options, api=audit, now=NOW + timedelta(minutes=minutes)), 0)
                self.assertEqual([row["kind"] for row in notices], ["quality_partial"])
                self.assertEqual(jobs.run_incremental(options, api=audit, now=NOW + timedelta(minutes=65)), 0)
            self.assertEqual([row["kind"] for row in notices], ["quality_partial", "quality_partial"])
            box = jobs.OpsOutbox(options.cache_dir, jobs.cache_scope(options))
            try:
                row = box.db.execute("SELECT * FROM incidents WHERE key=?", (box.scope_id + ":quality:" + ACCOUNT,)).fetchone()
                self.assertTrue(row["is_open"])
                self.assertEqual(row["generation"], 1)
            finally:
                box.close()


if __name__ == "__main__":
    unittest.main()
