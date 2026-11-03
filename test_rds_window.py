"""Fresh yesterday-to-now queries use fixed bounds and private account workers."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from zoneinfo import ZoneInfo

from rds_config import ACCOUNT_DEFAULTS, DEFAULTS
from rds_summary import SummaryAccumulator
from rds_window import FRESH_LOG_NOTE, collect_since_yesterday, window_identity
from test_rds_report import audit_event

UTC = timezone.utc
NOW = datetime(2026, 11, 3, 1, 23, 45, 123987, tzinfo=UTC)


class WindowIdentityTests(unittest.TestCase):
    def test_local_yesterday_midnight_and_exact_millisecond_floor(self):
        start, end, tag = window_identity({"TIMEZONE": "Asia/Shanghai"}, NOW)
        self.assertEqual(start, datetime(2026, 11, 1, 16, tzinfo=UTC))
        self.assertEqual(end, NOW.replace(microsecond=123000))
        self.assertEqual(tag, "since-yesterday-20261103T012345123Z")
        self.assertRegex(tag, r"\A[A-Za-z0-9_-]+\Z")
        self.assertEqual(window_identity({"TIMEZONE": "Asia/Shanghai"}, NOW.astimezone(ZoneInfo("Asia/Bangkok"))),
                         (start, end, tag))

    def test_dst_uses_local_calendar_yesterday_instead_of_subtracting_24_hours(self):
        zone = ZoneInfo("America/New_York")
        for today, expected_start, expected_hours in (
            (datetime(2026, 3, 9, 12, tzinfo=zone), datetime(2026, 3, 8, 5, tzinfo=UTC), 35),
            (datetime(2026, 11, 2, 12, tzinfo=zone), datetime(2026, 11, 1, 4, tzinfo=UTC), 37),
        ):
            with self.subTest(today=today):
                start, end, tag = window_identity({"TIMEZONE": "America/New_York"}, today)
                self.assertEqual(start, expected_start)
                self.assertEqual((end - start).total_seconds(), expected_hours * 3600)
                self.assertRegex(tag, r"\A[A-Za-z0-9_-]+\Z")

    def test_submillisecond_end_at_midnight_stays_on_the_correct_local_date(self):
        now = datetime(2026, 11, 3, 0, 0, 0, 999, tzinfo=ZoneInfo("Asia/Shanghai"))
        start, end, tag = window_identity({"TIMEZONE": "Asia/Shanghai"}, now)
        self.assertEqual(start, datetime(2026, 11, 1, 16, tzinfo=UTC))
        self.assertEqual(end, datetime(2026, 11, 2, 16, tzinfo=UTC))
        self.assertTrue(tag.endswith("000Z"))

    def test_naive_or_non_datetime_end_is_refused(self):
        for now in (datetime(2026, 11, 3), "2026-11-03", None):
            with self.subTest(now=now), self.assertRaises(ValueError):
                window_identity({"TIMEZONE": "UTC"}, now)


class FreshWindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {**deepcopy(DEFAULTS), "TIMEZONE": "Asia/Shanghai", "ACCOUNT_CONCURRENCY": 2,
                       "MAX_BUCKETS_PER_ACCOUNT_PER_RUN": 1,
                       "ACCOUNTS": [
                           {**ACCOUNT_DEFAULTS, "NAME": "production", "ACCOUNT_ID": "123456789012", "REGIONS": "us-east-1"},
                           {**ACCOUNT_DEFAULTS, "NAME": "staging", "ACCOUNT_ID": "210987654321", "REGIONS": "ap-east-1"},
                       ]}
        self.sessions = Mock(side_effect=lambda account: SimpleNamespace(account_id=account["ACCOUNT_ID"], key="PRIVATE-KEY"))
        self.identities = Mock(side_effect=lambda session, account: {"Account": session.account_id})

    def directory(self, account, tag):
        path = self.root / account["ACCOUNT_ID"] / tag
        path.mkdir(parents=True, exist_ok=True)
        (path / "marker.json").write_text(json.dumps({"account_id": account["ACCOUNT_ID"]}), encoding="utf-8")
        return path

    def summary(self, directory, start, end, count=1, times=None, unknown=False):
        with SummaryAccumulator(directory, start, end, dimension="ip") as accumulator:
            for index, when in enumerate(times if times is not None else [start] * count):
                accumulator.process_audit(audit_event(
                    sql="CALL private_procedure('PRIVATE-SQL')" if unknown else "UPDATE private_table SET secret='PRIVATE-SQL'",
                    when=when, event_id=str(index)))
            return accumulator.finish()

    def snapshot(self, directory, start, end, count=1):
        return {"summary": self.summary(directory, start, end, count), "complete": True, "errors": [], "audit_groups": 1}

    def run_collection(self, collector, **kwargs):
        return collect_since_yesterday(self.config, NOW, session_factory=kwargs.get("session_factory", self.sessions),
                                       identity_checker=kwargs.get("identity_checker", self.identities), collector=collector,
                                       directory_factory=kwargs.get("directory_factory", self.directory))

    def test_accounts_query_the_same_whole_window_once_without_segment_limit(self):
        calls = []

        def collector(config, account, session, identity, start, end, directory):
            calls.append((account["ACCOUNT_ID"], session, identity["Account"], start, end, directory))
            return self.snapshot(directory, start, end, count=1 if account["NAME"] == "production" else 3)

        reports = self.run_collection(collector)
        start, end, tag = window_identity(self.config, NOW)
        self.assertGreater((end - start).total_seconds(), 24 * 3600)
        self.assertEqual(len(calls), 2)  # No hourly/half-hourly slicing or six-bucket cap.
        self.assertEqual(self.sessions.call_count, 2)
        self.assertEqual(len({id(call[1]) for call in calls}), 2)
        self.assertTrue(all(call[0] == call[2] and call[3:5] == (start, end) for call in calls))
        self.assertEqual([report["account_id"] for report in reports], [account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"]])
        self.assertEqual([report["actors"][0]["total"] for report in reports], [1, 3])
        self.assertTrue(all(report["complete"] and report["artifact_tag"] == tag for report in reports))
        self.assertTrue(all(report["report_kind"] == "since_yesterday" and report["fresh_log_note"] == FRESH_LOG_NOTE for report in reports))
        self.assertTrue(all(report["date"] == "2026-11-03" for report in reports))
        self.assertTrue(all(report["window"]["end_exclusive"] == "2026-11-03T01:23:45.123000Z" for report in reports))
        self.assertTrue(all(not call[5].exists() for call in calls))

    def test_window_is_left_inclusive_right_exclusive_at_millisecond_boundary(self):
        start, end, _ = window_identity(self.config, NOW)
        times = [start - timedelta(milliseconds=1), start, end - timedelta(milliseconds=1), end, end + timedelta(milliseconds=1)]

        def collector(config, account, session, identity, left, right, directory):
            return {"summary": self.summary(directory, left, right, times=times), "complete": True, "errors": [], "audit_groups": 1}

        reports = self.run_collection(collector)
        self.assertTrue(all(report["actors"][0]["total"] == 2 for report in reports))
        self.assertTrue(all(report["complete"] for report in reports))

    def test_identity_mismatch_does_not_collect_or_mix_other_account_counts(self):
        checker = Mock(side_effect=lambda session, account: {"Account": "999999999999" if account["NAME"] == "production" else account["ACCOUNT_ID"]})
        collector = Mock(side_effect=lambda c, a, s, i, start, end, directory: self.snapshot(directory, start, end, 2))
        reports = self.run_collection(collector, identity_checker=checker)
        self.assertFalse(reports[0]["complete"])
        self.assertEqual(reports[0]["actors"], [])
        self.assertEqual(reports[0]["errors"][0]["error_type"], "ValueError")
        self.assertTrue(reports[1]["complete"])
        self.assertEqual(reports[1]["actors"][0]["total"], 2)
        collector.assert_called_once()
        self.assertEqual(collector.call_args.args[1]["ACCOUNT_ID"], "210987654321")

    def test_exception_is_sanitized_and_other_account_still_completes(self):
        def collector(config, account, session, identity, start, end, directory):
            (directory / "raw-sql.jsonl").write_text("PRIVATE-SQL", encoding="utf-8")
            if account["NAME"] == "production":
                raise RuntimeError("PRIVATE-KEY signed provider response PRIVATE-SQL")
            return self.snapshot(directory, start, end)

        reports = self.run_collection(collector)
        self.assertEqual(reports[0]["errors"], [{"scope": "collection", "error_type": "RuntimeError"}])
        self.assertFalse(reports[0]["complete"])
        self.assertTrue(reports[1]["complete"])
        self.assertNotIn("PRIVATE", json.dumps(reports))
        self.assertFalse(list(self.root.rglob("*.jsonl")))
        self.assertFalse(list(self.root.rglob(".window-attempt-*")))

    def test_returned_report_contains_only_whitelisted_summary_fields(self):
        def collector(config, account, session, identity, start, end, directory):
            snapshot = self.snapshot(directory, start, end)
            snapshot.update(raw_sql="PRIVATE-SQL", provider_response={"secret": "PRIVATE-KEY"})
            snapshot["summary"]["raw_sql"] = "PRIVATE-SQL"
            snapshot["summary"]["actors"][0]["sql"] = "PRIVATE-SQL"
            return snapshot

        reports = self.run_collection(collector)
        expected = {"schema_version", "dimension", "summary_only", "account_id", "account_name", "date", "timezone",
                    "generated_at", "window", "actors", "coverage", "complete", "errors", "audit_groups", "scope",
                    "report_kind", "artifact_tag", "fresh_log_note"}
        self.assertTrue(all(set(report) == expected for report in reports))
        self.assertNotIn("PRIVATE", json.dumps(reports))
        self.assertEqual({path.name for path in self.root.rglob("*") if path.is_file()}, {"marker.json"})

    def test_unknown_sql_parsing_keeps_report_incomplete_without_retaining_sql(self):
        def collector(config, account, session, identity, start, end, directory):
            return {"summary": self.summary(directory, start, end, unknown=True), "complete": False, "errors": [], "audit_groups": 1}

        reports = self.run_collection(collector)
        self.assertTrue(all(not report["complete"] and not report["actors"] for report in reports))
        self.assertTrue(all(report["coverage"]["unclassified"] == 1 for report in reports))
        self.assertTrue(all(report["errors"] for report in reports))
        self.assertNotIn("PRIVATE", json.dumps(reports))

    def test_no_audit_groups_cannot_be_reported_as_complete(self):
        def collector(config, account, session, identity, start, end, directory):
            snapshot = self.snapshot(directory, start, end)
            snapshot["audit_groups"] = 0
            return snapshot

        reports = self.run_collection(collector)
        self.assertTrue(all(not report["complete"] for report in reports))
        self.assertTrue(all(report["actors"][0]["total"] == 1 for report in reports))
        self.assertTrue(all(any(error.get("error_type") == "NoAuditLogGroups" for error in report["errors"]) for report in reports))

    def test_provider_error_fields_are_reduced_to_safe_types(self):
        def collector(config, account, session, identity, start, end, directory):
            snapshot = self.snapshot(directory, start, end)
            snapshot.update(complete=False, errors=[{"scope": "PRIVATE-SQL", "message": "PRIVATE-KEY", "error_type": "AccessDenied"}])
            return snapshot

        reports = self.run_collection(collector)
        self.assertTrue(all(report["errors"] == [{"scope": "collection", "error_type": "AccessDenied"}] for report in reports))
        self.assertNotIn("PRIVATE", json.dumps(reports))

    def test_invalid_summary_or_wrong_window_cannot_be_accepted(self):
        for mutation in (lambda value: value["summary"].update(schema_version=1),
                         lambda value: value["summary"]["window"].update(end_exclusive="2026-11-03T01:23:46Z"),
                         lambda value: value.update(complete="yes"),
                         lambda value: value.update(audit_groups=True)):
            def collector(config, account, session, identity, start, end, directory):
                snapshot = self.snapshot(directory, start, end)
                mutation(snapshot)
                return snapshot

            with self.subTest(mutation=mutation):
                reports = self.run_collection(collector)
                self.assertTrue(all(not report["complete"] and report["actors"] == [] for report in reports))
                self.assertTrue(all(report["errors"][0]["error_type"] == "ValueError" for report in reports))

    def test_directory_failure_returns_explicit_incomplete_report_for_renderer_to_handle(self):
        def directory(account, tag):
            if account["NAME"] == "production":
                raise OSError("PRIVATE-DIRECTORY provider response")
            return self.directory(account, tag)

        collector = Mock(side_effect=lambda c, a, s, i, start, end, output: self.snapshot(output, start, end))
        reports = self.run_collection(collector, directory_factory=directory)
        self.assertFalse(reports[0]["complete"])
        self.assertEqual(reports[0]["errors"][0]["error_type"], "OSError")
        self.assertTrue(reports[1]["complete"])
        collector.assert_called_once()
        self.assertNotIn("PRIVATE", json.dumps(reports))

    def test_configured_parallelism_overlaps_accounts_and_preserves_result_order(self):
        self.config["ACCOUNTS"].append({**ACCOUNT_DEFAULTS, "NAME": "third", "ACCOUNT_ID": "321098765432", "REGIONS": "us-east-1"})
        barrier = threading.Barrier(2)
        participants = {account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"][:2]}
        lock = threading.Lock()
        active = peak = 0

        def collector(config, account, session, identity, start, end, directory):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                if account["ACCOUNT_ID"] in participants:
                    barrier.wait(timeout=15)
                return self.snapshot(directory, start, end)
            finally:
                with lock:
                    active -= 1

        reports = self.run_collection(collector)
        self.assertEqual(peak, 2)
        self.assertTrue(all(report["complete"] for report in reports))
        self.assertEqual([report["account_id"] for report in reports], [account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"]])

    def test_disabled_accounts_never_create_session_or_output(self):
        for account in self.config["ACCOUNTS"]:
            account["ENABLED"] = False
        factory, collector, directory = Mock(), Mock(), Mock()
        self.assertEqual(self.run_collection(collector, session_factory=factory, directory_factory=directory), [])
        factory.assert_not_called()
        collector.assert_not_called()
        directory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
