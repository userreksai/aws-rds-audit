"""Exercise account isolation, interval recovery and combined-mail receipts offline."""
from copy import deepcopy
from contextlib import redirect_stdout, redirect_stderr
from datetime import date, datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import ModuleType
import unittest
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

import rds_multi as multi
from rds_config import ACCOUNT_DEFAULTS, DEFAULTS
from rds_mail import MailDeliveryError
from rds_summary import SummaryAccumulator
from test_rds_report import audit_event

UTC = timezone.utc
DAY = date(2026, 11, 3)
MIDNIGHT = datetime(2026, 11, 3, tzinfo=UTC)


class MultiFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = {**deepcopy(DEFAULTS), "OUTPUT_DIRECTORY": str(self.root / "data"),
                       "TIMEZONE": "UTC", "ACCOUNT_CONCURRENCY": 1, "SMTP_HOST": "smtp.example.com",
                       "SMTP_USERNAME": "audit@example.com", "SMTP_AUTH_CODE": "PRIVATE-SMTP-CODE",
                       "MAIL_RECIPIENTS": ["recipient@example.com"], "MAIL_CC": ["copy@example.com"],
                       "ACCOUNTS": [
                           {**ACCOUNT_DEFAULTS, "NAME": "production", "ACCOUNT_ID": "123456789012",
                            "REGIONS": "us-east-1", "AWS_ACCESS_KEY_ID": "PRIVATE-KEY-ONE", "AWS_SECRET_ACCESS_KEY": "PRIVATE-SECRET-ONE"},
                           {**ACCOUNT_DEFAULTS, "NAME": "staging", "ACCOUNT_ID": "210987654321",
                            "REGIONS": "us-east-1", "AWS_ACCESS_KEY_ID": "PRIVATE-KEY-TWO", "AWS_SECRET_ACCESS_KEY": "PRIVATE-SECRET-TWO"},
                       ]}
        self.account = self.config["ACCOUNTS"][0]
        self.addCleanup(patch.stopall)
        patch.object(multi, "sdk_config", return_value=None).start()

    def session(self, account, *, mismatch=False):
        session = Mock()
        session.client.return_value.get_caller_identity.return_value = {
            "Account": "999999999999" if mismatch else account["ACCOUNT_ID"],
            "Arn": "arn:aws:iam::" + account["ACCOUNT_ID"] + ":user/audit",
        }
        return session

    def summary(self, start, end, count=1, source="192.0.2.22"):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            with SummaryAccumulator(directory, start, end, dimension="ip") as accumulator:
                for index in range(count):
                    event = audit_event(when=start, event_id=str(index))
                    fields = event["message"].split(",", 8)
                    fields[3] = source
                    event["message"] = ",".join(fields)
                    accumulator.process_audit(event)
                return accumulator.finish()

    def snapshot(self, start, end, count=1, complete=True, errors=None):
        return {"summary": self.summary(start, end, count), "complete": complete,
                "audit_groups": 1, "errors": errors or []}

    def seed_start(self, account=None, day=DAY):
        account = account or self.account
        root = multi.account_directory(self.config, account)
        multi.atomic_json(root / (".scope-" + multi.scope_id(self.config, account) + ".json"),
                          {"first_date": day.isoformat()})

    def checkpoint(self, start, end, account=None, count=1, refresh_done=True):
        account = account or self.account
        path = multi.bucket_path(self.config, account, start)
        value = {"schema_version": 1, "scope": multi.scope_for(self.config, account),
                 "window": {"start_inclusive": multi.iso(start), "end_exclusive": multi.iso(end)},
                 "active": self.snapshot(start, end, count), "refresh_done": refresh_done,
                 "attempts": 1, "next_retry": 0, "last_errors": []}
        multi.atomic_json(path, value)
        return path

    def fake_pdf(self, report, destination, **kwargs):
        destination = Path(destination)
        destination.write_bytes(b"%PDF-1.4\n" + report["account_id"].encode())
        return destination

    def simple_report(self, config, account, day, now):
        start, end = multi.day_window(day, ZoneInfo(config["TIMEZONE"]))
        return {**self.summary(start, end), "account_id": account["ACCOUNT_ID"],
                "account_name": account["NAME"], "date": day.isoformat(), "complete": True,
                "timezone": config["TIMEZONE"], "generated_at": multi.iso(now),
                "segments": {"expected": 48, "present": 48}, "errors": [],
                "scope": multi.scope_for(config, account)}

    def configuration_path(self):
        path = self.root / "private.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        return path


class AccountCollectionTests(MultiFixture):
    def test_real_collector_adapter_reads_only_audit_and_keeps_source_ip(self):
        start, end = MIDNIGHT, MIDNIGHT + timedelta(minutes=30)
        event = audit_event(when=start)
        group = "/aws/rds/cluster/production/audit"
        logs, cloudtrail, session = Mock(), Mock(), Mock()
        logs.describe_log_groups.return_value = {"logGroups": [{"logGroupName": group}]}
        logs.filter_log_events.return_value = {"events": [event]}
        cloudtrail.lookup_events.return_value = {"Events": []}
        session.client.side_effect = lambda service, **kwargs: {"logs": logs, "cloudtrail": cloudtrail}[service]
        directory = self.root / "collector-adapter"
        directory.mkdir()
        snapshot = multi.collect_bucket(self.config, self.account, session, {"Account": self.account["ACCOUNT_ID"]}, start, end, directory)
        self.assertTrue(snapshot["complete"])
        self.assertEqual(snapshot["summary"]["dimension"], "ip")
        self.assertEqual(snapshot["summary"]["actors"][0]["source_ip"], "192.0.2.22")
        self.assertEqual(snapshot["summary"]["actors"][0]["counts"]["修改"], 1)
        self.assertEqual(logs.filter_log_events.call_args.kwargs["startTime"], int(start.timestamp() * 1000))
        self.assertEqual(logs.filter_log_events.call_args.kwargs["endTime"], int(end.timestamp() * 1000))
        self.assertEqual({call.args[0] for call in session.client.call_args_list}, {"logs", "cloudtrail"})
        self.assertFalse(list(directory.rglob("*.jsonl")))
        for path in directory.rglob("*.json"):
            self.assertNotIn("UPDATE users", path.read_text(encoding="utf-8"))

    def test_two_accounts_have_separate_sessions_directories_and_checkpoints(self):
        for account in self.config["ACCOUNTS"]:
            self.seed_start(account)
        factory = Mock(side_effect=self.session)
        collected = []

        def collector(config, account, session, identity, start, end, directory):
            collected.append((account["ACCOUNT_ID"], session, identity["Account"], start, end))
            return self.snapshot(start, end, count=1 if account is self.account else 2)

        with redirect_stdout(StringIO()):
            results = multi.collect_accounts(self.config, MIDNIGHT + timedelta(minutes=35),
                                             session_factory=factory, collector=collector)
        self.assertEqual([(row["processed"], row["failed"]) for row in results], [(1, 0), (1, 0)])
        self.assertEqual(factory.call_count, 2)
        self.assertIsNot(collected[0][1], collected[1][1])
        self.assertEqual([row[0] for row in collected], [row[2] for row in collected])
        for index, account in enumerate(self.config["ACCOUNTS"], 1):
            report = multi.build_report(self.config, account, DAY, MIDNIGHT + timedelta(minutes=35))
            self.assertEqual(report["account_id"], account["ACCOUNT_ID"])
            self.assertEqual(report["actors"][0]["total"], index)
            self.assertEqual(report["segments"], {"expected": 1, "present": 1})
            self.assertTrue(report["complete"])
        text = "\n".join(path.read_text(encoding="utf-8") for path in Path(self.config["OUTPUT_DIRECTORY"]).rglob("*.json"))
        for secret in ("PRIVATE-KEY", "PRIVATE-SECRET", "PRIVATE-SMTP", "UPDATE users"):
            self.assertNotIn(secret, text)

    def test_identity_mismatch_stops_before_any_cloudwatch_collection(self):
        collector = Mock()
        with self.assertRaisesRegex(ValueError, "ACCOUNT_ID"):
            multi.collect_account(self.config, self.account, MIDNIGHT + timedelta(minutes=35),
                                  session_factory=lambda account: self.session(account, mismatch=True), collector=collector)
        collector.assert_not_called()
        self.assertFalse(Path(self.config["OUTPUT_DIRECTORY"]).exists())

    def test_account_failure_does_not_block_other_accounts_or_leak_provider_text(self):
        for account in self.config["ACCOUNTS"]:
            self.seed_start(account)

        def collector(config, account, session, identity, start, end, directory):
            if account is self.account:
                raise RuntimeError("PRIVATE-SECRET-ONE provider response DO-NOT-ECHO")
            return self.snapshot(start, end, count=2)

        output = StringIO()
        with redirect_stdout(output):
            results = multi.collect_accounts(self.config, MIDNIGHT + timedelta(minutes=35),
                                             session_factory=self.session, collector=collector)
        self.assertEqual([row["failed"] for row in results], [1, 0])
        good = multi.build_report(self.config, self.config["ACCOUNTS"][1], DAY, MIDNIGHT + timedelta(minutes=35))
        self.assertEqual(good["actors"][0]["total"], 2)
        self.assertNotIn("DO-NOT-ECHO", output.getvalue())
        for path in Path(self.config["OUTPUT_DIRECTORY"]).rglob("*.json"):
            self.assertNotIn("DO-NOT-ECHO", path.read_text(encoding="utf-8"))

    def test_disabled_accounts_are_never_authenticated(self):
        self.config["ACCOUNTS"][1]["ENABLED"] = False
        self.seed_start()
        factory = Mock(side_effect=self.session)
        with redirect_stdout(StringIO()):
            results = multi.collect_accounts(self.config, MIDNIGHT + timedelta(minutes=35), session_factory=factory,
                                             collector=lambda c, a, s, i, start, end, d: self.snapshot(start, end))
        self.assertEqual(len(results), 1)
        factory.assert_called_once_with(self.account)

    def test_half_hour_and_hour_collection_wait_for_completed_buffered_bucket(self):
        for interval in (30, 60):
            with self.subTest(interval=interval):
                self.config["COLLECTION_INTERVAL_MINUTES"] = interval
                self.seed_start()
                collector = Mock(side_effect=lambda c, a, s, i, start, end, d: self.snapshot(start, end))
                early = MIDNIGHT + timedelta(minutes=interval + 4, seconds=59)
                result = multi.collect_account(self.config, self.account, early, session_factory=self.session, collector=collector)
                self.assertEqual(result["processed"], 0)
                collector.assert_not_called()
                result = multi.collect_account(self.config, self.account, MIDNIGHT + timedelta(minutes=interval + 5),
                                               session_factory=self.session, collector=collector)
                self.assertEqual(result["processed"], 1)
                self.assertEqual(collector.call_args.args[4:6], (MIDNIGHT, MIDNIGHT + timedelta(minutes=interval)))

    def test_delayed_refresh_replaces_snapshot_and_never_adds_old_count(self):
        self.seed_start()
        start, end = MIDNIGHT, MIDNIGHT + timedelta(minutes=30)
        target = self.checkpoint(start, end, count=1, refresh_done=False)
        for offset in (30, 60, 90):
            self.checkpoint(MIDNIGHT + timedelta(minutes=offset), MIDNIGHT + timedelta(minutes=offset + 30), count=0)
        collector = Mock(side_effect=lambda c, a, s, i, left, right, d: self.snapshot(left, right, count=3))
        now = MIDNIGHT + timedelta(hours=2, minutes=5)
        result = multi.collect_account(self.config, self.account, now, session_factory=self.session, collector=collector)
        self.assertEqual(result["processed"], 1)
        self.assertEqual(collector.call_args.args[4:6], (start, end))
        self.assertTrue(multi.read_json(target)["refresh_done"])
        report = multi.build_report(self.config, self.account, DAY, now)
        self.assertEqual(report["actors"][0]["total"], 3)
        self.assertTrue(report["complete"])
        collector.reset_mock()
        self.assertEqual(multi.collect_account(self.config, self.account, now, session_factory=self.session, collector=collector)["processed"], 0)
        collector.assert_not_called()

    def test_failed_refresh_preserves_previous_good_result_and_marks_report_incomplete(self):
        self.seed_start()
        start, end = MIDNIGHT, MIDNIGHT + timedelta(minutes=30)
        target = self.checkpoint(start, end, count=2, refresh_done=False)
        for offset in (30, 60, 90):
            self.checkpoint(MIDNIGHT + timedelta(minutes=offset), MIDNIGHT + timedelta(minutes=offset + 30), count=0)
        now = MIDNIGHT + timedelta(hours=2, minutes=5)
        collector = Mock(side_effect=lambda c, a, s, i, left, right, d: self.snapshot(
            left, right, count=9, complete=False, errors=[{"scope": "logs", "error_type": "AccessDenied"}]))
        result = multi.collect_account(self.config, self.account, now, session_factory=self.session, collector=collector)
        self.assertEqual(result["failed"], 1)
        state = multi.read_json(target)
        self.assertEqual(state["active"]["summary"]["actors"][0]["total"], 2)
        self.assertFalse(state["refresh_done"])
        report = multi.build_report(self.config, self.account, DAY, now)
        self.assertEqual(report["actors"][0]["total"], 2)
        self.assertFalse(report["complete"])
        collector.reset_mock()
        self.assertEqual(multi.collect_account(self.config, self.account, now + timedelta(minutes=4),
                                              session_factory=self.session, collector=collector)["processed"], 0)
        collector.assert_not_called()

    def test_missing_segments_are_reported_as_incomplete_instead_of_zero_success(self):
        self.checkpoint(MIDNIGHT, MIDNIGHT + timedelta(minutes=30), count=4)
        report = multi.build_report(self.config, self.account, DAY, MIDNIGHT + timedelta(days=1, hours=1))
        self.assertEqual(report["segments"], {"expected": 48, "present": 1})
        self.assertEqual(report["actors"][0]["total"], 4)
        self.assertFalse(report["complete"])
        self.assertEqual(sum(error["error_type"] == "MissingOrInvalidBucket" for error in report["errors"]), 47)

    def test_other_account_or_old_user_schema_checkpoint_cannot_enter_report(self):
        start, end = MIDNIGHT, MIDNIGHT + timedelta(minutes=30)
        path = self.checkpoint(start, end)
        value = multi.read_json(path)
        value["scope"]["account_id"] = self.config["ACCOUNTS"][1]["ACCOUNT_ID"]
        multi.atomic_json(path, value)
        report = multi.build_report(self.config, self.account, DAY, MIDNIGHT + timedelta(minutes=35))
        self.assertEqual(report["actors"], [])
        self.assertFalse(report["complete"])
        value["scope"] = multi.scope_for(self.config, self.account)
        value["active"]["summary"]["schema_version"] = 1
        multi.atomic_json(path, value)
        self.assertFalse(multi.build_report(self.config, self.account, DAY, MIDNIGHT + timedelta(minutes=35))["complete"])

    def test_unmarked_existing_account_and_day_directories_are_not_adopted(self):
        root = Path(self.config["OUTPUT_DIRECTORY"])
        account_path = root / (self.account["NAME"] + "-" + self.account["ACCOUNT_ID"])
        account_path.mkdir(parents=True)
        unknown = account_path / "keep.txt"
        unknown.write_text("existing unmanaged data", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "标记"):
            multi.account_directory(self.config, self.account)
        self.assertEqual(unknown.read_text(encoding="utf-8"), "existing unmanaged data")
        self.assertFalse((account_path / ".rds-audit-account").exists())
        other = self.config["ACCOUNTS"][1]
        other_root = multi.account_directory(self.config, other)
        day_path = other_root / DAY.isoformat()
        day_path.mkdir()
        with self.assertRaisesRegex(ValueError, "标记"):
            multi.day_directory(self.config, other, DAY)
        self.assertFalse((day_path / multi.DAY_MARKER).exists())

    def test_checkpoint_requires_boolean_active_completeness(self):
        start, end = MIDNIGHT, MIDNIGHT + timedelta(minutes=30)
        path = self.checkpoint(start, end)
        value = multi.read_json(path)
        value["active"]["complete"] = "true"
        multi.atomic_json(path, value)
        report = multi.build_report(self.config, self.account, DAY, MIDNIGHT + timedelta(minutes=35))
        self.assertFalse(report["complete"])
        self.assertEqual(report["actors"], [])

    def test_corrupt_checkpoint_shapes_and_retry_metadata_are_recollected(self):
        self.seed_start()
        start, end = MIDNIGHT, MIDNIGHT + timedelta(minutes=30)
        now = MIDNIGHT + timedelta(minutes=35)
        path = self.checkpoint(start, end)
        valid = multi.read_json(path)
        cases = [[], None, {**valid, "next_retry": "later"},
                 {**valid, "attempts": "not-a-number"}, {**valid, "attempts": -1},
                 {**valid, "attempts": True}, {**valid, "active": []},
                 {**valid, "last_errors": "invalid"}]
        for broken in cases:
            with self.subTest(broken=broken):
                multi.atomic_json(path, broken)
                collector = Mock(side_effect=lambda c, a, s, i, left, right, d: self.snapshot(left, right, count=3))
                result = multi.collect_account(self.config, self.account, now, session_factory=self.session, collector=collector)
                self.assertEqual((result["processed"], result["failed"]), (1, 0))
                collector.assert_called_once()
                recovered = multi.load_bucket(path, self.config, self.account, start, end)
                self.assertTrue(recovered["active"]["complete"])
                self.assertEqual(recovered["attempts"], 1)
                self.assertEqual(recovered["active"]["summary"]["actors"][0]["total"], 3)

    def test_corrupt_scope_metadata_is_recovered_without_blocking_account(self):
        self.seed_start()
        root = multi.account_directory(self.config, self.account)
        metadata = root / (".scope-" + multi.scope_id(self.config, self.account) + ".json")
        self.config["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"] = 1
        now = MIDNIGHT + timedelta(minutes=35)
        for broken in ([], None, {}, {"first_date": "invalid-date"}, {"first_date": (DAY + timedelta(days=1)).isoformat()}):
            with self.subTest(broken=broken):
                multi.atomic_json(metadata, broken)
                collector = Mock(side_effect=lambda c, a, s, i, left, right, d: self.snapshot(left, right))
                result = multi.collect_account(self.config, self.account, now, session_factory=self.session, collector=collector)
                self.assertEqual((result["processed"], result["failed"]), (1, 0))
                self.assertEqual(multi.read_json(metadata), {"first_date": (DAY - timedelta(days=1)).isoformat()})
                collector.assert_called_once()


class WindowTests(unittest.TestCase):
    def test_natural_day_uses_configured_timezone_and_dst_elapsed_hours(self):
        for day, zone, expected_hours in ((date(2026, 11, 3), "Asia/Shanghai", 24),
                                           (date(2026, 3, 8), "America/New_York", 23),
                                           (date(2026, 11, 1), "America/New_York", 25)):
            with self.subTest(day=day, zone=zone):
                start, end = multi.day_window(day, ZoneInfo(zone))
                self.assertEqual((end - start).total_seconds(), expected_hours * 3600)
                for interval in (30, 60):
                    buckets = list(multi.windows(day, ZoneInfo(zone), interval))
                    self.assertEqual(len(buckets), expected_hours * 60 // interval)
                    self.assertEqual(buckets[0][0], start)
                    self.assertEqual(buckets[-1][1], end)
                    self.assertTrue(all(left[1] == right[0] for left, right in zip(buckets, buckets[1:])))

    def test_schedule_boundary_uses_config_timezone_instead_of_host_date(self):
        config = {"TIMEZONE": "Asia/Shanghai", "DAILY_MAIL_TIME": "08:10"}
        self.assertIsNone(multi.scheduled_day(config, datetime(2026, 11, 3, 0, 9, 59, tzinfo=UTC)))
        self.assertEqual(multi.scheduled_day(config, datetime(2026, 11, 3, 0, 10, tzinfo=UTC)), date(2026, 11, 2))


class AccountConcurrencyTests(MultiFixture):
    def accounts(self, count):
        self.config["ACCOUNTS"] = [{**ACCOUNT_DEFAULTS, "NAME": "account-" + str(index),
                                   "ACCOUNT_ID": str(100000000000 + index), "REGIONS": "us-east-1"}
                                  for index in range(count)]
        for account in self.config["ACCOUNTS"]:
            self.seed_start(account)

    def test_eight_accounts_overlap_within_configured_limit_and_fail_independently(self):
        self.accounts(8)
        self.config["ACCOUNT_CONCURRENCY"] = 3
        rendezvous = threading.Barrier(3)
        rendezvous_ids = {account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"][:3]}
        lock = threading.Lock()
        active = peak = 0
        sessions, identities = {}, {}

        def collector(config, account, session, identity, left, right, directory):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                sessions[account["ACCOUNT_ID"]] = session
                identities[account["ACCOUNT_ID"]] = identity["Account"]
            try:
                if account["ACCOUNT_ID"] in rendezvous_ids:
                    # A sequential implementation cannot pass this rendezvous.
                    rendezvous.wait(timeout=15)
                if account["ACCOUNT_ID"] == self.config["ACCOUNTS"][0]["ACCOUNT_ID"]:
                    raise RuntimeError("one account failed without blocking others")
                return self.snapshot(left, right)
            finally:
                with lock:
                    active -= 1

        with redirect_stdout(StringIO()):
            results = multi.collect_accounts(self.config, MIDNIGHT + timedelta(minutes=35),
                                             session_factory=self.session, collector=collector)
        self.assertEqual(peak, 3)
        self.assertEqual(active, 0)
        self.assertEqual([row["account_id"] for row in results], [account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"]])
        self.assertEqual([row["failed"] for row in results], [1] + [0] * 7)
        self.assertEqual(len({id(session) for session in sessions.values()}), 8)
        self.assertEqual(identities, {account["ACCOUNT_ID"]: account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"]})

    def test_seven_enabled_accounts_can_all_collect_concurrently(self):
        self.accounts(7)
        self.config["ACCOUNT_CONCURRENCY"] = 7
        rendezvous = threading.Barrier(7)
        lock = threading.Lock()
        active = peak = 0

        def collector(config, account, session, identity, left, right, directory):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                rendezvous.wait(timeout=15)
                return self.snapshot(left, right)
            finally:
                with lock:
                    active -= 1

        with redirect_stdout(StringIO()):
            results = multi.collect_accounts(self.config, MIDNIGHT + timedelta(minutes=35),
                                             session_factory=self.session, collector=collector)
        self.assertEqual(peak, 7)
        self.assertEqual(len(results), 7)
        self.assertTrue(all(row["processed"] == 1 and row["failed"] == 0 for row in results))

    def test_concurrency_one_preserves_sequential_account_work(self):
        self.accounts(3)
        self.config["ACCOUNT_CONCURRENCY"] = 1
        events = []

        def collector(config, account, session, identity, left, right, directory):
            events.append((account["ACCOUNT_ID"], "start"))
            snapshot = self.snapshot(left, right)
            events.append((account["ACCOUNT_ID"], "end"))
            return snapshot

        with redirect_stdout(StringIO()):
            results = multi.collect_accounts(self.config, MIDNIGHT + timedelta(minutes=35),
                                             session_factory=self.session, collector=collector)
        expected = [(account["ACCOUNT_ID"], event) for account in self.config["ACCOUNTS"] for event in ("start", "end")]
        self.assertEqual(events, expected)
        self.assertEqual([row["account_id"] for row in results], [account["ACCOUNT_ID"] for account in self.config["ACCOUNTS"]])


class CollectionFailureIntegrationTests(MultiFixture):
    def setUp(self):
        super().setUp()
        self.config.update(LARK_ALERTS_ENABLED=True, LARK_ALERT_AFTER_FAILURES=2,
                           LARK_ALERT_REPEAT_MINUTES=60, LARK_NOTIFICATION_RETRY_MINUTES=5)

    def notifications(self):
        return Mock(return_value={"sent": 0, "pending": 0, "failed": 0})

    def observed_bucket(self, notifier):
        observations = notifier.call_args.args[3]
        return next(item for item in observations if item["key"].startswith("bucket:"))

    def test_retry_failures_persist_and_success_resets_consecutive_count(self):
        self.seed_start()
        now = MIDNIGHT + timedelta(minutes=35)
        notifier = self.notifications()
        failing = Mock(side_effect=RuntimeError("mock CloudWatch failure"))
        with patch.object(multi, "dispatch_collection_alerts", notifier):
            first = multi.collect_account(self.config, self.account, now, session_factory=self.session, collector=failing)
            self.assertEqual(first["failed"], 1)
            observation = self.observed_bucket(notifier)
            self.assertEqual(observation["consecutive_failures"], 1)
            self.assertTrue(observation["failed"])
            self.assertLess(observation["consecutive_failures"], self.config["LARK_ALERT_AFTER_FAILURES"])
            # Recreate the collector/session and reread disk state as a later worker would.
            second = multi.collect_account(self.config, self.account, now + timedelta(minutes=5),
                                           session_factory=self.session, collector=Mock(side_effect=RuntimeError("retry failed")))
            self.assertEqual(second["failed"], 1)
            self.assertEqual(self.observed_bucket(notifier)["consecutive_failures"], 2)
            path = multi.bucket_path(self.config, self.account, MIDNIGHT)
            self.assertEqual(multi.read_json(path)["consecutive_failures"], 2)
            waiting = Mock()
            third = multi.collect_account(self.config, self.account, now + timedelta(minutes=10),
                                          session_factory=self.session, collector=waiting)
            waiting.assert_not_called()
            self.assertEqual(third["processed"], 0)
            self.assertEqual(self.observed_bucket(notifier)["consecutive_failures"], 2)
            recovered = multi.collect_account(self.config, self.account, now + timedelta(minutes=15),
                                              session_factory=self.session,
                                              collector=lambda c, a, s, i, left, right, d: self.snapshot(left, right))
            self.assertEqual(recovered["failed"], 0)
            observation = self.observed_bucket(notifier)
            self.assertEqual(observation["consecutive_failures"], 0)
            self.assertFalse(observation["failed"])
            self.assertEqual(multi.read_json(path)["consecutive_failures"], 0)

    def test_first_failed_refresh_does_not_reuse_lifetime_attempts_for_alert_or_backoff(self):
        self.seed_start()
        path = self.checkpoint(MIDNIGHT, MIDNIGHT + timedelta(minutes=30), count=2, refresh_done=False)
        state = multi.read_json(path)
        state.update(attempts=20, consecutive_failures=0)
        multi.atomic_json(path, state)
        for offset in (30, 60, 90):
            self.checkpoint(MIDNIGHT + timedelta(minutes=offset), MIDNIGHT + timedelta(minutes=offset + 30), count=0)
        now = MIDNIGHT + timedelta(hours=2, minutes=5)
        notifier = self.notifications()
        with patch.object(multi, "dispatch_collection_alerts", notifier):
            multi.collect_account(self.config, self.account, now, session_factory=self.session,
                                  collector=Mock(side_effect=RuntimeError("first refresh failure")))
        state = multi.read_json(path)
        self.assertEqual(state["attempts"], 21)
        self.assertEqual(state["consecutive_failures"], 1)
        self.assertEqual(state["next_retry"], int(now.timestamp()) + 300)
        observation = next(row for row in notifier.call_args.args[3] if row["bucket_start"] == multi.iso(MIDNIGHT))
        self.assertEqual(observation["consecutive_failures"], 1)
        self.assertLess(observation["consecutive_failures"], self.config["LARK_ALERT_AFTER_FAILURES"])
        self.assertEqual(state["active"]["summary"]["actors"][0]["total"], 2)

    def test_two_identity_failures_are_account_scoped_and_other_account_continues(self):
        for account in self.config["ACCOUNTS"]:
            self.seed_start(account)
        now = MIDNIGHT + timedelta(minutes=35)
        notifier = self.notifications()
        identity_bad = True

        def session_factory(account):
            return self.session(account, mismatch=identity_bad and account is self.account)

        def collector(config, account, session, identity, left, right, directory):
            return self.snapshot(left, right)

        with patch.object(multi, "dispatch_collection_alerts", notifier), redirect_stdout(StringIO()):
            first = multi.collect_accounts(self.config, now, session_factory=session_factory, collector=collector)
            second = multi.collect_accounts(self.config, now + timedelta(minutes=5), session_factory=session_factory, collector=collector)
            self.assertEqual([row["failed"] for row in first], [1, 0])
            self.assertEqual([row["failed"] for row in second], [1, 0])
            health = [(call.args[1]["ACCOUNT_ID"], observation) for call in notifier.call_args_list
                      for observation in call.args[3] if observation["key"] == "account-health"]
            bad = [row for account, row in health if account == self.account["ACCOUNT_ID"]]
            good = [row for account, row in health if account != self.account["ACCOUNT_ID"]]
            self.assertEqual([row["consecutive_failures"] for row in bad], [1, 2])
            self.assertTrue(all(row["failed"] for row in bad))
            self.assertTrue(all(not row["failed"] and row["consecutive_failures"] == 0 for row in good))
            identity_bad = False
            third = multi.collect_accounts(self.config, now + timedelta(minutes=10), session_factory=session_factory, collector=collector)
        self.assertEqual([row["failed"] for row in third], [0, 0])
        root = multi.account_directory(self.config, self.account)
        self.assertEqual(multi.read_json(root / ".collection-health.json")["consecutive_failures"], 0)

    def test_notifier_exception_is_contained_and_backfill_and_other_accounts_continue(self):
        for account in self.config["ACCOUNTS"]:
            self.seed_start(account)
        # Exercise the actual dynamic-import wrapper while replacing its network helper.
        module = ModuleType("rds_failure_alerts")
        module.sync_collection_alerts = Mock(side_effect=RuntimeError("PRIVATE-NOTIFICATION-TOKEN"))
        now = MIDNIGHT + timedelta(minutes=35)
        bad = True

        def collector(config, account, session, identity, left, right, directory):
            if bad and account is self.account:
                raise RuntimeError("mock source failure")
            return self.snapshot(left, right)

        output = StringIO()
        with patch.dict(sys.modules, {"rds_failure_alerts": module}), redirect_stdout(output), redirect_stderr(output):
            first = multi.collect_accounts(self.config, now, session_factory=self.session, collector=collector)
            self.assertEqual([row["failed"] for row in first], [1, 0])
            self.assertTrue(all(row["alert_failed"] for row in first))
            bad = False
            second = multi.collect_accounts(self.config, now + timedelta(minutes=5), session_factory=self.session, collector=collector)
        self.assertEqual([row["failed"] for row in second], [0, 0])
        self.assertTrue(all(row["alert_failed"] for row in second))
        self.assertNotIn("PRIVATE-NOTIFICATION-TOKEN", output.getvalue())
        self.assertTrue(multi.build_report(self.config, self.account, DAY, now + timedelta(minutes=5))["complete"])

    def test_invalid_persisted_consecutive_counter_is_recollected_safely(self):
        self.seed_start()
        path = self.checkpoint(MIDNIGHT, MIDNIGHT + timedelta(minutes=30))
        valid = multi.read_json(path)
        notifier = self.notifications()
        with patch.object(multi, "dispatch_collection_alerts", notifier):
            for invalid in (True, -1, "2", None, 1.5):
                with self.subTest(invalid=invalid):
                    multi.atomic_json(path, {**valid, "consecutive_failures": invalid})
                    result = multi.collect_account(self.config, self.account, MIDNIGHT + timedelta(minutes=35),
                                                   session_factory=self.session,
                                                   collector=lambda c, a, s, i, left, right, d: self.snapshot(left, right))
                    self.assertEqual((result["processed"], result["failed"]), (1, 0))
                    recovered = multi.read_json(path)
                    self.assertEqual(recovered["consecutive_failures"], 0)
                    self.assertEqual(recovered["attempts"], 1)

    def test_two_interrupted_workers_are_observed_before_next_retry_and_success_recovers(self):
        self.seed_start()
        now = MIDNIGHT + timedelta(minutes=35)
        notifier = self.notifications()
        with patch.object(multi, "dispatch_collection_alerts", notifier):
            with self.assertRaises(SystemExit):
                multi.collect_account(self.config, self.account, now, session_factory=self.session,
                                      collector=Mock(side_effect=SystemExit("worker stopped")))
            path = multi.bucket_path(self.config, self.account, MIDNIGHT)
            self.assertTrue(multi.read_json(path)["in_progress"])
            notifier.assert_not_called()
            with self.assertRaises(SystemExit):
                multi.collect_account(self.config, self.account, now + timedelta(minutes=5), session_factory=self.session,
                                      collector=Mock(side_effect=SystemExit("second worker stopped")))
            self.assertEqual(self.observed_bucket(notifier)["consecutive_failures"], 1)
            self.assertIn("InterruptedCollection", self.observed_bucket(notifier)["error_types"])

            def recovered(config, account, session, identity, left, right, directory):
                # The second interruption must reach the notifier before any
                # third potentially hanging source call is attempted.
                self.assertEqual(self.observed_bucket(notifier)["consecutive_failures"], 2)
                self.assertTrue(self.observed_bucket(notifier)["failed"])
                return self.snapshot(left, right)

            result = multi.collect_account(self.config, self.account, now + timedelta(minutes=10),
                                           session_factory=self.session, collector=recovered)
        self.assertEqual(result["failed"], 0)
        self.assertFalse(self.observed_bucket(notifier)["failed"])
        self.assertEqual(self.observed_bucket(notifier)["consecutive_failures"], 0)
        self.assertFalse(multi.read_json(path)["in_progress"])
        self.assertEqual(multi.read_json(path)["attempts"], 3)

    def test_active_good_snapshot_is_still_marked_incomplete_while_refresh_is_interrupted(self):
        path = self.checkpoint(MIDNIGHT, MIDNIGHT + timedelta(minutes=30), count=2)
        state = multi.read_json(path)
        state["in_progress"] = True
        multi.atomic_json(path, state)
        report = multi.build_report(self.config, self.account, DAY, MIDNIGHT + timedelta(minutes=35))
        self.assertFalse(report["complete"])
        self.assertEqual(report["actors"][0]["total"], 2)


class TaskLockTests(MultiFixture):
    def clock(self, now):
        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now.astimezone(tz) if tz else now.replace(tzinfo=None)

        return patch.object(multi, "datetime", FrozenDatetime)

    def test_active_collection_does_not_block_scheduled_mail_but_defers_retention(self):
        path = self.configuration_path()
        root = multi.safe_directory(self.config["OUTPUT_DIRECTORY"])
        now = MIDNIGHT + timedelta(days=1, hours=9)
        with self.clock(now), patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), patch("rds_mail.send_reports", return_value={"message_id": "while-collecting"}) as sender, patch.object(multi, "collect_accounts") as collect, patch.object(multi, "prune", return_value=[]) as prune, redirect_stdout(StringIO()):
            with multi._exclusive(root / ".multi-account.collect.lock") as held:
                self.assertTrue(held)
                self.assertEqual(multi.main(["--config", str(path), "--scheduled"]), 0)
                sender.assert_called_once()
                prune.assert_not_called()
                # Another collection must still respect the same-mode lock.
                self.assertEqual(multi.main(["--config", str(path), "--collect"]), 0)
                collect.assert_not_called()
            self.assertEqual(multi.main(["--config", str(path), "--scheduled"]), 0)
            prune.assert_called()
            sender.assert_called_once()  # Releasing the lock does not duplicate mail.

    def test_active_delivery_allows_collection_but_prevents_other_delivery_and_retention(self):
        path = self.configuration_path()
        root = multi.safe_directory(self.config["OUTPUT_DIRECTORY"])
        now = MIDNIGHT + timedelta(days=1, hours=9)
        pruning_seen_by_collection = []
        with self.clock(now), patch.object(multi, "collect_accounts", return_value=[{"failed": 0}]) as collect, patch.object(multi, "deliver") as deliver, patch.object(multi, "prune", return_value=[]) as prune, redirect_stdout(StringIO()):
            def collection_work(config, started):
                pruning_seen_by_collection.append(prune.called)
                return [{"failed": 0}]

            collect.side_effect = collection_work
            with multi._exclusive(root / ".multi-account.delivery.lock") as held:
                self.assertTrue(held)
                self.assertEqual(multi.main(["--config", str(path), "--collect"]), 0)
                collect.assert_called_once()
                prune.assert_not_called()
                self.assertEqual(multi.main(["--config", str(path), "--scheduled"]), 0)
                deliver.assert_not_called()
            self.assertEqual(multi.main(["--config", str(path), "--collect"]), 0)
            self.assertEqual(collect.call_count, 2)
            prune.assert_called()
            self.assertEqual(pruning_seen_by_collection, [False, True])

    def test_expired_data_is_removed_before_collector_is_interrupted(self):
        self.config["RETENTION_DAYS"] = 3
        path = self.configuration_path()
        now = MIDNIGHT + timedelta(days=1, hours=9)
        today = now.date()
        expired = multi.day_directory(self.config, self.account, today - timedelta(days=3))
        (expired / "old-summary.json").write_text("{}", encoding="utf-8")
        retained = multi.day_directory(self.config, self.account, today - timedelta(days=2))

        def stopped_worker(config, started):
            self.assertFalse(expired.exists(), "Retention must run before a long source query can be killed")
            self.assertTrue(retained.exists())
            raise KeyboardInterrupt("simulate service termination during collection")

        with self.clock(now), patch.object(multi, "collect_accounts", side_effect=stopped_worker), redirect_stdout(StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                multi.main(["--config", str(path), "--collect"])
        self.assertFalse(expired.exists())
        self.assertTrue(retained.exists())
        root = multi.safe_directory(self.config["OUTPUT_DIRECTORY"])
        with multi._exclusive(root / ".multi-account.collect.lock") as released:
            self.assertTrue(released)


class CombinedDeliveryTests(MultiFixture):
    def test_backfill_sends_initial_incomplete_mail_then_only_one_complete_revision(self):
        sender = Mock(return_value={"message_id": "backfill"})
        now = MIDNIGHT + timedelta(days=1, hours=9)
        state = {"count": 1, "complete": False}

        def reports(config, account, day, generated):
            report = self.simple_report(config, account, day, generated)
            report["complete"] = state["complete"]
            actor = report["actors"][0]
            actor["total"] = actor["counts"]["修改"] = actor["attempted_counts"]["修改"] = state["count"]
            report["segments"]["present"] = 48 if state["complete"] else state["count"]
            return report

        with patch.object(multi, "build_report", side_effect=reports), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf) as pdf, redirect_stdout(StringIO()):
            first = multi.deliver(self.config, DAY, now, sender=sender)
            self.assertEqual(first["status"], "accepted")
            self.assertFalse(first["complete"])
            self.assertEqual(sender.call_count, 1)
            self.assertEqual(pdf.call_count, 2)
            state["count"] = 2
            partial = multi.deliver(self.config, DAY, now + timedelta(minutes=5), sender=sender)
            self.assertEqual(sender.call_count, 1)
            self.assertFalse(partial["complete"])
            self.assertEqual(pdf.call_count, 4)
            self.assertNotEqual(partial["fingerprint"], partial["local_fingerprint"])
            for account in self.config["ACCOUNTS"]:
                local = multi.read_json(multi.day_directory(self.config, account, DAY) / "ip-report.json")
                self.assertEqual(local["actors"][0]["total"], 2)
                self.assertFalse(local["complete"])
            multi.deliver(self.config, DAY, now + timedelta(minutes=10), sender=sender)
            self.assertEqual((sender.call_count, pdf.call_count), (1, 4))
            state["complete"] = True
            complete = multi.deliver(self.config, DAY, now + timedelta(minutes=15), sender=sender)
            self.assertTrue(complete["complete"])
            self.assertEqual((sender.call_count, pdf.call_count), (2, 6))
            self.assertIn("修订", sender.call_args.kwargs["subject"])
            self.assertNotIn("数据不完整", sender.call_args.kwargs["subject"])
            multi.deliver(self.config, DAY, now + timedelta(minutes=20), sender=sender)
            self.assertEqual((sender.call_count, pdf.call_count), (2, 6))

    def test_reordering_accounts_or_rotating_keys_does_not_duplicate_mail(self):
        sender = Mock(return_value={"message_id": "stable"})
        now = MIDNIGHT + timedelta(days=1, hours=9)
        with patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            receipt_path = multi._delivery_path(self.config, DAY)
            first = multi.deliver(self.config, DAY, now, sender=sender)
            self.config["ACCOUNTS"].reverse()
            for account in self.config["ACCOUNTS"]:
                account["AWS_ACCESS_KEY_ID"] = "ROTATED-KEY"
                account["AWS_SECRET_ACCESS_KEY"] = "ROTATED-SECRET"
            self.assertEqual(multi._delivery_path(self.config, DAY), receipt_path)
            second = multi.deliver(self.config, DAY, now + timedelta(hours=1), sender=sender)
        self.assertEqual(second, first)
        sender.assert_called_once()

    def test_changed_counts_send_revision_but_generation_time_alone_does_not(self):
        sender = Mock(return_value={"message_id": "revision"})
        now = MIDNIGHT + timedelta(days=1, hours=9)
        revision = False

        def report(config, account, day, generated):
            value = self.simple_report(config, account, day, generated)
            if revision and account is self.account:
                actor = value["actors"][0]
                actor["total"] = actor["counts"]["修改"] = actor["attempted_counts"]["修改"] = 2
            return value

        with patch.object(multi, "build_report", side_effect=report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            multi.deliver(self.config, DAY, now, sender=sender)
            multi.deliver(self.config, DAY, now + timedelta(minutes=5), sender=sender)
            self.assertEqual(sender.call_count, 1)
            revision = True
            status = multi.deliver(self.config, DAY, now + timedelta(minutes=10), sender=sender)
            self.assertEqual(status["status"], "accepted")
            self.assertEqual(sender.call_count, 2)
            self.assertIn("修订", sender.call_args.kwargs["subject"])
            multi.deliver(self.config, DAY, now + timedelta(minutes=15), sender=sender)
            self.assertEqual(sender.call_count, 2)

    def test_changed_recipients_send_new_combined_delivery(self):
        sender = Mock(return_value={"message_id": "recipients"})
        now = MIDNIGHT + timedelta(days=1, hours=9)
        with patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            multi.deliver(self.config, DAY, now, sender=sender)
            self.config["MAIL_RECIPIENTS"].append("another@example.com")
            multi.deliver(self.config, DAY, now + timedelta(minutes=5), sender=sender)
        self.assertEqual(sender.call_count, 2)
        self.assertIn("修订", sender.call_args.kwargs["subject"])

    def test_combined_mail_has_one_distinct_pdf_per_enabled_account(self):
        sender = Mock(return_value={"message_id": "offline-message"})
        with patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf) as pdf, redirect_stdout(StringIO()):
            status = multi.deliver(self.config, DAY, MIDNIGHT + timedelta(days=1, hours=9), sender=sender)
        self.assertEqual(status["status"], "accepted")
        sender.assert_called_once()
        attachments = sender.call_args.args[1]
        self.assertEqual(len(attachments), 2)
        self.assertEqual(len(set(attachments)), 2)
        self.assertEqual(pdf.call_count, 2)
        for path, account in zip(attachments, self.config["ACCOUNTS"]):
            self.assertIn(account["ACCOUNT_ID"], path.name)
            self.assertEqual(path.parent.parent.name, account["NAME"] + "-" + account["ACCOUNT_ID"])
            self.assertIn(account["ACCOUNT_ID"].encode(), path.read_bytes())
        self.assertIn("2 个账号", sender.call_args.args[2])
        self.assertNotIn("PRIVATE", sender.call_args.args[2])
        self.assertEqual(sender.call_args.kwargs["subject"], "AW-RDS审计报告 2026-11-03")
        self.assertIn("2026-11-03 00:00:00 至 2026-11-04 00:00:00（UTC", sender.call_args.args[2])
        self.assertNotIn("影响行数", sender.call_args.args[2])
        self.assertNotIn("最终事务提交数", sender.call_args.args[2])

    def test_repeated_scheduled_wake_does_not_resend_accepted_mail_and_runs_retention(self):
        path = self.configuration_path()
        now = MIDNIGHT + timedelta(days=1, hours=9)

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now.astimezone(tz) if tz else now.replace(tzinfo=None)

        with patch.object(multi, "datetime", FrozenDatetime), patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), patch("rds_mail.send_reports", return_value={"message_id": "accepted-once"}) as sender, patch.object(multi, "prune", return_value=[]) as prune, patch.object(multi, "create_session") as aws, redirect_stdout(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--scheduled"]), 0)
            self.assertEqual(multi.main(["--config", str(path), "--scheduled"]), 0)
        sender.assert_called_once()
        prune.assert_called()
        self.assertEqual(prune.call_args.args[1], date(2026, 11, 4))
        aws.assert_not_called()

    def test_uncertain_or_interrupted_delivery_requires_explicit_manual_resend(self):
        now = MIDNIGHT + timedelta(days=1, hours=9)
        sender = Mock(side_effect=MailDeliveryError("SMTP timeout", delivery_uncertain=True))
        with patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            first = multi.deliver(self.config, DAY, now, sender=sender)
            second = multi.deliver(self.config, DAY, now + timedelta(hours=2), sender=sender)
            self.assertEqual(first["status"], "uncertain")
            self.assertEqual(second, first)
            sender.assert_called_once()
            sender.side_effect = None
            sender.return_value = {"message_id": "verified-resend"}
            self.assertEqual(multi.deliver(self.config, DAY, now + timedelta(hours=3), force=True, sender=sender)["status"], "accepted")
            self.assertEqual(sender.call_count, 2)

    def test_crash_after_starting_smtp_keeps_sending_receipt_and_does_not_retry(self):
        sender = Mock(side_effect=SystemExit("simulated crash"))
        now = MIDNIGHT + timedelta(days=1, hours=9)
        with patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            with self.assertRaises(SystemExit):
                multi.deliver(self.config, DAY, now, sender=sender)
            receipt = multi.deliver(self.config, DAY, now + timedelta(hours=1), sender=sender)
        self.assertEqual(receipt["status"], "sending")
        sender.assert_called_once()

    def test_definite_pre_delivery_failure_retries_only_after_backoff(self):
        sender = Mock(side_effect=[MailDeliveryError("authentication failed", delivery_uncertain=False), {"message_id": "retry-success"}])
        now = MIDNIGHT + timedelta(days=1, hours=9)
        with patch.object(multi, "build_report", side_effect=self.simple_report), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            self.assertEqual(multi.deliver(self.config, DAY, now, sender=sender)["status"], "failed")
            self.assertEqual(multi.deliver(self.config, DAY, now + timedelta(minutes=14), sender=sender)["status"], "failed")
            self.assertEqual(sender.call_count, 1)
            self.assertEqual(multi.deliver(self.config, DAY, now + timedelta(minutes=15), sender=sender)["status"], "accepted")
        self.assertEqual(sender.call_count, 2)

    def test_incomplete_account_is_explicit_in_combined_subject_and_body(self):
        def reports(config, account, day, now):
            report = self.simple_report(config, account, day, now)
            report["complete"] = account is self.account
            return report

        sender = Mock(return_value={"message_id": "partial"})
        with patch.object(multi, "build_report", side_effect=reports), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            status = multi.deliver(self.config, DAY, MIDNIGHT + timedelta(days=1, hours=9), sender=sender)
        self.assertFalse(status["complete"])
        self.assertIn("数据不完整", sender.call_args.kwargs["subject"])
        self.assertIn("staging (210987654321)：数据不完整", sender.call_args.args[2])

    def test_config_precheck_does_not_authenticate_render_send_or_create_output(self):
        path = self.configuration_path()
        with patch.object(multi, "create_session") as aws, patch("rds_mail.send_reports") as smtp, patch("rds_pdf.render_account_pdf") as pdf, redirect_stdout(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--check-config"]), 0)
        aws.assert_not_called()
        smtp.assert_not_called()
        pdf.assert_not_called()
        self.assertFalse(Path(self.config["OUTPUT_DIRECTORY"]).exists())

    def test_collect_still_runs_retention_when_one_account_is_partial(self):
        path = self.configuration_path()
        events = []

        def collection(config, now):
            events.append("collect")
            return [{"failed": 1}]

        def pruning(config, today):
            events.append("prune")
            return []

        with patch.object(multi, "collect_accounts", side_effect=collection), patch.object(multi, "prune", side_effect=pruning) as prune, redirect_stdout(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--collect"]), 2)
        prune.assert_called()
        self.assertLess(events.index("prune"), events.index("collect"))

    def test_retention_cleans_removed_accounts_but_keeps_unmarked_data(self):
        self.config["RETENTION_DAYS"] = 3
        old = DAY - timedelta(days=3)
        recent = DAY - timedelta(days=2)
        account = self.config["ACCOUNTS"][1]
        old_path = multi.day_directory(self.config, account, old)
        (old_path / "summary.json").write_text("{}", encoding="utf-8")
        recent_path = multi.day_directory(self.config, account, recent)
        unknown = multi.account_directory(self.config, account) / (old - timedelta(days=1)).isoformat()
        unknown.mkdir()
        (unknown / "unknown.txt").write_text("keep", encoding="utf-8")
        self.config["ACCOUNTS"].remove(account)
        deleted = multi.prune(self.config, DAY)
        self.assertEqual(deleted, [account["NAME"] + "-" + account["ACCOUNT_ID"] + "/" + old.isoformat()])
        self.assertFalse(old_path.exists())
        self.assertTrue(recent_path.exists())
        self.assertTrue((unknown / "unknown.txt").exists())

    def test_invalid_account_marker_is_skipped_while_other_accounts_are_pruned(self):
        self.config["RETENTION_DAYS"] = 3
        old = DAY - timedelta(days=7)
        bad_account, good_account = self.config["ACCOUNTS"]
        bad_day = multi.day_directory(self.config, bad_account, old)
        marker = bad_day.parent / ".rds-audit-account"
        for broken in ([], None, {"account_name": "production", "account_id": []}, "not-json"):
            with self.subTest(broken=broken):
                good_day = multi.day_directory(self.config, good_account, old)
                if broken == "not-json":
                    marker.write_text("{broken-json", encoding="utf-8")
                else:
                    multi.atomic_json(marker, broken)
                deleted = multi.prune(self.config, DAY)
                self.assertEqual(deleted, [good_account["NAME"] + "-" + good_account["ACCOUNT_ID"] + "/" + old.isoformat()])
                self.assertTrue(bad_day.exists())
                self.assertFalse(good_day.exists())


if __name__ == "__main__":
    unittest.main()
