"""Exercise account isolation, interval recovery and combined-mail receipts offline."""
from copy import deepcopy
from contextlib import redirect_stdout, redirect_stderr
from datetime import date, datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile
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
                       "TIMEZONE": "UTC", "SMTP_HOST": "smtp.example.com",
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
        self.assertEqual(prune.call_count, 2)
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
        with patch.object(multi, "collect_accounts", return_value=[{"failed": 1}]), patch.object(multi, "prune", return_value=[]) as prune, redirect_stdout(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--collect"]), 2)
        prune.assert_called_once()

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
