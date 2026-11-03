"""Natural-day automatic-mail caps survive revisions, upgrades and restarts."""
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from rds_daily_mail import automatic_daily_mail

UTC = timezone.utc


class AutomaticDailyMailTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "output/.daily-mail-budget.json"
        self.now = datetime(2026, 11, 3, 0, 10, tzinfo=UTC)
        self.day = date(2026, 11, 2)
        self.config = {"TIMEZONE": "Asia/Shanghai", "RETENTION_DAYS": 7,
                       "SMTP_AUTH_CODE": "PRIVATE-AUTH-CODE", "AWS_SECRET_ACCESS_KEY": "PRIVATE-AWS-KEY",
                       "MAIL_RECIPIENTS": ["one@example.com"]}
        self.reports = [{"account_id": "123456789012", "complete": True, "date": self.day.isoformat(),
                         "actors": [{"source_ip": "192.0.2.1", "total": 1}],
                         "scope": {"version": 2}, "generated_at": "2026-11-03T00:10:00Z"},
                        {"account_id": "210987654321", "complete": True, "date": self.day.isoformat(),
                         "actors": [], "scope": {"version": 2}, "generated_at": "2026-11-03T00:10:00Z"}]
        self.build = Mock(side_effect=lambda: deepcopy(self.reports))
        self.render = Mock(return_value=[self.root / "one.pdf", self.root / "two.pdf"])
        self.deliver = Mock(return_value={"status": "accepted", "complete": True})
        self.receipts = Mock(return_value=[])

    def run_mail(self, *, now=None, day=None):
        return automatic_daily_mail(self.config, day or self.day, now or self.now,
                                    build_reports=self.build, render_reports=self.render,
                                    deliver_callback=self.deliver, receipts=self.receipts, state_path=self.path)

    def ledger(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def test_default_all_accounts_combined_only_once_per_natural_day(self):
        self.assertEqual(self.run_mail()["status"], "accepted")
        second = self.run_mail(now=self.now + timedelta(minutes=5))
        self.assertEqual((second["status"], second["reason"]), ("suppressed", "daily_limit"))
        self.deliver.assert_called_once()
        self.assertEqual(len(self.deliver.call_args.args[0]), 2)
        self.render.assert_called_once()
        self.assertEqual(self.build.call_count, 2)
        self.assertEqual(self.ledger()["entries"]["2026-11-03"]["used"], 1)

    def test_changed_counts_accounts_recipients_and_scopes_never_reset_budget(self):
        self.run_mail()
        for number in range(2, 6):
            self.reports[0]["actors"][0]["total"] = number
            self.reports[0]["scope"]["version"] = number
            self.config["MAIL_RECIPIENTS"] = [str(number) + "@example.com"]
            self.reports.append({"account_id": str(300000000000 + number), "complete": True,
                                 "actors": [], "scope": {"version": number}})
            result = self.run_mail(now=self.now + timedelta(minutes=number * 5))
            self.assertEqual(result["status"], "suppressed")
        self.deliver.assert_called_once()
        self.assertEqual(self.render.call_count, 5)

    def test_order_and_generation_time_do_not_rerender_or_resend(self):
        self.run_mail()
        self.reports.reverse()
        for report in self.reports:
            report["generated_at"] = "2026-11-03T12:00:00Z"
        self.run_mail(now=self.now + timedelta(hours=1))
        self.render.assert_called_once()
        self.deliver.assert_called_once()

    def test_partial_to_complete_updates_local_pdfs_without_automatic_revision(self):
        self.reports[0]["complete"] = False
        self.assertFalse(self.run_mail()["complete"])
        self.reports[0]["complete"] = True
        status = self.run_mail(now=self.now + timedelta(minutes=5))
        self.assertTrue(status["complete"])
        self.assertEqual(status["status"], "suppressed")
        self.assertEqual(self.render.call_count, 2)
        self.deliver.assert_called_once()

    def test_upgrade_imports_any_old_accepted_receipt_instead_of_sending_revision(self):
        self.receipts.return_value = [{"status": "accepted", "complete": False, "scope": "old"},
                                     {"status": "accepted", "complete": True, "scope": "different"}]
        status = self.run_mail()
        self.assertEqual((status["status"], status["reason"]), ("suppressed", "daily_limit"))
        self.assertEqual(self.ledger()["entries"]["2026-11-03"]["status"], "accepted")
        self.deliver.assert_not_called()
        self.render.assert_called_once()

    def test_old_sending_or_uncertain_receipts_are_not_retried(self):
        for old in ("sending", "uncertain", "reserved"):
            with self.subTest(old=old):
                self.path = self.root / old / "budget.json"
                self.receipts.return_value = [{"status": old}]
                status = self.run_mail()
                self.assertEqual(status["status"], "uncertain")
                self.assertEqual(self.run_mail(now=self.now + timedelta(hours=2))["status"], "uncertain")
        self.deliver.assert_not_called()

    def test_definite_failed_delivery_retries_after_fifteen_minutes_and_uses_no_credit(self):
        retry = int(self.now.timestamp()) + 900
        self.deliver.side_effect = [{"status": "failed", "next_retry": retry}, {"status": "accepted"}]
        first = self.run_mail()
        self.assertEqual((first["status"], first["used"]), ("failed", 0))
        early = self.run_mail(now=self.now + timedelta(minutes=14))
        self.assertEqual((early["status"], early["reason"]), ("failed", "retry_backoff"))
        self.assertEqual(self.deliver.call_count, 1)
        self.assertEqual(self.run_mail(now=self.now + timedelta(minutes=15))["status"], "accepted")
        self.assertEqual(self.deliver.call_count, 2)
        self.render.assert_called_once()

    def test_uncertain_delivery_never_retries_automatically(self):
        self.deliver.return_value = {"status": "uncertain"}
        self.assertEqual(self.run_mail()["status"], "uncertain")
        self.reports[0]["actors"][0]["total"] = 50
        self.assertEqual(self.run_mail(now=self.now + timedelta(hours=3))["status"], "uncertain")
        self.deliver.assert_called_once()
        self.assertEqual(self.render.call_count, 2)

    def test_reservation_is_on_disk_before_callback_and_survives_process_interruption(self):
        def crash(reports):
            entry = self.ledger()["entries"]["2026-11-03"]
            self.assertEqual((entry["status"], entry["used"]), ("sending", 1))
            raise KeyboardInterrupt("simulate process stop during SMTP")

        self.deliver.side_effect = crash
        with self.assertRaises(KeyboardInterrupt):
            self.run_mail()
        status = self.run_mail(now=self.now + timedelta(minutes=5))
        self.assertEqual(status["status"], "sending")
        self.deliver.assert_called_once()

    def test_generic_callback_failure_is_uncertain_and_not_blindly_retried(self):
        self.deliver.side_effect = RuntimeError("PRIVATE-SMTP-PROVIDER-REPLY")
        self.assertEqual(self.run_mail()["status"], "uncertain")
        self.assertEqual(self.run_mail(now=self.now + timedelta(hours=2))["status"], "uncertain")
        self.assertNotIn("PRIVATE", self.path.read_text(encoding="utf-8"))
        self.deliver.assert_called_once()

    def test_new_sending_day_gets_one_credit_without_replaying_previous_failures(self):
        self.deliver.side_effect = [{"status": "failed", "next_retry": int(self.now.timestamp()) + 900}, {"status": "accepted"}]
        self.run_mail()
        next_day = self.day + timedelta(days=1)
        for report in self.reports:
            report["date"] = next_day.isoformat()
        result = self.run_mail(now=self.now + timedelta(days=1), day=next_day)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(self.deliver.call_count, 2)
        self.assertTrue(all(report["date"] == next_day.isoformat() for report in self.deliver.call_args.args[0]))
        self.assertEqual(set(self.ledger()["entries"]), {"2026-11-03", "2026-11-04"})

    def test_new_sending_day_after_acceptance_can_send_once_again(self):
        self.run_mail()
        self.assertEqual(self.run_mail(now=self.now + timedelta(days=1))["status"], "accepted")
        self.assertEqual(self.run_mail(now=self.now + timedelta(days=1, minutes=5))["status"], "suppressed")
        self.assertEqual(self.deliver.call_count, 2)
        self.receipts.assert_called_once()  # Old receipts must not consume a fresh day's allowance.

    def test_zero_limit_updates_local_without_sending_and_does_not_reset_old_usage(self):
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 0
        self.assertEqual(self.run_mail()["status"], "disabled")
        self.deliver.assert_not_called()
        self.render.assert_called_once()
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 1
        self.assertEqual(self.run_mail()["status"], "accepted")
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 0
        self.assertEqual(self.run_mail()["status"], "disabled")
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 1
        self.assertEqual(self.run_mail()["status"], "suppressed")
        self.deliver.assert_called_once()

    def test_zero_limit_still_imports_existing_accepted_usage_before_reenable(self):
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 0
        self.receipts.return_value = [{"status": "accepted"}]
        self.assertEqual(self.run_mail()["status"], "disabled")
        self.config["AUTO_MAIL_MAX_PER_DAY"] = 1
        self.assertEqual(self.run_mail()["status"], "suppressed")
        self.deliver.assert_not_called()

    def test_retention_bounds_ledger_and_keeps_today_and_previous_dates(self):
        self.config["RETENTION_DAYS"] = 3
        for offset in range(6):
            self.run_mail(now=self.now + timedelta(days=offset), day=self.day + timedelta(days=offset))
        self.assertEqual(set(self.ledger()["entries"]), {"2026-11-06", "2026-11-07", "2026-11-08"})

    def test_timezone_natural_day_is_used_instead_of_utc_date(self):
        now = datetime(2026, 11, 3, 16, 1, tzinfo=UTC)
        self.run_mail(now=now)
        self.assertEqual(set(self.ledger()["entries"]), {"2026-11-04"})
        self.assertEqual(self.run_mail(now=now + timedelta(hours=7))["status"], "suppressed")
        self.deliver.assert_called_once()

    def test_state_stores_hashes_and_budget_only_without_credentials_sql_or_addresses(self):
        self.reports[0].update(sql="PRIVATE-SQL-TEXT", AWS_SECRET_ACCESS_KEY="PRIVATE-REPORT-KEY")
        self.run_mail()
        text = self.path.read_text(encoding="utf-8")
        for secret in ("PRIVATE", "192.0.2.1", "one@example.com", "123456789012", "SMTP", "SQL"):
            self.assertNotIn(secret, text)
        entry = self.ledger()["entries"]["2026-11-03"]
        self.assertEqual(set(entry), {"report_day", "used", "status", "last_attempt", "next_retry", "local_fingerprint"})
        self.assertRegex(entry["local_fingerprint"], r"\A[0-9a-f]{64}\Z")

    def test_corrupt_existing_ledger_is_never_reset_or_allowed_to_send(self):
        self.run_mail()
        valid = self.ledger()
        broken = deepcopy(valid)
        broken["entries"]["2026-11-03"].update(used=0)
        cases = ["{broken", "null", "[]", json.dumps({"schema_version": 1, "entries": []}),
                 json.dumps(broken), '{"schema_version":1,"schema_version":1,"entries":{}}']
        self.deliver.reset_mock()
        for index, raw in enumerate(cases):
            with self.subTest(raw=raw):
                self.path = self.root / ("corrupt-" + str(index) + ".json")
                self.path.write_text(raw, encoding="utf-8")
                status = self.run_mail()
                self.assertEqual((status["status"], status["reason"]), ("uncertain", "invalid_state"))
                self.assertEqual(self.path.read_text(encoding="utf-8"), raw)
        self.deliver.assert_not_called()

    def test_unreadable_receipt_history_reserves_credit_instead_of_treating_it_as_no_mail(self):
        self.receipts.side_effect = OSError("PRIVATE-RECEIPT-PATH")
        self.assertEqual(self.run_mail()["status"], "uncertain")
        self.assertEqual(self.run_mail(now=self.now + timedelta(minutes=5))["status"], "uncertain")
        self.deliver.assert_not_called()

    def test_render_failure_does_not_contact_delivery_callback(self):
        self.render.side_effect = OSError("no disk space")
        with self.assertRaises(OSError):
            self.run_mail()
        self.deliver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
