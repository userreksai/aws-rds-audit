"""Real scheduled CLI + durable allowance; PDF drawing and SMTP network are mocked."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import smtplib
import unittest
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

import rds_multi as multi
from test_rds_multi import MultiFixture

UTC = timezone.utc
NOW = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
REPORT_DAY = date(2026, 11, 2)


class ScheduledDailyMailIntegrationTests(MultiFixture):
    def setUp(self):
        super().setUp()
        self.config.update(COLLECTION_INTERVAL_MINUTES=60, AUTO_MAIL_MAX_PER_DAY=1,
                           LARK_ALERTS_ENABLED=False, DAILY_MAIL_TIME="08:10")
        self.smtp = Mock()
        self.smtp.ehlo.return_value = (250, b"fixture hello")
        self.smtp.send_message.return_value = {}
        self.smtp_constructor = patch("rds_mail.smtplib.SMTP_SSL", return_value=self.smtp).start()
        self.pdf = patch("rds_pdf.render_account_pdf", side_effect=self.record_pdf).start()

    def record_pdf(self, report, destination, **kwargs):
        # Keep enough visible data to prove later rounds refresh local artifacts.
        destination = Path(destination)
        payload = {key: report.get(key) for key in ("account_id", "complete", "actors", "scope", "window", "report_kind")}
        destination.write_bytes(b"%PDF-1.4\n" + json.dumps(payload, sort_keys=True).encode())
        return destination

    def run_main(self, now=NOW, arguments=("--scheduled",)):
        path = self.configuration_path()

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now.astimezone(tz) if tz else now.replace(tzinfo=None)

        output, errors = StringIO(), StringIO()
        with patch.object(multi, "datetime", FrozenDatetime), redirect_stdout(output), redirect_stderr(errors):
            result = multi.main(["--config", str(path), *arguments])
        self.last_output = output.getvalue() + errors.getvalue()
        return result

    def budget(self):
        return multi.read_json(Path(self.config["OUTPUT_DIRECTORY"]) / ".daily-mail-budget.json")

    def seed_one(self, count=1, day=REPORT_DAY, account=None):
        left, _ = multi.day_window(day, ZoneInfo(self.config["TIMEZONE"]))
        return self.checkpoint(left, left + timedelta(hours=1), account=account, count=count)

    def seed_complete_day(self, day=REPORT_DAY):
        for account in self.config["ACCOUNTS"]:
            if account["ENABLED"]:
                for left, right in multi.windows(day, ZoneInfo(self.config["TIMEZONE"]), 60):
                    self.checkpoint(left, right, account=account, count=1)

    def test_automatic_subject_uses_beijing_sending_day_and_body_keeps_data_window(self):
        self.config["TIMEZONE"] = "Asia/Shanghai"
        day = date(2026, 11, 3)
        now = datetime(2026, 11, 4, 0, 10, tzinfo=UTC)
        self.seed_complete_day(day=day)
        self.assertEqual(self.run_main(now), 0)
        message = self.smtp.send_message.call_args.args[0]
        self.assertEqual(str(message["Subject"]), "AW-RDS审计报告 2026-11-04")
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("查询范围（北京时间，结束时刻不含）：\n2026-11-03 00:00:00 至 2026-11-04 00:00:00", body)
        self.assertIn("<table", message.get_body(preferencelist=("html",)).get_content())
        self.assertNotIn("影响行数", body)
        self.assertNotIn("最终事务提交数", body)
        self.assertTrue(all("2026-11-03-RDS-IP审计.pdf" in part.get_filename()
                            for part in message.iter_attachments()))
        receipt = multi.read_json(multi._delivery_path(self.config, day))
        self.assertEqual(receipt["date"], "2026-11-03")
        self.assertEqual(receipt["label"], "2026-11-04")
        self.assertEqual(self.budget()["entries"]["2026-11-04"]["report_day"], "2026-11-03")
        self.assertEqual(self.run_main(now + timedelta(minutes=5)), 0)
        self.smtp.send_message.assert_called_once()

    def test_every_five_minutes_changes_never_send_a_second_automatic_revision(self):
        self.seed_one()
        self.assertEqual(self.run_main(), 2)  # Initial partial report is explicitly marked.
        self.assertEqual(self.smtp.send_message.call_count, 1)
        sent = self.smtp.send_message.call_args.args[0]
        self.assertEqual(len(list(sent.iter_attachments())), 2)
        self.assertNotIn("修订", str(sent["Subject"]))
        directory = multi.day_directory(self.config, self.account, REPORT_DAY)
        pdf_path = next(directory.glob("*.pdf"))
        first_pdf = pdf_path.read_bytes()
        for iteration in range(1, 13):
            if iteration == 2:
                self.seed_complete_day()
            elif iteration == 3:
                path = self.seed_one(count=3)
                snapshot = multi.read_json(path)
                snapshot["active"]["complete"] = False
                multi.atomic_json(path, snapshot)
            elif iteration == 4:
                for account in self.config["ACCOUNTS"]:
                    account["REGIONS"] = "eu-west-1"
                self.seed_one(count=4)
            elif iteration == 5:
                self.config["MAIL_RECIPIENTS"].append("new-recipient@example.com")
                self.seed_one(count=5)
            elif iteration == 7:
                self.config["ACCOUNTS"][0]["ENABLED"] = False
            elif iteration == 8:
                self.config["ACCOUNTS"][0]["ENABLED"] = True
                self.seed_one(count=8)
            else:
                self.seed_one(count=iteration + 1)
            self.assertEqual(self.run_main(NOW + timedelta(minutes=5 * iteration)), 0)
            self.assertEqual(self.smtp.send_message.call_count, 1,
                             "A five-minute wake must not send another revision after allowance is used")
            self.assertEqual(self.budget()["entries"]["2026-11-03"]["used"], 1)
        self.assertNotEqual(first_pdf, pdf_path.read_bytes())
        latest = multi.read_json(directory / "ip-report.json")
        self.assertEqual(latest["actors"][0]["total"], 13)
        self.assertEqual(latest["scope"]["regions"], "eu-west-1")
        self.assertFalse(latest["complete"])
        self.assertGreater(self.pdf.call_count, 2)
        saved = json.dumps(self.budget())
        self.assertNotIn("PRIVATE", saved)
        self.assertNotIn("recipient@example.com", saved)

    def test_local_midnight_allows_next_day_even_when_utc_date_is_unchanged(self):
        self.config.update(TIMEZONE="Asia/Shanghai", DAILY_MAIL_TIME="00:00")
        before = datetime(2026, 11, 3, 15, 55, tzinfo=UTC)
        after = before + timedelta(minutes=10)
        self.assertEqual(before.date(), after.date())
        self.assertEqual(self.run_main(before), 2)
        self.assertEqual(self.run_main(before + timedelta(minutes=4)), 0)
        self.assertEqual(self.run_main(after), 2)
        self.assertEqual(self.smtp.send_message.call_count, 2)
        self.assertEqual(set(self.budget()["entries"]), {"2026-11-03", "2026-11-04"})
        self.assertTrue(all(entry["used"] == 1 for entry in self.budget()["entries"].values()))
        self.assertTrue(all("修订" not in str(call.args[0]["Subject"])
                            for call in self.smtp.send_message.call_args_list))
        self.assertEqual([str(call.args[0]["Subject"]) for call in self.smtp.send_message.call_args_list],
                         ["AW-RDS审计报告 2026-11-03 [数据不完整]",
                          "AW-RDS审计报告 2026-11-04 [数据不完整]"])

    def test_upgrade_imports_accepted_receipt_from_previous_first_disabled_account(self):
        old_directory = multi.day_directory(self.config, self.account, REPORT_DAY)
        multi.atomic_json(old_directory / "combined-mail.json",
                          {"status": "accepted", "complete": False, "date": REPORT_DAY.isoformat(),
                           "at": multi.iso(NOW - timedelta(minutes=5))})
        self.config["ACCOUNTS"][0]["ENABLED"] = False
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.run_main(NOW + timedelta(minutes=5)), 0)
        self.smtp_constructor.assert_not_called()
        entry = self.budget()["entries"]["2026-11-03"]
        self.assertEqual((entry["used"], entry["status"]), (1, "accepted"))
        self.assertEqual(self.pdf.call_count, 1)

    def test_zero_limit_updates_pdf_without_smtp_configuration_or_network(self):
        self.config.update(AUTO_MAIL_MAX_PER_DAY=0, SMTP_HOST="", SMTP_USERNAME="", SMTP_AUTH_CODE="",
                           MAIL_RECIPIENTS=[], MAIL_CC=[])
        self.seed_one()
        self.assertEqual(self.run_main(), 0)
        directory = multi.day_directory(self.config, self.account, REPORT_DAY)
        first_pdf = next(directory.glob("*.pdf")).read_bytes()
        self.seed_one(count=7)
        self.assertEqual(self.run_main(NOW + timedelta(minutes=5)), 0)
        self.assertNotEqual(first_pdf, next(directory.glob("*.pdf")).read_bytes())
        self.smtp_constructor.assert_not_called()
        self.assertEqual(self.budget()["entries"]["2026-11-03"]["used"], 0)

    def test_uncertain_smtp_submission_stays_reserved_across_later_wakes(self):
        self.smtp.send_message.side_effect = smtplib.SMTPServerDisconnected("PRIVATE-PROVIDER-RESPONSE")
        self.assertEqual(self.run_main(), 3)
        self.smtp.send_message.side_effect = None
        for minutes in (5, 15, 60):
            self.seed_one(count=minutes)
            self.assertEqual(self.run_main(NOW + timedelta(minutes=minutes)), 3)
        self.assertEqual(self.smtp.send_message.call_count, 1)
        entry = self.budget()["entries"]["2026-11-03"]
        self.assertEqual((entry["used"], entry["status"]), (1, "uncertain"))
        self.assertNotIn("PRIVATE-PROVIDER-RESPONSE", json.dumps(self.budget()))

    def test_corrupt_allowance_is_not_replaced_by_empty_budget_or_new_mail(self):
        self.assertEqual(self.run_main(), 2)
        path = Path(self.config["OUTPUT_DIRECTORY"]) / ".daily-mail-budget.json"
        path.write_text('{"schema_version":1,"entries":"broken"}', encoding="utf-8")
        self.seed_one(count=4)
        self.assertEqual(self.run_main(NOW + timedelta(minutes=5)), 3)
        self.assertEqual(self.smtp.send_message.call_count, 1)
        self.assertIn('"entries":"broken"', path.read_text(encoding="utf-8"))
        self.assertGreater(self.pdf.call_count, 2)

    def test_explicit_manual_report_can_send_without_resetting_automatic_allowance(self):
        self.assertEqual(self.run_main(), 2)
        self.assertEqual(self.run_main(NOW + timedelta(minutes=1),
                                     ("--report", "--date", "2026-11-03", "--send-mail")), 2)
        self.assertEqual(self.smtp.send_message.call_count, 2)
        self.assertEqual(self.run_main(NOW + timedelta(minutes=5)), 0)
        self.assertEqual(self.smtp.send_message.call_count, 2)
        self.assertEqual(self.budget()["entries"]["2026-11-03"]["used"], 1)
    def test_explicit_since_yesterday_sends_separate_range_without_resetting_daily_allowance(self):
        self.assertEqual(self.run_main(), 2)

        def collect(config, account, session, identity, start, end, directory):
            return self.snapshot(start, end, count=2)

        with patch.object(multi, "create_session", side_effect=self.session), \
                patch.object(multi, "collect_bucket", side_effect=collect):
            self.assertEqual(self.run_main(NOW + timedelta(minutes=1),
                                         ("--since-yesterday", "--send-mail")), 0)
        self.assertEqual(self.smtp.send_message.call_count, 2)
        subject = str(self.smtp.send_message.call_args.args[0]["Subject"])
        self.assertIn("昨日到当前", subject)
        self.assertEqual(self.run_main(NOW + timedelta(minutes=5)), 0)
        self.assertEqual(self.smtp.send_message.call_count, 2)
        self.assertEqual(self.budget()["entries"]["2026-11-03"]["used"], 1)


if __name__ == "__main__":
    unittest.main()
