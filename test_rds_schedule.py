"""Configured cutoff windows, real cache aggregation and migration mail budgets."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import rds_multi as multi
from rds_config import load_config
from rds_schedule import (configured_window, latest_report_day, report_segments,
                          report_window, window_tag)
from test_rds_multi import MultiFixture


UTC = timezone.utc
END_DAY = date(2026, 11, 6)
NOW = datetime(2026, 11, 6, 2, 5, tzinfo=UTC)


class ConfiguredScheduleTests(MultiFixture):
    def setUp(self):
        super().setUp()
        self.config.update(TIMEZONE="Asia/Shanghai", COLLECTION_INTERVAL_MINUTES=30,
                           DAILY_MAIL_TIME="10:05", REPORT_START_TIME="10:00", REPORT_END_TIME="10:00",
                           LARK_ALERTS_ENABLED=False, LOG_DELAY_MINUTES=5)
        self.config["ACCOUNTS"][1]["ENABLED"] = False

    def loaded(self, **changes):
        self.config.update(changes)
        return load_config(self.configuration_path())

    def seed_window(self, *, end_day=END_DAY, count=1):
        start, end = report_window(self.config, end_day)
        for left, right in report_segments(self.config, start, end):
            self.checkpoint(left, right, count=count)
        return start, end

    def run_main(self, now=NOW, arguments=("--scheduled",)):
        path = self.configuration_path()

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now.astimezone(tz) if tz else now.replace(tzinfo=None)

        output = StringIO()
        with patch.object(multi, "datetime", FrozenDatetime), redirect_stdout(output), redirect_stderr(output):
            result = multi.main(["--config", str(path), *arguments])
        self.last_output = output.getvalue()
        return result

    def smtp(self):
        smtp = Mock()
        smtp.ehlo.return_value = (250, b"offline fixture")
        smtp.send_message.return_value = {}
        return smtp

    def budget_path(self):
        return Path(self.config["OUTPUT_DIRECTORY"]) / ".daily-mail-budget.json"

    def test_legacy_configs_keep_natural_day_dates_without_a_cutoff_tag(self):
        self.config.pop("REPORT_START_TIME")
        self.config.pop("REPORT_END_TIME")
        config = self.loaded(DAILY_MAIL_TIME="08:10")
        self.assertFalse(configured_window(config))
        self.assertIsNone(window_tag(config))
        self.assertEqual((config["REPORT_START_TIME"], config["REPORT_END_TIME"]), ("", ""))
        self.assertEqual(latest_report_day(config, NOW), END_DAY - timedelta(days=1))
        self.assertEqual(multi.scheduled_day(config, NOW), END_DAY - timedelta(days=1))
        self.assertNotIn("manual", multi._delivery_path(config, END_DAY - timedelta(days=1)).parts)

    def test_both_cutoff_fields_are_required_and_times_align_with_collection_buckets(self):
        invalid = (
            {"REPORT_START_TIME": "", "REPORT_END_TIME": "10:00"},
            {"REPORT_START_TIME": "10:00", "REPORT_END_TIME": ""},
            {"REPORT_START_TIME": None}, {"REPORT_END_TIME": True},
            {"REPORT_START_TIME": "9:00"}, {"REPORT_END_TIME": "24:00"},
            {"REPORT_START_TIME": "10:15"}, {"REPORT_END_TIME": "10:01"},
            {"REPORT_START_TIME": "10:30", "COLLECTION_INTERVAL_MINUTES": 60},
            {"DAILY_MAIL_TIME": "10:04"}, {"LOG_DELAY_MINUTES": 6},
        )
        original = deepcopy(self.config)
        for changes in invalid:
            with self.subTest(changes=changes):
                self.config = {**deepcopy(original), **changes}
                with self.assertRaises(ValueError):
                    load_config(self.configuration_path())
        self.config = original
        config = self.loaded()
        self.assertEqual(window_tag(config), "window-1000-1000")
        self.assertTrue(configured_window(config))

    def test_end_date_maps_to_requested_beijing_24_hour_range_and_buffer_boundary(self):
        start, end = report_window(self.config, END_DAY)
        self.assertEqual(start, datetime(2026, 11, 5, 2, tzinfo=UTC))
        self.assertEqual(end, datetime(2026, 11, 6, 2, tzinfo=UTC))
        self.assertEqual(latest_report_day(self.config, NOW - timedelta(microseconds=1)), END_DAY - timedelta(days=1))
        self.assertEqual(latest_report_day(self.config, NOW), END_DAY)
        self.assertIsNone(multi.scheduled_day(self.config, NOW - timedelta(microseconds=1)))
        self.assertEqual(multi.scheduled_day(self.config, NOW), END_DAY)
        self.assertEqual(multi.scheduled_day(self.config, datetime(2026, 11, 6, 15, 59, 59, tzinfo=UTC)), END_DAY)
        self.assertIsNone(multi.scheduled_day(self.config, datetime(2026, 11, 6, 16, tzinfo=UTC)))

    def test_distinct_start_and_end_times_keep_the_previous_day_start_semantics(self):
        self.config.update(REPORT_START_TIME="09:00", REPORT_END_TIME="10:00")
        start, end = report_window(self.config, END_DAY)
        segments = list(report_segments(self.config, start, end))
        self.assertEqual(end - start, timedelta(hours=25))
        self.assertEqual(len(segments), 50)
        self.config.update(REPORT_START_TIME="11:00")
        start, end = report_window(self.config, END_DAY)
        self.assertEqual(end - start, timedelta(hours=23))
        self.assertEqual(len(list(report_segments(self.config, start, end))), 46)

    def test_real_48_cached_segments_merge_across_dates_and_exclude_both_outside_neighbors(self):
        start, end = self.seed_window()
        self.checkpoint(start - timedelta(minutes=30), start, count=11)
        self.checkpoint(end, end + timedelta(minutes=30), count=13)
        report = multi.build_report(self.config, self.account, END_DAY, NOW)
        self.assertTrue(report["complete"])
        self.assertEqual(report["segments"], {"expected": 48, "present": 48})
        self.assertEqual(report["window"], {"start_inclusive": multi.iso(start), "end_exclusive": multi.iso(end)})
        self.assertEqual(report["actors"][0]["total"], 48)
        self.assertEqual(report["actors"][0]["counts"]["修改"], 48)
        self.assertEqual(report["artifact_tag"], "window-1000-1000")
        self.assertEqual(report["report_kind"], "configured_window")
        self.assertEqual(report["date"], "2026-11-06")

    def test_missing_cross_day_segment_is_incomplete_without_becoming_zero_success(self):
        start, end = self.seed_window()
        missing = start + timedelta(hours=14)
        multi.bucket_path(self.config, self.account, missing).unlink()
        report = multi.build_report(self.config, self.account, END_DAY, NOW)
        self.assertFalse(report["complete"])
        self.assertEqual(report["segments"], {"expected": 48, "present": 47})
        self.assertEqual(report["actors"][0]["total"], 47)
        self.assertTrue(any(error["error_type"] == "MissingOrInvalidBucket" for error in report["errors"]))
        with self.assertRaisesRegex(ValueError, "日志缓冲"):
            multi.build_report(self.config, self.account, END_DAY, NOW - timedelta(microseconds=1))

    def test_cutoff_pdf_and_receipt_do_not_overwrite_existing_natural_day_artifacts(self):
        self.seed_window()
        directory = multi.day_directory(self.config, self.account, END_DAY)
        legacy_files = {directory / "ip-report.json": b'{"legacy":"keep"}',
                        directory / "production-123456789012-2026-11-06-RDS-IP审计.pdf": b"%PDF-legacy",
                        directory / "combined-mail.json": b'{"status":"accepted","legacy":"keep"}'}
        for path, value in legacy_files.items():
            path.write_bytes(value)
        sender = Mock(return_value={"message_id": "cutoff"})
        with patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), redirect_stdout(StringIO()):
            result = multi.deliver(self.config, END_DAY, NOW, sender=sender)
        self.assertEqual(result["status"], "accepted")
        receipt = multi._delivery_path(self.config, END_DAY)
        self.assertEqual(receipt.parent, directory / "manual" / "window-1000-1000")
        self.assertEqual(multi.read_json(receipt)["date"], "2026-11-06")
        pdf = sender.call_args.args[1][0]
        self.assertEqual(pdf.parent, receipt.parent)
        self.assertIn("window-1000-1000", pdf.name)
        for path, value in legacy_files.items():
            self.assertEqual(path.read_bytes(), value)

    def test_scheduled_cli_uses_end_date_and_one_mail_when_cutoffs_and_tags_change(self):
        self.seed_window()
        self.account["TAG"] = "测试账号"
        smtp = self.smtp()
        with patch("rds_mail.smtplib.SMTP_SSL", return_value=smtp), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf):
            self.assertEqual(self.run_main(NOW - timedelta(seconds=1)), 0)
            smtp.send_message.assert_not_called()
            self.assertEqual(self.run_main(), 0, self.last_output)
            smtp.send_message.assert_called_once()
            message = smtp.send_message.call_args.args[0]
            self.assertIn("2026-11-06", str(message["Subject"]))
            self.assertIn("2026-11-05 10:00:00 至 2026-11-06 10:00:00", message.get_body(preferencelist=("plain",)).get_content())
            self.assertEqual(multi.read_json(self.budget_path())["entries"]["2026-11-06"]["report_day"], "2026-11-06")
            self.config.update(REPORT_START_TIME="09:00")
            self.account["TAG"] = "修改标签"
            self.config["MAIL_RECIPIENTS"].append("new@example.com")
            self.assertEqual(self.run_main(NOW + timedelta(minutes=5)), 0)
            smtp.send_message.assert_called_once()
            self.assertTrue((multi.day_directory(self.config, self.account, END_DAY) / "manual" / "window-0900-1000" / "ip-report.json").is_file())
            entry = multi.read_json(self.budget_path())["entries"]["2026-11-06"]
            self.assertEqual((entry["used"], entry["status"]), (1, "accepted"))

    def test_upgrade_without_budget_imports_legacy_previous_data_day_receipt(self):
        for status in ("accepted", "sending", "uncertain"):
            with self.subTest(status=status):
                if self.budget_path().exists():
                    self.budget_path().unlink()
                old_directory = multi.day_directory(self.config, self.account, END_DAY - timedelta(days=1))
                multi.atomic_json(old_directory / "combined-mail.json", {"status": status, "at": multi.iso(NOW - timedelta(minutes=1))})
                smtp = self.smtp()
                with patch("rds_mail.smtplib.SMTP_SSL", return_value=smtp), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf):
                    result = self.run_main()
                    self.assertEqual(result, 0 if status == "accepted" else 3, self.last_output)
                    smtp.send_message.assert_not_called()
                entry = multi.read_json(self.budget_path())["entries"]["2026-11-06"]
                self.assertEqual(entry["used"], 1)
                self.assertEqual(entry["status"], "accepted" if status == "accepted" else "uncertain")

    def test_window_receipts_survive_missing_budget_and_switching_back_to_legacy_mode(self):
        first = multi._delivery_path(self.config, END_DAY)
        multi.atomic_json(first, {"status": "accepted", "at": multi.iso(NOW)})
        self.config.update(REPORT_START_TIME="09:00")
        with patch("rds_mail.smtplib.SMTP_SSL") as smtp, patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf):
            self.assertEqual(self.run_main(), 0)
            smtp.assert_not_called()
        self.budget_path().unlink()
        self.config.update(REPORT_START_TIME="", REPORT_END_TIME="")
        with patch("rds_mail.smtplib.SMTP_SSL") as smtp, patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf):
            self.assertEqual(self.run_main(), 0)
            smtp.assert_not_called()
        self.assertEqual(multi.read_json(first)["status"], "accepted")
        self.assertEqual(multi.read_json(self.budget_path())["entries"]["2026-11-06"]["used"], 1)

    def test_yesterday_to_now_manual_receipts_do_not_consume_the_automatic_allowance(self):
        manual = multi.manual_directory(self.config, self.account, END_DAY, "since-yesterday-example")
        multi.atomic_json(manual / "combined-mail.json", {"status": "accepted", "at": multi.iso(NOW)})
        self.assertEqual(multi.daily_receipts(self.config, END_DAY), [])
        smtp = self.smtp()
        with patch("rds_mail.smtplib.SMTP_SSL", return_value=smtp), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf):
            self.assertEqual(self.run_main(), 2)
            smtp.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
