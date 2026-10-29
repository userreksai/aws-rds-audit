"""Exact-time query windows use one injected clock and no live AWS or Lark."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import rds_audit as audit

UTC = timezone.utc
NOW = datetime(2026, 10, 29, 13, 5, 7, tzinfo=UTC)


def options(*extra):
    return audit.build_parser().parse_args(["--regions", "ap-east-1", *extra])


class CustomWindowTests(unittest.TestCase):
    def test_since_yesterday_seven_uses_beijing_date_and_current_instant(self):
        kind, day, start, end = audit.resolve_report_window(options("--since-yesterday-7"), NOW)
        self.assertEqual((kind, day), ("custom", "2026-10-29"))
        self.assertEqual(start, datetime(2026, 10, 27, 23, tzinfo=UTC))
        self.assertEqual(end, NOW)
        # Beijing midnight already belongs to Oct 30 even while UTC is Oct 29.
        midnight = datetime(2026, 10, 29, 16, 0, 1, tzinfo=UTC)
        _, day, start, end = audit.resolve_report_window(options("--since-yesterday-7"), midnight)
        self.assertEqual(day, "2026-10-30")
        self.assertEqual(start, datetime(2026, 10, 28, 23, tzinfo=UTC))
        self.assertEqual(end, midnight)

    def test_end_now_is_resolved_once_from_the_supplied_clock(self):
        start, end = audit.make_window(options("--start", "2026-10-28T07:00:00+08:00", "--end", "now"), NOW)
        self.assertEqual(start, datetime(2026, 10, 27, 23, tzinfo=UTC))
        self.assertEqual(end, NOW)
        self.assertTrue(audit.in_window(start, start, end))
        self.assertFalse(audit.in_window(end, start, end))

    def test_explicit_range_keeps_exact_offset_and_validates_boundaries(self):
        start, end = audit.make_window(options("--start", "2026-10-29T20:59:59+08:00", "--end", "2026-10-29T21:05:07+08:00"), NOW)
        self.assertEqual(end - start, timedelta(minutes=5, seconds=8))
        for start_value, end_value in (
            ("2026-10-29T21:05:07+08:00", "now"),
            ("2026-10-29T21:05:08+08:00", "now"),
            ("2026-10-29T20:00:00+08:00", "2026-10-29T21:05:08+08:00"),
            ("2026-01-01T00:00:00Z", "now"),
        ):
            with self.subTest(start=start_value, end=end_value), self.assertRaises(ValueError):
                audit.make_window(options("--start", start_value, "--end", end_value), NOW)

    def test_shortcut_rejects_conflicting_modes_before_credentials(self):
        extras = (["--days", "1"], ["--start", "2026-10-28T07:00:00+08:00"], ["--end", "now"],
                  ["--daily"], ["--date", "2026-10-29"], ["--input-dir", "unused"], ["--from-cache"],
                  ["--collect-incremental"], ["--notify-service-failure"], ["--check-config"])
        for extra in extras:
            with self.subTest(extra=extra), patch.object(audit, "aws_session") as aws, redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main(["--since-yesterday-7", *extra]), 1)
                aws.assert_not_called()

    def test_daily_window_still_ends_at_eight_and_has_twenty_five_hours(self):
        _, start, end = audit.daily_window("2026-10-29", NOW)
        self.assertEqual(end - start, timedelta(hours=25))
        self.assertEqual(end, datetime(2026, 10, 29, 0, tzinfo=UTC))
        self.assertNotEqual(end, audit.make_window(options("--since-yesterday-7"), NOW)[1])

    def test_explicit_and_shortcut_queries_download_sql_without_extra_flag(self):
        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return NOW.astimezone(tz or UTC)

        for extra in (["--since-yesterday-7"], ["--start", "2026-10-28T07:00:00+08:00", "--end", "now"]):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                result = SimpleNamespace(report={"collection_status": "ok", "failed_check_count": 0}, run=Mock(return_value=0))
                with patch.object(audit, "datetime", FrozenDateTime), \
                        patch.object(audit, "aws_session", return_value=(Mock(), None, {"Account": "123456789012"})), \
                        patch.object(audit, "Collector", return_value=result) as collector, \
                        patch.object(audit, "finish_daily", return_value=0) as finish, \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(audit.main(["--regions", "ap-east-1", "--output-dir", temporary, *extra]), 0)
                call_args = collector.call_args.args
                self.assertTrue(call_args[5].download_sql_logs)
                self.assertEqual(call_args[2], datetime(2026, 10, 27, 23, tzinfo=UTC))
                self.assertEqual(call_args[3], NOW)
                self.assertEqual(finish.call_args.kwargs["period_kind"], "custom")
                self.assertTrue(Path(temporary, "123456789012").is_dir())


if __name__ == "__main__":
    unittest.main()
