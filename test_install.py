"""Deployment scheduler boundary tests; no AWS/Lark requests or service changes."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rds_deployment_runner", ROOT / "deploy/run_daily.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CompletedWindowTests(unittest.TestCase):
    def test_before_eight_uses_previous_completed_beijing_date(self):
        now = datetime(2026, 10, 29, 7, 59, 59, tzinfo=runner.BEIJING)
        self.assertEqual(runner.latest_completed_date(now), "2026-10-28")

    def test_eight_is_the_completion_boundary_regardless_of_server_timezone(self):
        self.assertEqual(runner.latest_completed_date(datetime(2026, 10, 29, 0, tzinfo=timezone.utc)), "2026-10-29")
        self.assertEqual(runner.latest_completed_date(datetime(2026, 10, 29, 8, 10, tzinfo=runner.BEIJING)), "2026-10-29")
        with self.assertRaises(ValueError):
            runner.latest_completed_date(datetime(2026, 10, 29, 8, 10))


class EnvironmentTests(unittest.TestCase):
    def test_environment_values_are_data_and_not_shell_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.env"
            path.write_text('# comment\nAWS_PROFILE="literal $(touch /tmp/no-command)"\nAWS_RDS_REPORT_ROOT="/opt/path with spaces/reports"\nEMPTY=\n', encoding="utf-8")
            with patch.object(runner.subprocess, "run") as execute:
                values = runner.load_environment(path)
            execute.assert_not_called()
            self.assertEqual(values["AWS_PROFILE"], "literal $(touch /tmp/no-command)")
            self.assertEqual(values["AWS_RDS_REPORT_ROOT"], "/opt/path with spaces/reports")
            self.assertEqual(values["EMPTY"], "")

    def test_unsupported_environment_syntax_is_rejected(self):
        for text in ("export AWS_PROFILE=a\n", "BAD KEY=value\n", "AWS_PROFILE=unquoted space\n", "MISSING_VALUE\n"):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "audit.env"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    runner.load_environment(path)

    def test_explicit_profile_and_publish_paths_remain_single_arguments(self):
        environment = {
            "AWS_PROFILE": "profile with spaces", "AWS_RDS_REGIONS": "eu-north-1,ap-southeast-1",
            "AWS_RDS_PUBLISH_DIR": "/srv/rds report", "AWS_RDS_REPORT_ROOT": "/private/rds reports",
        }
        command = runner.build_command(environment, now=datetime(2026, 10, 29, 0, tzinfo=timezone.utc))
        self.assertEqual(command[command.index("--date") + 1], "2026-10-29")
        self.assertEqual(command[command.index("--profile") + 1], "profile with spaces")
        self.assertEqual(command[command.index("--publish-dir") + 1], "/srv/rds report")
        self.assertIn("--send-lark", command)
        self.assertIn("--daily", command)

    def test_precheck_needs_no_completed_window_and_keeps_default_role_chain(self):
        command = runner.build_command({}, check=True)
        self.assertIn("--check-config", command)
        self.assertIn("--send-lark", command)
        for unwanted in ("--daily", "--date", "--profile", "--publish-dir"):
            self.assertNotIn(unwanted, command)

    def test_precheck_does_not_create_reports_or_run_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "rds_audit.py").write_text("# test\n", encoding="utf-8")
            reports = project / "not-created"
            with patch.object(runner, "PROJECT", project), patch.dict(os.environ, {"AWS_RDS_REPORT_ROOT": str(reports)}, clear=True), patch.object(runner.subprocess, "run", return_value=Mock(returncode=0)) as execute:
                self.assertEqual(runner.main(["--check-config"]), 0)
            execute.assert_called_once()
            self.assertFalse(reports.exists())


@unittest.skipUnless(sys.platform.startswith("linux"), "flock integration requires Linux")
class SchedulerLockTests(unittest.TestCase):
    def test_completed_day_is_sent_once_and_new_command_can_rerun(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(runner.subprocess, "run", return_value=Mock(returncode=0)) as execute, redirect_stdout(StringIO()):
                self.assertEqual(runner.run_locked(["python", "audit.py", "--profile", "first"], directory, "2026-10-29"), 0)
                self.assertEqual(runner.run_locked(["python", "audit.py", "--profile", "first"], directory, "2026-10-29"), 0)
                self.assertEqual(execute.call_count, 1)
                self.assertEqual(runner.run_locked(["python", "audit.py", "--profile", "second"], directory, "2026-10-29"), 0)
                self.assertEqual(execute.call_count, 2)
            record = json.loads((directory / ".daily-last-success.json").read_text(encoding="utf-8"))
            self.assertEqual(record["date"], "2026-10-29")

    def test_partial_failure_is_not_marked_success_and_can_be_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(runner.subprocess, "run", side_effect=[Mock(returncode=2), Mock(returncode=0)]) as execute:
                self.assertEqual(runner.run_locked(["python", "audit.py"], directory, "2026-10-29"), 2)
                self.assertFalse((directory / ".daily-last-success.json").exists())
                self.assertEqual(runner.run_locked(["python", "audit.py"], directory, "2026-10-29"), 0)
                self.assertEqual(execute.call_count, 2)

    def test_overlapping_runner_does_not_launch_a_second_collection(self):
        import fcntl

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with (directory / ".daily.lock").open("a") as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(runner.subprocess, "run") as execute, redirect_stdout(StringIO()):
                    self.assertEqual(runner.run_locked(["python", "audit.py"], directory, "2026-10-29"), 0)
                execute.assert_not_called()


class TimerContractTests(unittest.TestCase):
    def test_timer_is_fixed_to_beijing_without_random_delay(self):
        text = (ROOT / "deploy/aws-rds-audit.timer").read_text(encoding="utf-8")
        self.assertIn("OnCalendar=*-*-* 08:10:00 Asia/Shanghai", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("RandomizedDelaySec=0", text)


if __name__ == "__main__":
    unittest.main()
