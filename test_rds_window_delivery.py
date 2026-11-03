"""Fresh-window CLI integration: fake AWS/SMTP, real aggregation and PDF output."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import rds_multi as multi
from rds_window import window_identity
from test_rds_multi import MultiFixture
from test_rds_report import audit_event

UTC = timezone.utc
NOW = datetime(2026, 11, 3, 1, 23, 45, 123987, tzinfo=UTC)


class WindowDeliveryTests(MultiFixture):
    def setUp(self):
        super().setUp()
        self.config.update(TIMEZONE="Asia/Shanghai", ACCOUNT_CONCURRENCY=2,
                           MAX_BUCKETS_PER_ACCOUNT_PER_RUN=1)
        self.start, self.end, self.tag = window_identity(self.config, NOW)
        self.today = self.end.astimezone(multi.ZoneInfo(self.config["TIMEZONE"])).date()
        self.aws_sessions = {}

    def clock(self):
        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)

        return patch.object(multi, "datetime", FrozenDatetime)

    def event(self, sql, source, index, when):
        event = audit_event(sql=sql, event_id="statement-" + str(index), when=when)
        fields = event["message"].split(",", 8)
        fields[3] = source
        event["message"] = ",".join(fields)
        return event

    def fake_aws(self, account, *, fail=False):
        session, sts, logs, trail = Mock(), Mock(), Mock(), Mock()
        session.client.side_effect = lambda service, **kwargs: {"sts": sts, "logs": logs, "cloudtrail": trail}[service]
        sts.get_caller_identity.return_value = {"Account": account["ACCOUNT_ID"], "Arn": "arn:aws:iam::" + account["ACCOUNT_ID"] + ":user/audit"}
        logs.describe_log_groups.return_value = {"logGroups": [{"logGroupName": "/aws/rds/cluster/" + account["NAME"] + "/audit"}]}
        if fail:
            logs.filter_log_events.side_effect = RuntimeError("PRIVATE-KEY raw provider failure")
        else:
            source = "192.0.2.11" if account["NAME"] == "production" else "2001:db8::22"
            queries = ["INSERT INTO private_table VALUES ('PRIVATE-SQL')", "UPDATE private_table SET secret='PRIVATE-SQL'"] if account["NAME"] == "production" else ["DELETE FROM private_table", "DELETE FROM private_table WHERE secret='PRIVATE-SQL'"]
            logs.filter_log_events.return_value = {"events": [
                self.event(queries[0], source, 1, self.start),
                self.event(queries[1], source, 2, self.end - timedelta(milliseconds=1)),
                self.event("DELETE FROM private_table", source, 3, self.end),
            ]}
        trail.lookup_events.return_value = {"Events": []}
        self.aws_sessions[account["ACCOUNT_ID"]] = (session, sts, logs, trail)
        return session

    def smtp(self):
        smtp = Mock()
        smtp.ehlo.return_value = (250, b"ok")
        smtp.send_message.return_value = {}
        return smtp

    def manual_report(self, account):
        directory = multi.manual_directory(self.config, account, self.today, self.tag)
        return directory, multi.read_json(directory / "ip-report.json")

    def test_real_whole_window_collector_and_pdf_send_one_combined_mail_without_overwriting_daily_files(self):
        daily_files = {}
        for account in self.config["ACCOUNTS"]:
            directory = multi.day_directory(self.config, account, self.today)
            daily = directory / f"{account['NAME']}-{account['ACCOUNT_ID']}-{self.today.isoformat()}-RDS-IP审计.pdf"
            daily.write_bytes(b"daily-pdf-must-remain")
            daily_files[daily] = daily.read_bytes()
            report = directory / "ip-report.json"
            report.write_text('{"daily":"preserve"}', encoding="utf-8")
            daily_files[report] = report.read_bytes()
        receipt = multi._delivery_path(self.config, self.today)
        receipt.write_text('{"status":"accepted","daily":"preserve"}', encoding="utf-8")
        daily_files[receipt] = receipt.read_bytes()
        path, smtp = self.configuration_path(), self.smtp()
        output = StringIO()
        with self.clock(), patch.object(multi, "create_session", side_effect=self.fake_aws) as sessions, patch("rds_mail.smtplib.SMTP_SSL", return_value=smtp) as connect, redirect_stdout(output), redirect_stderr(output):
            result = multi.main(["--config", str(path), "--since-yesterday", "--send-mail"])
        self.assertEqual(result, 0, output.getvalue())
        self.assertEqual(sessions.call_count, 2)
        connect.assert_called_once()
        smtp.send_message.assert_called_once()
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(str(message["Subject"]), "AW-RDS审计报告 昨日到当前 2026-11-03 09:23:45")
        body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("2026-11-02 00:00:00 至 2026-11-03 09:23:45", body)
        self.assertIn("Asia/Shanghai", body)
        self.assertIn("临近", body.replace("最近", "临近"))
        attachments = list(message.iter_attachments())
        self.assertEqual(len(attachments), 2)
        self.assertTrue(all(part.get_content_type() == "application/pdf" and part.get_payload(decode=True).startswith(b"%PDF-") for part in attachments))
        self.assertEqual({part.get_filename() for part in attachments},
                         {f"{account['NAME']}-{account['ACCOUNT_ID']}-{self.today.isoformat()}-{self.tag}-RDS-IP审计.pdf" for account in self.config["ACCOUNTS"]})
        for account in self.config["ACCOUNTS"]:
            directory, report = self.manual_report(account)
            self.assertTrue(report["complete"])
            self.assertEqual(report["window"], {"start_inclusive": multi.iso(self.start), "end_exclusive": multi.iso(self.end)})
            self.assertEqual(report["report_kind"], "since_yesterday")
            self.assertEqual(report["scope"]["source_filter"], "ip_only")
            row = report["actors"][0]
            self.assertEqual(row["source_ip"], "192.0.2.11" if account["NAME"] == "production" else "2001:db8::22")
            self.assertEqual(row["total"], 2)
            self.assertEqual(row["counts"]["删除"], 0 if account["NAME"] == "production" else 2)
            logs = self.aws_sessions[account["ACCOUNT_ID"]][2]
            logs.filter_log_events.assert_called_once()
            request = logs.filter_log_events.call_args.kwargs
            self.assertEqual((request["startTime"], request["endTime"]),
                             (int(self.start.timestamp() * 1000), int(self.end.timestamp() * 1000)))
            self.assertGreater(request["endTime"] - request["startTime"], 24 * 3600 * 1000)
            self.assertEqual(len(list(directory.glob("*.pdf"))), 1)
        manual_receipt = multi.manual_directory(self.config, self.account, self.today, self.tag) / "combined-mail.json"
        self.assertEqual(multi.read_json(manual_receipt)["status"], "accepted")
        for file, original in daily_files.items():
            self.assertEqual(file.read_bytes(), original)
        self.assertFalse(list(Path(self.config["OUTPUT_DIRECTORY"]).rglob("*.jsonl")))
        self.assertFalse(list(Path(self.config["OUTPUT_DIRECTORY"]).rglob(".window-attempt-*")))
        self.assertNotIn("PRIVATE-KEY", output.getvalue())

    def test_without_send_mail_generates_pdfs_without_requiring_or_touching_smtp(self):
        self.config.update(SMTP_HOST="", SMTP_USERNAME="", SMTP_AUTH_CODE="", MAIL_RECIPIENTS=[], MAIL_CC=[])
        path = self.configuration_path()
        with self.clock(), patch.object(multi, "create_session", side_effect=self.fake_aws), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf) as pdf, patch("rds_mail.send_reports") as send, patch("rds_mail.smtplib.SMTP_SSL") as smtp, redirect_stdout(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--since-yesterday"]), 0)
        self.assertEqual(pdf.call_count, 2)
        send.assert_not_called()
        smtp.assert_not_called()
        for account in self.config["ACCOUNTS"]:
            directory, report = self.manual_report(account)
            self.assertTrue(report["complete"])
            self.assertTrue(list(directory.glob("*.pdf")))
            self.assertFalse((directory / "combined-mail.json").exists())

    def test_incomplete_account_is_explicit_in_combined_mail_and_returns_two(self):
        path, smtp = self.configuration_path(), self.smtp()
        with self.clock(), patch.object(multi, "create_session", side_effect=lambda account: self.fake_aws(account, fail=account["NAME"] == "production")), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf), patch("rds_mail.smtplib.SMTP_SSL", return_value=smtp), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--since-yesterday", "--send-mail"]), 2)
        smtp.send_message.assert_called_once()
        message = smtp.send_message.call_args.args[0]
        self.assertIn("数据不完整", str(message["Subject"]))
        self.assertIn("production (123456789012)：数据不完整", message.get_body(preferencelist=("plain",)).get_content())
        self.assertEqual(len(list(message.iter_attachments())), 2)
        self.assertFalse(self.manual_report(self.account)[1]["complete"])
        self.assertTrue(self.manual_report(self.config["ACCOUNTS"][1])[1]["complete"])

    def test_busy_collection_waits_then_times_out_without_aws_pdf_or_mail(self):
        path, output = self.configuration_path(), StringIO()

        @contextmanager
        def held(path):
            yield False

        with patch.object(multi, "_exclusive", side_effect=held), patch.object(multi.process_time, "monotonic", side_effect=[0, 0, 601]), patch.object(multi.process_time, "sleep") as sleep, patch.object(multi, "create_session") as aws, patch("rds_pdf.render_account_pdf") as pdf, patch("rds_mail.send_reports") as send, redirect_stdout(output):
            self.assertEqual(multi.main(["--config", str(path), "--since-yesterday", "--send-mail"]), 1)
        self.assertIn("等待正在运行的任务完成", output.getvalue())
        sleep.assert_called_once_with(2)
        aws.assert_not_called()
        pdf.assert_not_called()
        send.assert_not_called()

    def test_busy_delivery_preserves_collected_pdfs_without_sending(self):
        path = self.configuration_path()
        locks = []

        @contextmanager
        def task_lock(lock_path, wait_seconds=0):
            locks.append((lock_path.name, wait_seconds))
            yield lock_path.name.endswith(".collect.lock")

        with self.clock(), patch.object(multi, "task_lock", side_effect=task_lock), patch.object(multi, "create_session", side_effect=self.fake_aws), patch("rds_pdf.render_account_pdf", side_effect=self.fake_pdf) as pdf, patch("rds_mail.send_reports") as send, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--since-yesterday", "--send-mail"]), 3)
        self.assertEqual(locks, [(".multi-account.collect.lock", 600), (".multi-account.delivery.lock", 120)])
        self.assertEqual(pdf.call_count, 2)
        send.assert_not_called()
        self.assertTrue(all(list(self.manual_report(account)[0].glob("*.pdf")) for account in self.config["ACCOUNTS"]))

    def test_unsafe_artifact_tag_cannot_escape_manual_directory(self):
        for tag in ("../escape", "..", "/absolute", "bad\\path", "%n", "x" * 101):
            report = self.simple_report(self.config, self.account, self.today, NOW)
            report.update(report_kind="since_yesterday", artifact_tag=tag)
            with self.subTest(tag=tag), patch("rds_pdf.render_account_pdf") as render:
                with self.assertRaisesRegex(ValueError, "标识"):
                    multi._render_reports(self.config, [report])
                render.assert_not_called()
        self.assertFalse((self.root / "escape").exists())

    def test_no_enabled_accounts_never_collect_or_send(self):
        for account in self.config["ACCOUNTS"]:
            account["ENABLED"] = False
        path = self.configuration_path()
        with self.clock(), patch.object(multi, "create_session") as aws, patch("rds_pdf.render_account_pdf") as pdf, patch("rds_mail.send_reports") as send, redirect_stdout(StringIO()):
            self.assertEqual(multi.main(["--config", str(path), "--since-yesterday", "--send-mail"]), 0)
        aws.assert_not_called()
        pdf.assert_not_called()
        send.assert_not_called()

    def test_invalid_mode_options_are_rejected_before_loading_config_or_network(self):
        path = self.configuration_path()
        for arguments in (("--since-yesterday", "--date", "2026-11-02"),
                          ("--since-yesterday", "--force-resend"), ("--collect", "--send-mail")):
            with self.subTest(arguments=arguments), patch.object(multi, "load_config") as load, patch.object(multi, "create_session") as aws, patch("rds_mail.send_reports") as send, redirect_stderr(StringIO()):
                self.assertEqual(multi.main(["--config", str(path), *arguments]), 1)
                load.assert_not_called()
                aws.assert_not_called()
                send.assert_not_called()
        with patch.object(multi, "load_config") as load, redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                multi.main(["--config", str(path), "--report", "--since-yesterday"])
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
