"""Daily window, publication and signed summary integration checks; no network."""
import base64
import hashlib
import hmac
import io
import json
import os
import shutil
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import rds_audit as audit
import lark_notify as notify

UTC = timezone.utc
WEBHOOK = "https://open.larksuite.com/open-apis/bot/v2/hook/OFFLINE-TEST-ONLY"


def example_report():
    return {"metadata": {
        "audit_date": "2026-10-29", "account_id": "123456789012", "complete": True,
        "counts": {"新增": 2, "删除": 1, "修改": 3, "其他操作": 4},
        "source_counts": {"management": {"新增": 1, "删除": 1, "修改": 1}, "sql": {"新增": 1, "删除": 0, "修改": 2}},
        "total": 12, "failed_or_partial": 2,
        "window_start_utc": "2026-10-27T23:00:00Z", "window_end_utc_exclusive": "2026-10-29T00:00:00Z",
        "report_filename": "2026-10-29-rds操作审计.html", "offline": False,
    }, "events": [{"sql": "UPDATE customers SET private_value='MUST-NOT-LEAK'"}]}


class DailyWindowTests(unittest.TestCase):
    def test_beijing_window_is_25_hours_and_adjacent_days_overlap_one_hour(self):
        now = datetime(2026, 10, 29, 0, 10, tzinfo=UTC)
        day, start, end = audit.daily_window(None, now)
        self.assertEqual(day, "2026-10-29")
        self.assertEqual(start, datetime(2026, 10, 27, 23, tzinfo=UTC))
        self.assertEqual(end, datetime(2026, 10, 29, 0, tzinfo=UTC))
        self.assertEqual(end - start, timedelta(hours=25))
        _, _, prior_end = audit.daily_window("2026-10-28", now)
        self.assertEqual(prior_end - start, timedelta(hours=1))

    def test_early_and_future_windows_rejected(self):
        with self.assertRaisesRegex(ValueError, "尚未结束"):
            audit.daily_window(None, datetime(2026, 10, 28, 23, 59, tzinfo=UTC))
        with self.assertRaises(ValueError):
            audit.daily_window("2026-10-30", datetime(2026, 10, 29, 0, 10, tzinfo=UTC))

    def test_incompatible_arguments_never_connect_to_aws(self):
        for arguments in (["--daily", "--days", "1"], ["--date", "2026-10-29"], ["--send-lark"], ["--check-config", "--input-dir", "."]):
            with self.subTest(arguments=arguments), patch.object(audit, "aws_session") as connection, redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main(arguments), 1)
                connection.assert_not_called()


class RdsLarkTests(unittest.TestCase):
    def test_overview_has_source_counts_without_sql_or_previous_domain(self):
        report = example_report()
        payloads = notify.build_lark_payloads(report, {"message_mode": "overview"})
        text = payloads[0]["content"]["text"]
        self.assertIn("新增：2", text)
        self.assertIn("数据库SQL审计", text)
        self.assertIn("2026-10-28 07:00:00 至 2026-10-29 08:00:00", text)
        self.assertIn("未配置", text)
        self.assertNotIn("MUST-NOT-LEAK", text)
        self.assertNotIn("v668live", text)

    def test_rds_link_filename_and_signature(self):
        report = example_report()
        link = notify.format_report_url("https://reports.example.invalid/{account_id}/{filename}", report)
        self.assertIn("rds", link)
        self.assertNotIn("-aws", link)
        timestamp, secret = 1793232600, "TEST-ONLY-SECRET"
        expected = base64.b64encode(hmac.new(f"{timestamp}\n{secret}".encode(), b"", hashlib.sha256).digest()).decode()
        self.assertEqual(notify.make_lark_signature(secret, timestamp), expected)
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 200
        response.read.return_value = b'{"code":0}'
        opener = Mock(return_value=response)
        result = notify.send_lark_notification(report, {"webhook_url": WEBHOOK, "signing_secret": secret}, opener=opener, now=timestamp)
        self.assertEqual(result["code"], 0)
        data = json.loads(opener.call_args.args[0].data)
        self.assertEqual(data["sign"], expected)
        self.assertNotIn("MUST-NOT-LEAK", json.dumps(data))

    def test_invalid_webhook_and_remote_errors_do_not_expose_tokens(self):
        with self.assertRaises(ValueError) as caught:
            notify.validate_webhook_url(WEBHOOK + "?token=PRIVATE")
        self.assertNotIn("PRIVATE", str(caught.exception))
        opener = Mock(side_effect=OSError(WEBHOOK))
        with self.assertRaises(notify.LarkNotificationError) as caught:
            notify.send_lark_notification(example_report(), {"webhook_url": WEBHOOK}, opener=opener)
        self.assertNotIn(WEBHOOK, str(caught.exception))
        opener.assert_called_once()

    def test_summary_and_full_modes_are_rejected_before_transport(self):
        for mode in ("summary", "full"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                notify.build_lark_payloads(example_report(), {"message_mode": mode})

    def test_real_offline_archive_is_not_labeled_as_invented_data(self):
        report = example_report()
        report["metadata"]["offline"] = True
        text = notify.build_lark_payloads(report, {})[0]["content"]["text"]
        self.assertIn("离线归档", text)
        self.assertNotIn("非真实", text)
        report["metadata"]["example_data"] = True
        self.assertIn("示例数据", notify.build_lark_payloads(report, {})[0]["content"]["text"])


class DailyPublicationTests(unittest.TestCase):
    def test_existing_user_24_hour_collection_generates_html_without_redownload(self):
        start = datetime(2026, 10, 28, 9, 32, 55, tzinfo=UTC)
        end = start + timedelta(days=1)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "20261029T093255Z-20ece9a5"
            (directory / "cloudwatch").mkdir(parents=True)
            source = {"identity": {"Account": "123456789012"}, "window": {"start_inclusive": audit.iso(start), "end_exclusive": audit.iso(end)}, "collection_status": "ok", "checks": [], "sql_log_download_requested": True}
            raw = directory / "report.json"
            raw.write_text(json.dumps(source), encoding="utf-8")
            event = {"eventID": "create-one", "eventTime": audit.iso(start), "eventName": "CreateDBSnapshot", "userIdentity": {"type": "IAMUser", "userName": "example"}}
            (directory / "management-events.jsonl").write_text(json.dumps({"region": "ap-east-1", "event": event}) + "\n", encoding="utf-8")
            logs = []
            for event_id, when in (("inside", start + timedelta(seconds=1)), ("end-excluded", end)):
                logs.append({"region": "ap-east-1", "eventId": event_id, "logGroupName": "/aws/rds/cluster/shenji/audit", "logStreamName": "example", "timestamp": int(when.timestamp() * 1000), "message": f"{int(when.timestamp() * 1000000)},server,example,203.0.113.1,1,1,QUERY,shop,'UPDATE orders SET status=1',0"})
            sql_path = directory / "cloudwatch/audit.jsonl"
            sql_path.write_text("".join(json.dumps(row) + "\n" for row in logs), encoding="utf-8")
            original_raw, original_sql = raw.read_bytes(), sql_path.read_bytes()
            with patch.object(audit, "aws_session") as connection, patch.object(notify, "send_lark_notification") as send, redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main(["--input-dir", str(directory)]), 0)
            connection.assert_not_called()
            send.assert_not_called()
            normalized = json.loads((directory / "daily-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["metadata"]["period_kind"], "custom")
            self.assertEqual(normalized["metadata"]["window_start_utc"], audit.iso(start))
            self.assertEqual(normalized["metadata"]["window_end_utc_exclusive"], audit.iso(end))
            self.assertEqual(normalized["metadata"]["counts"]["新增"], 1)
            self.assertEqual(normalized["metadata"]["counts"]["修改"], 1)
            self.assertEqual(normalized["metadata"]["total"], 2)
            self.assertTrue((directory / "2026-10-29-rds操作审计-自定义窗口.html").exists())
            self.assertEqual(raw.read_bytes(), original_raw)
            self.assertEqual(sql_path.read_bytes(), original_sql)
            args = audit.build_parser().parse_args(["--input-dir", str(directory), "--date", "2026-10-29"])
            with self.assertRaisesRegex(ValueError, "未覆盖"):
                audit.resolve_report_window(args, end + timedelta(seconds=1))

    def test_live_days_collection_automatically_generates_html(self):
        def collect_without_network(instance):
            instance.report.update(collection_status="ok", failed_check_count=0)
            (instance.directory / "report.json").write_text(json.dumps(instance.report), encoding="utf-8")
            (instance.directory / "management-events.jsonl").write_text("", encoding="utf-8")
            return 0

        with tempfile.TemporaryDirectory() as temporary:
            output, session = io.StringIO(), Mock()
            with patch.object(audit, "aws_session", return_value=(session, None, {"Account": "123456789012", "Arn": "EXAMPLE"})), patch.object(audit.Collector, "run", collect_without_network), redirect_stdout(output):
                result = audit.main(["--profile", "audit", "--regions", "ap-east-1", "--days", "1", "--download-sql-logs", "--output-dir", temporary])
            self.assertEqual(result, 0)
            session.client.assert_not_called()
            pages = list(Path(temporary).rglob("*-自定义窗口.html"))
            self.assertEqual(len(pages), 1)
            self.assertIn("HTML报告", output.getvalue())
            meta = json.loads((pages[0].parent / "daily-report.json").read_text(encoding="utf-8"))["metadata"]
            self.assertEqual(meta["period_kind"], "custom")
            self.assertEqual(audit.parse_timestamp(meta["window_end_utc_exclusive"]) - audit.parse_timestamp(meta["window_start_utc"]), timedelta(days=1))

    def test_real_offline_entry_point_generates_full_report_without_aws(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "input"
            shutil.copytree(Path(__file__).parent / "examples/daily-sample", directory)
            with patch.object(audit, "aws_session") as connection, patch.object(notify, "send_lark_notification") as send, redirect_stdout(io.StringIO()):
                status = audit.main(["--input-dir", str(directory), "--date", "2026-10-29"])
            self.assertEqual(status, 0)
            connection.assert_not_called()
            send.assert_not_called()
            normalized = json.loads((directory / "daily-report.json").read_text(encoding="utf-8"))
            self.assertEqual([normalized["metadata"]["counts"][key] for key in ("新增", "删除", "修改")], [2, 2, 5])
            self.assertEqual(normalized["metadata"]["failed_or_partial"], 2)
            self.assertTrue((directory / "2026-10-29-rds操作审计.html").is_file())

    def test_publication_copies_only_html_css_and_notifies_after_success(self):
        import rds_report
        report = example_report()
        with tempfile.TemporaryDirectory() as temporary:
            directory, publish = Path(temporary) / "raw", Path(temporary) / "web"
            directory.mkdir()
            (directory / "rds-report.css").write_text("body{}", encoding="utf-8")
            (directory / "report.json").write_text("RAW", encoding="utf-8")
            html = directory / report["metadata"]["report_filename"]
            html.write_text("<html>demo</html>", encoding="utf-8")
            args = audit.build_parser().parse_args(["--daily", "--publish-dir", str(publish), "--send-lark"])
            with patch.object(rds_report, "build_daily_report", return_value=report), patch.object(rds_report, "write_report", return_value=html), patch.object(notify, "send_lark_notification") as send, redirect_stdout(io.StringIO()):
                status = audit.finish_daily(directory, "2026-10-29", datetime.now(UTC), datetime.now(UTC), args, 0, {"webhook_url": WEBHOOK})
            self.assertEqual(status, 0)
            self.assertEqual((publish / "index.html").read_text(), "<html>demo</html>")
            self.assertEqual(sorted(path.suffix for path in publish.iterdir()), [".css", ".html", ".html"])
            send.assert_called_once()

    def test_publish_failure_retains_archive_and_does_not_send_stale_link(self):
        import rds_report
        report = example_report()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            html = directory / "report.html"
            html.write_text("saved", encoding="utf-8")
            args = audit.build_parser().parse_args(["--daily", "--publish-dir", str(directory / "web"), "--send-lark"])
            with patch.object(rds_report, "build_daily_report", return_value=report), patch.object(rds_report, "write_report", return_value=html), patch.object(audit, "atomic_copy", side_effect=OSError("cannot publish")), patch.object(notify, "send_lark_notification") as send, redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(audit.finish_daily(directory, "2026-10-29", datetime.now(UTC), datetime.now(UTC), args, 0, {"webhook_url": WEBHOOK}), 4)
            self.assertEqual(html.read_text(), "saved")
            send.assert_not_called()

    def test_lark_failure_keeps_partial_status_priority(self):
        import rds_report
        report = example_report()
        args = audit.build_parser().parse_args(["--daily", "--send-lark"])
        with tempfile.TemporaryDirectory() as temporary, patch.object(rds_report, "build_daily_report", return_value=report), patch.object(rds_report, "write_report", return_value=Path(temporary) / "kept.html"), patch.object(notify, "send_lark_notification", side_effect=notify.LarkNotificationError("failed")), redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            self.assertEqual(audit.finish_daily(Path(temporary), "2026-10-29", datetime.now(UTC), datetime.now(UTC), args, 2, {"webhook_url": WEBHOOK}), 2)


class ConfigurationTests(unittest.TestCase):
    def test_hong_kong_screenshot_audit_group_is_found_and_probe_is_not_collection(self):
        ct, rds, logs = Mock(), Mock(), Mock()
        ct.lookup_events.return_value = {"Events": []}
        rds.describe_db_instances.return_value = {"DBInstances": [{"DBInstanceIdentifier": "shenji-1", "Engine": "aurora-mysql"}]}
        rds.describe_db_clusters.return_value = {"DBClusters": [{"DBClusterIdentifier": "shenji", "Engine": "aurora-mysql"}]}
        rds.describe_events.return_value = {"Events": []}
        rds.describe_db_log_files.return_value = {"DescribeDBLogFiles": []}
        audit_group = "/aws/rds/cluster/shenji/audit"
        logs.describe_log_groups.return_value = {"logGroups": [{"logGroupName": name} for name in (audit_group, "/aws/rds/cluster/shenji/error", "/aws/rds/cluster/test-shenji/error")]}
        logs.filter_log_events.return_value = {"events": []}
        session = Mock(client=Mock(side_effect=lambda service, **kwargs: {"cloudtrail": ct, "rds": rds, "logs": logs}[service]))
        with tempfile.TemporaryDirectory() as temporary:
            args = audit.build_parser().parse_args(["--check-config", "--regions", "ap-east-1", "--output-dir", temporary])
            output = io.StringIO()
            with patch.object(audit, "aws_session", return_value=(session, None, {"Account": "123456789012", "Arn": "EXAMPLE"})), redirect_stdout(output):
                self.assertEqual(audit.check_configuration(args), 0)
            self.assertEqual(list(Path(temporary).iterdir()), [])
        request = logs.filter_log_events.call_args.kwargs
        self.assertEqual(logs.filter_log_events.call_count, 1)
        self.assertEqual(request["logGroupName"], audit_group)
        self.assertEqual(request["limit"], 1)
        self.assertEqual(request["endTime"] - request["startTime"], 1)
        self.assertIn("ap-east-1: 已发现 /aws/rds/ 日志组 3 个，其中 audit/general 1 个", output.getvalue())
        self.assertIn(audit_group + " 读取接口验证通过", output.getvalue())
        self.assertIn("预检不下载日志", output.getvalue())
        self.assertNotIn("未发现audit/general", output.getvalue())

    def test_preflight_does_not_write_report_or_send_notification(self):
        ct, rds, logs = Mock(), Mock(), Mock()
        ct.lookup_events.return_value = {"Events": []}
        rds.describe_db_instances.return_value = {"DBInstances": []}
        rds.describe_db_clusters.return_value = {"DBClusters": []}
        rds.describe_events.return_value = {"Events": []}
        logs.describe_log_groups.return_value = {"logGroups": []}
        session = Mock(client=Mock(side_effect=lambda service, **kwargs: {"cloudtrail": ct, "rds": rds, "logs": logs}[service]))
        with tempfile.TemporaryDirectory() as temporary:
            args = audit.build_parser().parse_args(["--check-config", "--regions", "ap-southeast-1", "--output-dir", temporary])
            with patch.object(audit, "aws_session", return_value=(session, None, {"Account": "123456789012", "Arn": "EXAMPLE"})), patch.object(notify, "send_lark_notification") as send, redirect_stdout(io.StringIO()):
                self.assertEqual(audit.check_configuration(args), 0)
            self.assertEqual(list(Path(temporary).iterdir()), [])
            send.assert_not_called()
            ct.lookup_events.assert_called_once()

    def test_unwritable_publication_target_fails_before_region_queries(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "a-file"
            target.write_text("existing", encoding="utf-8")
            args = audit.build_parser().parse_args(["--check-config", "--regions", "ap-southeast-1", "--output-dir", temporary, "--publish-dir", str(target)])
            session = Mock()
            with patch.object(audit, "aws_session", return_value=(session, None, {"Account": "123456789012", "Arn": "EXAMPLE"})), self.assertRaises(PermissionError):
                audit.check_configuration(args)
            session.client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
