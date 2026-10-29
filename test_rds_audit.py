"""Offline boundary checks for RDS collection; no AWS credentials/network needed."""
import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import rds_audit as audit

UTC = timezone.utc
REGION = "eu-north-1"
START = datetime(2026, 10, 27, tzinfo=UTC)
END = START + timedelta(days=1)


def aws_client(service):
    # Explicit inert credentials prevent any use of a real profile or metadata.
    return boto3.client(service, region_name=REGION, aws_access_key_id="testing", aws_secret_access_key="testing")


def args(*extra):
    return audit.build_parser().parse_args(["--regions", REGION, *extra])


def summary():
    return {
        "management_event_count": 0, "rds_service_event_count": 0,
        "instances": [], "clusters": [], "sql_log_groups": [], "notes": [],
    }


def collector(path, cli_args=None, session=None, start=START, end=END):
    return audit.Collector(
        session or Mock(), None, start, end, Path(path), cli_args or args(),
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/audit", "UserId": "example"},
    )


def cloudtrail_event(event_id, name, when, read_only):
    raw = {
        "eventID": event_id, "eventName": name, "eventTime": audit.iso(when),
        "eventSource": "rds.amazonaws.com", "readOnly": read_only,
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/audit/session"},
        "requestParameters": {"dBInstanceIdentifier": "deleted-db"},
    }
    return {
        "EventId": event_id, "EventName": name, "EventTime": when,
        "ReadOnly": str(read_only).lower(), "CloudTrailEvent": json.dumps(raw),
    }


class TimeWindowTests(unittest.TestCase):
    def test_region_validation_supports_sovereign_cloud_and_normalizes_duplicates(self):
        self.assertEqual(audit.validate_regions(" eusc-de-east-1,eu-north-1,eusc-de-east-1 "), "eusc-de-east-1,eu-north-1")

    def test_timezone_is_explicit_and_normalized(self):
        self.assertEqual(audit.parse_timestamp("2026-10-28T07:00:00+07:00"), END)
        with self.assertRaises(argparse.ArgumentTypeError):
            audit.parse_timestamp("2026-10-28T07:00:00")

    def test_invalid_or_unavailable_windows_are_rejected(self):
        for extra in (
            ["--days", "0"], ["--days", "90"], ["--days", "nan"],
            ["--start", "2026-10-27T00:00:00Z"],
            ["--start", "2026-10-27T00:00:00Z", "--end", "2026-10-29T00:00:00Z"],
            ["--start", "2026-01-01T00:00:00Z", "--end", "2026-10-27T00:00:00Z"],
            ["--days", "2", "--start", "2026-10-27T00:00:00Z", "--end", "2026-10-28T00:00:00Z"],
        ):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                audit.make_window(args(*extra), END)

    def test_default_window_is_seven_days_with_half_open_bounds(self):
        start, end = audit.make_window(args(), END)
        self.assertEqual(end - start, timedelta(days=7))
        self.assertTrue(audit.in_window(start, start, end))
        self.assertFalse(audit.in_window(end, start, end))

    def test_cli_usage_errors_return_one_before_credential_loading(self):
        for extra in (["--regions", ""], ["--regions", "eu-north-1,"], ["--start", "2026-10-28T07:00:00"], ["--unknown"]):
            with self.subTest(extra=extra), patch("boto3.Session") as session, redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main(extra), 1)
                session.assert_not_called()

    def test_help_returns_zero_without_loading_credentials(self):
        with patch("boto3.Session") as session, redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(["--help"]), 0)
            session.assert_not_called()


class PaginationTests(unittest.TestCase):
    def test_empty_cloudtrail_page_does_not_end_query(self):
        client = aws_client("cloudtrail")
        with Stubber(client) as stub:
            stub.add_response("lookup_events", {"Events": [], "NextToken": "next"}, {"MaxResults": 50})
            stub.add_response("lookup_events", {"Events": [cloudtrail_event("one", "DescribeDBInstances", START, True)]}, {"MaxResults": 50, "NextToken": "next"})
            rows = list(audit.iter_items(client, "lookup_events", "Events", request_token="NextToken", response_token="NextToken", MaxResults=50))
            self.assertEqual([row["EventId"] for row in rows], ["one"])
            stub.assert_no_pending_responses()

    def test_repeated_cursor_is_an_error_and_prior_rows_are_preserved(self):
        client = Mock()
        client.list_rows.side_effect = [{"rows": [1], "Marker": "same"}, {"rows": [], "Marker": "same"}]
        with tempfile.TemporaryDirectory() as directory:
            c = collector(directory)
            with redirect_stderr(io.StringIO()):
                rows = c.collect_items("test", client, "list_rows", "rows")
            self.assertEqual(rows, [1])
            self.assertEqual(c.report["checks"][0]["status"], "error")
            self.assertIn("incomplete", c.report["checks"][0]["message"])


class ManagementHistoryTests(unittest.TestCase):
    def test_reads_writes_deleted_resources_deduplication_and_end_boundary(self):
        client = aws_client("cloudtrail")
        rows = [
            cloudtrail_event("read", "DescribeDBInstances", START, True),
            cloudtrail_event("write", "DeleteDBInstance", START + timedelta(hours=1), False),
            cloudtrail_event("write", "DeleteDBInstance", START + timedelta(hours=1), False),
            cloudtrail_event("end", "ModifyDBInstance", END, False),
        ]
        request = {
            "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": "rds.amazonaws.com"}],
            "StartTime": START, "EndTime": END, "MaxResults": 50,
        }
        with tempfile.TemporaryDirectory() as directory, Stubber(client) as stub:
            stub.add_response("lookup_events", {"Events": rows}, request)
            c = collector(directory, session=Mock(client=Mock(return_value=client)))
            output, counts = io.StringIO(), summary()
            c.management_events(REGION, output, counts)
            result = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual([row["event"]["eventID"] for row in result], ["read", "write"])
            self.assertEqual(result[1]["event"]["requestParameters"]["dBInstanceIdentifier"], "deleted-db")
            self.assertEqual(counts["management_event_count"], 2)
            stub.assert_no_pending_responses()


class InstanceLogTests(unittest.TestCase):
    def test_download_starts_at_zero_and_follows_all_portions(self):
        client = aws_client("rds")
        base_request = {"DBInstanceIdentifier": "db", "LogFileName": "audit/server_audit.log", "NumberOfLines": 10000}
        with tempfile.TemporaryDirectory() as directory, Stubber(client) as stub:
            stub.add_response("download_db_log_file_portion", {"LogFileData": "first\n", "Marker": "0:6", "AdditionalDataPending": True}, {**base_request, "Marker": "0"})
            stub.add_response("download_db_log_file_portion", {"LogFileData": "last\n", "Marker": "0:11", "AdditionalDataPending": False}, {**base_request, "Marker": "0:6"})
            path = Path(directory) / "audit.log"
            result = audit.download_instance_log(client, "db", "audit/server_audit.log", path)
            self.assertEqual(path.read_text(encoding="utf-8"), "first\nlast\n")
            self.assertEqual(result["portions"], 2)
            stub.assert_no_pending_responses()

    def test_partial_instance_log_survives_later_api_failure(self):
        client = Mock()
        client.download_db_log_file_portion.side_effect = [
            {"LogFileData": "already obtained\n", "Marker": "next", "AdditionalDataPending": True},
            ClientError({"Error": {"Code": "DBLogFileNotFoundFault", "Message": "rotated"}}, "DownloadDBLogFilePortion"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partial.log"
            with self.assertRaises(ClientError):
                audit.download_instance_log(client, "db", "general/mysql-general.log", path)
            self.assertEqual(path.read_text(encoding="utf-8"), "already obtained\n")


class CloudWatchTests(unittest.TestCase):
    def test_hong_kong_download_reports_window_count_without_exposing_sql(self):
        client = Mock()
        group = "/aws/rds/cluster/shenji/audit"
        client.describe_log_groups.return_value = {"logGroups": [{"logGroupName": group}, {"logGroupName": "/aws/rds/cluster/shenji/error"}, {"logGroupName": "RDSOSMetrics"}]}
        client.filter_log_events.return_value = {"events": [{"eventId": "hk-1", "timestamp": int(START.timestamp() * 1000), "message": "UPDATE private_business_value", "logStreamName": "shenji-1"}]}
        with tempfile.TemporaryDirectory() as directory:
            c = collector(directory, cli_args=args("--download-sql-logs"), session=Mock(client=Mock(return_value=client)))
            counts, output = summary(), io.StringIO()
            with redirect_stdout(output):
                c.cloudwatch("ap-east-1", counts)
            self.assertEqual(len(counts["sql_log_groups"]), 1)
            self.assertEqual(counts["sql_log_groups"][0]["download"]["event_count"], 1)
            self.assertIn("已下载 1 条 CloudWatch 日志事件", output.getvalue())
            self.assertNotIn("private_business_value", output.getvalue())
            client.filter_log_events.assert_called_once()

    def test_deleted_database_group_and_unfiltered_prepared_multiline_sql(self):
        client = aws_client("logs")
        group = "/aws/rds/cluster/deleted-cluster/audit"
        base_request = {"logGroupName": group, "startTime": int(START.timestamp() * 1000), "endTime": int(END.timestamp() * 1000)}
        messages = ["Execute stmt-123", "CALL change_balance(42)", "UPDATE users\nSET name='中文' WHERE id=1"]
        events = [{"eventId": str(index), "timestamp": int((START + timedelta(minutes=index)).timestamp() * 1000), "message": message, "logStreamName": "old-reader"} for index, message in enumerate(messages)]
        events.append({"eventId": "end", "timestamp": int(END.timestamp() * 1000), "message": "not in requested window", "logStreamName": "old-reader"})
        with tempfile.TemporaryDirectory() as directory, Stubber(client) as stub:
            stub.add_response("describe_log_groups", {"logGroups": [{"logGroupName": group, "retentionInDays": 30}]}, {"logGroupNamePrefix": "/aws/rds/"})
            stub.add_response("filter_log_events", {"events": [], "nextToken": "continue"}, base_request)
            stub.add_response("filter_log_events", {"events": events}, {**base_request, "nextToken": "continue"})
            c = collector(directory, cli_args=args("--download-sql-logs"), session=Mock(client=Mock(return_value=client)))
            counts = summary()
            c.cloudwatch(REGION, counts)
            item = counts["sql_log_groups"][0]
            output = Path(directory) / item["download"]["path"]
            result = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([row["message"] for row in result], messages)
            self.assertEqual(item["download"]["event_count"], 3)
            self.assertEqual(item["download"]["status"], "ok")
            self.assertEqual(counts["instances"], [])
            stub.assert_no_pending_responses()

    def test_group_download_failure_does_not_hide_other_groups(self):
        client = Mock()
        first, second = "/aws/rds/instance/a/audit", "/aws/rds/instance/b/general"
        client.describe_log_groups.return_value = {"logGroups": [{"logGroupName": first}, {"logGroupName": second}]}
        client.filter_log_events.side_effect = [ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "FilterLogEvents"), {"events": []}]
        with tempfile.TemporaryDirectory() as directory:
            c = collector(directory, cli_args=args("--download-sql-logs"), session=Mock(client=Mock(return_value=client)))
            counts = summary()
            with redirect_stderr(io.StringIO()):
                c.cloudwatch(REGION, counts)
            self.assertEqual([item["download"]["status"] for item in counts["sql_log_groups"]], ["error", "ok"])
            self.assertEqual(c.report["checks"][0]["status"], "error")


class CoverageTests(unittest.TestCase):
    def test_rds_client_creation_failure_does_not_skip_logs_or_later_regions(self):
        first, second = REGION, "us-east-1"
        ct, rds, logs = Mock(), Mock(), Mock()
        ct.lookup_events.return_value = {"Events": []}
        rds.describe_events.return_value = {"Events": []}
        rds.describe_db_instances.return_value = {"DBInstances": []}
        rds.describe_db_clusters.return_value = {"DBClusters": []}
        logs.describe_log_groups.return_value = {"logGroups": []}

        def get_client(service, region_name=None, **kwargs):
            if service == "rds" and region_name == first:
                raise ValueError("bad regional endpoint configuration")
            return {"cloudtrail": ct, "rds": rds, "logs": logs}[service]

        session = Mock(client=Mock(side_effect=get_client))
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as directory:
            c = collector(directory, cli_args=args("--regions", f"{first},{second}"), session=session, start=now - timedelta(days=1), end=now)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = c.run()
            self.assertEqual(code, 2)
            self.assertEqual(list(c.report["regions"]), [first, second])
            self.assertEqual(ct.lookup_events.call_count, 2)
            self.assertEqual(logs.describe_log_groups.call_count, 2)
            rds.describe_db_instances.assert_called_once()
            self.assertEqual(c.report["failed_check_count"], 1)

    def test_current_pending_configuration_never_implies_historical_coverage(self):
        rds = Mock()
        rds.describe_db_instances.return_value = {"DBInstances": [{
            "DBInstanceIdentifier": "db", "Engine": "mysql", "EnabledCloudwatchLogsExports": ["audit"],
            "DBParameterGroups": [{"DBParameterGroupName": "custom", "ParameterApplyStatus": "pending-reboot"}],
            "OptionGroupMemberships": [{"OptionGroupName": "audit", "Status": "pending-apply"}],
        }]}
        rds.describe_db_clusters.return_value = {"DBClusters": []}
        rds.describe_db_parameters.return_value = {"Parameters": [{"ParameterName": "general_log", "ParameterValue": "1", "ApplyType": "static"}]}
        rds.describe_option_groups.return_value = {"OptionGroupsList": [{"Options": [{"OptionName": "MARIADB_AUDIT_PLUGIN", "OptionSettings": [{"Name": "SERVER_AUDIT_LOGGING", "Value": "ON"}]}]}]}
        rds.describe_db_log_files.return_value = {"DescribeDBLogFiles": []}
        with tempfile.TemporaryDirectory() as directory:
            c = collector(directory)
            counts = summary()
            c.inventory(REGION, rds, counts)
            instance = counts["instances"][0]
            self.assertEqual(instance["audit_parameter_groups"][0]["membership"]["ParameterApplyStatus"], "pending-reboot")
            self.assertEqual(instance["audit_option_groups"][0]["membership"]["Status"], "pending-apply")
            self.assertIn("configuration only", instance["audit_inspection"])

    def test_denied_region_continues_and_persists_partial_report(self):
        first, second = REGION, "us-east-1"
        cloudtrail_a, cloudtrail_b = Mock(), Mock()
        cloudtrail_a.lookup_events.side_effect = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "LookupEvents")
        cloudtrail_b.lookup_events.return_value = {"Events": []}
        rds = Mock()
        rds.describe_events.return_value = {"Events": []}
        rds.describe_db_instances.return_value = {"DBInstances": []}
        rds.describe_db_clusters.return_value = {"DBClusters": []}
        logs = Mock()
        logs.describe_log_groups.return_value = {"logGroups": []}

        def get_client(service, region_name=None, **kwargs):
            if service == "cloudtrail":
                return cloudtrail_a if region_name == first else cloudtrail_b
            return {"rds": rds, "logs": logs}[service]

        session = Mock(client=Mock(side_effect=get_client))
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as directory:
            c = collector(directory, cli_args=args("--regions", f"{first},{second}"), session=session, start=now - timedelta(days=1), end=now)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = c.run()
            report = json.loads((Path(directory) / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 2)
            self.assertEqual(report["collection_status"], "partial")
            self.assertEqual(report["failed_check_count"], 1)
            self.assertEqual(report["historical_sql_completeness"], "not_established")
            self.assertEqual(list(report["regions"]), [first, second])
            cloudtrail_b.lookup_events.assert_called_once()
            self.assertTrue((Path(directory) / "management-events.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
