#!/usr/bin/env python3
"""Read-only RDS management history and MySQL/Aurora MySQL audit-log collector.

No database connections or configuration changes are made. See RDS_AUDIT.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

UTC = timezone.utc
MYSQL_ENGINES = {"mysql", "aurora-mysql", "aurora"}
PARAMETERS = {
    "general_log", "log_output", "binlog_format", "binlog_row_image",
    "binlog_expire_logs_seconds", "expire_logs_days", "log_bin", "aws_default_logs_role",
}
LIMITATIONS = [
    "CloudTrail is RDS management API history, not ordinary database SQL history; both read and write API calls are retained.",
    "Only the current account and selected Regions are queried. CloudTrail history is limited to 90 days; S3/Lake archives and Data API data events are not queried.",
    "RDS service notifications cover at most the last 14 days; they are not a record of all user actions.",
    "MySQL audit settings are current AWS control-plane configuration, not proof of effective runtime values or past audit coverage.",
    "SQL activity is available only if logging was enabled at the time and the logs are still retained. Empty results do not prove no activity.",
    "SQL logs can be truncated, filtered by user/event, delayed, rotated, or masked. General logs do not prove success or COMMIT; audit return codes do not prove transaction COMMIT.",
    "Audit SQL does not guarantee row-level before/after values or identify a human behind a shared database account.",
    "CloudWatch discovery covers standard /aws/rds/instance|cluster/<id>/audit|general groups, including retained groups for deleted databases; custom destinations are not discovered.",
    "Database TABLE log destinations (mysql.general_log), slow-query logs, binary logs, and Database Activity Stream payloads are not collected by this script.",
    "Instance-log downloads preserve whole currently visible audit/general files, without the requested time filter. Live files can change during collection.",
]


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def json_default(value):
    if isinstance(value, datetime):
        return iso(value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def write_json_line(handle, record):
    handle.write(json.dumps(record, ensure_ascii=False, default=json_default) + "\n")


def parse_timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("时间必须是 ISO8601，例如 2026-10-28T00:00:00+08:00") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise argparse.ArgumentTypeError("时间必须包含时区，例如 Z、+07:00 或 +08:00")
    return result.astimezone(UTC)


def validate_regions(value: str) -> str:
    if value == "all":
        return value
    regions = [part.strip() for part in value.split(",")]
    if not regions or any(not re.fullmatch(r"[a-z]{2,}(?:-[a-z0-9]+)+-\d+", region) for region in regions):
        raise argparse.ArgumentTypeError("--regions 必须是 all 或用逗号分隔的 AWS 区域，例如 ap-southeast-1,eu-north-1")
    return ",".join(dict.fromkeys(regions))


def make_window(args, now: datetime) -> tuple[datetime, datetime]:
    if bool(args.start) != bool(args.end):
        raise ValueError("--start 和 --end 必须同时提供")
    if args.start and args.days is not None:
        raise ValueError("--days 不能与 --start/--end 同时使用")
    if args.start:
        start, end = args.start, args.end
    else:
        days = args.days if args.days is not None else 7
        if not 0 < days < 90:
            raise ValueError("--days 必须大于 0 且小于 90；边界需留出 AWS 查询时间")
        end = now
        start = end - timedelta(days=days)
    if start >= end:
        raise ValueError("开始时间必须早于结束时间")
    if end > now:
        raise ValueError("结束时间不能晚于当前时间")
    if start < now - timedelta(days=90) + timedelta(minutes=1):
        raise ValueError("CloudTrail LookupEvents 仅支持近 90 天；请留出 1 分钟边界余量。更早记录需要已有 S3/Lake 归档")
    return start, end


def iter_items(client, operation, result_key, *, request_token="Marker", response_token="Marker", delay=0, **kwargs):
    """Continue even after empty pages; fail loudly if an API repeats its cursor."""
    tokens = set()
    while True:
        response = getattr(client, operation)(**kwargs)
        yield from response.get(result_key, [])
        token = response.get(response_token)
        if not token:
            return
        if token in tokens:
            raise RuntimeError(f"{operation}: repeated pagination token; results are incomplete")
        tokens.add(token)
        kwargs[request_token] = token
        if delay:
            time.sleep(delay)


def safe_name(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")[:110] or "log"
    return stem + "-" + hashlib.sha256(value.encode()).hexdigest()[:12]


def is_sql_log_file(name: str) -> bool:
    name = name.lower()
    return name.startswith(("audit/", "general/")) or bool(re.search(r"(?:^|/)\w*(?:audit|general)\w*\.log", name))


def in_window(event_time: datetime, start: datetime, end: datetime) -> bool:
    return start <= event_time < end


def download_instance_log(rds, instance: str, name: str, path: Path) -> dict:
    """Marker='0' is essential: without it AWS returns only a tail by default."""
    marker = "0"
    tokens = {marker}
    portions = 0
    with path.open("x", encoding="utf-8", newline="") as handle:
        while True:
            response = rds.download_db_log_file_portion(
                DBInstanceIdentifier=instance, LogFileName=name, Marker=marker, NumberOfLines=10000,
            )
            handle.write(response.get("LogFileData", ""))
            portions += 1
            if not response.get("AdditionalDataPending", False):
                break
            marker = response.get("Marker")
            if not marker or marker in tokens:
                raise RuntimeError("DownloadDBLogFilePortion cursor did not advance; partial file retained")
            tokens.add(marker)
    return {"portions": portions, "bytes": path.stat().st_size}


class Collector:
    def __init__(self, session, config, start, end, directory, args, identity):
        self.session, self.config = session, config
        self.start, self.end = start, end
        self.directory, self.args = directory, args
        self.report = {
            "schema_version": 1, "identity": identity,
            "started_at": iso(datetime.now(UTC)),
            "window": {"start_inclusive": iso(start), "end_exclusive": iso(end)},
            "scope": "Current account; RDS management history; MySQL/Aurora MySQL SQL audit inspection",
            "sql_log_download_requested": args.download_sql_logs,
            "instance_log_download_requested": args.download_instance_logs,
            "limitations": LIMITATIONS, "checks": [], "regions": {},
        }
        self.parameter_cache, self.option_cache = {}, {}

    def client(self, service, region):
        return self.session.client(service, region_name=region, config=self.config)

    def check(self, scope, function):
        check = {"scope": scope, "status": "ok"}
        self.report["checks"].append(check)
        try:
            return function()
        except Exception as exc:
            check.update(status="error", error_type=type(exc).__name__, message=str(exc))
            print(f"[部分失败] {scope}: {exc}", file=sys.stderr)
            return None

    def collect_items(self, scope, client, operation, result_key, **kwargs):
        items = []
        self.check(scope, lambda: items.extend(iter_items(client, operation, result_key, **kwargs)))
        return items

    def regions(self):
        if self.args.regions != "all":
            return validate_regions(self.args.regions).split(",")
        seed = self.args.discovery_region or self.session.region_name or "us-east-1"
        response = self.client("ec2", seed).describe_regions(AllRegions=False)
        result = sorted(item["RegionName"] for item in response["Regions"])
        if not result:
            raise RuntimeError("未发现已启用区域，请核对身份或显式提供 --regions")
        self.report["region_discovery"] = {"region": seed, "status": "ok", "regions": result}
        return result

    def management_events(self, region, handle, summary):
        ct = self.client("cloudtrail", region)
        seen = set()
        for event in iter_items(
            ct, "lookup_events", "Events", request_token="NextToken", response_token="NextToken", delay=0.55,
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "rds.amazonaws.com"}],
            StartTime=self.start, EndTime=self.end, MaxResults=50,
        ):
            if not in_window(event["EventTime"], self.start, self.end):
                continue
            event_id = event["EventId"]
            if event_id in seen:
                continue
            seen.add(event_id)
            raw = json.loads(event["CloudTrailEvent"])
            write_json_line(handle, {"region": region, "event": raw, "lookup": {k: v for k, v in event.items() if k != "CloudTrailEvent"}})
            summary["management_event_count"] += 1

    def service_events(self, region, rds, handle, summary):
        # AWS's rolling 14-day limit advances while this process runs.
        earliest = datetime.now(UTC) - timedelta(days=14) + timedelta(minutes=1)
        start = max(self.start, earliest)
        summary["rds_service_window"] = {"start_inclusive": iso(start), "end_exclusive": iso(self.end)} if start < self.end else None
        if start >= self.end:
            summary["notes"].append("查询窗口早于 RDS 服务通知保留期，已跳过；这不表示当时没有事件。")
            return
        for event in iter_items(rds, "describe_events", "Events", StartTime=start, EndTime=self.end, MaxRecords=100):
            if in_window(event["Date"], start, self.end):
                write_json_line(handle, {"region": region, **event})
                summary["rds_service_event_count"] += 1

    def parameters(self, region, rds, name, cluster=False):
        key = (region, cluster, name)
        if key not in self.parameter_cache:
            rows = []

            def read():
                operation = "describe_db_cluster_parameters" if cluster else "describe_db_parameters"
                argument = "DBClusterParameterGroupName" if cluster else "DBParameterGroupName"
                for row in iter_items(rds, operation, "Parameters", **{argument: name, "MaxRecords": 100}):
                    parameter = row.get("ParameterName", "")
                    if parameter.startswith("server_audit_") or parameter in PARAMETERS:
                        rows.append({k: row[k] for k in ("ParameterName", "ParameterValue", "Source", "ApplyType", "ApplyMethod", "IsModifiable") if k in row})
                return True

            ok = self.check(f"{region}:parameters:{'cluster' if cluster else 'instance'}:{name}", read)
            self.parameter_cache[key] = {"group_name": name, "status": "ok" if ok else "error", "parameters": rows}
        return self.parameter_cache[key]

    def options(self, region, rds, name):
        key = (region, name)
        if key not in self.option_cache:
            options = []

            def read():
                for group in iter_items(rds, "describe_option_groups", "OptionGroupsList", OptionGroupName=name):
                    options.extend(option for option in group.get("Options", []) if option["OptionName"] == "MARIADB_AUDIT_PLUGIN")
                return True

            ok = self.check(f"{region}:option-group:{name}", read)
            self.option_cache[key] = {"group_name": name, "status": "ok" if ok else "error", "audit_options": options}
        return self.option_cache[key]

    def inventory(self, region, rds, summary):
        instances = self.collect_items(f"{region}:describe_db_instances", rds, "describe_db_instances", "DBInstances", MaxRecords=100)
        clusters = self.collect_items(f"{region}:describe_db_clusters", rds, "describe_db_clusters", "DBClusters", MaxRecords=100)
        for source, is_cluster in ((instances, False), (clusters, True)):
            for resource in source:
                keys = (
                    "DBInstanceIdentifier", "DBClusterIdentifier", "DBInstanceArn", "DBClusterArn", "Engine", "EngineVersion",
                    "DBInstanceStatus", "Status", "EnabledCloudwatchLogsExports", "DBParameterGroups", "DBClusterParameterGroup",
                    "OptionGroupMemberships", "DBClusterMembers", "ActivityStreamStatus", "BackupRetentionPeriod",
                )
                item = {key: resource[key] for key in keys if key in resource}
                item["audit_inspection"] = "AWS configuration only; verify applied status and actual SQL logs"
                summary["clusters" if is_cluster else "instances"].append(item)
                if resource["Engine"] not in MYSQL_ENGINES:
                    item["audit_inspection"] = "SQL audit configuration not inspected for this engine"
                    continue
                if is_cluster:
                    name = resource.get("DBClusterParameterGroup")
                    if name:
                        item["audit_parameter_group"] = self.parameters(region, rds, name, cluster=True)
                else:
                    item["audit_parameter_groups"] = [
                        {"membership": group, **self.parameters(region, rds, group["DBParameterGroupName"])}
                        for group in resource.get("DBParameterGroups", [])
                    ]
                    item["audit_option_groups"] = [
                        {"membership": group, **self.options(region, rds, group["OptionGroupName"])}
                        for group in resource.get("OptionGroupMemberships", [])
                    ]
                    self.instance_logs(region, rds, resource["DBInstanceIdentifier"], item)

    def instance_logs(self, region, rds, instance, item):
        files = self.collect_items(
            f"{region}:list_instance_logs:{instance}", rds, "describe_db_log_files", "DescribeDBLogFiles",
            DBInstanceIdentifier=instance, MaxRecords=100,
        )
        item["available_sql_log_files"] = [dict(row) for row in files if is_sql_log_file(row["LogFileName"])]
        if not self.args.download_instance_logs:
            return
        directory = self.directory / "instance-logs"
        directory.mkdir(exist_ok=True)
        for row in item["available_sql_log_files"]:
            name = row["LogFileName"]
            path = directory / (safe_name(f"{region}/{instance}/{name}") + ".log")
            row["download"] = {"path": str(path.relative_to(self.directory)), "status": "error", "time_filter_applied": False}
            result = self.check(f"{region}:download_instance_log:{instance}:{name}", lambda: download_instance_log(rds, instance, name, path))
            if result is not None:
                row["download"].update(status="ok", **result)

    def cloudwatch(self, region, summary):
        logs = self.client("logs", region)
        for group in iter_items(
            logs, "describe_log_groups", "logGroups", request_token="nextToken", response_token="nextToken",
            logGroupNamePrefix="/aws/rds/",
        ):
            name = group["logGroupName"]
            if not re.fullmatch(r"/aws/rds/(instance|cluster)/[^/]+/(audit|general)", name):
                continue
            item = {key: group[key] for key in ("logGroupName", "retentionInDays", "storedBytes", "creationTime", "logGroupClass") if key in group}
            summary["sql_log_groups"].append(item)
            if not self.args.download_sql_logs:
                item["download"] = {"status": "not_requested"}
                continue
            directory = self.directory / "cloudwatch"
            directory.mkdir(exist_ok=True)
            path = directory / (safe_name(f"{region}/{name}") + ".jsonl")
            item["download"] = {"path": str(path.relative_to(self.directory)), "status": "error", "event_count": 0}

            def download():
                with path.open("x", encoding="utf-8", newline="\n") as handle:
                    for event in iter_items(
                        logs, "filter_log_events", "events", request_token="nextToken", response_token="nextToken",
                        logGroupName=name, startTime=int(self.start.timestamp() * 1000), endTime=int(self.end.timestamp() * 1000),
                    ):
                        timestamp = datetime.fromtimestamp(event["timestamp"] / 1000, UTC)
                        if in_window(timestamp, self.start, self.end):
                            write_json_line(handle, {"region": region, "logGroupName": name, **event})
                            item["download"]["event_count"] += 1
                item["download"]["status"] = "ok"

            self.check(f"{region}:download_cloudwatch:{name}", download)

    def run(self):
        try:
            regions = self.regions()
            self.report["selected_regions"] = regions
            with (self.directory / "management-events.jsonl").open("x", encoding="utf-8") as management, (self.directory / "rds-events.jsonl").open("x", encoding="utf-8") as events:
                for region in regions:
                    print(f"查询区域 {region} …", flush=True)
                    summary = {"management_event_count": 0, "rds_service_event_count": 0, "instances": [], "clusters": [], "sql_log_groups": [], "notes": []}
                    self.report["regions"][region] = summary
                    self.check(f"{region}:cloudtrail", lambda: self.management_events(region, management, summary))
                    rds = self.check(f"{region}:initialize_rds_client", lambda: self.client("rds", region))
                    if rds is not None:
                        self.check(f"{region}:service_events", lambda: self.service_events(region, rds, events, summary))
                        self.check(f"{region}:inventory", lambda: self.inventory(region, rds, summary))
                    self.check(f"{region}:cloudwatch_discovery", lambda: self.cloudwatch(region, summary))
                    if not summary["sql_log_groups"]:
                        summary["notes"].append("未发现标准路径的 audit/general 日志组；请检查查询状态、实际生效配置、本地日志及自定义日志目的地。")
        except Exception as exc:
            self.report["checks"].append({"scope": "collection", "status": "error", "error_type": type(exc).__name__, "message": str(exc)})
            print(f"[部分失败] 采集未完成: {exc}", file=sys.stderr)
        finally:
            self.report["finished_at"] = iso(datetime.now(UTC))
            errors = sum(check["status"] == "error" for check in self.report["checks"])
            self.report["collection_status"] = "partial" if errors else "ok"
            self.report["failed_check_count"] = errors
            self.report["historical_sql_completeness"] = "not_established"
            (self.directory / "report.json").write_text(json.dumps(self.report, ensure_ascii=False, indent=2, default=json_default) + "\n", encoding="utf-8")
        return 2 if errors else 0


def build_parser():
    parser = argparse.ArgumentParser(description="只读导出 RDS 管理操作、检查 MySQL/Aurora MySQL 审计配置并下载已有日志")
    parser.add_argument("--profile", help="AWS 配置名；省略时使用 boto3 默认凭据链")
    parser.add_argument("--regions", type=validate_regions, default="all", help="all 或逗号分隔的区域；默认 all")
    parser.add_argument("--discovery-region", help="区域发现/STS 使用的区域，默认 SDK 配置区域或 us-east-1")
    parser.add_argument("--days", type=float, help="最近天数，默认 7，小于 90；与 start/end 互斥")
    parser.add_argument("--start", type=parse_timestamp, help="开始时间（含时区），包含该时刻")
    parser.add_argument("--end", type=parse_timestamp, help="结束时间（含时区），不包含该时刻")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/rds"), help="输出父目录，每次运行新建子目录")
    parser.add_argument("--download-sql-logs", action="store_true", help="导出已有 CloudWatch audit/general 日志原文")
    parser.add_argument("--download-instance-logs", action="store_true", help="备用：下载全部当前可见 audit/general 实例日志整文件，会使用实例资源")
    return parser


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 1
    try:
        start, end = make_window(args, datetime.now(UTC))
        # Deferred import permits --help and offline tests without AWS dependencies.
        import boto3
        from botocore.config import Config

        session = boto3.Session(profile_name=args.profile)
        config = Config(retries={"mode": "standard", "total_max_attempts": 8}, connect_timeout=10, read_timeout=60)
        seed = args.discovery_region or session.region_name or "us-east-1"
        if args.regions != "all":
            seed = next((part.strip() for part in args.regions.split(",") if part.strip()), seed)
        identity = session.client("sts", region_name=seed, config=config).get_caller_identity()
        identity = {key: identity[key] for key in ("Account", "Arn", "UserId")}
        directory = args.output_dir / identity["Account"] / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
        directory.mkdir(parents=True, exist_ok=False)
        collector = Collector(session, config, start, end, directory, args, identity)
        status = collector.run()
        print(f"结果: {directory.resolve()}")
        print(f"采集状态: {collector.report['collection_status']}；失败检查数: {collector.report['failed_check_count']}。日志为空不代表没有操作。")
        return status
    except ImportError:
        print("缺少 boto3；请使用运行脚本的同一个 Python 执行 -m pip install -r requirements.txt", file=sys.stderr)
    except Exception as exc:
        print(f"运行失败: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
