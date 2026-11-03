#!/usr/bin/env python3
"""Read-only RDS management history and MySQL/Aurora MySQL user-summary collector.

No database connections or configuration changes are made. See RDS_AUDIT.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import date, datetime, time as day_time, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

UTC = timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_PUBLISH_DIR = PROJECT_ROOT / "index"
MYSQL_ENGINES = {"mysql", "aurora-mysql", "aurora"}
PARAMETERS = {
    "general_log", "log_output", "binlog_format", "binlog_row_image",
    "binlog_expire_logs_seconds", "expire_logs_days", "log_bin", "aws_default_logs_role",
}
LIMITATIONS = [
    "CloudTrail is RDS management API history, not ordinary database SQL history; only recognized create/delete/modify requests are counted by user, including separate failure totals.",
    "Only the current account and selected Regions are queried. CloudTrail history is limited to 90 days; S3/Lake archives and Data API data events are not queried.",
    "RDS service notifications cover at most the last 14 days; they are not a record of all user actions.",
    "MySQL audit settings are current AWS control-plane configuration, not proof of effective runtime values or past audit coverage.",
    "SQL activity is available only if logging was enabled at the time and the logs are still retained. Empty results do not prove no activity.",
    "SQL logs can be truncated, filtered by user/event, delayed, rotated, or masked. General logs do not prove success or COMMIT; audit return codes do not prove transaction COMMIT.",
    "Audit SQL does not guarantee row-level before/after values or identify a human behind a shared database account.",
    "CloudWatch discovery covers standard /aws/rds/instance|cluster/<id>/audit|general groups, including retained groups for deleted databases; custom destinations are not discovered.",
    "Database TABLE log destinations (mysql.general_log), slow-query logs, binary logs, and Database Activity Stream payloads are not collected by this script.",
    "Only user counts are retained; raw SQL, execution details and per-statement alerts are disabled.",
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


def parse_end_timestamp(value: str) -> datetime | str:
    """Resolve `now` once per run, using the same clock as window validation."""
    return "now" if value.strip().lower() == "now" else parse_timestamp(value)


def parse_sql_alert_commands(value: str) -> tuple[str, ...]:
    commands = tuple(dict.fromkeys(part.strip().upper() for part in value.split(",")))
    if not commands or any(command not in {"DELETE", "UPDATE", "DROP", "TRUNCATE", "ALTER"} for command in commands):
        raise argparse.ArgumentTypeError("SQL告警命令仅支持逗号分隔的 DELETE,UPDATE,DROP,TRUNCATE,ALTER")
    return commands


def validate_query_shortcut(args):
    if not getattr(args, "since_yesterday_7", False):
        return
    if (args.days is not None or args.start or args.end or args.daily or args.date or args.input_dir or
            args.from_cache or args.collect_incremental or args.check_config or args.notify_service_failure):
        raise ValueError("--since-yesterday-7 不能与其他时间窗口、日报、离线输入、缓存、增量采集、预检或服务失败告警模式混用")


def make_window(args, now: datetime) -> tuple[datetime, datetime]:
    validate_query_shortcut(args)
    shortcut = getattr(args, "since_yesterday_7", False)
    if not shortcut and bool(args.start) != bool(args.end):
        raise ValueError("--start 和 --end 必须同时提供")
    if args.start and args.days is not None:
        raise ValueError("--days 不能与 --start/--end 同时使用")
    if shortcut:
        beijing = ZoneInfo("Asia/Shanghai")
        yesterday = now.astimezone(beijing).date() - timedelta(days=1)
        start = datetime.combine(yesterday, day_time(7), beijing).astimezone(UTC)
        end = now.astimezone(UTC)
    elif args.start:
        start, end = args.start, now if args.end == "now" else args.end
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


def daily_window(value: str | None, now: datetime) -> tuple[str, datetime, datetime]:
    """The date labels the end of a fixed Beijing 07:00 yesterday–08:00 today window."""
    beijing = ZoneInfo("Asia/Shanghai")
    day = date.fromisoformat(value) if value else now.astimezone(beijing).date()
    start = datetime.combine(day - timedelta(days=1), day_time(7), beijing).astimezone(UTC)
    end = datetime.combine(day, day_time(8), beijing).astimezone(UTC)
    if end > now:
        raise ValueError("该日报窗口尚未结束；请在报表日期北京时间 08:00 之后执行，或用 --date 指定已结束的日期")
    return day.isoformat(), start, end


def iter_items(client, operation, result_key, *, request_token="Marker", response_token="Marker", delay=0, **kwargs):
    """Continue even after empty pages; fail loudly if an API repeats its cursor."""
    tokens = None
    try:
        while True:
            response = getattr(client, operation)(**kwargs)
            yield from response.get(result_key, [])
            token = response.get(response_token)
            if not token:
                return
            if tokens is None:
                # Empty filename uses an automatically deleted SQLite temporary
                # database; page count must not grow the process's Python heap.
                tokens = sqlite3.connect("")
                tokens.execute("PRAGMA journal_mode=OFF")
                tokens.execute("PRAGMA cache_size=-256")
                tokens.execute("CREATE TABLE cursors (digest BLOB PRIMARY KEY) WITHOUT ROWID")
            digest = hashlib.sha256(str(token).encode()).digest()
            if not tokens.execute("INSERT OR IGNORE INTO cursors VALUES(?)", (digest,)).rowcount:
                raise RuntimeError(f"{operation}: repeated pagination token; results are incomplete")
            kwargs[request_token] = token
            if delay:
                time.sleep(delay)
    finally:
        if tokens is not None:
            tokens.close()


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
            "operation_scope": "changes_only", "summary_only": True,
            "sql_log_download_requested": args.download_sql_logs,
            "instance_log_download_requested": args.download_instance_logs,
            "limitations": LIMITATIONS, "checks": [], "regions": {},
        }
        self.parameter_cache, self.option_cache = {}, {}
        self.accumulator = None

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
        for event in iter_items(
            ct, "lookup_events", "Events", request_token="NextToken", response_token="NextToken", delay=0.55,
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "rds.amazonaws.com"}],
            StartTime=self.start, EndTime=self.end, MaxResults=50,
        ):
            if not in_window(event["EventTime"], self.start, self.end):
                continue
            raw = json.loads(event["CloudTrailEvent"])
            result = self.accumulator.process_management({
                "region": region, "event": raw,
                "lookup": {key: value for key, value in event.items() if key != "CloudTrailEvent"},
            })
            summary["management_event_count"] += result.get("change_records", 0)
            summary["filtered_management_event_count"] = summary.get("filtered_management_event_count", 0) + result.get("filtered_management", 0)

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
            if name.endswith("/general"):
                item["download"] = {"status": "skipped_read_logs"}
                continue
            counts = item["download"] = {
                "status": "error", "summary_only": True, "event_count": 0,
                "received_event_count": 0, "change_record_count": 0,
                "filtered_read_record_count": 0, "filtered_auxiliary_record_count": 0,
                "quarantined_record_count": 0,
            }

            def aggregate():
                for event in iter_items(
                    logs, "filter_log_events", "events", request_token="nextToken", response_token="nextToken",
                    logGroupName=name, startTime=int(self.start.timestamp() * 1000), endTime=int(self.end.timestamp() * 1000),
                ):
                    occurred = datetime.fromtimestamp(event["timestamp"] / 1000, UTC)
                    if not in_window(occurred, self.start, self.end):
                        continue
                    counts["received_event_count"] += 1
                    decision = self.accumulator.process_audit({"region": region, "logGroupName": name, **event})
                    counts["change_record_count"] += decision["change_records"]
                    counts["filtered_read_record_count"] += decision["read_records"]
                    counts["filtered_auxiliary_record_count"] += decision["auxiliary_records"]
                    counts["quarantined_record_count"] += decision["unknown_records"]
                    counts["event_count"] += bool(decision["change_records"])
                counts["status"] = "ok"

            self.check(f"{region}:aggregate_cloudwatch:{name}", aggregate)
            if counts["quarantined_record_count"]:
                self.report["checks"].append({
                    "scope": f"{region}:classify_sql:{name}", "status": "error", "error_type": "UnclassifiedSqlRecords",
                    "message": f"{counts['quarantined_record_count']} 条审计记录无法可靠分类，已仅保存问题计数；未计入增删改。",
                })
            print(f"{region}: {name} 已读取候选事件 {counts['received_event_count']} 条，汇总增删改 {counts['change_record_count']} 条；不保存日志正文。", flush=True)

    def run(self):
        from rds_summary import SummaryAccumulator

        try:
            if self.args.download_instance_logs:
                raise ValueError("仅汇总模式不支持下载实例原始日志")
            with SummaryAccumulator(self.directory, self.start, self.end,
                                    dimension=getattr(self.args, "summary_dimension", "user")) as accumulator:
                self.accumulator = accumulator
                regions = self.regions()
                self.report["selected_regions"] = regions
                for region in regions:
                    summary = {"management_event_count": 0, "rds_service_event_count": 0, "instances": [], "clusters": [], "sql_log_groups": [], "notes": []}
                    self.report["regions"][region] = summary
                    self.check(f"{region}:cloudtrail", lambda: self.management_events(region, None, summary))
                    if not getattr(self.args, "metadata_light", False):
                        rds = self.check(f"{region}:initialize_rds_client", lambda: self.client("rds", region))
                        if rds is not None:
                            self.check(f"{region}:inventory", lambda: self.inventory(region, rds, summary))
                    self.check(f"{region}:cloudwatch_discovery", lambda: self.cloudwatch(region, summary))
                    if not summary["sql_log_groups"]:
                        summary["notes"].append("未发现标准 audit/general 日志组，不能据此判断没有数据库操作。")
                payload = accumulator.finish()
                if not payload.get("complete", True) and not any(check.get("error_type") == "UnclassifiedSqlRecords" for check in self.report["checks"]):
                    self.report["checks"].append({"scope": "summary_quality", "status": "error", "error_type": "UnclassifiedSqlRecords", "message": "部分记录无法可靠解析或去重，仅保存问题计数，未冒充完整汇总。"})
        except Exception as exc:
            self.report["checks"].append({"scope": "collection", "status": "error", "error_type": type(exc).__name__, "message": str(exc)})
            print(f"[部分失败] 采集未完成: {exc}", file=sys.stderr)
        finally:
            self.accumulator = None
            self.report["finished_at"] = iso(datetime.now(UTC))
            errors = sum(check["status"] == "error" for check in self.report["checks"])
            self.report["collection_status"] = "partial" if errors else "ok"
            self.report["failed_check_count"] = errors
            self.report["historical_sql_completeness"] = "not_established"
            (self.directory / "report.json").write_text(json.dumps(self.report, ensure_ascii=False, indent=2, default=json_default) + "\n", encoding="utf-8")
        return 2 if errors else 0


def build_parser():
    parser = argparse.ArgumentParser(description="只读采集 RDS 审计日志，生成按用户的增删改汇总，不保存SQL正文或执行明细")
    parser.add_argument("--profile", help="AWS 配置名；省略时使用 boto3 默认凭据链")
    parser.add_argument("--regions", type=validate_regions, default="all", help="all 或逗号分隔的区域；默认 all")
    parser.add_argument("--discovery-region", help="区域发现/STS 使用的区域，默认 SDK 配置区域或 us-east-1")
    parser.add_argument("--days", type=float, help="最近天数，默认 7，小于 90；与 start/end 互斥")
    parser.add_argument("--start", type=parse_timestamp, help="开始时间（含时区），包含该时刻")
    parser.add_argument("--end", type=parse_end_timestamp, help="结束时间（含时区或 now），不包含该时刻")
    parser.add_argument("--since-yesterday-7", action="store_true", help="查询昨日北京时间07:00至当前时间，读取audit日志并即时汇总，不保存正文")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/rds"), help="输出父目录，每次运行新建子目录")
    parser.add_argument("--download-sql-logs", action="store_true", help="读取已有 CloudWatch audit 日志并汇总，不保存正文")
    parser.add_argument("--download-instance-logs", action="store_true", help="已停用：仅汇总模式不允许下载实例原始日志")
    parser.add_argument("--daily", action="store_true", help="生成北京时间昨天07:00至今天08:00的HTML日报，读取CloudWatch audit日志并仅保存用户汇总")
    parser.add_argument("--date", help="日报窗口结束日期 YYYY-MM-DD，默认北京时间今天")
    parser.add_argument("--input-dir", type=Path, help="按已有采集目录的原始窗口离线生成HTML；加--daily/--date时生成固定日报，不连接AWS")
    publication = parser.add_mutually_exclusive_group()
    publication.add_argument("--publish-dir", type=Path, default=DEFAULT_PUBLISH_DIR, help="整套报告网页发布目录，默认项目下index/，首页index.html")
    publication.add_argument("--no-publish", dest="publish_dir", action="store_const", const=None, help="仅生成归档，不更新网页发布目录")
    parser.add_argument("--send-lark", action="store_true", help="生成HTML后向配置的Lark群发送汇总")
    parser.add_argument("--sql-alerts", action=argparse.BooleanOptionalAction, default=False, help="逐条SQL告警已停用；兼容--no-sql-alerts，拒绝启用")
    parser.add_argument("--sql-alert-commands", type=parse_sql_alert_commands, default=("DELETE", "UPDATE", "DROP", "TRUNCATE", "ALTER"), help="SQL即时告警命令，默认 DELETE,UPDATE,DROP,TRUNCATE,ALTER")
    parser.add_argument("--lark-config", type=Path, default=Path("lark-config.json"), help="Lark私有配置路径")
    parser.add_argument("--check-config", action="store_true", help="只检查AWS身份/可见资源读取权限及可选Lark配置，不生成报告、不发消息")
    parser.add_argument("--collect-incremental", action="store_true", help="按半小时/小时分段采集增删改到本地缓存，失败重试并可发Lark告警")
    parser.add_argument("--from-cache", action="store_true", help="--daily仅汇总本地成功分段，不发起25小时AWS查询")
    parser.add_argument("--cache-dir", type=Path, default=Path("reports/cache"), help="增量缓存及检查点目录")
    parser.add_argument("--cache-account-id", help="本地缓存有多个账号时指定账号ID")
    parser.add_argument("--interval-minutes", type=int, choices=(30, 60), default=30, help="采集分段分钟数，默认30")
    parser.add_argument("--cache-lookback-hours", type=int, default=26, help="自动补齐最近小时数，默认26")
    parser.add_argument("--max-buckets-per-run", type=int, default=6, help="单次最多处理分段数，默认6，分摊首次回补压力")
    parser.add_argument("--notify-service-failure", action="store_true", help="systemd异常退出告警入口，不连接AWS")
    parser.add_argument("--source-service", help="异常退出的本项目服务名称")
    return parser


def aws_session(args):
    import boto3
    from botocore.config import Config

    session = boto3.Session(profile_name=args.profile)
    config = Config(retries={"mode": "standard", "total_max_attempts": 8}, connect_timeout=10, read_timeout=60)
    seed = args.discovery_region or session.region_name or "us-east-1"
    if args.regions != "all":
        seed = args.regions.split(",")[0]
    identity = session.client("sts", region_name=seed, config=config).get_caller_identity()
    return session, config, {key: identity[key] for key in ("Account", "Arn", "UserId")}


def lark_configuration(args, audit_date=None):
    if not args.send_lark:
        return None
    from lark_notify import load_lark_config, format_report_url

    config = load_lark_config(args.lark_config)
    if config.get("message_mode", "overview") != "overview":
        raise ValueError("RDS日报只发送 overview 汇总；请将Lark配置 message_mode 设为 overview")
    sample = {"metadata": {"audit_date": audit_date or datetime.now(UTC).astimezone(ZoneInfo("Asia/Shanghai")).date().isoformat(), "account_id": "000000000000", "report_filename": "index.html"}}
    format_report_url(config.get("report_url_template", ""), sample)
    return config


def check_configuration(args):
    """Exercise actual read APIs without saving events or sending a notification."""
    lark_configuration(args)
    session, config, identity = aws_session(args)
    # Check as the same OS user that systemd will use, without creating probe files.
    for path in (args.output_dir / identity["Account"], args.publish_dir, args.cache_dir):
        if path is None:
            continue
        existing = path.resolve()
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        if not existing.is_dir() or not os.access(existing, os.W_OK | os.X_OK):
            raise PermissionError(f"服务用户无法在目标目录写入报告: {path}")
    now = datetime.now(UTC)
    c = Collector(session, config, now - timedelta(hours=1), now, Path("."), args, identity)
    regions = c.regions()
    print(f"AWS账号: {identity['Account']}；身份: {identity['Arn']}")
    for region in regions:
        print(f"检查 {region} …", flush=True)

        def inspect():
            ct = c.client("cloudtrail", region)
            ct.lookup_events(LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "rds.amazonaws.com"}], MaxResults=1)
            rds = c.client("rds", region)
            instances = list(iter_items(rds, "describe_db_instances", "DBInstances", MaxRecords=100))
            clusters = list(iter_items(rds, "describe_db_clusters", "DBClusters", MaxRecords=100))
            mysql_instances = [item for item in instances if item["Engine"] in MYSQL_ENGINES]
            mysql_clusters = [item for item in clusters if item["Engine"] in MYSQL_ENGINES]
            if mysql_instances or mysql_clusters:
                print(f"{region}: 已发现 MySQL/Aurora MySQL 实例 {len(mysql_instances)} 个、集群 {len(mysql_clusters)} 个。", flush=True)
            rds.describe_events(Duration=60, MaxRecords=20)
            for item in instances:
                if item["Engine"] not in MYSQL_ENGINES:
                    continue
                for group in item.get("DBParameterGroups", []):
                    c.parameters(region, rds, group["DBParameterGroupName"])
                for group in item.get("OptionGroupMemberships", []):
                    c.options(region, rds, group["OptionGroupName"])
                rds.describe_db_log_files(DBInstanceIdentifier=item["DBInstanceIdentifier"], MaxRecords=20)
            for item in clusters:
                if item["Engine"] in MYSQL_ENGINES and item.get("DBClusterParameterGroup"):
                    c.parameters(region, rds, item["DBClusterParameterGroup"], cluster=True)
            logs = c.client("logs", region)
            groups = list(iter_items(logs, "describe_log_groups", "logGroups", request_token="nextToken", response_token="nextToken", logGroupNamePrefix="/aws/rds/"))
            sql_groups = [g["logGroupName"] for g in groups if re.fullmatch(r"/aws/rds/(instance|cluster)/[^/]+/(audit|general)", g["logGroupName"])]
            if groups:
                print(f"{region}: 已发现 /aws/rds/ 日志组 {len(groups)} 个，其中 audit/general {len(sql_groups)} 个。", flush=True)
            for name in sql_groups:
                if name.endswith("/general"):
                    print(f"{region}: {name} 仅列目录；增删改采集不下载 general 正文。", flush=True)
                    continue
                print(f"{region}: 已发现 SQL 日志组 {name}，正在验证读取接口权限…", flush=True)
                stamp = int(datetime.now(UTC).timestamp() * 1000)
                logs.filter_log_events(logGroupName=name, startTime=stamp - 1, endTime=stamp, limit=1)
                print(f"{region}: {name} 读取接口验证通过（预检不下载日志，也不判断历史日志是否有内容）。", flush=True)
            if not sql_groups:
                print(f"{region}: 未发现audit/general日志组；无法在现有资源上验证SQL日志读取权限，也不代表已启用SQL审计。")
            if not any(i["Engine"] in MYSQL_ENGINES for i in instances + clusters):
                print(f"{region}: 未发现MySQL/Aurora MySQL；参数组和选项组权限无法用现存资源验证。")
            if args.download_instance_logs:
                print(f"{region}: 预检不下载实例文件，DownloadDBLogFilePortion权限需在实际下载时验证。")

        c.check(f"{region}:preflight", inspect)
    failed = [row for row in c.report["checks"] if row["status"] == "error"]
    if failed:
        print(f"预检失败: {len(failed)} 项。请修正网络、身份或IAM授权后重跑。", file=sys.stderr)
        return 1
    print("现有可见资源预检通过；未保存日志、未发送Lark。真实Webhook可用性及未来资源权限不在本地预检保证范围。")
    return 0


def atomic_copy(source: Path, target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".rds-", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            with source.open("rb") as original:
                shutil.copyfileobj(original, handle)
        if os.name == "posix":
            temporary.chmod(0o644)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def finish_daily(directory, audit_date, start, end, args, status, lark_config=None, *, period_kind="daily"):
    from rds_report import build_daily_report, write_report

    report = build_daily_report(directory, audit_date=audit_date, start=start, end=end, offline=bool(args.input_dir), period_kind=period_kind)
    html_path = write_report(report, directory)
    args._delivery_failed = False
    status = 2 if status == 2 or not report["metadata"]["complete"] else status
    print(f"{'HTML日报' if period_kind == 'daily' else 'HTML报告'}: {html_path.resolve()}")
    if args.publish_dir:
        try:
            publish = args.publish_dir.resolve()
            publish.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                publish.chmod(0o755)
                if publish.is_relative_to(PROJECT_ROOT):
                    # Nginx can traverse the project without granting directory
                    # listing access or changing private archive/config modes.
                    mode = PROJECT_ROOT.stat().st_mode & 0o7777
                    if not mode & 0o001:
                        PROJECT_ROOT.chmod(mode | 0o001)
            # Publish the complete paginated snapshot before replacing the entry point.
            artifacts = report.get("artifacts") or {}
            manifest = artifacts.get("manifest") or ["rds-report.css", html_path.name]
            prepared = []
            root = directory.resolve()
            for name in manifest:
                relative = Path(name)
                source = (directory / relative).resolve()
                if relative.is_absolute() or ".." in relative.parts or not source.is_relative_to(root):
                    raise OSError("报告附件路径越出归档目录")
                allowed = name in {"rds-report.css", html_path.name, artifacts.get("bundle_filename")}
                allowed = allowed or (relative.parts and relative.parts[0] == artifacts.get("detail_directory") and relative.suffix == ".html")
                if not allowed or not source.is_file():
                    raise OSError(f"报告附件缺失或不允许发布: {name}")
                prepared.append((source, publish / relative))
            for source, target in prepared:
                if target.name != html_path.name:
                    atomic_copy(source, target)
                    if target.parent != publish:
                        target.parent.chmod(0o755)
            atomic_copy(html_path, publish / html_path.name)
            atomic_copy(html_path, publish / "index.html")
            print(f"最新网页: {publish / 'index.html'}")
        except OSError as exc:
            args._delivery_failed = True
            print(f"网页发布失败，未发送Lark，归档已保留: {exc}", file=sys.stderr)
            return 2 if status == 2 else 4
    if args.send_lark:
        from lark_notify import send_lark_notification
        try:
            send_lark_notification(report, lark_config or lark_configuration(args, audit_date))
            print("Lark汇总已发送。")
        except (ValueError, RuntimeError, OSError) as exc:
            args._delivery_failed = True
            print(f"Lark汇总发送失败，报告已保留: {exc}", file=sys.stderr)
            return 2 if status == 2 else 3
    return status


def resolve_report_window(args, now):
    """Keep an archived collection's exact window unless a daily window is requested."""
    validate_query_shortcut(args)
    has_custom_window = args.days is not None or args.start or args.end or args.since_yesterday_7
    if (args.daily or args.input_dir) and has_custom_window:
        raise ValueError("--daily/--input-dir 不能与 --days/--start/--end 混用")
    if args.date and not (args.daily or args.input_dir):
        raise ValueError("--date 需要 --daily 或 --input-dir")
    if args.send_lark and not (args.daily or args.input_dir or has_custom_window):
        raise ValueError("--send-lark 需要显式指定 --daily、--input-dir 或自定义时间窗口")
    beijing = ZoneInfo("Asia/Shanghai")
    if args.input_dir:
        source = json.loads((args.input_dir / "report.json").read_text(encoding="utf-8-sig"))
        source_start = parse_timestamp(source["window"]["start_inclusive"])
        source_end = parse_timestamp(source["window"]["end_exclusive"])
        if source_start >= source_end:
            raise ValueError("输入目录中的采集窗口无效：开始时间必须早于结束时间")
        day = args.date or source_end.astimezone(beijing).date().isoformat()
        kind = "daily" if args.daily or args.date else source.get("period_kind", "custom")
        if kind == "daily":
            day, start, end = daily_window(day, now)
            if source_start > start or source_end < end:
                raise ValueError("输入目录采集窗口未覆盖请求的25小时日报窗口；省略 --daily/--date 可按原始窗口生成自定义HTML")
            return kind, day, start, end
        if kind != "custom":
            raise ValueError("输入目录的 period_kind 必须为 daily 或 custom")
        return kind, day, source_start, source_end
    if args.daily:
        day, start, end = daily_window(args.date, now)
        if start < now - timedelta(days=90) + timedelta(minutes=1):
            raise ValueError("该日报已超出CloudTrail近90天范围；请使用已有归档 --input-dir")
        return "daily", day, start, end
    start, end = make_window(args, now)
    return "custom", end.astimezone(beijing).date().isoformat(), start, end


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 1
    try:
        validate_query_shortcut(args)
        if args.sql_alerts:
            raise ValueError("仅汇总模式不支持 --sql-alerts；请移除该参数或使用 --no-sql-alerts")
        if args.download_instance_logs:
            raise ValueError("仅汇总模式不支持 --download-instance-logs；不会下载或保存原始SQL")
        if sum(bool(flag) for flag in (args.collect_incremental, args.from_cache, args.notify_service_failure)) > 1:
            raise ValueError("增量采集、缓存汇总和服务失败告警模式不能同时使用")
        if args.check_config:
            if args.input_dir:
                raise ValueError("--check-config 不支持 --input-dir")
            return check_configuration(args)
        if args.notify_service_failure:
            from rds_jobs import notify_service_failure
            return notify_service_failure(args, api=sys.modules[__name__])
        if args.collect_incremental:
            if args.daily or args.from_cache or args.input_dir or args.date or args.days is not None or args.start or args.end:
                raise ValueError("增量采集模式不能与日报/离线输入/自定义窗口混用")
            from rds_jobs import run_incremental
            return run_incremental(args, api=sys.modules[__name__])
        if args.from_cache:
            if not args.daily or args.input_dir or args.days is not None or args.start or args.end:
                raise ValueError("--from-cache 必须配合 --daily，不能与其他输入窗口混用")
            from rds_jobs import run_cached_daily
            return run_cached_daily(args, api=sys.modules[__name__])
        now = datetime.now(UTC)
        period_kind, audit_date, start, end = resolve_report_window(args, now)
        config_lark = lark_configuration(args, audit_date)
        if args.input_dir:
            return finish_daily(args.input_dir.resolve(), audit_date, start, end, args, 0, config_lark, period_kind=period_kind)
        if period_kind == "daily" or args.since_yesterday_7 or args.start:
            args.download_sql_logs = True
        session, config, identity = aws_session(args)
        base = args.output_dir / identity["Account"]
        if period_kind == "daily":
            base /= audit_date
        directory = base / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
        directory.mkdir(parents=True, exist_ok=False)
        beijing = ZoneInfo("Asia/Shanghai")
        print(f"采集窗口（北京时间）: {start.astimezone(beijing):%Y-%m-%d %H:%M:%S} 至 {end.astimezone(beijing):%Y-%m-%d %H:%M:%S}（左闭右开）", flush=True)
        collector = Collector(session, config, start, end, directory, args, identity)
        collector.report["period_kind"] = period_kind
        status = collector.run()
        print(f"结果: {directory.resolve()}")
        print(f"采集状态: {collector.report['collection_status']}；失败检查数: {collector.report['failed_check_count']}。日志为空不代表没有操作。")
        return finish_daily(directory, audit_date, start, end, args, status, config_lark, period_kind=period_kind)
    except ImportError:
        print("缺少 boto3；请使用运行脚本的同一个 Python 执行 -m pip install -r requirements.txt", file=sys.stderr)
    except Exception as exc:
        print(f"运行失败: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
