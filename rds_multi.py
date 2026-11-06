#!/usr/bin/env python3
"""Multi-account source-IP audit, bounded day storage and combined PDF mail.

Only counts survive collection. Credentials never enter checkpoints or reports.
The legacy user-report CLI remains available in rds_audit.py.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time as process_time
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from rds_audit import Collector, iso, iter_items
from rds_cache import _exclusive
from rds_config import load_config
from rds_retention import DAY_MARKER, _is_link, prune_account_days
from rds_summary import merge_summaries, validate_summary
from rds_schedule import configured_window, latest_report_day, report_segments, report_window, window_tag

UTC = timezone.utc
PROJECT = Path(__file__).resolve().parent


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def safe_directory(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if (component.exists() or component.is_symlink()) and _is_link(component):
            raise ValueError("数据目录及其父目录不得为符号链接或 junction")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path.resolve()


def account_directory(config, account):
    root = safe_directory(config["OUTPUT_DIRECTORY"])
    candidate = root / (account["NAME"] + "-" + account["ACCOUNT_ID"])
    existed = candidate.exists()
    path = safe_directory(candidate)
    if path.parent != root:
        raise ValueError("账号目录超出输出目录")
    marker = path / ".rds-audit-account"
    identity = {"account_id": account["ACCOUNT_ID"], "account_name": account["NAME"]}
    if existed and (not marker.is_file() or _is_link(marker)):
        raise ValueError("已有账号目录缺少本程序标记，请使用空输出目录或核实旧数据")
    if marker.exists() and read_json(marker) != identity:
        raise ValueError("账号目录标记与配置不一致")
    if not existed:
        atomic_json(marker, identity)
    return path


def day_directory(config, account, day):
    candidate = account_directory(config, account) / day.isoformat()
    existed = candidate.exists()
    path = safe_directory(candidate)
    marker = path / DAY_MARKER
    value = {"account_id": account["ACCOUNT_ID"], "date": day.isoformat()}
    if existed and (not marker.is_file() or _is_link(marker) or read_json(marker) != value):
        raise ValueError("已有日期目录缺少匹配标记，拒绝收编或清理未知数据")
    if not existed:
        atomic_json(marker, value)
    return path


def day_window(day, zone):
    return (datetime.combine(day, time(), zone).astimezone(UTC),
            datetime.combine(day + timedelta(days=1), time(), zone).astimezone(UTC))


def windows(day, zone, minutes):
    start, end = day_window(day, zone)
    step = timedelta(minutes=minutes)
    while start < end:
        right = min(start + step, end)
        yield start, right
        start = right


def scope_for(config, account):
    return {"version": 2, "dimension": "ip", "source_filter": "ip_only", "account_id": account["ACCOUNT_ID"],
            "regions": account["REGIONS"], "timezone": config["TIMEZONE"],
            "interval_minutes": config["COLLECTION_INTERVAL_MINUTES"]}


def scope_id(config, account):
    return hashlib.sha256(json.dumps(scope_for(config, account), sort_keys=True).encode()).hexdigest()[:20]


def bucket_path(config, account, start):
    local_day = start.astimezone(ZoneInfo(config["TIMEZONE"])).date()
    directory = day_directory(config, account, local_day) / "segments" / scope_id(config, account)
    safe_directory(directory)
    return directory / (start.strftime("%Y%m%dT%H%MZ") + ".json")


def create_session(account):
    import boto3

    if account.get("AWS_ACCESS_KEY_ID"):
        return boto3.Session(aws_access_key_id=account["AWS_ACCESS_KEY_ID"],
                             aws_secret_access_key=account["AWS_SECRET_ACCESS_KEY"],
                             aws_session_token=account.get("AWS_SESSION_TOKEN") or None)
    return boto3.Session(profile_name=account.get("AWS_PROFILE") or None)


def sdk_config():
    from botocore.config import Config

    return Config(connect_timeout=10, read_timeout=60, retries={"max_attempts": 3, "mode": "standard"})


def check_identity(session, account):
    region = "us-east-1" if account["REGIONS"] == "all" else account["REGIONS"].split(",")[0]
    identity = session.client("sts", region_name=region, config=sdk_config()).get_caller_identity()
    if str(identity.get("Account")) != account["ACCOUNT_ID"]:
        raise ValueError("AWS Key 对应的账号与 ACCOUNT_ID 不一致")
    return identity


def verify_account(session, account):
    """Read-only preflight: identity, region discovery and one event per source."""
    check_identity(session, account)
    if account["REGIONS"] == "all":
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1", config=sdk_config())
        regions = [row["RegionName"] for row in ec2.describe_regions(AllRegions=False)["Regions"]]
    else:
        regions = account["REGIONS"].split(",")
    found = 0
    now = datetime.now(UTC)
    for region in regions:
        logs = session.client("logs", region_name=region, config=sdk_config())
        for group in iter_items(logs, "describe_log_groups", "logGroups", request_token="nextToken",
                                response_token="nextToken", logGroupNamePrefix="/aws/rds/"):
            name = group["logGroupName"]
            import re
            if re.fullmatch(r"/aws/rds/(?:instance|cluster)/[^/]+/audit", name):
                logs.filter_log_events(logGroupName=name, startTime=int((now - timedelta(minutes=1)).timestamp() * 1000),
                                       endTime=int(now.timestamp() * 1000), limit=1)
                found += 1
        session.client("cloudtrail", region_name=region, config=sdk_config()).lookup_events(
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "rds.amazonaws.com"}],
            StartTime=now - timedelta(minutes=1), EndTime=now, MaxResults=1)
    if not found:
        raise ValueError("未找到标准 RDS audit 日志组，请检查账号/区域/日志配置")


def collect_bucket(config, account, session, identity, start, end, directory):
    args = SimpleNamespace(regions=account["REGIONS"], discovery_region=None,
                           download_sql_logs=True, download_instance_logs=False,
                           metadata_light=True, summary_dimension="ip", quiet=True)
    collector = Collector(session, sdk_config(), start, end, directory, args, identity)
    # Per-instance quiet mode avoids process-global stdout mutation in threads.
    result = collector.run()
    summary = validate_summary(read_json(directory / "operation-summary.json"), start, end, dimension="ip")
    report = collector.report
    groups = sum(group["logGroupName"].endswith("/audit") for region in report["regions"].values()
                 for group in region["sql_log_groups"])
    errors = [{"scope": str(check.get("scope", "")), "error_type": str(check.get("error_type", "CollectionError"))}
              for check in report["checks"] if check.get("status") == "error"]
    if not groups:
        errors.append({"scope": "sql_coverage", "error_type": "NoAuditLogGroups"})
    return {"summary": summary, "complete": result == 0 and summary["complete"] and bool(groups),
            "audit_groups": groups, "errors": errors}


def load_bucket(path, config, account, start, end):
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError("分段必须为 JSON 对象")
    if (type(value.get("schema_version")) is not int or value.get("schema_version") != 1
            or value.get("scope") != scope_for(config, account)
            or value.get("window") != {"start_inclusive": iso(start), "end_exclusive": iso(end)}):
        raise ValueError("分段账号、窗口或配置不匹配")
    for name in ("attempts", "next_retry", "consecutive_failures"):
        if type(value.get(name, 0)) is not int or value.get(name, 0) < 0:
            raise ValueError("分段重试状态必须为非负整数")
    if not isinstance(value.get("last_errors", []), list):
        raise ValueError("分段错误状态必须为数组")
    if not isinstance(value.get("in_progress", False), bool):
        raise ValueError("分段运行状态必须为布尔值")
    if value.get("active") is not None:
        if not isinstance(value["active"], dict) or not isinstance(value["active"].get("complete"), bool):
            raise ValueError("分段完整度必须为布尔值")
        validate_summary(value["active"]["summary"], start, end, dimension="ip")
    return value


def dispatch_collection_alerts(config, account, root, observations, now):
    if not config.get("LARK_ALERTS_ENABLED", False):
        return {"sent": 0, "pending": 0, "failed": 0}
    try:
        from rds_failure_alerts import sync_collection_alerts

        return sync_collection_alerts(config, account, root / ".lark-state.json", observations, now,
                                      collection_scope=scope_id(config, account))
    except Exception as exc:
        print(f"账号 {account['ACCOUNT_ID']}：Lark异常通知待重试（{type(exc).__name__}）。", file=sys.stderr)
        return {"sent": 0, "pending": 1, "failed": 1}


def bucket_observation(config, account, state, start, end):
    return {"key": "bucket:" + scope_id(config, account) + ":" + iso(start),
            "failed": bool(state.get("last_errors")) or not bool((state.get("active") or {}).get("complete")),
            "consecutive_failures": state.get("consecutive_failures", 0), "attempts": state.get("attempts", 0),
            "bucket_start": iso(start), "bucket_end": iso(end),
            "error_types": [str(error.get("error_type", "CollectionError")) for error in state.get("last_errors", [])
                            if isinstance(error, dict)]}


def collect_account(config, account, now, *, session_factory=create_session, collector=collect_bucket, monotonic=None):
    clock = monotonic or process_time.monotonic
    run_started = clock()

    def effective_now():
        # Anchor persisted wall-clock timestamps to the caller's run time while
        # accounting for slow requests without depending on wall-clock jumps.
        return now + timedelta(seconds=max(0, clock() - run_started))

    session = session_factory(account)
    identity = check_identity(session, account)
    zone = ZoneInfo(config["TIMEZONE"])
    today = now.astimezone(zone).date()
    root = account_directory(config, account)
    scope = scope_id(config, account)
    info_path = root / (".scope-" + scope + ".json")
    if info_path.exists():
        try:
            first = date.fromisoformat(read_json(info_path)["first_date"])
            if first > today:
                raise ValueError("future scope start")
        except (OSError, ValueError, KeyError, TypeError):
            first = today - timedelta(days=1)
            atomic_json(info_path, {"first_date": first.isoformat()})
    else:
        first = today - timedelta(days=1)
        atomic_json(info_path, {"first_date": first.isoformat()})
    first = max(first, today - timedelta(days=config["RETENTION_DAYS"] - 1))
    cutoff = now - timedelta(minutes=config["LOG_DELAY_MINUTES"])
    pending, refresh, observations = [], [], {}
    interrupted = False
    day = first
    while day <= today:
        for start, end in windows(day, zone, config["COLLECTION_INTERVAL_MINUTES"]):
            if end > cutoff:
                continue
            path = bucket_path(config, account, start)
            try:
                state = load_bucket(path, config, account, start, end) if path.exists() else {}
            except (ValueError, KeyError, TypeError):
                state = {}  # A corrupt checkpoint is collected again, never counted as zero.
            if state.get("in_progress"):
                # The OS lock has been reacquired, so the previous worker exited
                # before committing. Count that failed attempt and recollect it.
                state.update(in_progress=False, consecutive_failures=state.get("consecutive_failures", 0) + 1,
                             last_errors=[{"scope": "collect", "error_type": "InterruptedCollection"}], next_retry=0)
                atomic_json(path, state)
                interrupted = True
            if state:
                observations[iso(start)] = bucket_observation(config, account, state, start, end)
            if state.get("next_retry", 0) > effective_now().timestamp():
                continue
            active = state.get("active")
            if not active or not active.get("complete"):
                pending.append((start, end, path))
            elif (not state.get("refresh_done") and
                  effective_now() >= end + timedelta(minutes=config["REFRESH_DELAY_MINUTES"])):
                refresh.append((start, end, path))
        day += timedelta(days=1)
    # Prioritise fresh/missing data over the single delayed refresh of complete buckets.
    # Planning retains only bucket paths and small alert metadata. Incomplete
    # snapshots can contain many IP counters; do not queue their full payloads.
    state = active = None
    done, failed = 0, 0
    if interrupted:
        dispatch_collection_alerts(config, account, root, list(observations.values()), effective_now())
    for start, end, path in (pending + refresh)[:config["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"]]:
        state = previous = snapshot = None
        try:
            state = load_bucket(path, config, account, start, end) if path.exists() else {}
        except (ValueError, KeyError, TypeError):
            state = {}
        attempt_started = effective_now()
        attempt = int(state.get("attempts", 0)) + 1
        previous_failures = state.get("consecutive_failures", 0)
        previous = state.get("active")
        state.update(schema_version=1, scope=scope_for(config, account),
                     window={"start_inclusive": iso(start), "end_exclusive": iso(end)},
                     attempts=attempt, in_progress=True, last_attempt_at=iso(attempt_started))
        atomic_json(path, state)
        errors = []
        try:
            with tempfile.TemporaryDirectory(prefix=".attempt-", dir=path.parent) as temporary:
                snapshot = collector(config, account, session, identity, start, end, Path(temporary))
            validate_summary(snapshot["summary"], start, end, dimension="ip")
            finished = effective_now()
            snapshot["collected_at"] = iso(finished)
            if snapshot["complete"] or not previous or not previous.get("complete"):
                state["active"] = snapshot
            errors = snapshot.get("errors", [])
            succeeded = bool(snapshot["complete"])
        except Exception as exc:
            finished = effective_now()
            errors = [{"scope": "collect", "error_type": type(exc).__name__}]
            succeeded = False
        if not succeeded and not errors:
            errors = [{"scope": "collect", "error_type": "IncompleteCollection"}]
        refreshed = bool(state.get("refresh_done")) or (succeeded and attempt_started >= end + timedelta(minutes=config["REFRESH_DELAY_MINUTES"]))
        consecutive = 0 if succeeded else previous_failures + 1
        state.update(schema_version=1, scope=scope_for(config, account),
                     window={"start_inclusive": iso(start), "end_exclusive": iso(end)},
                     attempts=attempt, last_attempt_at=iso(attempt_started), last_errors=errors, in_progress=False,
                     consecutive_failures=consecutive,
                     refresh_done=refreshed,
                     next_retry=0 if succeeded else int(finished.timestamp()) + min(3600, 300 * 2 ** min(consecutive - 1, 4)))
        atomic_json(path, state)
        observations[iso(start)] = bucket_observation(config, account, state, start, end)
        if not succeeded:
            coverage = ((state.get("active") or {}).get("summary") or {}).get("coverage", {})
            kinds = sorted({str(error.get("error_type", "CollectionError")) for error in errors})
            print(f"账号 {account['ACCOUNT_ID']} 分段 {iso(start)} 至 {iso(end)} 不完整："
                  f"{','.join(kinds)}；未解析/未分类 {coverage.get('unparsed_records', 0)} 条；"
                  f"已排除无IP {coverage.get('filtered_no_ip_records', 0)} 条。", flush=True)
        done += 1
        failed += not succeeded
    result = {"processed": done, "failed": failed, "remaining": max(0, len(pending + refresh) - done)}
    notification = dispatch_collection_alerts(config, account, root, list(observations.values()), effective_now())
    if config.get("LARK_ALERTS_ENABLED", False):
        result.update(alert_failed=notification["failed"], alert_pending=notification["pending"])
    return result


def _collect_one_account(config, account, now, kwargs):
    clock = kwargs.get("monotonic") or process_time.monotonic
    run_started = clock()

    def effective_now():
        return now + timedelta(seconds=max(0, clock() - run_started))

    try:
        result = collect_account(config, account, now, **kwargs)
    except Exception as exc:
        # No arbitrary provider error text or credential values persist.
        result = {"processed": 0, "failed": 1, "error_type": type(exc).__name__}
    try:
        directory = day_directory(config, account, now.astimezone(ZoneInfo(config["TIMEZONE"])).date())
        if config.get("LARK_ALERTS_ENABLED", False):
            health_path = directory.parent / ".collection-health.json"
            try:
                health = read_json(health_path) if health_path.exists() else {}
                count = health.get("consecutive_failures", 0)
                if type(count) is not int or count < 0:
                    raise ValueError("invalid health counter")
            except (ValueError, KeyError, TypeError, AttributeError):
                count = 0
            unhealthy = bool(result.get("error_type"))
            count = count + 1 if unhealthy else 0
            finished = effective_now()
            atomic_json(health_path, {"consecutive_failures": count, "at": iso(finished)})
            notification = dispatch_collection_alerts(config, account, directory.parent,
                [{"key": "account-health", "failed": unhealthy, "consecutive_failures": count,
                  "attempts": count, "error_types": [result["error_type"]] if unhealthy else []}], finished)
            result.update(alert_failed=result.get("alert_failed", 0) + notification["failed"],
                          alert_pending=notification["pending"])
        atomic_json(directory / "collection-status.json", {"at": iso(effective_now()), **result})
    except Exception as exc:
        result.update(failed=max(1, result["failed"]), storage_error_type=type(exc).__name__)
    print(f"账号 {account['NAME']} ({account['ACCOUNT_ID']})：采集 {result['processed']} 段，失败 {result['failed']}。")
    if result.get("error_type") or result.get("storage_error_type"):
        print(f"账号 {account['ACCOUNT_ID']}：{result.get('error_type') or result.get('storage_error_type')}。", flush=True)
    return {"account_id": account["ACCOUNT_ID"], **result}


def collect_accounts(config, now, **kwargs):
    accounts = [account for account in config["ACCOUNTS"] if account["ENABLED"]]
    if not accounts:
        return []
    workers = min(config.get("ACCOUNT_CONCURRENCY", 7), len(accounts))
    # One worker owns each account's session, checkpoints and alert state. There
    # is no concurrent paging within an account and no shared boto3 Session.
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rds-account") as pool:
        futures = [pool.submit(_collect_one_account, config, account, now, kwargs) for account in accounts]
        return [future.result() for future in futures]


def build_report(config, account, day, now):
    zone = ZoneInfo(config["TIMEZONE"])
    custom = configured_window(config)
    start, day_end = day_window(day, zone)
    if custom:
        start, day_end = report_window(config, day)
        if day_end + timedelta(minutes=config["LOG_DELAY_MINUTES"]) > now:
            raise ValueError("配置的报告窗口尚未结束或仍处于日志缓冲期")
    if day > now.astimezone(zone).date():
        raise ValueError("不能生成未来日期的报告")
    end = day_end
    if not custom and day == now.astimezone(zone).date():
        elapsed = max(0, (now - start).total_seconds() - config["LOG_DELAY_MINUTES"] * 60)
        completed = int(elapsed // (config["COLLECTION_INTERVAL_MINUTES"] * 60))
        end = min(day_end, start + timedelta(minutes=completed * config["COLLECTION_INTERVAL_MINUTES"]))
        if end <= start:
            raise ValueError("今日尚无已结束且经过日志缓冲的采集分段")
    errors = []
    expected = present = 0

    def summaries():
        nonlocal expected, present
        for left, right in report_segments(config, start, end):
            expected += 1
            path = bucket_path(config, account, left)
            try:
                state = load_bucket(path, config, account, left, right)
                active = state.get("active")
                if not active:
                    raise ValueError("missing active snapshot")
                present += 1
                if not active.get("complete") or state.get("last_errors") or state.get("in_progress"):
                    errors.append({"scope": iso(left), "error_type": "IncompleteCollection"})
                # Merge each segment before reading the next. Peak report input
                # memory then depends on one bucket instead of all 48/96 files.
                yield active["summary"]
            except (OSError, ValueError, KeyError, TypeError):
                errors.append({"scope": iso(left), "error_type": "MissingOrInvalidBucket"})

    merged = merge_summaries(summaries(), start, end, dimension="ip")
    return {**merged, **({"artifact_tag": window_tag(config), "report_kind": "configured_window"} if custom else {}),
            "account_id": account["ACCOUNT_ID"], "account_name": account["NAME"],
            "date": day.isoformat(), "timezone": config["TIMEZONE"], "generated_at": iso(now),
            "complete": bool(merged["complete"] and not errors), "errors": errors + merged["errors"],
            "segments": {"expected": expected, "present": present},
            "scope": scope_for(config, account)}


def report_accounts(config, day, now):
    reports = [build_report(config, account, day, now) for account in config["ACCOUNTS"] if account["ENABLED"]]
    return reports, _render_reports(config, reports)


def _render_reports(config, reports):
    from rds_pdf import render_account_pdf

    attachments = []
    accounts = {item["ACCOUNT_ID"]: item for item in config["ACCOUNTS"]}
    for report in reports:
        account = accounts[report["account_id"]]
        directory = day_directory(config, account, date.fromisoformat(report["date"]))
        tag = report.get("artifact_tag")
        if tag:
            directory = manual_directory(config, account, date.fromisoformat(report["date"]), tag)
        suffix = "-" + tag if tag else ""
        pdf = directory / f"{account['NAME']}-{account['ACCOUNT_ID']}-{report['date']}{suffix}-RDS-IP审计.pdf"
        render_account_pdf(report, pdf, font_path=config.get("PDF_FONT_PATH") or None)
        atomic_json(directory / "ip-report.json", report)
        attachments.append(pdf)
    return attachments


def manual_directory(config, account, day, tag):
    import re

    if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", tag):
        raise ValueError("手动报告标识无效")
    return safe_directory(day_directory(config, account, day) / "manual" / tag)


def _delivery_path(config, day):
    # A single combined-mail receipt belongs to one enabled account/day, so it
    # expires with that day's PDFs rather than growing a global delivery ledger.
    account = min((account for account in config["ACCOUNTS"] if account["ENABLED"]), key=lambda item: item["ACCOUNT_ID"])
    if configured_window(config):
        return manual_directory(config, account, day, window_tag(config)) / "combined-mail.json"
    return day_directory(config, account, day) / "combined-mail.json"


def deliver(config, day, now, *, force=False, sender=None, reports=None, receipt_path=None, label=None, automatic=False):
    from rds_mail import MailDeliveryError, send_reports
    from rds_mail_summary import message_body, message_body_html

    receipt_path = Path(receipt_path) if receipt_path is not None else _delivery_path(config, day)
    # Automatic subjects name the sending day; report paths and receipts retain
    # the data day. Explicit historical/range reports keep their own labels.
    label = label or (now.astimezone(ZoneInfo(config["TIMEZONE"])).date().isoformat()
                      if automatic else day.isoformat())
    previous = read_json(receipt_path) if receipt_path.exists() else {}
    if not force and previous.get("status") in {"sending", "uncertain"}:
        return previous
    if not force and previous.get("next_retry", 0) > now.timestamp():
        return previous
    if reports is None:
        reports = [build_report(config, account, day, now) for account in config["ACCOUNTS"] if account["ENABLED"]]
    complete = all(report["complete"] for report in reports)
    # Account order, generation time and credential rotation do not create a new
    # delivery; changed counts/coverage/accounts/recipients do create a revision.
    content = {"reports": sorted(({key: value for key, value in report.items() if key != "generated_at"}
                                  for report in reports), key=lambda item: item["account_id"]),
               "mail": {key: config[key] for key in ("MAIL_SUBJECT", "SMTP_HOST", "SMTP_USERNAME", "MAIL_SENDER_NAME")},
               "to": sorted(config["MAIL_RECIPIENTS"]), "cc": sorted(config["MAIL_CC"])}
    # Display tags are public metadata, never credentials. Preserve old receipt
    # fingerprints when no tag was configured, so upgrading the body alone does
    # not create another manual delivery of an otherwise identical report.
    tags = {account["ACCOUNT_ID"]: account["TAG"] for account in config["ACCOUNTS"]
            if account.get("TAG") and account["ACCOUNT_ID"] in {report["account_id"] for report in reports}}
    if tags:
        content["account_tags"] = tags
    fingerprint = hashlib.sha256(json.dumps(content, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    context = {"scopes": sorted((report["scope"] for report in reports), key=lambda item: item["account_id"]),
               "mail": content["mail"], "to": content["to"], "cc": content["cc"]}
    delivery_key = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
    if not force and previous.get("status") == "accepted" and previous.get("fingerprint") == fingerprint:
        return previous
    if (not force and previous.get("status") == "accepted" and previous.get("complete") is False
            and not complete and previous.get("delivery_key") == delivery_key):
        # Keep local PDFs current during backfill, then mail one complete revision.
        if previous.get("local_fingerprint") != fingerprint:
            _render_reports(config, reports)
            previous["local_fingerprint"] = fingerprint
            atomic_json(receipt_path, previous)
        return previous
    attachments = _render_reports(config, reports)
    body = message_body(config, reports)
    html_body = message_body_html(config, reports)
    status = {"date": day.isoformat(), "label": label, "at": iso(now), "status": "sending", "complete": complete,
              "account_ids": sorted(report["account_id"] for report in reports), "fingerprint": fingerprint,
              "delivery_key": delivery_key,
              "attempts": int(previous.get("attempts", 0)) + 1}
    atomic_json(receipt_path, status)  # Crash after SMTP acceptance must not trigger blind duplicates.
    try:
        result = (sender or send_reports)(config, attachments, body,
                                         subject=config["MAIL_SUBJECT"] + " " + label
                                         + (" [修订]" if previous.get("status") == "accepted" and not automatic else "")
                                         + ("" if complete else " [数据不完整]"), html_body=html_body)
        status.update(status="accepted", smtp_accepted=True, message_id=result.get("message_id"))
    except MailDeliveryError as exc:
        status.update(status="uncertain" if exc.delivery_uncertain else "failed",
                      error_type=type(exc).__name__, next_retry=int(now.timestamp()) + 900)
    except Exception as exc:
        status.update(status="uncertain", error_type=type(exc).__name__)
    atomic_json(receipt_path, status)
    print(f"合并邮件 {label}：{status['status']}，PDF {len(attachments)} 份。")
    return status


def daily_receipts(config, day):
    """Find previous daily submissions across our account trees, excluding manual runs."""
    receipts = []
    root = Path(config["OUTPUT_DIRECTORY"])
    for directory in root.iterdir():
        if not directory.is_dir() or _is_link(directory):
            continue
        marker = directory / ".rds-audit-account"
        if not marker.is_file() or _is_link(marker):
            continue
        owner = read_json(marker)
        if not isinstance(owner, dict) or directory.name != str(owner.get("account_name", "")) + "-" + str(owner.get("account_id", "")):
            continue
        # Recognise legacy evidence across the change from data-day dates to
        # cutoff end dates, without including yesterday-to-now manual reports.
        days = (day, day - timedelta(days=1)) if configured_window(config) else (day, day + timedelta(days=1))
        for candidate in days:
            day_path = directory / candidate.isoformat()
            if not day_path.is_dir() or _is_link(day_path):
                continue
            paths = [day_path / "combined-mail.json"] if candidate == day or configured_window(config) else []
            manual = day_path / "manual"
            if manual.is_dir() and not _is_link(manual):
                for window in manual.glob("window-*"):
                    if _is_link(window):
                        raise ValueError("日报投递目录不可为链接")
                    if window.is_dir():
                        paths.append(window / "combined-mail.json")
            for path in paths:
                if path.exists():
                    if _is_link(path):
                        raise ValueError("日报投递状态不可为链接")
                    value = read_json(path)
                    if not isinstance(value, dict):
                        raise ValueError("日报投递状态格式异常")
                    receipts.append(value)
    return receipts


def deliver_automatic(config, day, now):
    from rds_daily_mail import automatic_daily_mail

    result = automatic_daily_mail(config, day, now,
        build_reports=lambda: [build_report(config, account, day, now)
                               for account in config["ACCOUNTS"] if account["ENABLED"]],
        render_reports=lambda reports: _render_reports(config, reports),
        deliver_callback=lambda reports: deliver(config, day, now, reports=reports, automatic=True),
        receipts=lambda: daily_receipts(config, day),
        state_path=Path(config["OUTPUT_DIRECTORY"]) / ".daily-mail-budget.json")
    if result["status"] in {"suppressed", "disabled"}:
        print("自动日报本轮未发邮件：" + ("已达到每日一封上限；补采只更新本地PDF。" if result["status"] == "suppressed"
                                             else "自动邮件已关闭；仅更新本地PDF。"))
    elif result["status"] in {"uncertain", "sending", "failed"}:
        print(f"自动邮件状态：{result['status']}（{result.get('reason', 'delivery_status')}）；"
              "按投递状态保留限额，不确定投递不会自动重发。", flush=True)
    return result


def prune(config, today):
    root = safe_directory(config["OUTPUT_DIRECTORY"])
    deleted = []
    # Also expire data of disabled/removed accounts, but only our marked trees.
    for path in root.iterdir():
        if not path.is_dir() or _is_link(path):
            continue
        marker = path / ".rds-audit-account"
        if marker.is_file() and not _is_link(marker):
            try:
                value = read_json(marker)
                if (not isinstance(value, dict) or not isinstance(value.get("account_name"), str)
                        or not isinstance(value.get("account_id"), str)):
                    continue
            except (OSError, ValueError, TypeError):
                continue
            if path.name == value.get("account_name", "") + "-" + value.get("account_id", ""):
                deleted.extend(path.name + "/" + day for day in prune_account_days(path, today, config["RETENTION_DAYS"]))
    return deleted


def scheduled_day(config, now):
    local = now.astimezone(ZoneInfo(config["TIMEZONE"]))
    hour, minute = map(int, config["DAILY_MAIL_TIME"].split(":"))
    if (local.hour, local.minute) < (hour, minute):
        return None
    if configured_window(config):
        day = latest_report_day(config, now)
        return day if day == local.date() else None
    return local.date() - timedelta(days=1)


def prune_when_idle(config, today, other_lock):
    # Collection and PDF/mail may run together. Retention requires both mode
    # locks so it cannot remove a directory being read or written by either.
    with _exclusive(other_lock) as idle:
        if idle:
            for item in prune(config, today):
                print("已清理过期日期目录：" + item)


@contextmanager
def task_lock(path, wait_seconds=0):
    deadline = process_time.monotonic() + wait_seconds
    announced = False
    while True:
        with _exclusive(path) as acquired:
            if acquired:
                yield True
                return
        remaining = deadline - process_time.monotonic()
        if remaining <= 0:
            yield False
            return
        if not announced:
            print("等待正在运行的任务完成，再执行本次报告。", flush=True)
            announced = True
        process_time.sleep(min(2, remaining))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=PROJECT / "rds-audit-config.json")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-config", action="store_true")
    mode.add_argument("--verify-accounts", action="store_true")
    mode.add_argument("--collect", action="store_true")
    mode.add_argument("--scheduled", action="store_true")
    mode.add_argument("--report", action="store_true")
    mode.add_argument("--since-yesterday", action="store_true", help="直接采集昨日00:00到本次开始时刻，生成跨日PDF")
    parser.add_argument("--date", type=date.fromisoformat, help="报告日期；配置 REPORT_START/END_TIME 时为窗口结束日")
    parser.add_argument("--send-mail", action="store_true")
    parser.add_argument("--force-resend", action="store_true", help="仅人工核实投递后显式重发")
    args = parser.parse_args(argv)
    try:
        if args.date and not args.report:
            raise ValueError("--date 仅可用于 --report")
        if (args.send_mail or args.force_resend) and not (args.report or args.since_yesterday):
            raise ValueError("--send-mail/--force-resend 仅可用于 --report 或 --since-yesterday")
        if args.force_resend and not args.send_mail:
            raise ValueError("--force-resend 需要 --send-mail")
        config = load_config(args.config, require_mail=False)
        if args.send_mail or ((args.check_config or args.scheduled) and config.get("AUTO_MAIL_MAX_PER_DAY", 1) > 0):
            config = load_config(args.config, require_mail=True)
        if args.check_config:
            if config.get("LARK_ALERTS_ENABLED") and not config.get("LARK_WEBHOOK_URL"):
                raise ValueError("启用异常群通知时必须填写 LARK_WEBHOOK_URL")
            print("配置结构检查通过；" + ("自动邮件已关闭。" if not config.get("AUTO_MAIL_MAX_PER_DAY", 1)
                                                else "SMTP字段检查通过。") + "尚未连接 AWS 或邮件服务器。")
            return 0
        if args.verify_accounts:
            failures = 0
            for account in config["ACCOUNTS"]:
                if account["ENABLED"]:
                    try:
                        verify_account(create_session(account), account)
                        print(f"账号 {account['ACCOUNT_ID']}：身份及日志读取预检通过。")
                    except Exception as exc:
                        failures += 1
                        print(f"账号 {account['ACCOUNT_ID']}：预检失败（{type(exc).__name__}），检查身份、权限、区域和 audit 日志。", file=sys.stderr)
            return 2 if failures else 0
        root = safe_directory(config["OUTPUT_DIRECTORY"])
        mode = "collect" if args.collect or args.since_yesterday else "delivery"
        other = "delivery" if args.collect or args.since_yesterday else "collect"
        with task_lock(root / (".multi-account." + mode + ".lock"), wait_seconds=600 if args.since_yesterday else 0) as acquired:
            if not acquired:
                print("已有同类多账号任务运行，等待下一轮。")
                return 1 if args.since_yesterday else 0
            now = datetime.now(UTC)
            today = now.astimezone(ZoneInfo(config["TIMEZONE"])).date()
            if args.date and (args.date > today or args.date < today - timedelta(days=config["RETENTION_DAYS"] - 1)):
                raise ValueError("报告日期必须位于当前本地保留窗口内")
            # Prepare shared account/day ownership markers in a short critical
            # section; no network request or PDF rendering holds this lock.
            with _exclusive(root / ".multi-account.layout.lock") as ready:
                if not ready:
                    return 0
                days = {today - timedelta(days=offset) for offset in range(config["RETENTION_DAYS"])}
                for account in config["ACCOUNTS"]:
                    if account["ENABLED"]:
                        for day in days:
                            try:
                                day_directory(config, account, day)
                            except (OSError, ValueError):
                                # Each account worker / report will surface its
                                # own storage error without adopting unknown data.
                                pass
            if not any(account["ENABLED"] for account in config["ACCOUNTS"]):
                prune_when_idle(config, today, root / (".multi-account." + other + ".lock"))
                print("没有启用账号，已跳过采集和邮件。")
                return 0
            result = 0
            if args.collect:
                # Expire old data before long polling too, so a worker killed by
                # its runtime limit cannot indefinitely postpone retention.
                prune_when_idle(config, today, root / (".multi-account." + other + ".lock"))
                results = collect_accounts(config, now)
                result = 2 if any(item["failed"] or item.get("alert_failed") or item.get("alert_pending") for item in results) else 0
            elif args.since_yesterday:
                from rds_window import collect_since_yesterday, window_identity

                start, end, tag = window_identity(config, now)
                print(f"直接采集昨日到当前：{iso(start)} 至 {iso(end)}（UTC），仅统计有效来源IP。", flush=True)
                reports = collect_since_yesterday(config, now, session_factory=create_session,
                    identity_checker=check_identity, collector=collect_bucket,
                    directory_factory=lambda account, artifact_tag: manual_directory(config, account, today, artifact_tag))
                for report in reports:
                    print(f"账号 {report['account_id']}：{'采集步骤完整' if report['complete'] else '采集或解析不完整'}；"
                          f"未解析/未分类 {report['coverage'].get('unparsed_records', 0)} 条；"
                          f"已排除无IP {report['coverage'].get('filtered_no_ip_records', 0)} 条。", flush=True)
                if args.send_mail:
                    account = min((item for item in config["ACCOUNTS"] if item["ENABLED"]), key=lambda item: item["ACCOUNT_ID"])
                    receipt = manual_directory(config, account, today, tag) / "combined-mail.json"
                    with task_lock(root / ".multi-account.delivery.lock", wait_seconds=120) as delivery_ready:
                        if not delivery_ready:
                            _render_reports(config, reports)
                            print("邮件任务仍忙，本次PDF已保存，尚未提交邮件。", file=sys.stderr)
                            return 3
                        status = deliver(config, today, now, reports=reports, receipt_path=receipt,
                                         label="昨日到当前 " + end.astimezone(ZoneInfo(config["TIMEZONE"])).strftime("%Y-%m-%d %H:%M:%S"),
                                         force=args.force_resend)
                        result = (0 if status["complete"] else 2) if status["status"] == "accepted" else 3
                else:
                    attachments = _render_reports(config, reports)
                    print("PDF 已生成：\n" + "\n".join(str(path) for path in attachments))
                    result = 0 if all(report["complete"] for report in reports) else 2
            elif args.scheduled:
                day = scheduled_day(config, now)
                if day is not None:
                    status = deliver_automatic(config, day, now)
                    if status["status"] in {"suppressed", "disabled"}:
                        result = 0
                    else:
                        result = (0 if status["complete"] else 2) if status["status"] == "accepted" else 3
            else:
                day = args.date or latest_report_day(config, now)
                if day < today - timedelta(days=config["RETENTION_DAYS"] - 1):
                    raise ValueError("报告日期已超出本地保留窗口，请先调整配置并另行补采")
                if args.send_mail:
                    status = deliver(config, day, now, force=args.force_resend)
                    result = (0 if status["complete"] else 2) if status["status"] == "accepted" else 3
                else:
                    reports, attachments = report_accounts(config, day, now)
                    print("PDF 已生成：\n" + "\n".join(str(path) for path in attachments))
                    result = 0 if all(report["complete"] for report in reports) else 2
            prune_when_idle(config, today, root / (".multi-account." + other + ".lock"))
            return result
    except Exception as exc:
        # Config validation messages contain field names only; no provider bodies.
        detail = str(exc) if isinstance(exc, (ValueError, FileNotFoundError)) else type(exc).__name__
        print("RDS 多账号任务失败：" + detail, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
