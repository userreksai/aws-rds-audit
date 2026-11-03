"""Fresh, whole-window source-IP collection from local yesterday midnight.

The caller supplies AWS, identity and marked-directory boundaries. Only validated
IP counts leave each worker; the caller renders and persists the final reports.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
import re
import tempfile
from zoneinfo import ZoneInfo

from rds_summary import merge_summaries, validate_summary

UTC = timezone.utc
FRESH_LOG_NOTE = "统计截至本次开始时刻已发布的日志，临近日志可能延迟到达"


def _iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def window_identity(config, now):
    """Freeze a UTC millisecond end and use the configured local calendar date."""
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("窗口截止时间必须包含时区")
    zone = ZoneInfo(config["TIMEZONE"])
    end = now.astimezone(UTC)
    end = end.replace(microsecond=(end.microsecond // 1000) * 1000)
    yesterday = end.astimezone(zone).date() - timedelta(days=1)
    start = datetime.combine(yesterday, time(), zone).astimezone(UTC)
    tag = "since-yesterday-" + end.strftime("%Y%m%dT%H%M%S") + f"{end.microsecond // 1000:03d}Z"
    return start, end, tag


def _scope(config, account):
    return {"version": 2, "dimension": "ip", "source_filter": "ip_only", "account_id": account["ACCOUNT_ID"],
            "regions": account["REGIONS"], "timezone": config["TIMEZONE"],
            "interval_minutes": config["COLLECTION_INTERVAL_MINUTES"]}


def _collection_errors(errors):
    if not isinstance(errors, list) or any(not isinstance(error, dict) for error in errors):
        raise ValueError("采集错误必须为对象数组")
    result = []
    for error in errors:
        kind = error.get("error_type", "CollectionError")
        if not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,99}", kind):
            kind = "CollectionError"
        # Provider scope/message fields can contain arbitrary response text.
        result.append({"scope": "collection", "error_type": kind})
    return result


def collect_since_yesterday(config, now, *, session_factory, identity_checker, collector, directory_factory):
    """Query each enabled account once for the same complete, unsegmented range.

    directory_factory(account, tag) must return an existing marked manual-output
    directory. No segment limits or log-delay subtraction apply to this explicit
    fresh query. A failed account produces an explicit incomplete report while
    other accounts continue; persistent output failures remain the renderer's
    responsibility and must not be treated as successfully delivered reports.
    """
    start, end, tag = window_identity(config, now)
    accounts = [account for account in config["ACCOUNTS"] if account["ENABLED"]]
    if not accounts:
        return []
    concurrency = config.get("ACCOUNT_CONCURRENCY", 7)
    if type(concurrency) is not int or concurrency < 1:
        raise ValueError("ACCOUNT_CONCURRENCY 必须为正整数")
    local_day = end.astimezone(ZoneInfo(config["TIMEZONE"])).date().isoformat()

    def worker(account):
        errors, audit_groups = [], 0
        summary = merge_summaries([], start, end, dimension="ip")
        complete = False
        try:
            session = session_factory(account)
            identity = identity_checker(session, account)
            if not isinstance(identity, dict) or str(identity.get("Account")) != account["ACCOUNT_ID"]:
                raise ValueError("AWS身份与配置账号不匹配")
            directory = Path(directory_factory(account, tag))
            if not directory.is_dir():
                raise ValueError("范围报告目录尚未准备完成")
            with tempfile.TemporaryDirectory(prefix=".window-attempt-", dir=directory) as temporary:
                snapshot = collector(config, account, session, identity, start, end, Path(temporary))
                if not isinstance(snapshot, dict) or not isinstance(snapshot.get("complete"), bool):
                    raise ValueError("采集快照或完整度无效")
                validated = validate_summary(snapshot["summary"], start, end, dimension="ip")
                groups = snapshot.get("audit_groups")
                if type(groups) is not int or groups < 0:
                    raise ValueError("采集审计日志组计数无效")
                collection_errors = _collection_errors(snapshot.get("errors", []))
                summary, audit_groups = validated, groups
                errors = collection_errors + summary["errors"]
                if not audit_groups:
                    errors.append({"scope": "sql_coverage", "error_type": "NoAuditLogGroups"})
                if not snapshot["complete"] and not errors:
                    errors.append({"scope": "collection", "error_type": "IncompleteCollection"})
                complete = bool(snapshot["complete"] and summary["complete"] and audit_groups and not errors)
        except Exception as exc:
            # Never persist exception messages, raw provider responses, keys,
            # SQL text, or any fields from an unvalidated collector snapshot.
            summary = merge_summaries([], start, end, dimension="ip")
            errors = [{"scope": "collection", "error_type": type(exc).__name__}]
            audit_groups, complete = 0, False
        return {"schema_version": summary["schema_version"], "dimension": "ip", "summary_only": True,
                "account_id": account["ACCOUNT_ID"], "account_name": account["NAME"],
                "date": local_day, "timezone": config["TIMEZONE"], "generated_at": _iso(end),
                "window": {"start_inclusive": _iso(start), "end_exclusive": _iso(end)},
                "actors": summary["actors"], "coverage": summary["coverage"],
                "complete": complete, "errors": errors, "audit_groups": audit_groups,
                "scope": _scope(config, account), "report_kind": "since_yesterday",
                "artifact_tag": tag, "fresh_log_note": FRESH_LOG_NOTE}

    with ThreadPoolExecutor(max_workers=min(concurrency, len(accounts)), thread_name_prefix="rds-window") as pool:
        futures = [pool.submit(worker, account) for account in accounts]
        return [future.result() for future in futures]
