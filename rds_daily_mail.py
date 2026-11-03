"""A persistent natural-day budget for automatic combined report email.

The caller owns the delivery lock. This module never sends mail itself and never
stores report contents, credentials, recipient addresses or provider responses.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from zoneinfo import ZoneInfo

UTC = timezone.utc
_STATUSES = {"idle", "disabled", "reserved", "sending", "accepted", "failed", "uncertain"}
_UNCERTAIN = {"reserved", "sending", "uncertain"}


class InvalidDailyMailState(ValueError):
    pass


def _iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _date_text(value):
    if not isinstance(value, str) or date.fromisoformat(value).isoformat() != value:
        raise InvalidDailyMailState("日报邮件状态日期无效")
    return value


def _integer(value):
    if type(value) is not int or value < 0:
        raise InvalidDailyMailState("日报邮件状态计数无效")
    return value


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidDailyMailState("日报邮件状态包含重复字段")
        result[key] = value
    return result


def _load(path, today):
    try:
        if path.is_symlink():
            raise InvalidDailyMailState("日报邮件状态不能为符号链接")
        raw = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_pairs)
        if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
            raise InvalidDailyMailState("日报邮件状态版本无效")
        entries = raw["entries"]
        if not isinstance(entries, dict):
            raise InvalidDailyMailState("日报邮件状态结构无效")
        result = {}
        for key, entry in entries.items():
            _date_text(key)
            if date.fromisoformat(key) > today or not isinstance(entry, dict):
                raise InvalidDailyMailState("日报邮件状态日期或结构无效")
            report_day = _date_text(entry["report_day"])
            used = _integer(entry["used"])
            status = entry["status"]
            if used not in (0, 1) or status not in _STATUSES:
                raise InvalidDailyMailState("日报邮件状态额度或状态无效")
            if status in ({"accepted"} | _UNCERTAIN) and used != 1:
                raise InvalidDailyMailState("日报邮件状态额度与投递状态不一致")
            if status in {"idle", "disabled", "failed"} and used != 0:
                raise InvalidDailyMailState("日报邮件状态额度与投递状态不一致")
            last_attempt = entry["last_attempt"]
            if last_attempt is not None:
                if not isinstance(last_attempt, str):
                    raise InvalidDailyMailState("日报邮件状态时间无效")
                parsed = datetime.fromisoformat(last_attempt.replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise InvalidDailyMailState("日报邮件状态时间必须含时区")
            fingerprint = entry["local_fingerprint"]
            if not isinstance(fingerprint, str) or (fingerprint and not re.fullmatch(r"[0-9a-f]{64}", fingerprint)):
                raise InvalidDailyMailState("日报邮件本地内容指纹无效")
            result[key] = {"report_day": report_day, "used": used, "status": status,
                           "last_attempt": last_attempt, "next_retry": _integer(entry["next_retry"]),
                           "local_fingerprint": fingerprint}
        return {"schema_version": 1, "entries": result}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise InvalidDailyMailState("日报邮件状态损坏或无法读取，请人工核对后修复；不会自动重置额度") from None


def _save(path, state):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".daily-mail-budget-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
        Path(temporary).chmod(0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _fingerprint(reports):
    content = [{key: value for key, value in report.items() if key != "generated_at"} for report in reports]
    content.sort(key=lambda report: str(report.get("account_id", "")))
    return hashlib.sha256(json.dumps(content, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def automatic_daily_mail(config, day, now, *, build_reports, render_reports, deliver_callback, receipts, state_path):
    """Refresh local reports and submit at most one automatic email per local day.

    Explicit delivery failures release the reservation and can retry after their
    deadline. Acceptance, uncertainty or an interrupted worker reserve the day's
    sole allowance independently of report revisions and configuration changes.
    """
    if not isinstance(day, date) or isinstance(day, datetime):
        raise ValueError("报告日期必须为自然日")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("任务时间必须包含时区")
    limit = config.get("AUTO_MAIL_MAX_PER_DAY", 1)
    if type(limit) is not int or limit not in (0, 1):
        raise ValueError("AUTO_MAIL_MAX_PER_DAY 仅支持0或1")
    retention = config.get("RETENTION_DAYS", 7)
    if type(retention) is not int or retention < 1:
        raise ValueError("RETENTION_DAYS 必须为正整数")
    today = now.astimezone(ZoneInfo(config["TIMEZONE"])).date()
    key, report_day = today.isoformat(), day.isoformat()
    reports = build_reports()
    if not isinstance(reports, list) or any(not isinstance(report, dict) or not isinstance(report.get("complete"), bool) for report in reports):
        raise ValueError("日报构建结果无效")
    complete = all(report["complete"] for report in reports)
    if not reports:
        return {"status": "disabled", "complete": complete, "reason": "no_reports", "used": 0}
    fingerprint = _fingerprint(reports)
    path = Path(state_path)
    existed = path.exists() or path.is_symlink()
    try:
        state = _load(path, today) if existed else {"schema_version": 1, "entries": {}}
    except InvalidDailyMailState:
        # Keep evidence intact. Unknown previous usage must not become an empty
        # budget after a parse error, directory failure or partial file write.
        render_reports(reports)
        return {"status": "uncertain", "complete": complete, "reason": "invalid_state", "used": 1}
    cutoff = today - timedelta(days=retention - 1)
    state["entries"] = {date_key: entry for date_key, entry in state["entries"].items()
                        if date.fromisoformat(date_key) >= cutoff}
    entry = state["entries"].get(key)
    if entry is None:
        entry = {"report_day": report_day, "used": 0, "status": "idle", "last_attempt": None,
                 "next_retry": 0, "local_fingerprint": ""}
        state["entries"][key] = entry
    if not existed:
        try:
            previous = receipts()
            if not isinstance(previous, list) or any(not isinstance(item, dict) or item.get("status") not in {"accepted", "failed", "sending", "reserved", "uncertain"} for item in previous):
                raise ValueError("历史邮件回执无效")
            statuses = {item["status"] for item in previous}
            if statuses & _UNCERTAIN:
                entry.update(used=1, status="uncertain", last_attempt=_iso(now))
            elif "accepted" in statuses:
                entry.update(used=1, status="accepted", last_attempt=_iso(now))
            elif "failed" in statuses:
                retry = max((_integer(item.get("next_retry", 0)) for item in previous), default=0)
                entry.update(status="failed", next_retry=retry)
        except Exception:
            entry.update(used=1, status="uncertain", last_attempt=_iso(now))
    if entry["local_fingerprint"] != fingerprint:
        render_reports(reports)
        entry["local_fingerprint"] = fingerprint
    _save(path, state)

    def result(status, reason=None):
        value = {"status": status, "complete": complete, "used": entry["used"],
                 "report_day": report_day, "sending_day": key, "next_retry": entry["next_retry"]}
        if reason:
            value["reason"] = reason
        return value

    if not limit:
        return result("disabled", "automatic_mail_disabled")
    unresolved = any(item["report_day"] == report_day and item["status"] in _UNCERTAIN for item in state["entries"].values())
    if unresolved:
        return result("sending" if entry["status"] in {"reserved", "sending"} else "uncertain", "delivery_unresolved")
    if entry["used"]:
        return result("suppressed", "daily_limit")
    if entry["next_retry"] > now.timestamp():
        return result("failed", "retry_backoff")
    entry.update(report_day=report_day, used=1, status="sending", last_attempt=_iso(now), next_retry=0)
    _save(path, state)  # Commit reservation before any callback can contact SMTP.
    try:
        delivery = deliver_callback(reports)
        if not isinstance(delivery, dict) or delivery.get("status") not in {"accepted", "failed", "sending", "uncertain"}:
            raise ValueError("邮件投递结果无效")
        status = delivery["status"]
        retry = _integer(delivery.get("next_retry", 0)) if status == "failed" else 0
        entry.update(status=status, used=0 if status == "failed" else 1, next_retry=retry)
    except Exception:
        entry.update(status="uncertain", used=1, next_retry=0)
    _save(path, state)
    return result(entry["status"])
