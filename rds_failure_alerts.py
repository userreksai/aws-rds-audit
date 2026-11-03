"""Bounded, durable per-account collection/retry alerts; no SQL or credentials.

The caller owns that account's collection lock. Each incident retains only its
current event, allowing failed delivery to retry without an ever-growing outbox.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from zoneinfo import ZoneInfo

from lark_notify import send_lark_alert, validate_webhook_url

UTC = timezone.utc


def _iso(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _date_time(value):
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.astimezone(UTC) if stamp.tzinfo is not None else None
    except (TypeError, ValueError):
        return None


def _integer(value):
    return value if type(value) is int and value >= 0 else 0


def _save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".lark-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _queue(item, kind, account_id):
    if item.get("pending") == kind:
        return
    item["pending"] = kind
    item["next_retry"] = 0
    seed = f"{account_id}:{item['id']}:{item.get('generation', 0)}:{kind}"
    item["event_id"] = hashlib.sha256(seed.encode()).hexdigest()[:24]


def sync_collection_alerts(config, account, state_path: Path, observations: list[dict],
                           now: datetime, sender=None) -> dict:
    """Send at most one failure and one recovery digest for this account/round.

    Missing observations do not mean recovery. Only a healthy observation can
    close an incident. Pending counts exclude already-delivered active incidents.
    """
    if not config.get("LARK_ALERTS_ENABLED", False):
        return {"sent": 0, "pending": 0, "failed": 0}
    if now.tzinfo is None:
        raise ValueError("Alert time must include a timezone")
    path = Path(state_path)
    try:
        previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if not isinstance(previous, dict) or not isinstance(previous.get("incidents", {}), dict):
            raise ValueError("invalid alert state")
        if previous.get("account_id") not in (None, account["ACCOUNT_ID"]):
            raise ValueError("alert state belongs to another account")
    except (OSError, ValueError, TypeError):
        previous = {}
    incidents = previous.get("incidents", {})
    zone = ZoneInfo(config.get("TIMEZONE", "Asia/Shanghai"))
    cutoff = now.astimezone(zone).date() - timedelta(days=config.get("RETENTION_DAYS", 7) - 1)
    # Raw observation keys never enter the state or the webhook message.
    incidents = {key: item for key, item in incidents.items()
                 if isinstance(item, dict) and (item.get("account_health") is True or
                    ((_date_time(item.get("bucket_start")) or _date_time(item.get("first_seen"))) is not None
                     and (_date_time(item.get("bucket_start")) or _date_time(item.get("first_seen"))).astimezone(zone).date() >= cutoff))}
    threshold = config.get("LARK_ALERT_AFTER_FAILURES", 2)
    repeat_seconds = config.get("LARK_ALERT_REPEAT_MINUTES", 60) * 60
    retry_seconds = config.get("LARK_NOTIFICATION_RETRY_MINUTES", 5) * 60
    account_id = account["ACCOUNT_ID"]
    for observed in observations:
        if not isinstance(observed, dict) or not isinstance(observed.get("key"), str):
            continue
        occurred = _date_time(observed.get("bucket_start"))
        if occurred and occurred.astimezone(zone).date() < cutoff:
            continue
        key = hashlib.sha256(observed["key"].encode()).hexdigest()
        failed = observed.get("failed") is True
        consecutive = _integer(observed.get("consecutive_failures"))
        if key not in incidents and not failed:
            continue
        item = incidents.setdefault(key, {"id": key, "generation": 0, "open": False,
                                          "failure_notified": False, "first_seen": _iso(now)})
        item["account_health"] = observed["key"] == "account-health"
        item["attempts"] = _integer(observed.get("attempts"))
        item["consecutive_failures"] = consecutive
        item["failed"] = failed
        for name in ("bucket_start", "bucket_end"):
            stamp = _date_time(observed.get(name))
            if stamp:
                item[name] = _iso(stamp)
        item["error_types"] = sorted({value for value in observed.get("error_types", [])
                                       if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", value)})[:8]
        if failed:
            if item.get("pending") == "recovery":
                item["pending"] = None
            if consecutive >= threshold and not item.get("open"):
                item.update(open=True, failure_notified=False, generation=_integer(item.get("generation")) + 1,
                            last_failure_sent=0)
                _queue(item, "failure", account_id)
        elif item.get("open"):
            if item.get("failure_notified"):
                _queue(item, "recovery", account_id)
            else:
                # No failure message reached the group: cancel it rather than
                # sending a stale failure followed by an unexplained recovery.
                item.update(open=False, pending=None, next_retry=0)
    for item in incidents.values():
        if (item.get("open") and item.get("failed") and not item.get("pending")
                and now.timestamp() - _integer(item.get("last_failure_sent")) >= repeat_seconds):
            _queue(item, "failure", account_id)
    state = {"schema_version": 1, "account_id": account_id, "incidents": incidents}
    _save(path, state)
    statistics = {"sent": 0, "pending": 0, "failed": 0}
    for kind in ("failure", "recovery"):
        due = [item for item in incidents.values() if item.get("pending") == kind
               and _integer(item.get("next_retry")) <= now.timestamp()]
        if not due:
            continue
        event_ids = sorted(item["event_id"] for item in due)
        lines = [f"账号标签：{account.get('NAME', '')}",
                 f"{'补采仍失败' if kind == 'failure' else '采集已恢复'}：{len(due)} 项。"]
        for item in due[:12]:
            label = "账号身份/连接检查" if item.get("account_health") else "分段 " + item.get("bucket_start", "未知窗口")
            lines.append(label + f"；连续失败 {item.get('consecutive_failures', 0)}；累计尝试 {item.get('attempts', 0)}；"
                         + ",".join(item.get("error_types", [])))
        if len(due) > 12:
            lines.append(f"另有 {len(due) - 12} 项，详见本地状态。")
        alert = {"kind": "collection_retry_failed" if kind == "failure" else "collection_recovery",
                 "account_id": account_id, "regions": account.get("REGIONS", ""),
                 "event_id": hashlib.sha256("|".join(event_ids).encode()).hexdigest()[:24],
                 "missing_count": len(due), "attempts": max(item.get("attempts", 0) for item in due),
                 "occurred_at": _iso(now), "message": "\n".join(lines)}
        try:
            webhook = validate_webhook_url(config.get("LARK_WEBHOOK_URL", ""))
            transport_config = {"webhook_url": webhook, "signing_secret": config.get("LARK_SIGNING_SECRET", "")}
            # A long collection round must sign with the current wall clock, not
            # the earlier timestamp used to plan that round's data windows.
            (sender or send_lark_alert)(alert, transport_config, now=now if sender is not None else None)
        except Exception as exc:
            statistics["failed"] += 1
            for item in due:
                item.update(next_retry=int(now.timestamp()) + retry_seconds, delivery_error_type=type(exc).__name__)
        else:
            statistics["sent"] += 1
            for item in due:
                item.update(pending=None, next_retry=0, delivery_error_type=None)
                if kind == "failure":
                    item.update(failure_notified=True, last_failure_sent=int(now.timestamp()))
                else:
                    item.update(open=False, failure_notified=False)
        _save(path, state)
    statistics["pending"] = sum(bool(item.get("pending")) for item in incidents.values())
    return statistics
