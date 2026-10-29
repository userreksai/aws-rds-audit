"""Interval collection and local-cache daily jobs; no bulk daily AWS refetch."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, nullcontext
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
from uuid import uuid4
from zoneinfo import ZoneInfo

from rds_cache import CacheStore, _exclusive

UTC = timezone.utc
BEIJING = ZoneInfo("Asia/Shanghai")


def cache_scope(args):
    regions = args.regions if args.regions == "all" else ",".join(sorted(set(args.regions.split(","))))
    return {"profile": args.profile or "default", "regions": regions,
            "interval_minutes": args.interval_minutes, "filter_version": "changes-v1"}


def _safe_message(value):
    value = re.sub(r"https?://\S+", "[URL]", str(value))
    return re.sub(r"(?i)(password|secretaccesskey|sessiontoken|aws_access_key_id|aws_secret_access_key|authorization|webhook)\s*[=:]\s*\S+", r"\1=[REDACTED]", value)[:1200]


class OpsOutbox:
    """Durable alerts for identity, report completeness and delivery failures."""
    def __init__(self, root, scope):
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        self.scope = scope
        self.scope_id = hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()[:24]
        self.lock = root / ".ops-alerts.lock"
        self.db = sqlite3.connect(root / "ops-alerts.sqlite3", timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS incidents(key TEXT PRIMARY KEY, generation INTEGER, is_open INTEGER, last_notice INTEGER);
            CREATE TABLE IF NOT EXISTS notices(id TEXT PRIMARY KEY, scope TEXT, payload TEXT, status TEXT, attempts INTEGER DEFAULT 0, next_attempt INTEGER DEFAULT 0, last_error TEXT);
            CREATE TABLE IF NOT EXISTS daily_requests(scope TEXT, day TEXT, requested_at INTEGER, PRIMARY KEY(scope,day));
            CREATE TABLE IF NOT EXISTS quality_state(scope TEXT, account TEXT, notified_fingerprint TEXT NOT NULL DEFAULT '', PRIMARY KEY(scope,account));
        """)
        self.cancel_legacy_quality_recoveries()

    def close(self):
        self.db.close()

    def is_open(self, key):
        row = self.db.execute("SELECT is_open FROM incidents WHERE key=?", (self.scope_id + ":" + key,)).fetchone()
        return bool(row and row["is_open"])

    def request_daily(self, day, now):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO daily_requests VALUES(?,?,?)", (self.scope_id, day, int(now.timestamp())))

    def daily_pending(self, day):
        return self.db.execute("SELECT 1 FROM daily_requests WHERE scope=? AND day=?", (self.scope_id, day)).fetchone() is not None

    def complete_daily(self, day):
        with self.db:
            self.db.execute("DELETE FROM daily_requests WHERE scope=? AND day=?", (self.scope_id, day))

    def failure(self, key, payload, now):
        stamp = int(now.timestamp())
        key = self.scope_id + ":" + key
        with self.db:
            old = self.db.execute("SELECT * FROM incidents WHERE key=?", (key,)).fetchone()
            generation = int(old["generation"]) + 1 if old and not old["is_open"] else int(old["generation"]) if old else 1
            if old and old["is_open"] and stamp - old["last_notice"] < 3600:
                return False
            self.db.execute("INSERT OR REPLACE INTO incidents VALUES(?,?,1,?)", (key, generation, stamp))
            payload = {**payload, "message": _safe_message(payload.get("message", "")), "regions": self.scope["regions"], "occurred_at": now.isoformat()}
            identifier = f"{key}:{generation}:failed:{stamp//3600}"
            payload["event_id"] = identifier
            self.db.execute("INSERT OR IGNORE INTO notices(id,scope,payload,status) VALUES(?,?,?,'pending')", (identifier, self.scope_id, json.dumps(payload, ensure_ascii=False)))
        return True

    def recovery(self, key, payload, now):
        key = self.scope_id + ":" + key
        with self.db:
            old = self.db.execute("SELECT * FROM incidents WHERE key=?", (key,)).fetchone()
            if not old or not old["is_open"]:
                return
            self.db.execute("UPDATE incidents SET is_open=0 WHERE key=?", (key,))
            # A stale failure must not arrive after a recovery as a fresh incident.
            self.db.execute("UPDATE notices SET status='cancelled' WHERE id LIKE ? AND status='pending'", (key + ":" + str(old["generation"]) + ":failed:%",))
            payload = {**payload, "kind": "recovered", "regions": self.scope["regions"]}
            identifier = f"{key}:{old['generation']}:recovered"
            payload["event_id"] = identifier
            self.db.execute("INSERT OR IGNORE INTO notices(id,scope,payload,status) VALUES(?,?,?,'pending')", (identifier, self.scope_id, json.dumps(payload, ensure_ascii=False)))

    def cancel_legacy_quality_recoveries(self):
        """Old recovery notices were based on unrelated successful segments."""
        expression = re.compile(re.escape(self.scope_id + ":quality:") + r"\d+:recovered$")
        with self.db:
            rows = self.db.execute("SELECT id FROM notices WHERE scope=? AND status='pending'", (self.scope_id,)).fetchall()
            self.db.executemany("UPDATE notices SET status='cancelled' WHERE id=?", ((row["id"],) for row in rows if expression.fullmatch(row["id"])))

    def sync_quality(self, store, now):
        """Track committed problem snapshots, across collection rounds/restarts."""
        quality = store.quality_status()
        account = str(store.account_id)
        key = "quality:" + account
        full_key = self.scope_id + ":" + key
        unresolved = quality["problem_segments"] + quality["unknown_segments"]
        state = self.db.execute("SELECT * FROM quality_state WHERE scope=? AND account=?", (self.scope_id, account)).fetchone()
        self.cancel_legacy_quality_recoveries()
        if state is None:
            # Adopt the legacy account's incident without opening another cycle
            # or immediately repeating a notification the operator already saw.
            legacy_key = self.scope_id + ":quality"
            legacy = self.db.execute("SELECT * FROM incidents WHERE key=?", (legacy_key,)).fetchone()
            expression = re.compile(re.escape(legacy_key) + r":\d+:(?:failed:\d+|recovered)$")
            notices = []
            for row in self.db.execute("SELECT * FROM notices WHERE scope=? ORDER BY rowid DESC", (self.scope_id,)):
                if expression.fullmatch(row["id"]):
                    payload = json.loads(row["payload"])
                    if str(payload.get("account_id")) == account:
                        notices.append(row)
            notified = ""
            with self.db:
                if legacy and notices:
                    current_prefix = legacy_key + ":" + str(legacy["generation"]) + ":failed:"
                    already_sent = any(row["status"] == "sent" and row["id"].startswith(current_prefix) for row in notices)
                    opened = bool(unresolved or legacy["is_open"])
                    last_notice = legacy["last_notice"] if already_sent else 0
                    self.db.execute("INSERT OR IGNORE INTO incidents VALUES(?,?,?,?)", (full_key, legacy["generation"], int(opened), last_notice))
                    self.db.execute("UPDATE incidents SET is_open=0 WHERE key=?", (legacy_key,))
                    self.db.executemany("UPDATE notices SET status='cancelled' WHERE id=? AND status='pending'", ((row["id"],) for row in notices))
                    if unresolved and already_sent:
                        notified = quality["fingerprint"]
                self.db.execute("INSERT INTO quality_state VALUES(?,?,?)", (self.scope_id, account, notified))
            state = {"notified_fingerprint": notified}
        if unresolved:
            # A queued recovery must not be delivered after another problem is
            # already known. All quality notices for this account are reconciled
            # before their outbox is flushed.
            expression = re.compile(re.escape(full_key) + r":\d+:recovered$")
            with self.db:
                rows = self.db.execute("SELECT id FROM notices WHERE scope=? AND status='pending'", (self.scope_id,)).fetchall()
                self.db.executemany("UPDATE notices SET status='cancelled' WHERE id=?", ((row["id"],) for row in rows if expression.fullmatch(row["id"])))
            if quality["fingerprint"] != state["notified_fingerprint"] or not self.is_open(key):
                segments = quality["segments"]
                payload = {"kind": "quality_partial", "account_id": account,
                           "bucket_start": min((row["start"] for row in segments), default=None),
                           "bucket_end": max((row["end"] for row in segments), default=None),
                           "message": f"当前累计 {quality['problem_segments']} 个分段含无法识别SQL，另 {quality['unknown_segments']} 个分段质量状态无法确认。问题证据已保留，未识别记录不计入增删改；仅原问题分段通过质量检查后才恢复。请查看质量问题页。"}
                if self.failure(key, payload, now):
                    with self.db:
                        self.db.execute("UPDATE quality_state SET notified_fingerprint=? WHERE scope=? AND account=?", (quality["fingerprint"], self.scope_id, account))
        else:
            self.recovery(key, {"account_id": account, "message": "此前问题分段的当前成功快照均已通过质量检查，未解决质量分段数为0；历史隔离归档仍保留供核查。"}, now)
            with self.db:
                self.db.execute("UPDATE quality_state SET notified_fingerprint=? WHERE scope=? AND account=?", (quality["fingerprint"], self.scope_id, account))
        return quality

    def flush(self, callback, now, *, include_quality=True):
        if callback is not None:
            with _exclusive(self.lock) as locked:
                if locked:
                    rows = self.db.execute("SELECT * FROM notices WHERE scope=? AND status='pending' AND next_attempt<=? AND (? OR id NOT LIKE ?) ORDER BY rowid LIMIT 30", (self.scope_id, int(now.timestamp()), int(include_quality), self.scope_id + ":quality:%")).fetchall()
                    for row in rows:
                        try:
                            result = callback(json.loads(row["payload"]))
                            if result is False or isinstance(result, dict) and (result.get("success") is False or result.get("code", result.get("StatusCode", 0)) not in (0, "0")):
                                raise RuntimeError("Notification was not accepted")
                        except Exception as exc:
                            count = row["attempts"] + 1
                            self.db.execute("UPDATE notices SET attempts=?,next_attempt=?,last_error=? WHERE id=?", (count, int(now.timestamp()) + min(3600, 60 * 2 ** min(count - 1, 6)), type(exc).__name__, row["id"]))
                            print(f"Lark告警投递未确认，已保留待重试（{type(exc).__name__}）。", file=sys.stderr)
                        else:
                            self.db.execute("UPDATE notices SET status='sent',attempts=attempts+1,last_error=NULL WHERE id=?", (row["id"],))
                        self.db.commit()
        return self.db.execute("SELECT count(*) FROM notices WHERE scope=? AND status='pending' AND (? OR id NOT LIKE ?)", (self.scope_id, int(include_quality), self.scope_id + ":quality:%")).fetchone()[0]


def _notifier(config, *, sleep=time.sleep):
    if config is None:
        return None
    from lark_notify import send_lark_alert
    sent = [False]

    def notify(payload):
        if sent[0]:
            sleep(0.7)
        sent[0] = True
        scope = payload.get("scope") or {}
        payload = {**payload, "regions": payload.get("regions") or scope.get("regions"),
                   "bucket_start": payload.get("bucket_start") or payload.get("window_start_utc"),
                   "bucket_end": payload.get("bucket_end") or payload.get("window_end_utc_exclusive")}
        return send_lark_alert(payload, config)
    return notify


def _api(api):
    if api is None:
        import rds_audit
        return rds_audit
    return api


def _load_state(store):
    path = store.directory / "daily-state.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _save_state(store, state):
    target = store.directory / "daily-state.json"
    temporary = target.with_suffix(".tmp-" + uuid4().hex)
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


def run_incremental(args, *, api=None, now=None):
    api, now = _api(api), now or datetime.now(UTC)
    scope = cache_scope(args)
    ops = OpsOutbox(args.cache_dir, scope)
    store = None
    notify = None
    locks = ExitStack()
    try:
        config = api.lark_configuration(args)
        notify = _notifier(config)
        ops.cancel_legacy_quality_recoveries()
        ops.flush(notify, now, include_quality=False)
        session, sdk_config, identity = api.aws_session(args)
        ops.recovery("identity", {"account_id": identity["Account"], "message": "AWS身份和增量采集入口已恢复。"}, now)
        store = CacheStore(args.cache_dir, identity["Account"], scope)
        if not locks.enter_context(_exclusive(store.directory / ".job.lock")):
            print("已有采集或日报任务运行，本次跳过；后续定时器会继续处理。", flush=True)
            return 0

        def collect(start, end, target):
            light = argparse.Namespace(**vars(args))
            light.download_sql_logs, light.download_instance_logs, light.metadata_light = True, False, True
            collector = api.Collector(session, sdk_config, start, end, target, light, identity)
            collector.report.update(period_kind="custom", incremental=True)
            collector.run()
            errors = [item for item in collector.report["checks"] if item["status"] == "error"]
            transport_errors = [item for item in errors if item.get("error_type") != "UnclassifiedSqlRecords"]
            quality = bool(errors) and not transport_errors
            return {"status": 2 if transport_errors else 0, "success": not transport_errors, "quality_partial": quality, "path": str(target), "error": "; ".join(_safe_message(item.get("message", "")) for item in transport_errors)[:1200]}

        stats = store.run_due(now, collect, notify, max_buckets=args.max_buckets_per_run, lookback_hours=args.cache_lookback_hours)
        if not stats.get("busy") and not stats.get("failed"):
            ops.recovery("service:aws-rds-audit-collect.service", {"account_id": identity["Account"], "message": "增量采集进程已恢复运行；数据完整性请查看分段状态和日报。"}, now)
        quality = ops.sync_quality(store, now)
        stats["quality_unresolved_segments"] = quality["problem_segments"]
        stats["quality_unknown_segments"] = quality["unknown_segments"]
        ops.flush(notify, now)
        print("增量采集: " + json.dumps(stats, ensure_ascii=False), flush=True)
        # Late arrivals or a recovered gap must be reflected in an already issued daily report.
        state = _load_state(store)
        today = now.astimezone(BEIJING).date().isoformat()
        previous = state.get(today)
        _, daily_start, daily_end = api.daily_window(today, now) if now.astimezone(BEIJING).hour >= 8 else (None, None, None)
        affects_daily = previous and daily_start is not None and any(daily_start <= api.parse_timestamp(stamp) < daily_end for stamp in stats.get("changed_starts", []))
        retry_daily = daily_start is not None and (ops.daily_pending(today) or ops.is_open("daily-config:" + today))
        if retry_daily or previous and (affects_daily or previous.get("delivery_pending") or previous.get("status") in (3, 4)):
            revised = argparse.Namespace(**vars(args))
            revised.daily, revised.from_cache, revised.collect_incremental = True, True, False
            revised.date, revised.input_dir, revised._cache_auto_revision = today, None, True
            revised.cache_account_id = identity["Account"]
            revised._cache_job_locked = True
            run_cached_daily(revised, api=api, now=now)
        pending = ops.flush(notify, now)
        return 2 if stats.get("failed") or stats.get("pending_alerts") or pending else 0
    except Exception as exc:
        ops.failure("identity", {"kind": "collection_start_failure", "message": _safe_message(exc)}, now)
        ops.flush(notify, now, include_quality=False)
        print("增量采集未完成，状态及告警已保留: " + _safe_message(exc), file=sys.stderr)
        return 2
    finally:
        locks.close()
        if store is not None:
            store.close()
        ops.close()


def run_cached_daily(args, *, api=None, now=None):
    api, now = _api(api), now or datetime.now(UTC)
    scope = cache_scope(args)
    ops = OpsOutbox(args.cache_dir, scope)
    store, notify = None, None
    day = args.date or now.astimezone(BEIJING).date().isoformat()
    ops.request_daily(day, now)
    try:
        config = api.lark_configuration(args, day)
        notify = _notifier(config)
        day, start, end = api.daily_window(args.date, now)
        store = CacheStore.discover(args.cache_dir, scope, account_id=args.cache_account_id)
        # Collection commits, snapshot assembly and daily-state publication share
        # one OS lock. A collector invoking a revision already owns that lock.
        with (nullcontext(True) if getattr(args, "_cache_job_locked", False) else _exclusive(store.directory / ".job.lock")) as locked:
            if not locked:
                print("已有采集或日报任务运行，日报请求已入队，后续定时器会自动重试。", flush=True)
                return 0
            directory = args.output_dir / store.account_id / day / (now.strftime("%Y%m%dT%H%M%SZ") + "-cache-" + uuid4().hex[:8])
            collection = store.assemble_window(start, end, directory)
            coverage = collection["source_cache"]
            state = _load_state(store)
            previous = state.get(day)
            automatic = getattr(args, "_cache_auto_revision", False)
            if automatic and previous and previous.get("fingerprint") == coverage["fingerprint"] and not previous.get("delivery_pending") and previous.get("status") not in (3, 4):
                print("已汇总日报的分段内容未改变，无需重复推送。", flush=True)
                ops.complete_daily(day)
                return 0
            collection["source_cache"]["revision"] = bool(previous)
            (directory / "report.json").write_text(json.dumps(collection, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            missing = coverage["missing_segments"]
            if missing:
                ops.failure("daily:" + day, {"kind": "daily_missing_segments", "account_id": store.account_id, "missing_count": len(missing), "bucket_start": api.iso(start), "bucket_end": api.iso(end), "message": "日报仅汇总本地成功分段，存在缺失/失败段；报告已标记不完整，采集任务会继续补采。"}, now)
            else:
                ops.recovery("daily:" + day, {"account_id": store.account_id, "message": "日报所需分段已补齐；已生成更新的汇总。"}, now)
            status = api.finish_daily(directory, day, start, end, args, 2 if collection["collection_status"] != "ok" else 0, config, period_kind="daily")
            state[day] = {"fingerprint": coverage["fingerprint"], "status": status, "delivery_pending": bool(getattr(args, "_delivery_failed", False)), "path": str(directory), "updated_at": api.iso(now)}
            _save_state(store, state)
            ops.complete_daily(day)
            if status in (3, 4) or getattr(args, "_delivery_failed", False):
                ops.failure("delivery:" + day, {"kind": "daily_delivery_failure", "account_id": store.account_id, "message": "日报生成后发布或通知失败，归档已保留，将在后续采集任务中重试。"}, now)
            else:
                ops.recovery("delivery:" + day, {"account_id": store.account_id, "message": "日报发布/通知步骤已恢复。"}, now)
            ops.recovery("service:aws-rds-audit.service", {"account_id": store.account_id, "message": "日报进程已恢复运行；数据完整性以报告覆盖状态为准。"}, now)
            ops.recovery("daily-config:" + day, {"account_id": store.account_id, "message": "日报缓存配置已恢复。"}, now)
            pending = ops.flush(notify, now, include_quality=False)
            return 2 if status == 2 or pending else status
    except Exception as exc:
        if store is not None:
            # Persist the first failed daily attempt as well as failures of revisions.
            # The incremental timer can then retry it without waiting another day.
            try:
                state = _load_state(store)
                state[day] = {**state.get(day, {}), "status": 4, "delivery_pending": True, "updated_at": api.iso(now)}
                _save_state(store, state)
            except Exception:
                pass  # The durable operations incident also requests a daily retry.
        ops.failure("daily-config:" + day, {"kind": "daily_cache_failure", "message": _safe_message(exc)}, now)
        ops.flush(notify, now, include_quality=False)
        print("本地缓存日报未完成: " + _safe_message(exc), file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()
        ops.close()


def notify_service_failure(args, *, api=None, now=None):
    """OnFailure entry point also covers a killed/timed-out collection process."""
    api, now = _api(api), now or datetime.now(UTC)
    if args.source_service not in {"aws-rds-audit.service", "aws-rds-audit-collect.service"}:
        raise ValueError("只接受本项目日报或增量采集服务名称")
    payload = {"kind": "service_process_failure", "source_service": args.source_service,
               "message": "systemd报告任务异常退出或超时；成功检查点保持不变，未成功分段会在后续唤醒时重试，请及时查看服务日志。"}
    config = None
    try:
        config = api.lark_configuration(args)
        ops = OpsOutbox(args.cache_dir, cache_scope(args))
    except Exception as exc:
        print("异常告警持久化或配置不可用: " + _safe_message(exc), file=sys.stderr)
        if config is not None:
            from lark_notify import send_lark_alert
            try:
                send_lark_alert({**payload, "message": payload["message"] + " 告警状态也无法写入本地缓存，请检查磁盘/目录权限。"}, config)
                return 0
            except Exception:
                print("异常告警投递未确认，请通过journalctl人工排查。", file=sys.stderr)
        return 2
    try:
        ops.failure("service:" + args.source_service, payload, now)
        return 2 if ops.flush(_notifier(config), now, include_quality=False) else 0
    finally:
        ops.close()
