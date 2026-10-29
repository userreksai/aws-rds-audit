"""Bounded interval collection, durable checkpoints, retries and alert outbox.

The collector and notifier are injected: this module never creates AWS clients or
sends messages itself. A committed snapshot is immutable and only its newest
successful version participates in a daily report.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
from uuid import uuid4

UTC = timezone.utc


def _stamp(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Cache timestamps must contain a timezone")
    return int(value.timestamp())


def _iso(value: int | datetime) -> str:
    stamp = datetime.fromtimestamp(value, UTC) if isinstance(value, int) else value.astimezone(UTC)
    return stamp.isoformat().replace("+00:00", "Z")


def _parse(value: str) -> int:
    return _stamp(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _safe_error(exc) -> str:
    # Do not copy a complete signed URL or arbitrarily large provider response.
    text = re.sub(r"https?://\S+", "[URL]", str(exc))
    return (type(exc).__name__ + ": " + text)[:1200]


@contextmanager
def _exclusive(path: Path):
    """OS locks are automatically released after a process crash, unlike a flag."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        locked = False
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK, errno.EBUSY):
                raise
        try:
            yield locked
        finally:
            if locked:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_UN)


class CacheStore:
    def __init__(self, root: Path, account_id: str, scope: dict):
        if not re.fullmatch(r"\d{12}", str(account_id)):
            raise ValueError("Cache account_id must be a 12-digit AWS account ID")
        interval = int(scope.get("interval_minutes", 30))
        if interval not in (30, 60):
            raise ValueError("interval_minutes must be 30 or 60")
        self.root = Path(root).resolve()
        self.account_id, self.scope = str(account_id), json.loads(_canonical(scope))
        self.interval_minutes, self.interval_seconds = interval, interval * 60
        self.scope_id = hashlib.sha256(_canonical(self.scope).encode()).hexdigest()[:24]
        self.directory = self.root / self.account_id / self.scope_id
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db_path = self.directory / "state.sqlite3"
        metadata = self.directory / "scope.json"
        value = {"schema_version": 1, "account_id": self.account_id, "scope": self.scope, "scope_id": self.scope_id}
        if metadata.exists():
            if json.loads(metadata.read_text(encoding="utf-8")) != value:
                raise ValueError("Cache scope metadata does not match requested identity")
        else:
            temporary = metadata.with_suffix(".tmp-" + uuid4().hex)
            temporary.write_text(_canonical(value) + "\n", encoding="utf-8")
            temporary.replace(metadata)
        self.connection = sqlite3.connect(self.db_path, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS buckets (
                start INTEGER PRIMARY KEY, end INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                active_path TEXT, active_digest TEXT, latest_attempt_path TEXT,
                last_error TEXT, last_success INTEGER, next_retry INTEGER NOT NULL DEFAULT 0,
                refresh_done INTEGER NOT NULL DEFAULT 0, failure_cycles INTEGER NOT NULL DEFAULT 0,
                incident_open INTEGER NOT NULL DEFAULT 0, incident_generation INTEGER NOT NULL DEFAULT 0,
                last_alert_queued INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, bucket_start INTEGER NOT NULL, kind TEXT NOT NULL,
                generation INTEGER NOT NULL, payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
                sent_at INTEGER, last_error TEXT
            );
        """)
        self.connection.commit()

    def close(self):
        self.connection.close()

    @classmethod
    def discover(cls, root: Path, scope: dict, account_id: str | None = None):
        """Find a cached identity without contacting STS; refuse ambiguous accounts."""
        scope_id = hashlib.sha256(_canonical(scope).encode()).hexdigest()[:24]
        matches = []
        for path in Path(root).glob(f"*/{scope_id}/scope.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("scope") != scope:
                continue
            account = str(data.get("account_id", ""))
            if account_id is None or account == str(account_id):
                if (path.parent / "state.sqlite3").is_file():
                    matches.append(account)
        if not matches:
            raise ValueError("没有该配置的本地分段缓存，请先运行增量采集；日报不会自动拉取25小时日志")
        if len(set(matches)) != 1:
            raise ValueError("该配置匹配多个AWS账号缓存，请显式指定账号，避免跨账号汇总")
        return cls(root, matches[0], scope)

    def bucket(self, start: datetime):
        row = self.connection.execute("SELECT * FROM buckets WHERE start=?", (_stamp(start),)).fetchone()
        return dict(row) if row else None

    def pending_alerts(self):
        return [dict(row) for row in self.connection.execute("SELECT * FROM alerts WHERE status='pending' ORDER BY created_at,id")]

    def _queue(self, bucket, kind, now, *, reminder=False):
        generation = int(bucket["incident_generation"])
        suffix = f":{now // 3600}" if reminder else ""
        event_id = f"{bucket['start']}:{generation}:{kind}{suffix}"
        payload = {
            "event_id": event_id, "kind": kind, "account_id": self.account_id,
            "scope_id": self.scope_id, "scope": self.scope,
            "window_start_utc": _iso(bucket["start"]), "window_end_utc_exclusive": _iso(bucket["end"]),
            "attempts": bucket["attempts"], "error": bucket["last_error"] or "",
            "occurred_at": _iso(now), "incident_generation": generation,
        }
        self.connection.execute("INSERT OR IGNORE INTO alerts(id,bucket_start,kind,generation,payload,created_at) VALUES(?,?,?,?,?,?)", (event_id, bucket["start"], kind, generation, _canonical(payload), now))

    def _flush_alerts(self, now, alert_callback, stats):
        if alert_callback is None:
            return
        rows = list(self.connection.execute("SELECT * FROM alerts WHERE status='pending' AND next_attempt<=? ORDER BY created_at,id LIMIT 30", (now,)))
        for row in rows:
            try:
                result = alert_callback(json.loads(row["payload"]))
                if result is False or (isinstance(result, dict) and (
                    result.get("success") is False or
                    ("code" in result and result["code"] not in (0, "0")) or
                    ("StatusCode" in result and result["StatusCode"] not in (0, "0"))
                )):
                    raise RuntimeError("Notifier did not confirm delivery")
            except Exception as exc:
                attempts = row["attempts"] + 1
                delay = min(3600, 60 * 2 ** min(attempts - 1, 6))
                self.connection.execute("UPDATE alerts SET attempts=?,next_attempt=?,last_error=? WHERE id=?", (attempts, now + delay, f"Notification failed ({type(exc).__name__})", row["id"]))
                stats["alert_failures"] += 1
            else:
                self.connection.execute("UPDATE alerts SET status='sent',attempts=attempts+1,sent_at=?,last_error=NULL WHERE id=?", (now, row["id"]))
                stats["alerts_sent"] += 1
            self.connection.commit()

    def _relative_snapshot(self, path):
        resolved = Path(path).resolve()
        if not resolved.is_relative_to(self.directory):
            raise ValueError("Snapshot directory must stay within its account/scope cache")
        return str(resolved.relative_to(self.directory))

    def _snapshot_path(self, relative):
        path = (self.directory / relative).resolve()
        if not path.is_relative_to(self.directory):
            raise ValueError("Unsafe snapshot path in cache ledger")
        return path

    def _validate_snapshot(self, path, start, end, quality_partial):
        report_path = Path(path) / "report.json"
        source = json.loads(report_path.read_text(encoding="utf-8-sig"))
        if str(source.get("identity", {}).get("Account", "")) != self.account_id:
            raise ValueError("Collected snapshot belongs to another AWS account")
        window = source.get("window") or {}
        if _parse(window["start_inclusive"]) != start or _parse(window["end_exclusive"]) != end:
            raise ValueError("Collected snapshot must match its exact segment window")
        errors = [row for row in source.get("checks", []) if row.get("status") == "error"]
        if source.get("collection_status") != "ok":
            if not (quality_partial and errors and all(row.get("error_type") == "UnclassifiedSqlRecords" for row in errors)):
                raise ValueError("Partial transport/permission/file collection cannot become a successful checkpoint")
        if errors and not (quality_partial and all(row.get("error_type") == "UnclassifiedSqlRecords" for row in errors)):
            raise ValueError("Snapshot contains unapproved collection errors")
        if not (Path(path) / "management-events.jsonl").is_file():
            raise ValueError("Snapshot is missing management-events.jsonl")
        digest = hashlib.sha256()
        digest.update(_canonical({"account_id": self.account_id, "start": start, "end": end, "errors": errors}).encode())
        files = [Path(path) / name for name in ("management-events.jsonl", "rds-events.jsonl")]
        files += sorted((Path(path) / "cloudwatch").glob("*.jsonl"))
        files += sorted((Path(path) / "quarantine").glob("*.jsonl"))
        for file in files:
            if not file.exists():
                continue
            digest.update(file.relative_to(path).as_posix().encode())
            with file.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        return source, digest.hexdigest()

    def run_due(self, now: datetime, collect_callback, alert_callback=None, *, max_buckets=6,
                lookback_hours=26, max_attempts=3, retry_base_seconds=2, sleep=time.sleep,
                publish_delay_minutes=5, refresh_after_minutes=60):
        stamp = _stamp(now)
        if not 1 <= max_buckets <= 100 or not 1 <= lookback_hours <= 24 * 89 or not 1 <= max_attempts <= 10:
            raise ValueError("Invalid collection bounds")
        stats = {"busy": False, "attempted_buckets": 0, "attempts": 0, "succeeded": 0, "failed": 0, "changed_starts": [],
                 "changed": 0, "quality_partial": 0, "alerts_sent": 0, "alert_failures": 0, "pending_alerts": 0}
        with _exclusive(self.directory / ".collect.lock") as acquired:
            if not acquired:
                stats["busy"] = True
                return stats
            # The OS lock proves no previous collector process still owns a running row.
            self.connection.execute("UPDATE buckets SET status='failed',next_retry=?,last_error='Previous collection process stopped before checkpoint commit' WHERE status='running'", (stamp,))
            latest_end = (stamp - publish_delay_minutes * 60) // self.interval_seconds * self.interval_seconds
            earliest = (stamp - int(lookback_hours * 3600)) // self.interval_seconds * self.interval_seconds
            for start in range(earliest, latest_end, self.interval_seconds):
                self.connection.execute("INSERT OR IGNORE INTO buckets(start,end) VALUES(?,?)", (start, start + self.interval_seconds))
            self.connection.commit()
            self._flush_alerts(stamp, alert_callback, stats)
            # Previously discovered missing/failed segments remain retryable across
            # day boundaries; the normal lookback only limits newly seeded work.
            # Keep a day of margin before CloudTrail's rolling 90-day boundary.
            retry_earliest = stamp - 89 * 24 * 3600
            rows = [dict(row) for row in self.connection.execute(
                "SELECT * FROM buckets WHERE end<=? AND (start>=? OR (end>=? AND status IN ('failed','pending')))",
                (latest_end, earliest, retry_earliest))]
            latest_start = latest_end - self.interval_seconds

            def priority(row):
                if row["start"] == latest_start and row["status"] != "succeeded":
                    return (0, row["start"])
                if row["status"] == "failed" and row["next_retry"] <= stamp:
                    return (1, row["start"])
                if row["status"] == "pending":
                    return (2, row["start"])
                if row["status"] == "succeeded" and not row["refresh_done"] and row["end"] + refresh_after_minutes * 60 <= stamp:
                    return (3, row["start"])
                return (9, row["start"])

            due = sorted((row for row in rows if priority(row)[0] < 9 and (row["status"] != "failed" or row["next_retry"] <= stamp)), key=priority)[:max_buckets]
            for original in due:
                stats["attempted_buckets"] += 1
                start, end = original["start"], original["end"]
                last_error, success = "", False
                for attempt in range(max_attempts):
                    target = self.directory / "segments" / f"{start}-{end}" / ("attempt-" + uuid4().hex)
                    target.mkdir(parents=True, exist_ok=False)
                    relative = self._relative_snapshot(target)
                    self.connection.execute("UPDATE buckets SET status='running',attempts=attempts+1,latest_attempt_path=? WHERE start=?", (relative, start))
                    self.connection.commit()
                    stats["attempts"] += 1
                    retryable = True
                    try:
                        result = collect_callback(datetime.fromtimestamp(start, UTC), datetime.fromtimestamp(end, UTC), target)
                        if isinstance(result, dict):
                            status = result.get("status", 0 if result.get("success") else 2)
                            explicit_success = result.get("success", status == 0)
                            quality_partial = bool(result.get("quality_partial"))
                            retryable = result.get("retryable", True)
                            path = Path(result.get("path") or result.get("directory") or target)
                            if status != 0 or not explicit_success:
                                raise RuntimeError(str(result.get("error") or f"Collector returned status {status}"))
                        else:
                            if result != 0:
                                raise RuntimeError(f"Collector returned status {result}")
                            path, quality_partial = target, False
                        relative = self._relative_snapshot(path)
                        source, digest = self._validate_snapshot(path, start, end, quality_partial)
                    except Exception as exc:
                        last_error = _safe_error(exc)
                        self.connection.execute("UPDATE buckets SET last_error=? WHERE start=?", (last_error, start))
                        self.connection.commit()
                        if not retryable:
                            break
                        if attempt + 1 < max_attempts:
                            sleep(retry_base_seconds * 2 ** attempt)
                        continue
                    previous = dict(self.connection.execute("SELECT * FROM buckets WHERE start=?", (start,)).fetchone())
                    refresh_done = bool(original["active_path"]) or stamp - end >= 2 * 3600
                    self.connection.execute("UPDATE buckets SET status='succeeded',active_path=?,active_digest=?,last_success=?,last_error=NULL,next_retry=0,refresh_done=?,failure_cycles=0,incident_open=0 WHERE start=?", (relative, digest, stamp, int(refresh_done), start))
                    if previous["incident_open"]:
                        self.connection.execute("UPDATE alerts SET status='cancelled' WHERE bucket_start=? AND generation=? AND status='pending'", (start, previous["incident_generation"]))
                        self._queue(previous, "recovered", stamp)
                    self.connection.commit()
                    stats["succeeded"] += 1
                    stats["quality_partial"] += bool(quality_partial)
                    changed = original["active_digest"] != digest or original["status"] != "succeeded"
                    stats["changed"] += changed
                    if changed:
                        stats["changed_starts"].append(_iso(start))
                    success = True
                    break
                if not success:
                    row = dict(self.connection.execute("SELECT * FROM buckets WHERE start=?", (start,)).fetchone())
                    generation = row["incident_generation"] + (not row["incident_open"])
                    cycles = row["failure_cycles"] + 1
                    next_retry = stamp + min(3600, 300 * 2 ** min(cycles - 1, 6))
                    self.connection.execute("UPDATE buckets SET status='failed',last_error=?,next_retry=?,failure_cycles=?,incident_open=1,incident_generation=? WHERE start=?", (last_error, next_retry, cycles, generation, start))
                    row.update(last_error=last_error, incident_open=1, incident_generation=generation)
                    if not original["incident_open"] or stamp - row["last_alert_queued"] >= 3600:
                        self._queue(row, "failed", stamp, reminder=bool(original["incident_open"]))
                        self.connection.execute("UPDATE buckets SET last_alert_queued=? WHERE start=?", (stamp, start))
                    self.connection.commit()
                    stats["failed"] += 1
                self._flush_alerts(stamp, alert_callback, stats)
            self._flush_alerts(stamp, alert_callback, stats)
            stats["pending_alerts"] = len(self.pending_alerts())
            stats["cache_directory"] = str(self.directory)
            return stats

    def assemble_window(self, start: datetime, end: datetime, destination: Path):
        first, last = _stamp(start), _stamp(end)
        if first >= last or first % self.interval_seconds or last % self.interval_seconds:
            raise ValueError("Daily cache window must align to interval boundaries")
        # A requested daily gap outside the rolling lookback must still enter the repair queue.
        self.connection.executemany("INSERT OR IGNORE INTO buckets(start,end) VALUES(?,?)", ((stamp, stamp + self.interval_seconds) for stamp in range(first, last, self.interval_seconds)))
        self.connection.commit()
        destination = Path(destination).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        # Refuse accidentally overwriting an existing raw collection or previous assembly.
        if (destination / "report.json").exists() or (destination / "management-events.jsonl").exists():
            raise FileExistsError("Use a new destination for each cache assembly")
        checks, selected, missing, filtering_regions, versions = [], [], [], {}, []
        streams = {}
        try:
            streams["management-events.jsonl"] = (destination / "management-events.jsonl").open("x", encoding="utf-8", newline="\n")
            streams["rds-events.jsonl"] = (destination / "rds-events.jsonl").open("x", encoding="utf-8", newline="\n")
            for stamp in range(first, last, self.interval_seconds):
                row = self.connection.execute("SELECT * FROM buckets WHERE start=?", (stamp,)).fetchone()
                row = dict(row) if row else None
                if row is None or not row["active_path"]:
                    state = row["status"] if row else "missing"
                    detail = {"start": _iso(stamp), "end": _iso(stamp + self.interval_seconds), "status": state, "error": row["last_error"] if row else "Segment has not been collected"}
                    missing.append(detail)
                    checks.append({"scope": "cache_segment", "status": "error", "error_type": "MissingCacheSegment", "message": _canonical(detail)})
                    versions.append({"start": stamp, "status": state, "digest": None})
                    continue
                path = self._snapshot_path(row["active_path"])
                try:
                    source, actual_digest = self._validate_snapshot(path, stamp, stamp + self.interval_seconds, True)
                    if actual_digest != row["active_digest"]:
                        raise ValueError("Committed snapshot contents changed after checkpoint")
                except Exception as exc:
                    self.connection.execute("UPDATE buckets SET status='failed',next_retry=0,last_error=? WHERE start=?", (_safe_error(exc), stamp))
                    self.connection.commit()
                    detail = {"start": _iso(stamp), "end": _iso(stamp + self.interval_seconds), "status": "corrupt", "error": _safe_error(exc)}
                    missing.append(detail)
                    checks.append({"scope": "cache_segment", "status": "error", "error_type": "InvalidCacheSnapshot", "message": _canonical(detail)})
                    versions.append({"start": stamp, "status": "corrupt", "digest": None})
                    continue
                if row["status"] != "succeeded":
                    checks.append({"scope": "cache_refresh", "status": "error", "error_type": "CacheRefreshFailed", "message": f"{_iso(stamp)} latest collection/refresh status is {row['status']}; using its last successful snapshot"})
                selected.append({"start": _iso(stamp), "end": _iso(stamp + self.interval_seconds), "digest": actual_digest})
                versions.append({"start": stamp, "status": row["status"], "digest": actual_digest})
                checks.extend(check for check in source.get("checks", []) if check.get("status") == "error")
                for region_name, data in source.get("regions", {}).items():
                    region = filtering_regions.setdefault(region_name, {"filtered_management_event_count": 0, "sql_log_groups": []})
                    region["filtered_management_event_count"] += int(data.get("filtered_management_event_count") or 0)
                    region["sql_log_groups"].extend(data.get("sql_log_groups", []))
                files = [path / name for name in ("management-events.jsonl", "rds-events.jsonl")]
                files += sorted((path / "cloudwatch").glob("*.jsonl"))
                files += sorted((path / "quarantine").glob("*.jsonl"))
                for file in files:
                    if not file.exists():
                        continue
                    relative = file.relative_to(path).as_posix()
                    # A shared group filename across segments intentionally appends to one file.
                    if relative not in streams:
                        target = destination / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        streams[relative] = target.open("x", encoding="utf-8", newline="\n")
                    with file.open(encoding="utf-8-sig") as original:
                        for line in original:
                            if line.strip():
                                streams[relative].write(line.rstrip("\r\n") + "\n")
        finally:
            for handle in streams.values():
                handle.close()
        fingerprint = hashlib.sha256(_canonical({"account": self.account_id, "scope": self.scope, "start": first, "end": last, "versions": versions}).encode()).hexdigest()
        report = {
            "schema_version": 1, "identity": {"Account": self.account_id},
            "window": {"start_inclusive": _iso(first), "end_exclusive": _iso(last)},
            "period_kind": "daily", "operation_scope": "changes_only", "sql_log_download_requested": True,
            "collection_status": "partial" if checks else "ok", "failed_check_count": len(checks),
            "checks": checks, "regions": filtering_regions, "historical_sql_completeness": "not_established",
            "source_cache": {"scope_id": self.scope_id, "interval_minutes": self.interval_minutes,
                             "expected_segments": (last - first) // self.interval_seconds,
                             "selected_segments": len(selected), "missing_segments": missing,
                             "segments": selected, "fingerprint": fingerprint},
        }
        with (destination / "report.json").open("x", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        return report
