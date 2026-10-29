"""Durable, deduplicated SQL change alerts from collected audit evidence.

The caller owns the collection job lock and supplies a notification callback.
This module never creates an AWS client or sends a network request itself.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import InvalidOperation
import hashlib
import json
from pathlib import Path
import re

from rds_cache import _exclusive, _iso, _parse, _stamp
from rds_report import audit_record_indexes, parse_audit_record, redact_text, row_disposition, split_audit_message, sql_body

DEFAULT_COMMANDS = ("DELETE", "UPDATE", "DROP", "TRUNCATE", "ALTER")
MAX_SQL_CHARS = 500
MAX_BATCH_EVENTS = 10
MAX_PAYLOAD_BYTES = 14000


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _short(value, maximum):
    text = str(value or "")
    # Preserve readable SQL line breaks while removing control characters.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = text.replace("<", "＜").replace(">", "＞")
    return text[:maximum] + ("…" if len(text) > maximum else "")


class SqlChangeAlerts:
    def __init__(self, store, now: datetime, commands=DEFAULT_COMMANDS):
        self.store, self.db = store, store.connection
        self.account_id = str(store.account_id)
        self.commands = tuple(sorted(set(str(command).strip().upper() for command in commands)))
        if not self.commands or any(not re.fullmatch(r"[A-Z]+", command) for command in self.commands):
            raise ValueError("SQL alert commands must be nonempty SQL command names")
        self.command_key = ",".join(self.commands)
        self.lock = Path(store.directory) / ".sql-alerts.lock"
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS sql_change_state(commands TEXT PRIMARY KEY, cutoff INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sql_change_events(
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at INTEGER NOT NULL,
                batch_id TEXT, sent INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sql_change_batches(
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
                last_error TEXT);
            CREATE TABLE IF NOT EXISTS sql_change_versions(
                start INTEGER NOT NULL, commands TEXT NOT NULL, digest TEXT NOT NULL,
                PRIMARY KEY(start,commands));
            CREATE INDEX IF NOT EXISTS sql_change_events_pending ON sql_change_events(sent,batch_id);
        """)
        cutoff = ((_stamp(now) - 5 * 60) // store.interval_seconds - 1) * store.interval_seconds
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO sql_change_state VALUES(?,?)", (self.command_key, cutoff))
        self.cutoff = self.db.execute("SELECT cutoff FROM sql_change_state WHERE commands=?", (self.command_key,)).fetchone()[0]
        self.queued = 0
        self._scanned_paths = set()

    def scan_snapshot(self, start: datetime, end: datetime, path: Path, now: datetime) -> int:
        first, last, stamp = _stamp(start), _stamp(end), _stamp(now)
        if first >= last:
            raise ValueError("SQL alert snapshot window is invalid")
        if first < self.cutoff:
            return 0  # Initial historical backfill does not become a live alert.
        directory = Path(path).resolve()
        if not directory.is_relative_to(Path(self.store.directory).resolve()):
            raise ValueError("SQL alert snapshot must stay within the account cache")
        source = json.loads((directory / "report.json").read_text(encoding="utf-8-sig"))
        if str(source.get("identity", {}).get("Account")) != self.account_id:
            raise ValueError("SQL alert snapshot belongs to another AWS account")
        window = source.get("window") or {}
        if _parse(window["start_inclusive"]) != first or _parse(window["end_exclusive"]) != last:
            raise ValueError("SQL alert snapshot does not match its segment window")
        count = 0
        for file in sorted((directory / "cloudwatch").glob("*.jsonl")):
            if not file.resolve().is_relative_to(directory):
                raise ValueError("SQL alert source file leaves its snapshot")
            with file.open(encoding="utf-8-sig") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        envelope = json.loads(line)
                        if (not isinstance(envelope, dict) or not envelope.get("eventId") or
                                not str(envelope.get("logGroupName") or "").endswith("/audit") or
                                not envelope.get("logStreamName")):
                            continue
                        segments = split_audit_message(str(envelope.get("message") or ""))
                        indexes = audit_record_indexes(envelope, len(segments))
                    except (ValueError, TypeError, KeyError):
                        continue  # The collector's quality channel handles unknown evidence.
                    for index, segment in zip(indexes, segments):
                        try:
                            row = parse_audit_record(segment, envelope, index)
                            command = re.match(r"[A-Za-z]+", sql_body(row.get("sql") or ""))
                            if (not command or command.group().upper() not in self.commands or
                                    row_disposition(row) != "change" or
                                    not self.cutoff <= _parse(row["time_utc"]) <= stamp):
                                continue
                        except (ValueError, TypeError, KeyError, OverflowError, InvalidOperation):
                            continue
                        identity = [self.account_id, envelope.get("region"), envelope.get("logGroupName"), envelope.get("logStreamName"), envelope["eventId"], index]
                        event_id = hashlib.sha256(_json(identity).encode()).hexdigest()
                        payload = {"id": event_id, "command": command.group().upper(),
                                   "actor": _short(row.get("actor"), 100), "time": _short(row.get("time_local"), 40),
                                   "region": _short(row.get("region"), 60), "instance": _short(row.get("serverhost"), 120),
                                   "database": _short(row.get("database"), 100), "stream": _short(row.get("log_stream"), 140),
                                   "result": _short(row.get("result"), 120),
                                   "sql": _short(redact_text(row.get("sql") or ""), MAX_SQL_CHARS)}
                        cursor = self.db.execute("INSERT OR IGNORE INTO sql_change_events(id,payload,created_at) VALUES(?,?,?)", (event_id, _json(payload), stamp))
                        count += cursor.rowcount
            self.db.commit()
        self.queued += count
        self._scanned_paths.add(directory)
        return count

    def scan_committed(self, now: datetime) -> int:
        """Compensate for a process crash between checkpoint commit and enqueue."""
        count = 0
        rows = self.db.execute("SELECT start,end,active_path,active_digest FROM buckets WHERE start>=? AND active_path IS NOT NULL ORDER BY start", (self.cutoff,)).fetchall()
        for row in rows:
            previous = self.db.execute("SELECT digest FROM sql_change_versions WHERE start=? AND commands=?", (row["start"], self.command_key)).fetchone()
            if previous and previous["digest"] == row["active_digest"]:
                continue
            directory = self.store._snapshot_path(row["active_path"])
            if directory not in self._scanned_paths:
                count += self.scan_snapshot(datetime.fromtimestamp(row["start"], timezone.utc), datetime.fromtimestamp(row["end"], timezone.utc), directory, now)
            with self.db:
                self.db.execute("INSERT OR REPLACE INTO sql_change_versions VALUES(?,?,?)", (row["start"], self.command_key, row["active_digest"]))
        return count

    def _batch_payload(self, entries):
        event_id = "sql-change:" + hashlib.sha256(_json([entry["id"] for entry in entries]).encode()).hexdigest()[:24]
        lines = [f"发现 {len(entries)} 条 SQL 删除/更新/结构变更操作（北京时间）"]
        for index, entry in enumerate(entries, 1):
            lines += [f"{index}. {entry['time']} · 账号：{entry['actor']} · {entry['command']}",
                      f"实例：{entry['instance']} · 数据库：{entry['database']} · {entry['region']}",
                      "结果：" + entry["result"], "SQL：" + entry["sql"]]
        return {"kind": "sql_change", "account_id": self.account_id, "event_id": event_id, "message": "\n".join(lines), "operation_count": len(entries)}

    def _make_batch(self):
        rows = self.db.execute("SELECT id,payload FROM sql_change_events WHERE sent=0 AND batch_id IS NULL ORDER BY rowid LIMIT ?", (MAX_BATCH_EVENTS,)).fetchall()
        if not rows:
            return None
        entries, identifiers = [], []
        for row in rows:
            candidate = entries + [json.loads(row["payload"])]
            if len(_json(self._batch_payload(candidate)).encode()) > MAX_PAYLOAD_BYTES:
                break
            entries, identifiers = candidate, identifiers + [row["id"]]
        if not entries:
            raise ValueError("A bounded SQL alert event exceeds the message budget")
        payload = self._batch_payload(entries)
        with self.db:
            self.db.execute("INSERT INTO sql_change_batches(id,payload) VALUES(?,?)", (payload["event_id"], _json(payload)))
            self.db.executemany("UPDATE sql_change_events SET batch_id=? WHERE id=?", ((payload["event_id"], identifier) for identifier in identifiers))
        return self.db.execute("SELECT * FROM sql_change_batches WHERE id=?", (payload["event_id"],)).fetchone()

    def stats(self):
        return {"queued_events": self.queued,
                "pending_events": self.db.execute("SELECT count(*) FROM sql_change_events WHERE sent=0").fetchone()[0],
                "pending_messages": self.db.execute("SELECT count(*) FROM sql_change_batches WHERE status='pending'").fetchone()[0]}

    def flush(self, callback, now: datetime, max_messages=5):
        if not 1 <= max_messages <= 100:
            raise ValueError("SQL alert message limit must be between 1 and 100")
        result = {"sent_messages": 0, "failed_messages": 0, "busy": False}
        if callback is None:
            return {**result, **self.stats()}
        stamp = _stamp(now)
        with _exclusive(self.lock) as locked:
            if not locked:
                return {**result, "busy": True, **self.stats()}
            attempted = set()
            for _ in range(max_messages):
                rows = self.db.execute("SELECT * FROM sql_change_batches WHERE status='pending' AND next_attempt<=? ORDER BY rowid LIMIT ?", (stamp, max_messages)).fetchall()
                batch = next((row for row in rows if row["id"] not in attempted), None)
                if batch is None:
                    batch = self._make_batch()
                if batch is None:
                    break
                attempted.add(batch["id"])
                try:
                    accepted = callback(json.loads(batch["payload"]))
                    if accepted is False or isinstance(accepted, dict) and (accepted.get("success") is False or accepted.get("code", accepted.get("StatusCode", 0)) not in (0, "0")):
                        raise RuntimeError("Notification was not accepted")
                except Exception as exc:
                    attempts = batch["attempts"] + 1
                    with self.db:
                        self.db.execute("UPDATE sql_change_batches SET attempts=?,next_attempt=?,last_error=? WHERE id=?", (attempts, stamp + min(3600, 60 * 2 ** min(attempts - 1, 6)), type(exc).__name__, batch["id"]))
                    result["failed_messages"] += 1
                else:
                    with self.db:
                        self.db.execute("UPDATE sql_change_batches SET status='sent',attempts=attempts+1,last_error=NULL WHERE id=?", (batch["id"],))
                        self.db.execute("UPDATE sql_change_events SET sent=1 WHERE batch_id=?", (batch["id"],))
                    result["sent_messages"] += 1
        return {**result, **self.stats()}
