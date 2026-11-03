"""Streaming user or source-IP counters; statement text exists only while parsing.

Temporary on-disk identities provide deduplication without a growing Python set.
Only summary counts and bounded quality reasons survive collection.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from decimal import InvalidOperation
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import tempfile

CATEGORIES = ("新增", "删除", "修改", "其他操作")
COVERAGE_FIELDS = ("audit_cloudwatch_events", "general_log_events_not_counted",
                   "duplicate_cloudwatch_events", "filtered_management", "filtered_queries",
                   "filtered_auxiliary", "unclassified", "unparsed_records")
IP_COVERAGE_FIELDS = ("filtered_no_ip_records", "source_unreadable_records")
IP_AUXILIARY_OPERATIONS = frozenset({"CONNECT", "DISCONNECT", "FAILED_CONNECT", "CHANGEUSER",
                                     "READ", "WRITE", "CREATE", "ALTER", "RENAME", "DROP"})
REASONS = {"parse_sql", "unclassified_sql", "invalid_record_indexes", "missing_event_id",
           "parse_management", "parse_jsonl", "read_jsonl", "quarantine_sql", "missing_segments"}


def _model():
    import rds_report
    return rds_report


def _number(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("summary counters must be nonnegative integers")
    return value


def _coverage_fields(dimension):
    return COVERAGE_FIELDS + IP_COVERAGE_FIELDS if dimension == "ip" else COVERAGE_FIELDS


def _empty_coverage(dimension="user"):
    return {**dict.fromkeys(_coverage_fields(dimension), 0), "unknown_reasons": {}}


def _dimension(value):
    if value not in {"user", "ip"}:
        raise ValueError("summary dimension must be user or ip")
    return value


def _summary_format(dimension):
    return {"schema_version": 3, "dimension": "ip"} if dimension == "ip" else {"schema_version": 1}


def canonical_source_ip(value):
    """Return a literal IP, optionally extracted from an unambiguous endpoint.

    DNS names, internal service labels and scoped interface names are excluded.
    IPv6 without brackets is always interpreted as an address, never guessed to
    contain a port. Bracketed IPv6 and IPv4:port accept only ports 0-65535.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    bracketed = re.fullmatch(r"\[([^\[\]]+)\](?::([0-9]+))?", value)
    if bracketed:
        host, port = bracketed.groups()
        version = 6
    elif value.count(":") == 1:
        host, port = value.split(":", 1)
        version = 4
    else:
        return None
    if port is not None:
        if not re.fullmatch(r"[0-9]+", port):
            return None
        significant = port.lstrip("0") or "0"
        if len(significant) > 5 or int(significant) > 65535:
            return None
    try:
        address = ipaddress.ip_address(host)
        return str(address) if address.version == version and "%" not in host else None
    except ValueError:
        return None


def _actor(row, dimension="user"):
    kind = row["source_kind"]
    if kind not in {"management", "sql"}:
        raise ValueError("unsupported summary identity source")
    if not isinstance(row["actor"], str) or not isinstance(row["actor_key"], str):
        raise ValueError("summary actor names and keys must be strings")
    if dimension == "ip":
        source = canonical_source_ip(row.get("source_ip"))
        if source is None:
            raise ValueError("IP operation summaries require a valid literal source IP")
        return {"actor": source, "actor_key": kind + ":source_ip:" + source,
                "actor_type": "来源 IP", "source_kind": kind, "source_ip": source,
                "total": 0, "failed": 0, "counts": dict.fromkeys(CATEGORIES, 0),
                "attempted_counts": dict.fromkeys(CATEGORIES, 0)}
    key = "sql:username:" + str(row["actor"]) if kind == "sql" else str(row["actor_key"])
    return {"actor": str(row["actor"]), "actor_key": key,
            "actor_type": "数据库账号" if kind == "sql" else "AWS 身份", "source_kind": kind,
            "total": 0, "failed": 0, "counts": dict.fromkeys(CATEGORIES, 0),
            "attempted_counts": dict.fromkeys(CATEGORIES, 0)}


def save_summary(payload, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "operation-summary.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return target


class SummaryAccumulator:
    def __init__(self, directory, start, end, dimension="user"):
        self.dimension = _dimension(dimension)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.start, self.end = _model().timestamp(start), _model().timestamp(end)
        if self.start >= self.end:
            raise ValueError("summary start must precede end")
        descriptor, filename = tempfile.mkstemp(prefix=".summary-identities-", suffix=".sqlite3", dir=self.directory)
        import os
        os.close(descriptor)
        self.path = Path(filename)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=OFF")
        self.db.execute("PRAGMA cache_size=-4096")
        self.db.execute("CREATE TABLE identities (kind TEXT, identity BLOB, PRIMARY KEY(kind,identity)) WITHOUT ROWID")
        self.actors = {}
        self.coverage = _empty_coverage(self.dimension)
        self.unknown = Counter()
        self.operations = 0

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        self.path.unlink(missing_ok=True)

    def _remember(self, kind, identity):
        encoded = json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode()
        digest = hashlib.sha256(encoded).digest()
        inserted = self.db.execute("INSERT OR IGNORE INTO identities VALUES(?,?)", (kind, digest)).rowcount
        self.operations += 1
        if self.operations % 10000 == 0:
            self.db.commit()
        return bool(inserted)

    def _unknown(self, reason):
        reason = reason if reason in REASONS else "quarantine_sql"
        self.unknown[reason] += 1
        self.coverage["unparsed_records"] += 1
        self.coverage["unclassified"] += reason == "unclassified_sql"

    def _add_row(self, row):
        actor = _actor(row, self.dimension)
        target = self.actors.setdefault(actor["actor_key"], actor)
        category = row["category"]
        target["total"] += 1
        target["failed"] += row["status"] == "failed"
        target["attempted_counts"][category] += 1
        if row["counted"]:
            target["counts"][category] += 1

    def process_management(self, envelope):
        result = dict.fromkeys(("change_records", "read_records", "auxiliary_records", "unknown_records", "filtered_management"), 0)
        try:
            row = _model().normalize_management(envelope)
            if not self.start <= _model().timestamp(row["time_utc"]) < self.end:
                return result
            # CloudTrail EventID is global, including cross-Region duplicates.
            if not self._remember("management", row["event_id"]):
                return result
            if self.dimension == "ip":
                source_ip = canonical_source_ip(row["source_ip"])
                if source_ip is None:
                    self.coverage["filtered_no_ip_records"] += 1
                    self.coverage["filtered_management"] += 1
                    result["filtered_management"] = 1
                    return result
                row["source_ip"] = source_ip
            if row["category"] not in _model().CHANGE_CATEGORIES:
                self.coverage["filtered_management"] += 1
                result["filtered_management"] = 1
            else:
                self._add_row(row)
                result["change_records"] = 1
        except (ValueError, TypeError, KeyError, OverflowError):
            self._unknown("parse_management")
            result["unknown_records"] = 1
        return result

    def _sql_key(self, envelope, index):
        return (str(envelope.get("region") or ""), str(envelope.get("logGroupName") or ""),
                str(envelope.get("logStreamName") or ""), str(envelope.get("eventId") or ""), index)

    def process_unknown(self, envelope, index=None, reason="quarantine_sql"):
        try:
            occurred = datetime.fromtimestamp(int(envelope["timestamp"]) / 1000, timezone.utc)
            if not self.start <= occurred < self.end:
                return False
        except (ValueError, TypeError, KeyError, OverflowError):
            pass
        index = envelope.get("record_index", index)
        if envelope.get("eventId") and not self._remember("sql_record", self._sql_key(envelope, index)):
            return False
        self._unknown(reason)
        return True

    def process_audit(self, envelope):
        result = dict.fromkeys(("change_records", "read_records", "auxiliary_records", "unknown_records"), 0)
        model = _model()
        group = str(envelope.get("logGroupName") or "")
        if group.endswith("/general"):
            self.coverage["general_log_events_not_counted"] += 1
            return result
        if not group.endswith("/audit"):
            return result
        try:
            occurred = datetime.fromtimestamp(int(envelope["timestamp"]) / 1000, timezone.utc)
        except (ValueError, TypeError, KeyError, OverflowError):
            self._unknown("parse_sql")
            result["unknown_records"] = 1
            return result
        if not self.start <= occurred < self.end:
            return result
        if not envelope.get("eventId"):
            self._unknown("missing_event_id")
            result["unknown_records"] = 1
            return result
        new_envelope = self._remember("sql_envelope", self._sql_key(envelope, None))
        if new_envelope:
            self.coverage["audit_cloudwatch_events"] += 1
        else:
            self.coverage["duplicate_cloudwatch_events"] += 1
        segments = model.split_audit_message(str(envelope.get("message") or ""))
        try:
            indexes = model.audit_record_indexes(envelope, len(segments))
        except ValueError:
            if self.process_unknown(envelope, reason="invalid_record_indexes"):
                result["unknown_records"] += 1
            return result
        for index, segment in zip(indexes, segments):
            if not self._remember("sql_record", self._sql_key(envelope, index)):
                continue
            source_ip = None
            if self.dimension == "ip":
                # Scope must be established from the CSV header before reading
                # SQL, return codes or timestamp variants. A known non-IP source
                # cannot make this IP-only report incomplete. An unreadable
                # header is retained as a quality issue, never guessed away.
                try:
                    header, _ = model._read_prefix(segment.strip())
                    source_ip = canonical_source_ip(header[3])
                except (ValueError, TypeError, IndexError):
                    self.coverage["source_unreadable_records"] += 1
                    self._unknown("parse_sql")
                    result["unknown_records"] += 1
                    continue
                if source_ip is None:
                    self.coverage["filtered_no_ip_records"] += 1
                    continue
                # TABLE/connection records are not SQL statements. Their
                # documented forms may omit retcode; do not invent a return
                # code merely to exclude them from statement counts.
                operation = header[6].strip().upper()
                if operation in IP_AUXILIARY_OPERATIONS:
                    self.coverage["filtered_auxiliary"] += 1
                    result["auxiliary_records"] += 1
                    continue
                if operation != "QUERY" and not operation.startswith("QUERY_"):
                    self._unknown("parse_sql")
                    result["unknown_records"] += 1
                    continue
            try:
                row = model.parse_audit_record(segment, envelope, index)
                if source_ip is not None:
                    row["source_ip"] = source_ip
                disposition = model.row_disposition(row)
                if disposition == "change":
                    self._add_row(row)
                    result["change_records"] += 1
                elif disposition == "read":
                    self.coverage["filtered_queries"] += 1
                    result["read_records"] += 1
                elif disposition == "auxiliary":
                    self.coverage["filtered_auxiliary"] += 1
                    result["auxiliary_records"] += 1
                else:
                    self._unknown("unclassified_sql")
                    result["unknown_records"] += 1
            except (ValueError, TypeError, KeyError, OverflowError, InvalidOperation):
                self._unknown("parse_sql")
                result["unknown_records"] += 1
        return result

    def finish(self):
        coverage = {**self.coverage, "unknown_reasons": dict(sorted(self.unknown.items()))}
        payload = {**_summary_format(self.dimension), "summary_only": True,
                   "window": {"start_inclusive": _model().iso(self.start), "end_exclusive": _model().iso(self.end)},
                   "actors": sorted(self.actors.values(), key=lambda row: (-row["total"], row["actor_key"])),
                   "coverage": coverage, "complete": not self.unknown,
                   "errors": [{"scope": "summary_quality", "reason": reason, "count": count} for reason, count in sorted(self.unknown.items())]}
        save_summary(payload, self.directory)
        return payload


def merge_summaries(payloads, start, end, dimension="user"):
    """Merge disjoint segments; gaps remain explicitly incomplete."""
    dimension = _dimension(dimension)
    model = _model()
    start, end = model.timestamp(start), model.timestamp(end)
    if start >= end:
        raise ValueError("summary start must precede end")
    actors, coverage, unknown = {}, _empty_coverage(dimension), Counter()
    windows, complete = [], True
    for payload in payloads:
        expected_version = 3 if dimension == "ip" else 1
        if (type(payload.get("schema_version")) is not int or payload["schema_version"] != expected_version or
                payload.get("summary_only") is not True or
                (dimension == "ip" and payload.get("dimension") != "ip") or
                (dimension == "user" and payload.get("dimension") not in (None, "user"))):
            raise ValueError("unsupported operation summary format")
        if not isinstance(payload.get("complete"), bool) or not isinstance(payload.get("actors"), list) or not isinstance(payload.get("coverage"), dict):
            raise ValueError("invalid operation summary shape")
        window = payload["window"]
        left, right = model.timestamp(window["start_inclusive"]), model.timestamp(window["end_exclusive"])
        if not start <= left < right <= end:
            raise ValueError("summary segment leaves requested window")
        windows.append((left, right))
        complete &= payload.get("complete") is True
        for row in payload.get("actors", []):
            if dimension == "ip" and "source_ip" not in row:
                raise ValueError("IP operation summary is missing source_ip")
            sanitized = _actor(row, dimension)
            total, failed = _number(row["total"]), _number(row["failed"])
            counts = {category: _number(row["counts"].get(category, 0)) for category in CATEGORIES}
            attempted = {category: _number(row["attempted_counts"].get(category, 0)) for category in CATEGORIES}
            if failed + sum(counts.values()) != total or sum(attempted.values()) != total or any(counts[key] > attempted[key] for key in CATEGORIES):
                raise ValueError("inconsistent operation summary counters")
            target = actors.setdefault(sanitized["actor_key"], sanitized)
            target["total"] += total
            target["failed"] += failed
            for category in CATEGORIES:
                target["counts"][category] += counts[category]
                target["attempted_counts"][category] += attempted[category]
        for field in _coverage_fields(dimension):
            coverage[field] += _number(payload.get("coverage", {}).get(field, 0))
        if (dimension == "ip" and payload["coverage"].get("source_unreadable_records", 0)
                > payload["coverage"].get("unparsed_records", 0)):
            raise ValueError("unreadable source count exceeds unresolved records")
        for reason, count in payload.get("coverage", {}).get("unknown_reasons", {}).items():
            unknown[reason if reason in REASONS else "quarantine_sql"] += _number(count)
        if sum(payload.get("coverage", {}).get("unknown_reasons", {}).values()) != payload.get("coverage", {}).get("unparsed_records", 0):
            raise ValueError("inconsistent operation summary quality counters")
    position = start
    for left, right in sorted(windows):
        if left < position:
            raise ValueError("summary segments overlap")
        if left > position:
            complete = False
        position = right
    if position < end:
        complete = False
    coverage["unknown_reasons"] = dict(sorted(unknown.items()))
    return {**_summary_format(dimension), "summary_only": True,
            "window": {"start_inclusive": model.iso(start), "end_exclusive": model.iso(end)},
            "actors": sorted(actors.values(), key=lambda row: (-row["total"], row["actor_key"])),
            "coverage": coverage, "complete": bool(complete and not unknown),
            "errors": [{"scope": "summary_quality", "reason": reason, "count": count} for reason, count in sorted(unknown.items())]}


def summarize_archive(directory, start, end):
    """Read a legacy archive once without changing or copying its raw logs."""
    directory = Path(directory)
    with tempfile.TemporaryDirectory(prefix=".summary-convert-", dir=directory) as temporary:
        with SummaryAccumulator(temporary, start, end) as accumulator:
            def rows(path):
                try:
                    with path.open(encoding="utf-8-sig") as handle:
                        for line in handle:
                            if not line.strip():
                                continue
                            try:
                                row = json.loads(line)
                                if not isinstance(row, dict):
                                    raise ValueError("JSON line is not an object")
                            except (ValueError, TypeError):
                                accumulator._unknown("parse_jsonl")
                                continue
                            yield row
                except OSError:
                    accumulator._unknown("read_jsonl")

            for envelope in rows(directory / "management-events.jsonl"):
                accumulator.process_management(envelope)
            for path in sorted((directory / "cloudwatch").glob("*.jsonl")):
                for envelope in rows(path):
                    accumulator.process_audit(envelope)
            quarantine = directory / "quarantine" / "sql-unclassified.jsonl"
            if quarantine.is_file():
                for envelope in rows(quarantine):
                    accumulator.process_unknown(envelope, reason=envelope.get("reason", "quarantine_sql"))
            return accumulator.finish()


def validate_summary(payload, start, end, dimension="user"):
    model = _model()
    start, end = model.timestamp(start), model.timestamp(end)
    window = payload["window"]
    if model.timestamp(window["start_inclusive"]) != start or model.timestamp(window["end_exclusive"]) != end:
        raise ValueError("operation summary window does not match requested window")
    result = merge_summaries([payload], start, end, dimension=dimension)
    if payload.get("complete") is True and result["coverage"]["unparsed_records"]:
        raise ValueError("complete operation summary contains unresolved records")
    return result


def summarize_directory(directory, start, end):
    directory = Path(directory)
    source = directory / "operation-summary.json"
    if source.is_file():
        return validate_summary(json.loads(source.read_text(encoding="utf-8-sig")), start, end)
    return summarize_archive(directory, start, end)
