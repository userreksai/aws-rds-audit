"""Normalize RDS management/audit evidence and render a static Chinese daily report.

Counts describe API requests and SQL audit statements, never affected row counts.
Only unambiguous SQL statement prefixes are classified as create/delete/modify.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import html
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo

UTC = timezone.utc
BEIJING = ZoneInfo("Asia/Shanghai")
CATEGORIES = ("新增", "删除", "修改", "其他操作")
SOURCE_LABELS = {"management": "RDS 管理 API", "sql": "数据库 SQL 审计"}
SENSITIVE_PARTS = ("password", "secret", "token", "credential", "privatekey", "accesskey")
AUDIT_START = re.compile(r"(?m)^(?:\d{8}\s\d{2}:\d{2}:\d{2}|\d{10,16}(?:\.\d+)?),")
CONNECTION_TYPES = {"Undefined", "TCP/IP", "Socket", "Named pipe", "SSL/TLS", "Shared memory"}

CSS = """
:root{font-family:system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;color:#1b2c42;background:#f2f5f9;font-size:14px}*{box-sizing:border-box}body{margin:0}main{max-width:1560px;margin:auto;padding:32px 28px 64px}h1{font-size:30px;margin:0 0 10px}h2{font-size:21px;margin:0 0 18px}h3{font-size:17px;margin:0 0 10px}p{line-height:1.75}.muted,small{color:#586b80}.topline{display:flex;justify-content:space-between;gap:20px;align-items:start}.badge{display:inline-block;background:#e4edf7;color:#164d7b;border-radius:6px;padding:6px 10px;font-size:13px}.badge.error{background:#ffe8e4;color:#9a3126}.badge.demo{background:#fff2c8;color:#7b5a00}.window{margin:16px 0 22px}.cards{display:grid;grid-template-columns:repeat(3,minmax(120px,1fr));gap:16px;margin:22px 0}.card,section{background:white;border:1px solid #dfe6ee;border-radius:10px}.card{padding:20px 24px;border-top:4px solid #287d69}.card.delete{border-top-color:#c35b52}.card.modify{border-top-color:#bc8a2e}.card strong{display:block;font-size:36px;line-height:1.3}.card span{color:#4c6078}.card small{display:block;margin-top:10px}section{padding:24px;margin:22px 0}.notice{background:#eef4fa;border-left:4px solid #4d7caa;padding:12px 16px;line-height:1.8;margin:16px 0}.notice.error{background:#fff0ed;border-left-color:#c65d4f}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{background:#f1f5f9;text-align:left;color:#4b6078;font-weight:600;white-space:nowrap}td,th{padding:12px;border-bottom:1px solid #e1e8f0;vertical-align:top}td{line-height:1.7;overflow-wrap:anywhere}.number{text-align:right;font-variant-numeric:tabular-nums}.failed td{background:#fff5f2}.nowrap{white-space:nowrap}a{color:#1d63a1;text-decoration:none}a:hover{text-decoration:underline}details{margin-top:8px}summary{cursor:pointer;color:#1d63a1}pre{font:12px/1.65 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fa;border-radius:6px;padding:12px;max-width:100%}.actor-block{scroll-margin-top:16px;border-top:1px solid #dfe6ee;padding-top:22px;margin-top:26px}.actor-block:first-of-type{border-top:0;padding-top:0}.actor-meta{margin-bottom:12px}.chip{display:inline-block;padding:2px 8px;background:#edf2f7;border-radius:4px;font-size:12px}.operations .time{min-width:146px}.operations .operation{min-width:300px}.operations .resource{min-width:170px}.empty{color:#65788e;padding:16px 0}.fine{font-size:12px;color:#586b80}.coverage-list{padding-left:22px;line-height:1.9}@media(max-width:700px){main{padding:20px 12px}.topline{display:block}.cards{gap:8px}.card{padding:14px 12px}.card strong{font-size:28px}section{padding:16px}h1{font-size:25px}}
""".strip() + "\n"


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def timestamp(value) -> datetime:
    result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("record timestamp has no timezone")
    return result.astimezone(UTC)


def local_time(value) -> str:
    return timestamp(value).astimezone(BEIJING).strftime("%Y-%m-%d %H:%M:%S")


def redact_text(value: str) -> str:
    # SQL credentials are removed conservatively through the rest of the statement.
    # Other SQL values may contain business data; this is stated in report coverage.
    return re.sub(
        r"(?is)(\bIDENTIFIED\s+(?:WITH\s+[\w]+\s+)?(?:BY|AS)\s+|\b(?:PASSWORD|SECRET_ACCESS_KEY|SESSION_TOKEN)\s*=\s*).*",
        r"\1[REDACTED]", value,
    )


def redact(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            compact = re.sub(r"[^a-z0-9]", "", str(key).lower())
            result[key] = "[REDACTED]" if any(part in compact for part in SENSITIVE_PARTS) else redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value


def classify_api(name: str, read_only=False) -> str:
    if str(read_only).lower() == "true" or name.startswith(("Describe", "Get", "List", "Download", "Describe")):
        return "其他操作"
    if name.startswith(("AddTags", "RemoveTags", "Associate", "Disassociate")):
        return "修改"
    if name.startswith(("Create", "Restore", "Copy", "Import", "Register", "Add", "Authorize", "Purchase")):
        return "新增"
    if name.startswith(("Delete", "Remove", "Deregister", "Revoke")):
        return "删除"
    if name.startswith(("Modify", "Update", "Reboot", "Start", "Stop", "Failover", "Promote", "Reset", "Apply", "Enable", "Disable", "Switchover", "Tag", "Untag")):
        return "修改"
    return "其他操作"


def classify_sql(sql: str) -> str:
    remaining = sql.lstrip()
    while remaining:
        if remaining.startswith("/*") and not remaining.startswith(("/*!", "/*+")):
            end = remaining.find("*/")
            if end < 0:
                return "其他操作"
            remaining = remaining[end + 2:].lstrip()
            continue
        comment = re.match(r"(?:--(?=\s)|#)[^\r\n]*(?:\r?\n|$)", remaining)
        if comment:
            remaining = remaining[comment.end():].lstrip()
            continue
        break
    word = re.match(r"[A-Za-z]+", remaining)
    command = word.group().upper() if word else ""
    # This parser deliberately does not implement MySQL's complete lexical rules.
    # An internal semicolon can delimit another statement or be a literal value;
    # preserve such ambiguous batches as other operations instead of counting the
    # first keyword as the category of the whole audit record.
    if ";" in remaining.rstrip().removesuffix(";"):
        return "其他操作"
    if command in {"INSERT", "CREATE"}:
        return "新增"
    if command in {"DELETE", "DROP", "TRUNCATE"}:
        return "删除"
    if command in {"UPDATE", "ALTER", "RENAME", "GRANT", "REVOKE"}:
        return "修改"
    return "其他操作"


def _actor(identity, fallback=""):
    identity = identity if isinstance(identity, dict) else {}
    arn = str(identity.get("arn") or "")
    kind = identity.get("type") or "Unknown"
    if kind == "Root":
        display = "Root（AWS 根用户）"
    elif kind == "AWSService":
        display = str(identity.get("invokedBy") or "AWS 服务")
    else:
        display = str(identity.get("userName") or (arn.split(":assumed-role/", 1)[-1] if ":assumed-role/" in arn else arn) or fallback or identity.get("principalId") or "未知 AWS 身份")
    return display, arn or str(identity.get("principalId") or display)


def _resources(event):
    values = []
    for item in event.get("resources") or []:
        if isinstance(item, dict):
            value = item.get("ARN") or item.get("arn") or item.get("ResourceName")
            if value:
                values.append(str(value))
    params = event.get("requestParameters") or {}
    if isinstance(params, dict):
        for key, value in params.items():
            compact = re.sub(r"[^a-z]", "", str(key).lower())
            if compact in {"dbinstanceidentifier", "dbclusteridentifier", "dbsnapshotidentifier", "dbclustersnapshotidentifier", "dbparametergroupname", "dbclusterparametergroupname", "optiongroupname", "resourcearn", "sourcedbinstanceidentifier", "targetdbinstanceidentifier"} and value is not None:
                values.append(f"{key}={value}")
    return list(dict.fromkeys(values))


def normalize_management(envelope):
    event = envelope["event"]
    if not isinstance(event, dict):
        raise ValueError("CloudTrail event is not an object")
    lookup = envelope.get("lookup") or {}
    occurred = timestamp(event.get("eventTime") or lookup.get("EventTime"))
    name = str(event.get("eventName") or lookup.get("EventName") or "未知 API")
    identity = event.get("userIdentity") or {}
    actor, actor_key = _actor(identity, lookup.get("Username", ""))
    failed = bool(event.get("errorCode") or event.get("errorMessage"))
    category = classify_api(name, event.get("readOnly", lookup.get("ReadOnly", False)))
    event_id = str(event.get("eventID") or lookup.get("EventId") or "")
    if not event_id:
        raise ValueError("CloudTrail event has no eventID")
    return {
        "event_id": event_id, "source_kind": "management", "source": "rds.amazonaws.com",
        "time_utc": iso(occurred), "time_local": local_time(occurred), "actor": actor,
        "actor_key": "management:" + actor_key, "actor_type": "AWS 身份", "identity": redact(identity),
        "category": category, "counted": not failed, "status": "failed" if failed else "success",
        "event_name": name, "description": name, "region": str(envelope.get("region") or event.get("awsRegion") or ""),
        "source_ip": str(event.get("sourceIPAddress") or ""), "resources": _resources(event),
        "result": "失败：" + str(event.get("errorCode") or event.get("errorMessage")) if failed else "API 未报错（异步结果需核实）",
        "parameters": redact(event.get("requestParameters")), "response": redact(event.get("responseElements")),
        "error_code": str(event.get("errorCode") or ""), "error_message": redact_text(str(event.get("errorMessage") or "")),
        "user_agent": str(event.get("userAgent") or ""),
    }


def _read_prefix(record: str):
    # The first eight CSV fields precede SQL. Reading them separately avoids
    # splitting SQL commas or interpreting its quotes/backslashes as CSV escapes.
    fields = []
    position = 0
    for _ in range(8):
        if position >= len(record):
            raise ValueError("audit record has fewer than ten fields")
        if record[position] in "\"'":
            quote, position = record[position], position + 1
            value = []
            while position < len(record):
                char = record[position]
                if char == quote:
                    if record[position:position + 2] == quote * 2:
                        value.append(quote)
                        position += 2
                        continue
                    position += 1
                    break
                if char == "\\" and position + 1 < len(record):
                    value.extend(record[position:position + 2])
                    position += 2
                else:
                    value.append(char)
                    position += 1
            else:
                raise ValueError("unterminated quoted CSV field")
            if position >= len(record) or record[position] != ",":
                raise ValueError("invalid quoted CSV field delimiter")
            fields.append("".join(value))
        else:
            end = record.find(",", position)
            if end < 0:
                raise ValueError("audit record has fewer than ten fields")
            fields.append(record[position:end])
            position = end
        position += 1
    return fields, record[position:]


def parse_audit_record(record: str, envelope: dict, index=0):
    fields, tail = _read_prefix(record.strip())
    # RDS MySQL can append connection_type after retcode. Aurora has ten fields.
    object_and_code = tail.rsplit(",", 1)
    if len(object_and_code) != 2:
        raise ValueError("audit record is missing return code")
    if object_and_code[-1].strip() in CONNECTION_TYPES:
        object_and_code = object_and_code[0].rsplit(",", 1)
    if len(object_and_code) != 2 or not re.fullmatch(r"-?\d+", object_and_code[-1].strip()):
        raise ValueError("audit return code is not an integer or record is truncated")
    object_text, retcode = object_and_code[0], int(object_and_code[-1])
    if object_text.startswith(("'", '"')):
        if len(object_text) < 2 or object_text[-1] != object_text[0]:
            raise ValueError("audit SQL quote is not closed; record may be truncated")
        object_text = object_text[1:-1]
    raw_time, serverhost, username, host, connection_id, query_id, operation, database = fields
    if not serverhost or not operation:
        raise ValueError("audit serverhost or operation is missing")
    cw_time = datetime.fromtimestamp(int(envelope["timestamp"]) / 1000, UTC)
    if re.fullmatch(r"\d{10,16}(?:\.\d+)?", raw_time):
        number = Decimal(raw_time)
        if number >= Decimal("100000000000000"):
            number /= 1000000
        elif number >= Decimal("100000000000"):
            number /= 1000
        occurred = datetime.fromtimestamp(float(number), UTC)
        time_source = "审计日志 Unix 时间戳"
    elif re.fullmatch(r"\d{8}\s\d{2}:\d{2}:\d{2}", raw_time):
        datetime.strptime(raw_time, "%Y%m%d %H:%M:%S")
        occurred, time_source = cw_time, "CloudWatch 事件时间（日志原时间无时区）"
    else:
        raise ValueError("unsupported audit timestamp")
    operation = operation.upper()
    is_query = operation == "QUERY" or operation.startswith("QUERY_")
    sql = redact_text(object_text) if is_query else ""
    category = classify_sql(object_text) if is_query else "其他操作"
    failed = retcode != 0
    actor = username or "未知数据库账号"
    group, stream = str(envelope.get("logGroupName") or ""), str(envelope.get("logStreamName") or "")
    key = ":".join((group, stream, serverhost, username))
    return {
        "event_id": str(envelope.get("eventId") or "") + f":{index}", "source_kind": "sql", "source": "mysql.audit",
        "time_utc": iso(occurred), "time_local": local_time(occurred), "timestamp_raw": raw_time, "timestamp_source": time_source,
        "actor": actor, "actor_key": "sql:" + key, "actor_type": "数据库账号", "identity": {"username": actor, "serverhost": serverhost, "connection_id": connection_id, "query_id": query_id},
        "category": category, "counted": is_query and not failed, "status": "failed" if failed else "success",
        "event_name": operation, "description": sql if is_query else f"{operation} {object_text}".strip(), "sql": sql,
        "region": str(envelope.get("region") or ""), "source_ip": host,
        "resources": [item for item in (serverhost, f"数据库：{database}" if database else "", f"对象：{object_text}" if object_text and not is_query else "") if item],
        "database": database, "serverhost": serverhost, "log_group": group, "log_stream": stream,
        "return_code": retcode, "result": f"失败：返回码 {retcode}" if failed else ("返回码 0（不证明事务提交）" if is_query else "返回码 0（辅助审计事件，不计入语句汇总）"),
        "parameters": None, "response": None, "error_code": str(retcode) if failed else "", "error_message": "", "user_agent": "",
    }


def _json_lines(path, errors):
    try:
        with path.open(encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    result = json.loads(line)
                    if not isinstance(result, dict):
                        raise ValueError("JSON line is not an object")
                    yield line_number, result
                except (ValueError, TypeError) as exc:
                    errors.append({"scope": "parse_jsonl", "file": path.name, "line": line_number, "message": str(exc)})
    except OSError as exc:
        errors.append({"scope": "read_jsonl", "file": path.name, "message": str(exc)})


def build_daily_report(directory: Path, *, audit_date: str, start: datetime, end: datetime, offline=False) -> dict:
    directory = Path(directory)
    start, end = timestamp(start), timestamp(end)
    if start >= end:
        raise ValueError("report window start must precede end")
    # Never interpolate an arbitrary supplied date into an output pathname.
    datetime.strptime(audit_date, "%Y-%m-%d")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", audit_date):
        raise ValueError("audit_date must be YYYY-MM-DD")
    collection = json.loads((directory / "report.json").read_text(encoding="utf-8-sig"))
    errors = [redact(check) for check in collection.get("checks", []) if check.get("status") == "error"]
    events, unparsed, seen_management, seen_sql = [], [], set(), set()
    for line_number, envelope in _json_lines(directory / "management-events.jsonl", errors):
        try:
            row = normalize_management(envelope)
            if not start <= timestamp(row["time_utc"]) < end or row["event_id"] in seen_management:
                continue
            seen_management.add(row["event_id"])
            events.append(row)
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            errors.append({"scope": "parse_management", "line": line_number, "message": str(exc)})
    general_count, audit_envelopes, sql_duplicates = 0, 0, 0
    for path in sorted((directory / "cloudwatch").glob("*.jsonl")):
        for line_number, envelope in _json_lines(path, errors):
            group = str(envelope.get("logGroupName") or "")
            if group.endswith("/general"):
                general_count += 1
                continue
            if not group.endswith("/audit"):
                continue
            # eventId is unique only within a log stream; SQL text isn't a dedup key.
            event_id = str(envelope.get("eventId") or "")
            if not event_id:
                errors.append({"scope": "parse_sql", "file": path.name, "line": line_number, "message": "CloudWatch audit event has no eventId; no safe dedup key"})
            else:
                dedup = (str(envelope.get("region") or ""), group, str(envelope.get("logStreamName") or ""), event_id)
                if dedup in seen_sql:
                    sql_duplicates += 1
                    continue
                seen_sql.add(dedup)
            audit_envelopes += 1
            message = str(envelope.get("message") or "")
            starts = [match.start() for match in AUDIT_START.finditer(message)]
            if not starts or message[:starts[0]].strip():
                starts = []
            segments = [message[position:(starts[index + 1] if index + 1 < len(starts) else len(message))] for index, position in enumerate(starts)] or [message]
            for index, segment in enumerate(segments):
                try:
                    row = parse_audit_record(segment, envelope, index)
                    if start <= timestamp(row["time_utc"]) < end:
                        events.append(row)
                except (ValueError, TypeError, KeyError, OverflowError, InvalidOperation) as exc:
                    evidence = {"scope": "parse_sql", "file": path.name, "line": line_number, "record_index": index, "message": str(exc), "log_group": group, "log_stream": str(envelope.get("logStreamName") or ""), "raw": redact_text(segment)}
                    unparsed.append(evidence)
                    errors.append({key: value for key, value in evidence.items() if key != "raw"})
    events.sort(key=lambda row: (row["time_utc"], row["source_kind"], row["event_id"]))
    counts = dict.fromkeys(CATEGORIES, 0)
    attempted = dict.fromkeys(CATEGORIES, 0)
    by_source = {kind: {"label": label, "total": 0, "failed": 0, "counted_total": 0, "counts": dict.fromkeys(CATEGORIES, 0), "attempted_counts": dict.fromkeys(CATEGORIES, 0)} for kind, label in SOURCE_LABELS.items()}
    actor_rows = {}
    for row in events:
        source = by_source[row["source_kind"]]
        source["total"] += 1
        source["failed"] += row["status"] == "failed"
        attempted[row["category"]] += 1
        source["attempted_counts"][row["category"]] += 1
        key = row["actor_key"]
        actor_row = actor_rows.setdefault(key, {"actor": row["actor"], "actor_key": key, "actor_type": row["actor_type"], "source_kind": row["source_kind"], "total": 0, "failed": 0, "counts": dict.fromkeys(CATEGORIES, 0), "anchor": "actor-" + hashlib.sha256(key.encode()).hexdigest()[:16]})
        actor_row["total"] += 1
        actor_row["failed"] += row["status"] == "failed"
        if row["counted"]:
            counts[row["category"]] += 1
            source["counts"][row["category"]] += 1
            source["counted_total"] += 1
            actor_row["counts"][row["category"]] += 1
    notes = [
        "新增、删除、修改统计的是日志中未报错的 API 请求或 SQL 语句条数，不是受影响行数。失败请求保留在明细和失败数量中，不计入成功返回的增删改。",
        "API 未报错不保证异步变更最终完成；SQL 返回码 0 不证明事务最终 COMMIT。两种来源分别汇总，共用数据库账号不能推定真实人员。",
        "只对可见的 audit 日志进行 SQL 分类；general 日志保留原文而不重复计数，TABLE/连接等辅助审计事件只列明细，不计入语句数量。复杂 WITH、CALL、PREPARE、EXECUTE、包含内部分号的语句等无法可靠识别时保留其他操作。",
        "无日志不等于无 SQL 操作：审计可能未启用、被用户/事件过滤、延迟、截断或超过保留期。当前配置不能证明历史覆盖完整。",
        "MySQL 无时区的日志原时间不用于猜测时区，报告使用 CloudWatch 事件时间；原时间保留。Aurora Unix 时间戳按 UTC 转换。",
        "SQL 正文可能包含业务数据。已对常见凭据字段和口令语句脱敏，无法保证识别全部业务敏感值；请限制报告访问。",
        "相邻日报的前一日 07:00 至当日 08:00 窗口有意重叠 1 小时，跨日报数量不可直接相加。",
    ]
    if not collection.get("sql_log_download_requested"):
        notes.append("本次未请求下载 CloudWatch SQL 日志，数据库内部增删改未建立采集覆盖。")
    if not audit_envelopes:
        notes.append("本次没有可解析的 CloudWatch audit 事件输入；不能据此认定数据库内部没有增删改。")
    return {
        "metadata": {
            "audit_date": audit_date, "account_id": str(collection.get("identity", {}).get("Account") or "unknown"),
            "generated_at": iso(datetime.now(UTC)), "window_start_utc": iso(start), "window_end_utc_exclusive": iso(end),
            "timezone": "Asia/Shanghai", "complete": collection.get("collection_status") == "ok" and not errors,
            "report_type": "rds", "source_counts": {key: value["counts"] for key, value in by_source.items()},
            "errors": errors, "offline": bool(offline), "example_data": bool(collection.get("example_data", False)), "counts": counts, "attempted_counts": attempted,
            "total": len(events), "counted_total": sum(counts.values()), "failed_or_partial": sum(row["status"] == "failed" for row in events),
            "historical_sql_completeness": "not_established", "report_filename": f"{audit_date}-rds操作审计.html",
        },
        "events": events, "by_source": by_source,
        "actors": sorted(actor_rows.values(), key=lambda item: (-item["total"], item["actor_key"])),
        "coverage": {"notes": notes, "audit_cloudwatch_events": audit_envelopes, "general_log_events_not_counted": general_count, "duplicate_cloudwatch_events": sql_duplicates, "unparsed_records": len(unparsed), "collection_status": collection.get("collection_status", "unknown")},
        "unparsed": unparsed,
    }


def _e(value):
    return html.escape(str(value), quote=True)


def _json(value):
    return _e(json.dumps(redact(value), ensure_ascii=False, indent=2))


def generate_html(report: dict) -> str:
    meta = report["metadata"]
    cards = []
    for category, css_class in (("新增", "create"), ("删除", "delete"), ("修改", "modify")):
        parts = [f"{_e(source['label'])} {int(source['counts'].get(category, 0))}" for source in report["by_source"].values()]
        cards.append(f'<div class="card {css_class}"><span>{category}</span><strong>{int(meta["counts"].get(category, 0))}</strong><small>{" · ".join(parts)}</small></div>')
    badges = '<span class="badge">采集步骤完成</span>' if meta["complete"] else '<span class="badge error">采集或解析不完整</span>'
    if meta.get("example_data"):
        badges += ' <span class="badge demo">虚构示例，非真实账号数据</span>'
    elif meta.get("offline"):
        badges += ' <span class="badge demo">离线输入，未向 AWS 验证</span>'
    source_rows = []
    for source in report["by_source"].values():
        cells = "".join(f'<td class="number">{int(source["counts"][category])}</td>' for category in CATEGORIES)
        source_rows.append(f'<tr><td>{_e(source["label"])}</td>{cells}<td class="number">{source["failed"]}</td><td class="number">{source["total"]}</td></tr>')
    actor_summary = []
    for actor in report["actors"]:
        cells = "".join(f'<td class="number">{int(actor["counts"][category])}</td>' for category in CATEGORIES[:3])
        actor_summary.append(f'<tr><td><a href="#{actor["anchor"]}">{_e(actor["actor"])}</a><br><small>{_e(actor["actor_type"])}</small></td><td>{_e(SOURCE_LABELS[actor["source_kind"]])}</td>{cells}<td class="number">{actor["failed"]}</td><td class="number">{actor["total"]}</td></tr>')
    grouped = defaultdict(list)
    for row in report["events"]:
        grouped[row["actor_key"]].append(row)
    operations = []
    for actor in report["actors"]:
        rows = []
        for row in grouped[actor["actor_key"]]:
            details = {"记录ID": row["event_id"], "身份": row.get("identity"), "时间来源": row.get("timestamp_source", "CloudTrail eventTime"), "原日志时间": row.get("timestamp_raw", ""), "日志组": row.get("log_group", ""), "日志流": row.get("log_stream", ""), "请求参数": row.get("parameters"), "响应": row.get("response"), "错误码": row.get("error_code", ""), "错误信息": row.get("error_message", ""), "UserAgent": row.get("user_agent", "")}
            description = _e(row.get("description") or row["event_name"])
            if row.get("sql"):
                description = f'<pre>{description}</pre>'
            resource = "<br>".join(_e(item) for item in row.get("resources", [])) or "—"
            result_class = ' class="failed"' if row["status"] == "failed" else ""
            rows.append(f'<tr{result_class}><td class="time nowrap">{_e(row["time_local"])}</td><td><span class="chip">{_e(row["category"])}</span></td><td class="operation">{description}<details><summary>身份与操作参数</summary><pre>{_json(details)}</pre></details></td><td class="resource">{resource}</td><td>{_e(row["source_ip"]) or "—"}<br><small>{_e(row["region"])}</small></td><td>{_e(row["result"])}</td></tr>')
        operations.append(f'<div class="actor-block" id="{actor["anchor"]}"><h3>{_e(actor["actor"])}</h3><div class="actor-meta muted">{_e(actor["actor_type"])} · {_e(SOURCE_LABELS[actor["source_kind"]])} · {actor["total"]} 条记录</div><div class="scroll"><table class="operations"><thead><tr><th>北京时间</th><th>分类</th><th>操作信息</th><th>资源 / 数据库</th><th>来源 / 区域</th><th>请求结果</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></div>')
    coverage_notes = "".join(f"<li>{_e(note)}</li>" for note in report["coverage"]["notes"])
    errors = ""
    if meta["errors"]:
        errors = f'<div class="notice error">存在 {len(meta["errors"])} 项采集或解析失败，当前数量仅包含已取得的记录。请检查并补跑。</div><details><summary>查看失败范围</summary><pre>{_json(meta["errors"])}</pre></details>'
    unparsed = ""
    if report.get("unparsed"):
        unparsed = f'<details><summary>查看未解析审计记录（{len(report["unparsed"])} 条，未纳入操作计数）</summary><pre>{_json(report["unparsed"])}</pre></details>'
    css_version = hashlib.sha256(CSS.encode()).hexdigest()[:12]
    empty = '<p class="empty">当前范围没有取得操作记录，请同时核对采集状态和 SQL 审计覆盖。</p>'
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(meta["audit_date"])} RDS 操作审计日报</title><link rel="stylesheet" href="rds-report.css?v={css_version}"></head>
<body><main><header><div class="topline"><div><h1>RDS 操作审计日报</h1><div class="muted">报告日期 {_e(meta["audit_date"])} · AWS 账号 {_e(meta["account_id"])}</div></div><div>{badges}</div></div><p class="window">北京时间 {_e(local_time(meta["window_start_utc"]))} 至 {_e(local_time(meta["window_end_utc_exclusive"]))}（左闭右开）<br><small>生成于 {_e(local_time(meta["generated_at"]))}（北京时间）</small></p></header>
<div class="cards">{"".join(cards)}</div><p class="fine">增删改按未报错的请求 / 语句计数；不等于影响行数或最终提交结果。共 {meta["total"]} 条明细，其中失败 {meta["failed_or_partial"]} 条。</p>
<section><h2>按来源汇总</h2><div class="scroll"><table><thead><tr><th>来源</th><th>新增</th><th>删除</th><th>修改</th><th>其他未报错记录</th><th>失败记录</th><th>全部明细</th></tr></thead><tbody>{"".join(source_rows)}</tbody></table></div><p class="fine">SQL 的连接、表访问等辅助事件只列明细，不加入语句汇总，因此汇总列之和可能小于全部明细。</p></section>
<section><h2>按操作者汇总</h2><p class="muted">点击操作者查看对应明细；AWS 身份与数据库账号分别展示，角色会话名不等于真实人员姓名。</p><div class="scroll"><table><thead><tr><th>操作者</th><th>来源</th><th>新增</th><th>删除</th><th>修改</th><th>失败</th><th>明细数量</th></tr></thead><tbody>{"".join(actor_summary)}</tbody></table></div>{empty if not actor_summary else ""}</section>
<section><h2>人员与操作明细</h2>{"".join(operations) or empty}</section>
<section><h2>采集状态与统计口径</h2>{errors}<ul class="coverage-list">{coverage_notes}</ul>{unparsed}<p class="fine">本次 audit CloudWatch 事件 {report["coverage"]["audit_cloudwatch_events"]} 条；general 原文事件 {report["coverage"]["general_log_events_not_counted"]} 条（不重复计数）；未解析记录 {report["coverage"]["unparsed_records"]} 条。</p></section>
</main></body></html>'''


def write_report(report: dict, directory: Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    filename = report["metadata"]["report_filename"]
    if Path(filename).name != filename or not re.fullmatch(r"\d{4}-\d{2}-\d{2}-rds操作审计\.html", filename):
        raise ValueError("unsafe report filename")
    (directory / "daily-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "rds-report.css").write_text(CSS, encoding="utf-8")
    path = directory / filename
    path.write_text(generate_html(report), encoding="utf-8")
    return path
