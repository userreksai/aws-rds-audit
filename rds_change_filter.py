"""Conservative collection-time filters; preserve uncertain records separately."""
from __future__ import annotations

from decimal import InvalidOperation

from rds_report import CHANGE_CATEGORIES, audit_record_indexes, classify_api, parse_audit_record, row_disposition, split_audit_message


def keep_management_event(raw_event: dict) -> bool:
    return classify_api(str(raw_event.get("eventName") or ""), raw_event.get("readOnly", False)) in CHANGE_CATEGORIES


def audit_event_decision(envelope: dict) -> dict:
    """Inspect each CSV record without mutating or splitting its source envelope.

    A mixed envelope is retained once if it contains any classified mutation.
    retained_segments lets the caller save only the original CRUD fragments,
    with original_record_indexes preserving each source record's identity.
    """
    result = {"keep": False, "change_records": 0, "read_records": 0, "auxiliary_records": 0, "unknown_records": [], "parse_errors": 0, "retained_segments": []}
    segments = split_audit_message(str(envelope.get("message") or ""))
    try:
        indexes = audit_record_indexes(envelope, len(segments))
    except ValueError as exc:
        result["parse_errors"] = 1
        result["unknown_records"].append({"reason": "parse_error", "message": str(exc), "raw": str(envelope.get("message") or ""), "record_index": None, **{key: envelope.get(key) for key in ("region", "eventId", "logGroupName", "logStreamName", "timestamp")}})
        return result
    for index, segment in zip(indexes, segments):
        reason, message = "", ""
        try:
            row = parse_audit_record(segment, envelope, index)
            disposition = row_disposition(row)
            if disposition == "change":
                result["change_records"] += 1
                result["keep"] = True
                result["retained_segments"].append({"raw": segment, "record_index": index})
            elif disposition == "read":
                result["read_records"] += 1
            elif disposition == "auxiliary":
                result["auxiliary_records"] += 1
            else:
                reason = "unclassified_sql"
                message = "SQL cannot be reliably classified as create/delete/modify"
        except (ValueError, TypeError, KeyError, OverflowError, InvalidOperation) as exc:
            reason, message = "parse_error", str(exc)
            result["parse_errors"] += 1
        if reason:
            result["unknown_records"].append({
                "reason": reason, "message": message, "raw": segment, "record_index": index,
                **{key: envelope.get(key) for key in ("region", "eventId", "logGroupName", "logStreamName", "timestamp")},
            })
    return result
