"""Configured daily report windows over complete, reusable collection buckets."""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
import re
from zoneinfo import ZoneInfo

UTC = timezone.utc


def configured_window(config):
    return bool(config.get("REPORT_START_TIME") and config.get("REPORT_END_TIME"))


def validate_report_schedule(config):
    values = [config.get(key, "") for key in ("REPORT_START_TIME", "REPORT_END_TIME")]
    for key, value in zip(("REPORT_START_TIME", "REPORT_END_TIME"), values):
        if not isinstance(value, str) or (value and not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value)):
            raise ValueError(key + " 必须为空或 HH:MM")
    if bool(values[0]) != bool(values[1]):
        raise ValueError("REPORT_START_TIME 和 REPORT_END_TIME 必须同时填写或同时留空")
    if not values[0]:
        return
    interval = config["COLLECTION_INTERVAL_MINUTES"]
    minutes = [int(value[:2]) * 60 + int(value[3:]) for value in values]
    if any(value % interval for value in minutes):
        raise ValueError("REPORT_START_TIME 和 REPORT_END_TIME 必须对齐 COLLECTION_INTERVAL_MINUTES 分段边界")
    mail_hour, mail_minute = map(int, config["DAILY_MAIL_TIME"].split(":"))
    if mail_hour * 60 + mail_minute < minutes[1] + config["LOG_DELAY_MINUTES"]:
        raise ValueError("DAILY_MAIL_TIME 必须不早于 REPORT_END_TIME 加 LOG_DELAY_MINUTES")


def report_window(config, end_day):
    """Interpret a configured date as the end date; legacy callers keep day dates."""
    zone = ZoneInfo(config["TIMEZONE"])
    start = datetime.combine(end_day - timedelta(days=1), time.fromisoformat(config["REPORT_START_TIME"]), zone)
    end = datetime.combine(end_day, time.fromisoformat(config["REPORT_END_TIME"]), zone)
    return start.astimezone(UTC), end.astimezone(UTC)


def window_tag(config):
    if not configured_window(config):
        return None
    return "window-" + config["REPORT_START_TIME"].replace(":", "") + "-" + config["REPORT_END_TIME"].replace(":", "")


def latest_report_day(config, now):
    local = now.astimezone(ZoneInfo(config["TIMEZONE"]))
    day = local.date()
    if not configured_window(config):
        return day - timedelta(days=1)
    _, end = report_window(config, day)
    return day if now >= end + timedelta(minutes=config["LOG_DELAY_MINUTES"]) else day - timedelta(days=1)


def report_segments(config, start, end):
    """Yield whole cached buckets inside the requested window across local dates."""
    from rds_multi import windows

    zone = ZoneInfo(config["TIMEZONE"])
    day = start.astimezone(zone).date()
    final = end.astimezone(zone).date()
    while day <= final:
        for left, right in windows(day, zone, config["COLLECTION_INTERVAL_MINUTES"]):
            if start <= left < right <= end:
                yield left, right
        day += timedelta(days=1)
