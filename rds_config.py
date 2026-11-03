"""Validated private JSON/JSONC settings for multi-account RDS IP audit delivery.

Configuration errors name fields, never credential values or provider replies.
Relative data/font paths are resolved beside the configuration file.
"""
from __future__ import annotations

from copy import deepcopy
from email.utils import parseaddr
import json
import math
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULTS = {
    "OUTPUT_DIRECTORY": "output",
    "COLLECTION_INTERVAL_MINUTES": 30,
    "ACCOUNT_CONCURRENCY": 7,
    "RETENTION_DAYS": 7,
    "TIMEZONE": "Asia/Shanghai",
    "DAILY_MAIL_TIME": "08:10",
    "MAIL_REPORT_MODE": "previous_day",
    "MAIL_SUBJECT": "AW-RDS审计报告",
    "MAIL_SENDER_NAME": "",
    "SMTP_HOST": "",
    "SMTP_PORT": 465,
    "SMTP_USERNAME": "",
    "SMTP_AUTH_CODE": "",
    "SMTP_SECURITY": "ssl",
    "SMTP_TIMEOUT": 30,
    "MAIL_RECIPIENTS": [],
    "MAIL_CC": [],
    "PDF_FONT_PATH": "",
    "MAX_BUCKETS_PER_ACCOUNT_PER_RUN": 6,
    "LOG_DELAY_MINUTES": 5,
    "REFRESH_DELAY_MINUTES": 60,
    # Existing JSON files keep their prior notification behavior. New templates
    # explicitly opt into collection-failure alerts after one failed retry.
    "LARK_ALERTS_ENABLED": False,
    "LARK_WEBHOOK_URL": "",
    "LARK_SIGNING_SECRET": "",
    "LARK_ALERT_AFTER_FAILURES": 2,
    "LARK_ALERT_REPEAT_MINUTES": 60,
    "LARK_NOTIFICATION_RETRY_MINUTES": 5,
}
ACCOUNT_DEFAULTS = {
    "AWS_ACCESS_KEY_ID": "",
    "AWS_SECRET_ACCESS_KEY": "",
    "AWS_SESSION_TOKEN": "",
    "AWS_PROFILE": "",
    "REGIONS": "all",
    "ENABLED": True,
}
_REGION = re.compile(r"[a-z]{2,}(?:-[a-z0-9]+)+-\d+\Z")


def _text(value, name, *, required=False):
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(name + " 必须是无控制字符的字符串")
    value = value.strip()
    if required and not value:
        raise ValueError(name + " 不能为空")
    return value


def _integer(value, name, minimum=1, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(name + " 必须为有效整数")
    return value


def _addresses(value, name):
    if not isinstance(value, list):
        raise ValueError(name + " 必须为邮箱地址数组")
    result = []
    for item in value:
        address = _text(item, name, required=True)
        parsed_name, parsed_address = parseaddr(address)
        if (parsed_name or parsed_address != address
                or not re.fullmatch(r"[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+", address)):
            raise ValueError(name + " 包含无效邮箱地址")
        local, domain = address.rsplit("@", 1)
        if not local or not domain:
            raise ValueError(name + " 包含无效邮箱地址")
        if address not in result:
            result.append(address)
    return result


def validate_mail_config(config, require_complete=True):
    """Return validated mail settings; blank credentials are allowed in templates."""
    if not isinstance(config, dict):
        raise ValueError("邮件配置必须为对象")
    result = {key: deepcopy(config.get(key, value)) for key, value in DEFAULTS.items()
              if key.startswith(("SMTP_", "MAIL_")) and key != "MAIL_REPORT_MODE"}
    for key in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE", "MAIL_SUBJECT", "MAIL_SENDER_NAME", "SMTP_SECURITY"):
        result[key] = _text(result[key], key)
    if not result["MAIL_SUBJECT"]:
        raise ValueError("MAIL_SUBJECT 不能为空")
    _integer(result["SMTP_PORT"], "SMTP_PORT", maximum=65535)
    if result["SMTP_SECURITY"] not in ("ssl", "starttls"):
        raise ValueError("SMTP_SECURITY 必须为 ssl 或 starttls")
    timeout = result["SMTP_TIMEOUT"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 600):
        raise ValueError("SMTP_TIMEOUT 必须大于 0 且不超过 600 秒")
    result["MAIL_RECIPIENTS"] = _addresses(result["MAIL_RECIPIENTS"], "MAIL_RECIPIENTS")
    result["MAIL_CC"] = _addresses(result["MAIL_CC"], "MAIL_CC")
    if require_complete:
        for key in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE"):
            if not result[key]:
                raise ValueError(key + " 不能为空")
        if not result["MAIL_RECIPIENTS"]:
            raise ValueError("MAIL_RECIPIENTS 至少配置一个收件人")
        _addresses([result["SMTP_USERNAME"]], "SMTP_USERNAME")
    return result


def _regions(value):
    if isinstance(value, str):
        if value.strip() == "all":
            return "all"
        values = value.split(",")
    elif isinstance(value, list):
        values = value
    else:
        raise ValueError("ACCOUNTS.REGIONS 必须为 all、区域数组或逗号分隔字符串")
    regions = []
    for item in values:
        region = _text(item, "ACCOUNTS.REGIONS", required=True)
        if not _REGION.fullmatch(region):
            raise ValueError("ACCOUNTS.REGIONS 包含无效区域")
        if region not in regions:
            regions.append(region)
    if not regions:
        raise ValueError("ACCOUNTS.REGIONS 不能为空")
    return ",".join(regions)


def _validate_lark_settings(config, require_complete):
    if not isinstance(config["LARK_ALERTS_ENABLED"], bool):
        raise ValueError("LARK_ALERTS_ENABLED 必须为 true 或 false")
    for key in ("LARK_WEBHOOK_URL", "LARK_SIGNING_SECRET"):
        config[key] = _text(config[key], key)
    _integer(config["LARK_ALERT_AFTER_FAILURES"], "LARK_ALERT_AFTER_FAILURES", minimum=2)
    _integer(config["LARK_ALERT_REPEAT_MINUTES"], "LARK_ALERT_REPEAT_MINUTES")
    _integer(config["LARK_NOTIFICATION_RETRY_MINUTES"], "LARK_NOTIFICATION_RETRY_MINUTES")
    if config["LARK_WEBHOOK_URL"]:
        from lark_notify import validate_webhook_url

        try:
            validate_webhook_url(config["LARK_WEBHOOK_URL"])
        except ValueError:
            # Do not propagate a token-bearing URL or any future validator's
            # arbitrary message into unattended task logs.
            raise ValueError("LARK_WEBHOOK_URL 必须为有效的 Lark/飞书 HTTPS 群机器人地址") from None
    elif require_complete and config["LARK_ALERTS_ENABLED"]:
        raise ValueError("启用异常群通知时必须填写 LARK_WEBHOOK_URL")


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("配置存在重复字段")
        result[key] = value
    return result


def strip_json_comments(text):
    """Remove JSONC comments while preserving strings and source positions.

    Comment characters become spaces, with CR/LF kept intact. This prevents a
    comment between two tokens from silently joining them, and keeps JSON
    decoder line numbers useful. Escaped quotes and backslashes are scanned
    before testing string delimiters; URL slashes inside strings are literal.
    Trailing commas and other JSON extensions are deliberately not accepted by
    the subsequent JSON decoder.
    """
    if not isinstance(text, str):
        raise ValueError("配置内容必须为字符串")
    result = []
    position, length = 0, len(text)
    in_string = escaped = False
    while position < length:
        char = text[position]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            position += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            position += 1
            continue
        if char == "/" and position + 1 < length and text[position + 1] == "/":
            result.extend((" ", " "))
            position += 2
            while position < length and text[position] not in "\r\n":
                result.append(" ")
                position += 1
            continue
        if char == "/" and position + 1 < length and text[position + 1] == "*":
            result.extend((" ", " "))
            position += 2
            while position < length:
                if text[position:position + 2] == "*/":
                    result.extend((" ", " "))
                    position += 2
                    break
                result.append(text[position] if text[position] in "\r\n" else " ")
                position += 1
            else:
                raise ValueError("配置块注释未闭合")
            continue
        result.append(char)
        position += 1
    if in_string:
        raise ValueError("配置字符串未闭合")
    return "".join(result)


def _reject_json_constant(_value):
    raise ValueError("配置不能包含非 JSON 数值常量")


def load_config(path, require_mail=False):
    """Load private settings without creating files or contacting AWS/SMTP."""
    source = Path(path).expanduser().resolve()
    try:
        content = strip_json_comments(source.read_text(encoding="utf-8-sig"))
        raw = json.loads(content, object_pairs_hook=_unique_json_pairs, parse_constant=_reject_json_constant)
    except OSError:
        raise ValueError("无法读取配置文件，请检查路径和权限") from None
    except (ValueError, UnicodeError):
        raise ValueError("配置文件不是有效且无重复字段的 UTF-8 JSON/JSONC，请检查语法和注释闭合") from None
    if not isinstance(raw, dict):
        raise ValueError("配置必须为 JSON 对象")
    result = {**deepcopy(DEFAULTS), **raw}
    for key in ("OUTPUT_DIRECTORY", "TIMEZONE", "DAILY_MAIL_TIME", "MAIL_REPORT_MODE", "PDF_FONT_PATH"):
        result[key] = _text(result[key], key, required=key != "PDF_FONT_PATH")
    output = Path(result["OUTPUT_DIRECTORY"]).expanduser()
    result["OUTPUT_DIRECTORY"] = str((source.parent / output).resolve() if not output.is_absolute() else output.resolve())
    if result["PDF_FONT_PATH"]:
        font = Path(result["PDF_FONT_PATH"]).expanduser()
        result["PDF_FONT_PATH"] = str((source.parent / font).resolve() if not font.is_absolute() else font.resolve())
    _integer(result["COLLECTION_INTERVAL_MINUTES"], "COLLECTION_INTERVAL_MINUTES")
    if result["COLLECTION_INTERVAL_MINUTES"] not in (30, 60):
        raise ValueError("COLLECTION_INTERVAL_MINUTES 必须为 30 或 60")
    _integer(result["ACCOUNT_CONCURRENCY"], "ACCOUNT_CONCURRENCY", maximum=32)
    # Yesterday must survive until its scheduled morning PDF/mail is produced.
    _integer(result["RETENTION_DAYS"], "RETENTION_DAYS", minimum=2)
    _integer(result["MAX_BUCKETS_PER_ACCOUNT_PER_RUN"], "MAX_BUCKETS_PER_ACCOUNT_PER_RUN")
    _integer(result["LOG_DELAY_MINUTES"], "LOG_DELAY_MINUTES", minimum=0)
    _integer(result["REFRESH_DELAY_MINUTES"], "REFRESH_DELAY_MINUTES", minimum=0)
    try:
        ZoneInfo(result["TIMEZONE"])
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError("TIMEZONE 必须为有效 IANA 时区") from None
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", result["DAILY_MAIL_TIME"]):
        raise ValueError("DAILY_MAIL_TIME 必须为 HH:MM")
    if result["MAIL_REPORT_MODE"] != "previous_day":
        raise ValueError("MAIL_REPORT_MODE 目前仅支持 previous_day 自然日汇总")
    _validate_lark_settings(result, require_complete=require_mail)
    result.update(validate_mail_config(result, require_complete=require_mail))
    accounts = result.get("ACCOUNTS")
    if not isinstance(accounts, list) or not accounts:
        raise ValueError("ACCOUNTS 必须为非空账号数组")
    normalized, names, identities = [], set(), set()
    for position, item in enumerate(accounts, 1):
        prefix = "ACCOUNTS[{}]".format(position)
        if not isinstance(item, dict):
            raise ValueError(prefix + " 必须为对象")
        account = {**ACCOUNT_DEFAULTS, **item}
        for key in ("NAME", "ACCOUNT_ID", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
            account[key] = _text(account.get(key), prefix + "." + key, required=key in ("NAME", "ACCOUNT_ID"))
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", account["NAME"]):
            raise ValueError(prefix + ".NAME 仅允许 1-80 位字母、数字、下划线和连字符")
        if not re.fullmatch(r"\d{12}", account["ACCOUNT_ID"]):
            raise ValueError(prefix + ".ACCOUNT_ID 必须为 12 位数字")
        if account["NAME"].casefold() in names or account["ACCOUNT_ID"] in identities:
            raise ValueError("ACCOUNTS 的 NAME 和 ACCOUNT_ID 必须分别唯一")
        names.add(account["NAME"].casefold())
        identities.add(account["ACCOUNT_ID"])
        if not isinstance(account["ENABLED"], bool):
            raise ValueError(prefix + ".ENABLED 必须为 true 或 false")
        has_key, has_secret = bool(account["AWS_ACCESS_KEY_ID"]), bool(account["AWS_SECRET_ACCESS_KEY"])
        if has_key != has_secret:
            raise ValueError(prefix + " 的 AWS_ACCESS_KEY_ID 与 AWS_SECRET_ACCESS_KEY 必须成对配置")
        if has_key and account["AWS_PROFILE"]:
            raise ValueError(prefix + " 不能同时配置 Access Key 和 AWS_PROFILE")
        if account["AWS_SESSION_TOKEN"] and not has_key:
            raise ValueError(prefix + ".AWS_SESSION_TOKEN 需要配套 Access Key")
        account["REGIONS"] = _regions(account["REGIONS"])
        normalized.append(account)
    result["ACCOUNTS"] = normalized
    return result
