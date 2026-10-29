"""复用原项目的 Lark Webhook 校验、签名与传输，仅发送 RDS 日报汇总。"""
from __future__ import annotations

import base64
import argparse
import hashlib
import hmac
import json
import os
import re
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

DEFAULT_REPORT_URL = ""

class LarkNotificationError(RuntimeError):
    """可安全显示的推送错误，不包含 Webhook、签名或消息原文。"""


def validate_webhook_url(url):
    if not isinstance(url, str):
        raise ValueError("webhook_url 必须为字符串；请检查配置字段名称。")
    if not url:
        raise ValueError("Webhook 地址为空；请填写 webhook_url，并检查环境变量是否为空。")
    if url.startswith(("[", "<", "\"", "'", "`")) or "](" in url:
        raise ValueError("Webhook 包含 Markdown 链接、尖括号或额外引号；请只粘贴纯 HTTPS 地址。")
    if any(ch.isspace() or ch in "\u200b\ufeff\u2060" or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError("Webhook 地址含空格、换行或不可见字符；请重新复制纯地址。")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("Webhook 地址结构或端口格式无效；请从群机器人设置重新复制。") from None
    if parts.scheme != "https":
        raise ValueError("Webhook 必须以 https:// 开头。")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Webhook 地址不能包含用户名或密码。")
    if parts.hostname not in {"open.larksuite.com", "open.feishu.cn"}:
        raise ValueError("Webhook 域名须为 open.larksuite.com 或 open.feishu.cn，请使用机器人提供的地址。")
    if port not in (None, 443):
        raise ValueError("Webhook 端口必须为默认 HTTPS 端口 443。")
    if parts.query or parts.fragment:
        raise ValueError("Webhook 地址带有 ? 查询参数或 # 片段；请复制原始地址，不要附加参数。")
    if not re.fullmatch(r"/open-apis/bot/v2/hook/[A-Za-z0-9_-]+", parts.path):
        raise ValueError("Webhook 路径须为 /open-apis/bot/v2/hook/ 后接机器人标识；请复制完整地址。")
    if parts.path.rsplit("/", 1)[-1].upper() in {"REPLACE_WITH_YOUR_TOKEN", "YOUR_TOKEN", "REPLACE_ME"}:
        raise ValueError("Webhook 仍为模板占位地址；请将 REPLACE/YOUR_TOKEN 替换为群机器人的真实地址。")
    return url


def load_lark_config(path):
    config = {}
    target = Path(path)
    if target.exists():
        try:
            config = json.loads(target.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            raise ValueError("Lark 配置文件无法读取或不是有效 JSON。") from None
        if not isinstance(config, dict):
            raise ValueError("Lark 配置文件必须为 JSON 对象。")
    elif not os.environ.get("LARK_WEBHOOK_URL"):
        raise ValueError("未找到 Lark 配置；请创建 lark-config.json 或设置 LARK_WEBHOOK_URL。")
    if "LARK_WEBHOOK_URL" in os.environ:
        config["webhook_url"] = os.environ["LARK_WEBHOOK_URL"]
    if "LARK_SIGNING_SECRET" in os.environ:
        config["signing_secret"] = os.environ["LARK_SIGNING_SECRET"]
    source = "LARK_WEBHOOK_URL 环境变量（覆盖配置文件）" if "LARK_WEBHOOK_URL" in os.environ else "配置文件的 webhook_url"
    try:
        validate_webhook_url(config.get("webhook_url", ""))
    except ValueError as exc:
        raise ValueError(f"生效来源：{source}。{exc}") from None
    for key in ("signing_secret", "report_url_template", "title_prefix", "message_mode"):
        if key in config and not isinstance(config[key], str):
            raise ValueError(f"Lark 配置的 {key} 必须为字符串。")
    if config.get("message_mode", "overview") not in {"overview", "summary", "full"}:
        raise ValueError("Lark message_mode 必须为 overview、summary 或 full。")
    return config


def _validate_report_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
        if (not isinstance(url, str) or parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None or any(ch.isspace() for ch in url)):
            raise ValueError
        parts.port
    except (ValueError, TypeError, AttributeError):
        raise ValueError("报告链接必须是有效的 HTTP/HTTPS 地址。") from None
    return url


def format_report_url(template, report):
    if not template:
        return ""
    meta = report["metadata"]
    values = {"date": str(meta["audit_date"]), "account_id": str(meta["account_id"]),
              "filename": str(meta.get("report_filename") or f"{meta['audit_date']}-rds操作审计.html")}
    try:
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is not None and (name not in values or spec or conversion):
                raise ValueError
        result = template.format(**{key: urllib.parse.quote(value, safe="") for key, value in values.items()})
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("报告链接模板仅支持 {date}、{account_id}、{filename}。") from None
    return _validate_report_url(result)


def _fragment(value, limit=180):
    # 防止事件中的名字或资源名被解释为 @群成员指令。
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).replace("<", "＜").replace(">", "＞")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _beijing(value):
    if isinstance(value, datetime):
        stamp = value
    else:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("报告时间缺少时区。")
    return stamp.astimezone(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")


def build_lark_payloads(report, config, *, access_password=None):
    """Reuse the existing signed webhook transport; send RDS counts only."""
    if config.get("message_mode", "overview") != "overview" or access_password is not None:
        raise ValueError("RDS日报仅支持overview汇总通知。")
    meta = report["metadata"]
    counts = meta.get("counts", {})
    sources = meta.get("source_counts", {})
    lines = [f"{_fragment(config.get('title_prefix') or 'RDS操作审计日报', 100)} | {_fragment(meta['audit_date'], 20)}"]
    if meta.get("example_data"):
        lines.append("【离线示例数据，非真实AWS账号审计】")
    elif meta.get("offline"):
        lines.append("【离线归档输入，未向AWS验证覆盖】")
    if not meta.get("complete", False):
        lines.append("【采集或解析不完整，请检查报告并补跑】")
    lines.append("新增：{}　删除：{}　修改：{}".format(*(int(counts.get(key, 0)) for key in ("新增", "删除", "修改"))))
    lines.append("口径：未报错的API调用与SQL语句记录；不等于最终资源状态或事务提交。")
    for key, label in (("management", "RDS管理API"), ("sql", "数据库SQL审计")):
        values = sources.get(key, {})
        lines.append(label + "：" + "　".join(f"{name} {int(values.get(name, 0))}" for name in ("新增", "删除", "修改")))
    lines.append(f"全部明细 {int(meta.get('total', 0))} 条；失败或含失败响应 {int(meta.get('failed_or_partial', 0))} 条。")
    lines.append("账号：" + _fragment(meta['account_id'], 64))
    lines.append("北京时间：" + _beijing(meta['window_start_utc']) + " 至 " + _beijing(meta['window_end_utc_exclusive']))
    lines.append("SQL仅覆盖已记录且仍保留的审计日志；数据库账号不一定对应具体自然人。")
    report_url = format_report_url(config.get("report_url_template", ""), report)
    lines.append("详细报告：" + report_url if report_url else "详细报告已保存在服务器；尚未配置可访问链接。")
    return [{"msg_type": "text", "content": {"text": "\n".join(lines)}}]


def make_lark_signature(secret, timestamp):
    key = f"{int(timestamp)}\n{secret}".encode("utf-8")
    return base64.b64encode(hmac.new(key, b"", hashlib.sha256).digest()).decode("ascii")


def _payload_bytes(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _signed_payload(payload, secret, now):
    payload = dict(payload)
    if secret:
        if isinstance(now, datetime):
            if now.tzinfo is None:
                raise ValueError("签名时间必须包含时区。")
            timestamp = int(now.timestamp())
        else:
            timestamp = int(time.time() if now is None else now)
        payload["timestamp"] = str(timestamp)
        payload["sign"] = make_lark_signature(secret, timestamp)
    return payload


def _send_payload(payload, webhook, opener):
    data = _payload_bytes(payload)
    if len(data) > 20 * 1024:
        raise LarkNotificationError("Lark 消息超过 20 KB，请缩短标题或报告链接。")
    request = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    try:
        # 单次投递：网络超时可能是群已收到消息，不自动重试以免重复。
        with (opener or urllib.request.urlopen)(request, timeout=20) as response:
            status = getattr(response, "status", None) or response.getcode()
            if not 200 <= status < 300:
                raise LarkNotificationError(f"Lark HTTP 请求失败（状态码 {int(status)}）。")
            body = response.read(65537)
            if len(body) > 65536:
                raise LarkNotificationError("Lark 响应过大，未确认投递结果。")
    except urllib.error.HTTPError as exc:
        raise LarkNotificationError(f"Lark HTTP 请求失败（状态码 {exc.code}）。") from None
    except LarkNotificationError:
        raise
    except Exception as exc:
        raise LarkNotificationError(f"Lark 网络请求失败（{type(exc).__name__}）；投递结果未确认。") from None
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError):
        raise LarkNotificationError("Lark 响应不是有效 JSON，未确认投递结果。") from None
    if not isinstance(result, dict) or not ({"code", "StatusCode"} & result.keys()):
        raise LarkNotificationError("Lark 响应缺少状态码，未确认投递结果。")
    code = result.get("code", result.get("StatusCode"))
    if isinstance(code, bool) or code not in (0, "0"):
        safe_code = str(code) if re.fullmatch(r"[0-9]{1,10}", str(code)) else "未知"
        hints = {"19001": "请求参数或 Webhook 未被接受，不能仅凭错误码确定原因；请核对目标群机器人地址、LARK_WEBHOOK_URL 环境变量覆盖及消息格式", "19021": "请检查签名密钥及服务器时间", "19022": "请检查机器人 IP 白名单", "19024": "请检查机器人关键词与 title_prefix", "11232": "触发限流，请稍后手动重试"}
        message = str(result.get("msg", result.get("StatusMessage", ""))).lower()
        if safe_code == "19001" and "incoming webhook access token invalid" in message:
            hints["19001"] = "Webhook 访问标识无效；请从目标群机器人重新复制地址，检查机器人是否仍存在及 LARK_WEBHOOK_URL 是否覆盖配置文件"
        raise LarkNotificationError(f"Lark 返回错误码 {safe_code}；{hints.get(safe_code, '请检查机器人配置')}。")
    return result


def send_lark_notification(report, config, *, opener=None, now=None, sleep=None, access_password=None):
    webhook = validate_webhook_url(config.get("webhook_url", ""))
    payloads = build_lark_payloads(report, config, access_password=access_password)
    secret = config.get("signing_secret", "")
    # 所有消息先校验大小，防止格式问题导致前半份报告已发、后半份才失败。
    for payload in payloads:
        if len(_payload_bytes(_signed_payload(payload, secret, now))) > 20 * 1024:
            raise LarkNotificationError("Lark 消息超过 20 KB，请缩短标题或报告链接。")
    sent = 0
    result = None
    for payload in payloads:
        if sent:
            (sleep or time.sleep)(0.7)
        try:
            result = _send_payload(_signed_payload(payload, secret, now), webhook, opener)
        except LarkNotificationError as exc:
            raise LarkNotificationError(f"{exc} 已成功发送 {sent}/{len(payloads)} 条，已停止后续发送。") from None
        sent += 1
    if config.get("message_mode", "summary") == "full":
        return {"code": 0, "messages_sent": sent}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="本地检查 Lark 配置；不发送任何消息。")
    parser.add_argument("--config", default="lark-config.json")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)
    if not args.check_config:
        parser.error("请使用 --check-config；此入口只做本地配置检查。")
    print("配置文件路径：" + str(Path(args.config).resolve()))
    if "LARK_WEBHOOK_URL" in os.environ:
        print("Webhook 来源：LARK_WEBHOOK_URL 环境变量（覆盖文件" + ("，当前为空" if not os.environ["LARK_WEBHOOK_URL"] else "") + "）")
    else:
        print("Webhook 来源：配置文件")
    try:
        config = load_lark_config(args.config)
        print("Webhook 域名：" + urllib.parse.urlsplit(config["webhook_url"]).hostname)
        print("地址格式检查通过；未向 Lark 验证地址有效性，未发送消息。")
        print("发送模式：" + config.get("message_mode", "overview"))
        print("签名：" + ("已配置" if config.get("signing_secret") else "未配置"))
        print("报告链接：" + ("已配置" if config.get("report_url_template") else "未配置"))
        return 0
    except (ValueError, OSError) as exc:
        print(f"配置检查失败：{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
