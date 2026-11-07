"""Escaped email introductions and source-IP count tables, without raw SQL."""
from __future__ import annotations

from datetime import datetime
from html import escape
import unicodedata
from zoneinfo import ZoneInfo

from rds_summary import CATEGORIES, canonical_source_ip


_COLUMNS = ("来源 IP", "新增", "删除", "修改", "失败", "其他", "合计")
_SOURCES = (("sql", "数据库内部 SQL（语句次数）"), ("management", "RDS 管理 API（调用次数）"))
_EMPTY = "本窗口未取得可计数记录；请结合采集状态、日志启用情况和覆盖范围判断。"
_NOTE = "附件按账号分别生成。SQL 语句次数与 AWS 管理 API 调用分开统计；失败次数单列，不计入未报错的增删改。"
_HEAD_STYLE = "border:1px solid #cbd5e1;padding:8px;background-color:#f1f5f9;text-align:left;"
_CELL_STYLE = "border:1px solid #cbd5e1;padding:8px;text-align:right;vertical-align:top;"
_NAME_STYLE = "border:1px solid #cbd5e1;padding:8px;text-align:left;word-break:break-word;vertical-align:top;"


def _line(value):
    if not isinstance(value, str):
        return ""
    return "".join(" " if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else char
                   for char in value).strip()


def account_label(config, report):
    """Prefer the optional Chinese TAG while retaining old NAME-only configs."""
    identity = _line(report.get("account_id")) or "未知账号"
    accounts = {item["ACCOUNT_ID"]: item for item in config.get("ACCOUNTS", [])}
    account = accounts.get(identity, {})
    tag = _line(account.get("TAG")) or _line(report.get("account_tag"))
    tag = tag or _line(report.get("account_name")) or _line(account.get("NAME"))
    return tag + "-" + identity if tag else identity


def _mail_window(report):
    try:
        window = report["window"]
        stamps = [datetime.fromisoformat(window[key].replace("Z", "+00:00"))
                  for key in ("start_inclusive", "end_exclusive")]
        if any(stamp.tzinfo is None or stamp.utcoffset() is None for stamp in stamps) or stamps[0] >= stamps[1]:
            raise ValueError
        return tuple(stamp.astimezone(ZoneInfo("Asia/Shanghai")) for stamp in stamps)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("邮件报告必须提供有效且包含时区的统计起止时间。") from None


def _reports(reports):
    if not isinstance(reports, list) or not reports or any(not isinstance(report, dict) for report in reports):
        raise ValueError("邮件正文需要至少一份账号报告。")
    window = _mail_window(reports[0])
    if any(_mail_window(report) != window for report in reports[1:]):
        raise ValueError("同一封邮件中的账号必须使用相同统计窗口。")
    return reports, window


def _status(report):
    return "采集步骤完整" if report.get("complete") is True else "数据不完整，请核查缺段/日志/权限"


def _intro(config, reports, window):
    start, end = (stamp.strftime("%Y-%m-%d %H:%M:%S") for stamp in window)
    labels = [account_label(config, report) for report in reports]
    lines = ["各位领导和同事好：", "RDS 来源 IP 审计汇总",
             "查询范围（北京时间，结束时刻不含）：", start + " 至 " + end,
             f"账号总数：{len(reports)}", "账号信息：" + labels[0], *labels[1:]]
    lines.append("查询状态：所列查询完成。" if all(report.get("complete") is True for report in reports)
                 else "查询状态：数据不完整；部分账号采集或解析失败，请检查任务日志。")
    lines.append(_NOTE)
    if any(report.get("report_kind") == "since_yesterday" for report in reports):
        lines.append("仅统计有效来源 IPv4/IPv6；统计截至本次采集开始时刻已发布的日志，最近日志可能延迟到达。")
    return "\n".join(lines)


def _number(value):
    if type(value) is not int or value < 0:
        raise ValueError("邮件汇总计数必须为非负整数")
    return value


def _rows(report, source):
    actors = report.get("actors", [])
    if not isinstance(actors, list):
        raise ValueError("邮件 actors 必须为数组")
    rows = []
    for actor in actors:
        if not isinstance(actor, dict) or actor.get("source_kind") not in {"sql", "management"}:
            raise ValueError("邮件来源类型必须为 sql 或 management")
        if actor["source_kind"] != source:
            continue
        address = canonical_source_ip(actor.get("source_ip"))
        if address is None:
            raise ValueError("邮件来源必须为有效 IPv4/IPv6 地址")
        counts = {key: _number(actor.get("counts", {}).get(key, 0)) for key in CATEGORIES}
        failed = _number(actor.get("failed", 0))
        total = _number(actor.get("total", sum(counts.values()) + failed))
        if total != sum(counts.values()) + failed:
            raise ValueError("邮件汇总总计与分类计数不一致")
        if total:
            rows.append([address, counts["新增"], counts["删除"], counts["修改"], failed, counts["其他操作"], total])
    return sorted(rows, key=lambda row: (-row[-1], row[0]))


def _text_cell(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def message_body(config, reports):
    """Plain-text equivalent of the HTML tables, containing only summary fields."""
    reports, window = _reports(reports)
    sections = [_intro(config, reports, window)]
    for report in reports:
        lines = [account_label(config, report) + "：" + _status(report)]
        for source, title in _SOURCES:
            lines.extend(["", title])
            rows = _rows(report, source)
            if rows:
                lines.append(" | ".join(_COLUMNS))
                lines.append(" | ".join(["---"] * len(_COLUMNS)))
                lines.extend(" | ".join(_text_cell(value) for value in row) for row in rows)
            else:
                lines.append(_EMPTY)
        sections.append("\n".join(lines))
    return "\n\n".join(sections)


def message_body_html(config, reports):
    """Email-client friendly inline CSS with escaped labels and count tables."""
    reports, window = _reports(reports)
    parts = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1"></head>',
             '<body style="margin:0;padding:24px;color:#18304d;background:#fff;'
             'font-family:Arial,Microsoft YaHei,sans-serif;line-height:1.6">',
             '<div>' + escape(_intro(config, reports, window)).replace("\n", "<br>\n") + '</div>']
    for report in reports:
        parts.append('<section style="margin:24px 0"><h2 style="font-size:18px;margin:0 0 8px">'
                     + escape(account_label(config, report)) + '</h2><p>' + escape(_status(report)) + '</p>')
        for source, title in _SOURCES:
            parts.append('<h3 style="font-size:15px;margin:16px 0 8px">' + escape(title) + '</h3>')
            rows = _rows(report, source)
            if not rows:
                parts.append('<p>' + _EMPTY + '</p>')
                continue
            parts.append('<table style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr>')
            parts.extend('<th scope="col" style="' + _HEAD_STYLE + '">' + escape(column) + '</th>' for column in _COLUMNS)
            parts.append('</tr></thead><tbody>')
            for row in rows:
                parts.append('<tr>')
                parts.extend('<td style="' + (_NAME_STYLE if index == 0 else _CELL_STYLE) + '">'
                             + escape(str(value)) + '</td>' for index, value in enumerate(row))
                parts.append('</tr>')
            parts.append('</tbody></table>')
        parts.append('</section>')
    parts.append('</body></html>')
    return "".join(parts)
