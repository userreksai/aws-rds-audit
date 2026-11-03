"""Account-separated source-IP audit PDFs. Only whitelisted summary fields render."""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from pathlib import Path
import os
import tempfile
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (LongTable, Paragraph, SimpleDocTemplate,
                               Spacer, Table, TableStyle)

NAVY = colors.HexColor("#18304D")
BLUE = colors.HexColor("#2563A6")
MUTED = colors.HexColor("#526477")
PALE = colors.HexColor("#EDF3F9")
LINE = colors.HexColor("#D6E0EB")
CATEGORIES = ("新增", "删除", "修改", "其他操作")


def _font(font_path):
    if not font_path:
        candidates = [Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
                      Path("/usr/share/fonts/truetype/arphic/uming.ttc"),
                      Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "simsun.ttc"]
        font_path = next((str(item) for item in candidates if item.is_file()), None)
    if font_path:
        path = Path(font_path).expanduser().resolve()
        if not path.is_file():
            raise ValueError("PDF_FONT_PATH 指定的字体文件不存在")
        name = "RdsCjk-" + sha256(str(path).encode()).hexdigest()[:12]
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(path), subfontIndex=0))
        return name
    name = "STSong-Light"
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(UnicodeCIDFont(name))
    return name


def _text(value, maximum=1024):
    """Bound display metadata; SQL and arbitrary provider error text never enter it."""
    return escape(str(value if value is not None else "")[:maximum]).replace("\n", "<br/>")


def _number(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("PDF 汇总计数必须为非负整数")
    return value


def _local_time(value, zone):
    if not value:
        return "未提供"
    try:
        from zoneinfo import ZoneInfo
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return str(value)
        return stamp.astimezone(ZoneInfo(zone)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, KeyError):
        return str(value)


def render_account_pdf(report: dict, path: Path, font_path: str | None = None) -> Path:
    """Render one account report atomically, with repeating table headers on all pages."""
    font = _font(font_path)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = {
        "title": ParagraphStyle("Title", fontName=font, fontSize=20, leading=26, textColor=NAVY, spaceAfter=6),
        "sub": ParagraphStyle("Sub", fontName=font, fontSize=10, leading=14, textColor=MUTED, wordWrap="CJK"),
        "body": ParagraphStyle("Body", fontName=font, fontSize=9, leading=14, textColor=NAVY, wordWrap="CJK"),
        "section": ParagraphStyle("Section", fontName=font, fontSize=12, leading=18, textColor=BLUE, spaceBefore=10, spaceAfter=5),
        "cell": ParagraphStyle("Cell", fontName=font, fontSize=9, leading=13, textColor=NAVY, wordWrap="CJK", splitLongWords=True),
        "head": ParagraphStyle("Head", fontName=font, fontSize=9, leading=13, textColor=colors.white, alignment=TA_CENTER),
        "num": ParagraphStyle("Num", fontName=font, fontSize=10, leading=14, textColor=NAVY, alignment=TA_CENTER),
        "note": ParagraphStyle("Note", fontName=font, fontSize=8, leading=11, textColor=MUTED, wordWrap="CJK"),
    }
    p = lambda value, style="body": Paragraph(_text(value), styles[style])
    account = str(report.get("account_id", "未验证账号"))
    account_name = str(report.get("account_name", ""))
    zone = str(report.get("timezone", "Asia/Shanghai"))
    window = report.get("window") or {}
    complete = report.get("complete") is True
    status = "采集与解析完整" if complete else "采集或解析不完整，请检查缺段与权限"
    actors = report.get("actors", [])
    if not isinstance(actors, list):
        raise ValueError("PDF actors 必须为数组")
    normalized = []
    for row in actors:
        source = row.get("source_kind")
        if source not in ("sql", "management"):
            raise ValueError("PDF 来源类型必须为 sql 或 management")
        counts = {key: _number(row.get("counts", {}).get(key, 0)) for key in CATEGORIES}
        failed = _number(row.get("failed", 0))
        total = _number(row.get("total", sum(counts.values()) + failed))
        if total != sum(counts.values()) + failed:
            raise ValueError("PDF 汇总总计与分类计数不一致")
        normalized.append({"source_kind": source, "host": str(row.get("source_ip") or row.get("actor") or "未知来源"),
                           "actor_type": str(row.get("actor_type", "")), "counts": counts,
                           "failed": failed, "total": total})
    sql_rows = [row for row in normalized if row["source_kind"] == "sql"]
    totals = {key: sum(row["counts"][key] for row in sql_rows) for key in CATEGORIES}
    failed = sum(row["failed"] for row in sql_rows)
    total = sum(row["total"] for row in sql_rows)
    story = [p("AWS RDS 来源 IP 审计汇总", "title"),
             p(f"账号 {account}  |  {account_name}" if account_name else f"账号 {account}", "sub"),
             p(f"报表日期 {report.get('date', '')}  |  时区 {zone}", "sub"),
             p(f"查询窗口 {_local_time(window.get('start_inclusive'), zone)} 至 {_local_time(window.get('end_exclusive'), zone)}（左闭右开）", "sub"),
             Spacer(1, 5 * mm)]
    status_table = Table([[p(status)]], colWidths=[263 * mm])
    status_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PALE if complete else colors.HexColor("#FFF2DF")),
                                     ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                     ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.extend([status_table, Spacer(1, 4 * mm)])
    metric_labels = ["SQL 新增", "SQL 删除", "SQL 修改", "SQL 失败", "SQL 合计"]
    metric_values = [totals["新增"], totals["删除"], totals["修改"], failed, total]
    cards = Table([[p(label, "sub") for label in metric_labels],
                   [p(f"{value:,}", "num") for value in metric_values]], colWidths=[52.6 * mm] * 5)
    cards.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
                              ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(cards)
    if totals["其他操作"]:
        story.append(p(f"另有其他操作 {totals['其他操作']:,} 次，已纳入合计并在下表单列。", "note"))
    for source, title in (("sql", "数据库内部 SQL（语句次数）"), ("management", "RDS 管理 API（调用次数）")):
        rows = [row for row in normalized if row["source_kind"] == source]
        story.append(p(title, "section"))
        if not rows:
            story.append(p("本窗口未取得可计数记录。请结合日志启用情况、保留期、采集状态及覆盖范围判断，不能直接认定没有操作。", "note"))
            continue
        include_other = any(row["counts"]["其他操作"] for row in rows)
        labels = ["来源 IP / 主机", "新增", "删除", "修改", "失败"]
        if include_other:
            labels.append("其他")
        labels.append("合计")
        widths = [113 * mm] + [150 * mm / (len(labels) - 1)] * (len(labels) - 1)
        table_rows = [[p(label, "head") for label in labels]]
        for row in sorted(rows, key=lambda value: (-value["total"], value["host"])):
            host = row["host"]
            if "主机" in row["actor_type"]:
                host += "（来源主机，非 IP）"
            values = [row["counts"][key] for key in ("新增", "删除", "修改")] + [row["failed"]]
            if include_other:
                values.append(row["counts"]["其他操作"])
            values.append(row["total"])
            table_rows.append([p(host, "cell")] + [p(f"{value:,}", "num") for value in values])
        table = LongTable(table_rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY),
                                  ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                                  ("LINEBELOW", (0, 0), (-1, 0), 0.5, NAVY),
                                  ("GRID", (0, 1), (-1, -1), 0.3, LINE),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9)]))
        story.append(table)
    coverage = report.get("coverage") or {}
    unknown = _number(coverage.get("unparsed_records", 0))
    error_count = len(report.get("errors") or [])
    story.extend([p("统计口径与覆盖", "section"),
                  p(f"未解析 / 未分类记录 {unknown:,} 条；采集与覆盖问题 {error_count:,} 项。失败请求单列，不计入未报错的增删改。", "note"),
                  p("新增、删除、修改按审计语句或 API 请求条数计数，不等于受影响行数。SQL 返回码 0 不证明事务最终提交；API 未报错不证明异步变更最终完成。", "note"),
                  p("来源为数据库或 AWS 实际观测到的地址；代理、连接池或 NAT 可能使来源显示为应用 / 代理地址。非 IP 主机名及未知来源单独标识。管理 API 和数据库 SQL 分开汇总。", "note"),
                  p("仅包含当时已启用且仍在保留期内、当前身份有权读取的记录。日志延迟、用户过滤、截断、缺段或权限失败可能造成不完整；没有记录不等于没有操作。", "note")])
    if report.get("demo"):
        story.insert(0, p("离线演示 - 所有账号、IP 与统计均为虚构", "sub"))
    generated = _local_time(report.get("generated_at"), zone)

    def page_footer(canvas, document):
        width, height = landscape(A4)
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(17 * mm, 14 * mm, width - 17 * mm, 14 * mm)
        canvas.setFont(font, 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(17 * mm, 9.5 * mm, f"账号 {account[:36]}  |  生成 {generated[:32]}")
        canvas.drawRightString(width - 17 * mm, 9.5 * mm, f"第 {document.page} 页")
        canvas.restoreState()

    descriptor, temporary_name = tempfile.mkstemp(prefix=".rds-pdf-", suffix=".pdf", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        document = SimpleDocTemplate(str(temporary), pagesize=landscape(A4),
                                     leftMargin=17 * mm, rightMargin=17 * mm,
                                     topMargin=15 * mm, bottomMargin=21 * mm,
                                     title=f"AWS RDS 来源 IP 审计汇总 {account}", author="AWS RDS Audit")
        document.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path
