"""Small, self-styled static report pages; browsers never load the full archive."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZipFile

PAGE_SIZE = 100
PREVIEW_SIZE = 20
FORMAT_VERSION = "change-pages-v3"
SHORT_LIMIT = 240
SQL_LIMIT = 4096
FIELD_LIMIT = 8192
TRUNCATED = "…【展示已截断，完整字段保存在服务器归档 daily-report.json】"
EXTRA_CSS = """
.report-nav,.pagination{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin:16px 0}.report-nav a,.pagination a,.button{display:inline-block;background:#eaf1f9;border:1px solid #d4e1ef;padding:8px 12px;border-radius:6px}.pagination span{padding:8px}.record-id{font-size:11px;color:#697b91}.record-preview{max-width:520px}.record-preview pre{margin:4px 0}.state{font-size:12px}.summary-note{max-width:1100px}.operations td{max-width:720px}.operations pre{margin:4px 0}.record-details{max-width:820px}.statline{display:flex;flex-wrap:wrap;gap:20px}.error-item{border-bottom:1px solid #dfe6ee;padding:12px 0}.actor-context{max-width:560px;font-size:11px;overflow-wrap:anywhere}@media(max-width:700px){.operations .operation{min-width:230px}.report-nav a,.pagination a{padding:8px}.statline{gap:10px}}
.summary-table{table-layout:fixed}.summary-table th,.summary-table td{vertical-align:middle}.summary-table th.number,.summary-table td.number{text-align:right;white-space:nowrap}.source-summary{min-width:620px}.actor-summary{min-width:850px}.actor-details{margin-top:4px;font-size:12px}.actor-details summary{display:inline-block;color:#586b80}.actor-context{margin-top:6px;max-width:100%;white-space:normal;word-break:break-all}.record-preview{min-width:260px}.operation-details>summary{display:inline-block;padding:5px 0;font-weight:500}.operation-content{padding-top:8px}.operation-content h3{font-size:13px;margin:12px 0 6px}.operation-content pre{margin:6px 0 12px}.section-footer{margin:16px 0 0}.index-records{min-width:960px}.index-records td{vertical-align:top}
.source-summary col.source-label{width:24%}.source-summary col.summary-number{width:15.2%}.actor-summary col.actor-label{width:34%}.actor-summary col.actor-source{width:18%}.actor-summary col.summary-number{width:9.6%}
""".strip()


def _model():
    # Called after rds_report has initialized; no module-level circular import.
    import rds_report
    return rds_report


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _text(value, limit=SHORT_LIMIT) -> str:
    text = str(value or "")
    clipped = text[:limit]
    clipped = _model().redact_text(clipped)
    return clipped + (TRUNCATED if len(text) > limit else "")


def _bounded(value, budget=FIELD_LIMIT, depth=0):
    """Bound values before JSON encoding or redaction can duplicate large fields."""
    if budget <= 0 or depth > 8:
        return TRUNCATED
    if isinstance(value, dict):
        result = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 40 or budget <= 0:
                result["展示限制"] = TRUNCATED
                break
            key = str(key)[:100]
            rendered = _bounded(item, min(budget, 2048), depth + 1)
            result[key] = rendered
            budget -= len(str(rendered)) + len(key)
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for index, item in enumerate(value):
            if index >= 20 or budget <= 0:
                result.append(TRUNCATED)
                break
            rendered = _bounded(item, min(budget, 2048), depth + 1)
            result.append(rendered)
            budget -= len(str(rendered))
        return result
    if isinstance(value, str):
        return value[:budget] + (TRUNCATED if len(value) > budget else "")
    return value


def _json(value, budget=FIELD_LIMIT):
    data = _model().redact(_bounded(value, budget))
    encoded = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    return _e(encoded[:budget] + (TRUNCATED if len(encoded) > budget else ""))


def _filename(report):
    filename = str(report["metadata"]["report_filename"])
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}-rds操作审计(?:-自定义窗口)?\.html", filename):
        raise ValueError("unsafe report filename")
    return filename


def _css():
    return _model().CSS + "\n" + EXTRA_CSS + "\n"


def _artifacts(report):
    filename = _filename(report)
    # generated_at and an old manifest must not create a new tree on each rerun.
    payload = {key: value for key, value in report.items() if key != "artifacts"}
    payload["metadata"] = {key: value for key, value in report["metadata"].items() if key != "generated_at"}
    digest = hashlib.sha256((FORMAT_VERSION + _css()).encode("utf-8"))
    for chunk in json.JSONEncoder(ensure_ascii=False, sort_keys=True, default=str).iterencode(payload):
        digest.update(chunk.encode("utf-8"))
    return {
        "format": FORMAT_VERSION, "page_size": PAGE_SIZE,
        "detail_directory": filename[:-5] + "-pages-" + digest.hexdigest()[:12],
        "bundle_filename": filename[:-5] + "-完整报告.zip",
        "detail_pages": max(1, (len(report.get("events", [])) + PAGE_SIZE - 1) // PAGE_SIZE),
    }


def _href(path):
    return quote(str(path), safe="/-_.#")


def _event_link(index):
    return f"events-{index // PAGE_SIZE + 1:06d}.html#event-{index + 1:06d}"


def _actor_prefix(key):
    return "actor-" + hashlib.sha256(str(key).encode()).hexdigest()[:16]


def _pagination(prefix, page, pages):
    links = []
    if page > 1:
        links += [f'<a href="{prefix}-000001.html">首页</a>', f'<a href="{prefix}-{page - 1:06d}.html">上一页</a>']
    links.append(f"<span>第 {page} / {pages} 页 · 每页最多 {PAGE_SIZE} 条</span>")
    if page < pages:
        links += [f'<a href="{prefix}-{page + 1:06d}.html">下一页</a>', f'<a href="{prefix}-{pages:06d}.html">末页</a>']
    return '<nav class="pagination" aria-label="分页">' + "".join(links) + "</nav>"


def _document(report, title, body, *, child=False):
    meta = report["metadata"]
    model = _model()
    prefix = "../" if child else ""
    css = _css()
    css_hash = hashlib.sha256(css.encode()).hexdigest()[:12]
    status = "采集步骤完成" if meta.get("complete") else "采集或解析不完整"
    badges = f'<span class="badge{ " error" if not meta.get("complete") else ""}">{status}</span>'
    if meta.get("example_data"):
        badges += ' <span class="badge demo">虚构示例，非真实账号数据</span>'
    elif meta.get("offline"):
        badges += ' <span class="badge demo">离线输入，未向 AWS 验证</span>'
    label = meta.get("period_label") or ("自定义时间窗口" if meta.get("period_kind") == "custom" else "北京时间日报")
    generated = model.local_time(meta["generated_at"]) if meta.get("generated_at") else ""
    back = f'<p><a href="{_href(prefix + _filename(report))}">← 返回报告总览</a></p>' if child else ""
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(meta['audit_date'])} {_e(title)}</title><link rel="stylesheet" href="{prefix}rds-report.css?v={css_hash}"><style>{css}</style></head>
<body><main>{back}<header><div class="topline"><div><h1>{_e(title)}</h1><div class="muted">{_e(label)} · 窗口结束日期 {_e(meta['audit_date'])} · AWS 账号 {_e(_text(meta['account_id'], 80))}</div></div><div>{badges}</div></div><p class="window">北京时间 {_e(model.local_time(meta['window_start_utc']))} 至 {_e(model.local_time(meta['window_end_utc_exclusive']))}（左闭右开）<br><small>生成于 {_e(generated)}（北京时间）</small></p></header>{body}</main></body></html>'''


def _index_table(report, indices, *, prefix=""):
    rows = []
    events = report.get("events", [])
    for index in indices:
        row = events[index]
        css_class = ' class="failed"' if row.get("status") == "failed" else ""
        statement = _text(row.get("description") or row.get("event_name"))
        rows.append(f'<tr{css_class} data-event-index="{index}"><td class="nowrap">{_e(row.get("time_local", ""))}</td><td>{_e(_text(row.get("actor"), 120))}<br><small>{_e(row.get("actor_type", ""))}</small></td><td>{_e(row.get("category", ""))}</td><td class="record-preview"><pre>{_e(statement)}</pre>{_operation_details(row)}</td><td>{_e(_text(row.get("source_ip"), 120))}<br><small>{_e(_text(row.get("region"), 60))}</small></td><td>{_e(_text(row.get("result")))}</td></tr>')
    return '<div class="scroll"><table class="index-records"><thead><tr><th>北京时间</th><th>操作者</th><th>分类</th><th>操作信息</th><th>来源 / 区域</th><th>结果</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>' if rows else '<p class="empty">本页没有符合条件的操作记录。</p>'


def _operation_details(row, *, include_statement=True):
    """This page's evidence expands locally, including when copied by itself."""
    is_sql = bool(row.get("sql")) or row.get("source_kind") == "sql"
    label = "展开 SQL 与操作详情" if is_sql and include_statement else "展开操作详情"
    content = ""
    if include_statement:
        title = "SQL 语句" if is_sql else "管理 API"
        statement = row.get("sql") or row.get("description") or row.get("event_name")
        content += f'<h3>{title}</h3><pre class="sql-text">{_e(_text(statement, SQL_LIMIT))}</pre>'
    details = {
        "记录ID": row.get("event_id"), "执行时间": row.get("time_local"),
        "操作者": row.get("actor"), "身份": row.get("identity"),
        "数据库": row.get("database"), "实例": row.get("serverhost"),
        "来源IP": row.get("source_ip"), "区域": row.get("region"),
        "执行结果": row.get("result"), "返回码": row.get("return_code"),
        "时间来源": row.get("timestamp_source", "CloudTrail eventTime"),
        "原日志时间": row.get("timestamp_raw"), "日志组": row.get("log_group"),
        "日志流": row.get("log_stream"), "请求参数": row.get("parameters"),
        "响应": row.get("response"), "错误码": row.get("error_code"),
        "错误信息": row.get("error_message"), "UserAgent": row.get("user_agent"),
    }
    details = {key: value for key, value in details.items() if value is not None and value != ""}
    content += '<h3>执行信息与参数</h3><pre>' + _json(details) + '</pre>'
    return f'<details class="operation-details"><summary>{label}</summary><div class="operation-content">{content}</div></details>'


def _actor_table(actors, *, prefix=""):
    rows = []
    for actor in actors:
        key = str(actor["actor_key"])
        cells = "".join(f'<td class="number">{int(actor.get("counts", {}).get(category, 0))}</td>' for category in ("新增", "删除", "修改"))
        contexts = actor.get("contexts") or []
        context_details = ''.join('<div class="actor-context muted">' + _e(_text(' · '.join(str(context.get(field) or '') for field in ('region', 'serverhost', 'database', 'log_group', 'log_stream') if context.get(field)) or context.get('actor_key'), 600)) + '</div>' for context in contexts[:10]) if contexts else '<div class="actor-context muted">' + _e(_text(key, 600)) + '</div>'
        if len(contexts) > 10:
            context_details += f'<small>共 {len(contexts)} 项上下文，完整内容见服务器归档。</small>'
        rows.append(f'<tr><td><a href="{_href(prefix + _actor_prefix(key) + "-000001.html")}">{_e(_text(actor.get("actor"), 120))}</a><br><small>{_e(actor.get("actor_type", ""))}</small><details class="actor-details"><summary>实例与身份</summary>{context_details}</details></td><td>{_e(_model().SOURCE_LABELS.get(actor.get("source_kind"), actor.get("source_kind", "")))}</td>{cells}<td class="number">{int(actor.get("failed", 0))}</td><td class="number">{int(actor.get("total", 0))}</td></tr>')
    columns = '<colgroup><col class="actor-label"><col class="actor-source">' + '<col class="summary-number">' * 5 + '</colgroup>'
    return '<div class="scroll"><table class="summary-table actor-summary">' + columns + '<thead><tr><th>操作者 / 实例上下文</th><th>来源</th><th class="number">新增</th><th class="number">删除</th><th class="number">修改</th><th class="number">失败</th><th class="number">明细数量</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>' if rows else '<p class="empty">当前未取得可展示的增删改操作者。</p>'


def generate_overview(report: dict) -> str:
    meta = report["metadata"]
    art = _artifacts(report)
    directory = art["detail_directory"] + "/"
    cards = []
    for category, css_class in (("新增", "create"), ("删除", "delete"), ("修改", "modify")):
        parts = [f"{_e(source.get('label', kind))} {int(source.get('counts', {}).get(category, 0))}" for kind, source in report.get("by_source", {}).items()]
        cards.append(f'<div class="card {css_class}"><span>{category}</span><strong>{int(meta.get("counts", {}).get(category, 0))}</strong><small>{" · ".join(parts)}</small></div>')
    source_rows = []
    for kind, source in report.get("by_source", {}).items():
        cells = "".join(f'<td class="number">{int(source.get("counts", {}).get(category, 0))}</td>' for category in ("新增", "删除", "修改"))
        source_rows.append(f'<tr><td>{_e(source.get("label", kind))}</td>{cells}<td class="number">{int(source.get("failed", 0))}</td><td class="number">{int(source.get("total", 0))}</td></tr>')
    actors = report.get("actors", [])
    notes = "".join(f'<li>{_e(_text(note, 1200))}</li>' for note in report.get("coverage", {}).get("notes", [])[:20])
    errors, unparsed = len(meta.get("errors", [])), len(report.get("unparsed", []))
    issues = f'<p>采集/解析问题 {errors} 项；未解析或隔离证据 {unparsed} 条。<a href="{_href(directory + "errors-000001.html")}">查看问题分页</a> · <a href="{_href(directory + "unparsed-000001.html")}">查看隔离证据分页</a></p>'
    body = '<div class="cards">' + "".join(cards) + '</div>'
    coverage = meta.get("source_cache")
    if coverage:
        missing = len(coverage.get("missing_segments", []))
        body += f'<div class="notice{ " error" if missing else ""}">本地分段覆盖 {int(coverage.get("selected_segments", 0))} / {int(coverage.get("expected_segments", 0))}；缺失 {missing} 段。缺失段不按零操作处理。{"本报告已按补采结果修订。" if coverage.get("revision") else ""}</div>'
    columns = '<colgroup><col class="source-label">' + '<col class="summary-number">' * 5 + '</colgroup>'
    body += '<section><h2>按来源汇总</h2><div class="scroll"><table class="summary-table source-summary">' + columns + '<thead><tr><th>来源</th><th class="number">新增</th><th class="number">删除</th><th class="number">修改</th><th class="number">失败</th><th class="number">明细数量</th></tr></thead><tbody>' + "".join(source_rows) + '</tbody></table></div></section>'
    more_actors = f'<p class="section-footer"><a href="{_href(directory + "actors-000001.html")}">更多操作者</a></p>' if len(actors) > PAGE_SIZE else ""
    body += '<section><h2>按操作者汇总</h2>' + _actor_table(actors[:PAGE_SIZE], prefix=directory) + more_actors + '</section>'
    total = len(report.get("events", []))
    more_records = f'<p class="section-footer"><a href="{_href(directory + "events-000001.html")}">更多记录（共 {total} 条）</a></p>' if total > PREVIEW_SIZE else ""
    body += '<section><h2>增删改操作明细</h2>' + _index_table(report, range(min(total, PREVIEW_SIZE)), prefix=directory) + more_records + '</section>'
    body += '<section><h2>采集状态与统计口径</h2>' + issues + '<ul class="coverage-list">' + notes + '</ul></section>'
    title = "RDS 操作审计报告" if meta.get("period_kind") == "custom" else "RDS 操作审计日报"
    return _document(report, title, body)


def _record_table(report, indices):
    rows = []
    for index in indices:
        row = report["events"][index]
        resources = '<br>'.join(_e(_text(item, 600)) for item in row.get("resources", [])[:10]) or "—"
        css_class = "failed" if row.get("status") == "failed" else ""
        rows.append(f'<tr class="record {css_class}" id="event-{index + 1:06d}"><td class="time nowrap">{_e(row.get("time_local", ""))}<br><small class="record-id">#{index + 1}</small></td><td>{_e(_text(row.get("actor"), 120))}<br><small>{_e(row.get("actor_type", ""))}</small><br><span class="chip">{_e(row.get("category", ""))}</span></td><td class="operation"><pre>{_e(_text(row.get("description") or row.get("sql") or row.get("event_name"), SQL_LIMIT))}</pre>{_operation_details(row, include_statement=False)}</td><td>{resources}</td><td>{_e(_text(row.get("source_ip"), 120))}<br><small>{_e(_text(row.get("region"), 60))}</small></td><td>{_e(_text(row.get("result"), 600))}</td></tr>')
    return '<div class="scroll"><table class="operations"><thead><tr><th>北京时间</th><th>操作者 / 分类</th><th>操作信息</th><th>资源 / 数据库</th><th>来源 / 区域</th><th>请求结果</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>' if rows else '<p class="empty">没有符合条件的增删改明细。</p>'


def _pages(indices):
    return max(1, (len(indices) + PAGE_SIZE - 1) // PAGE_SIZE)


def write_paginated_report(report: dict, directory: Path) -> Path:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    filename = _filename(report)
    art = _artifacts(report)
    assets = directory / art["detail_directory"]
    if assets.is_symlink():
        raise ValueError("detail directory cannot be a symbolic link")
    assets.mkdir(exist_ok=True)
    files = [filename, "rds-report.css"]

    def save(name, markup):
        if not re.fullmatch(r"[a-z0-9-]+\.html", name):
            raise ValueError("unsafe generated page name")
        (assets / name).write_text(markup, encoding="utf-8")
        files.append(art["detail_directory"] + "/" + name)

    events = report.get("events", [])
    indices = list(range(len(events)))
    total_pages = _pages(indices)
    for page in range(1, total_pages + 1):
        pagination = _pagination("events", page, total_pages)
        body = pagination + '<section><h2>完整操作明细</h2><p class="fine">单页最多 100 条；长 SQL 和大字段只展示有界片段，完整字段保存在服务器归档 daily-report.json，不会由网页自动读取。</p>' + _record_table(report, indices[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]) + '</section>' + pagination
        save(f"events-{page:06d}.html", _document(report, "增删改操作明细", body, child=True))

    actor_indices = defaultdict(list)
    failed = []
    categories = {"create": [], "delete": [], "modify": []}
    category_keys = {"新增": "create", "删除": "delete", "修改": "modify"}
    for index, row in enumerate(events):
        actor_indices[str(row.get("actor_group_key") or row.get("actor_key", "unknown"))].append(index)
        if row.get("status") == "failed":
            failed.append(index)
        if row.get("category") in category_keys:
            categories[category_keys[row["category"]]].append(index)

    def index_pages(prefix, title, selected):
        count = _pages(selected)
        for page in range(1, count + 1):
            pagination = _pagination(prefix, page, count)
            body = pagination + f'<section><h2>{_e(title)}</h2><p>共 {len(selected)} 条；点击记录进入对应的明细页。</p>' + _index_table(report, selected[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]) + '</section>' + pagination
            save(f"{prefix}-{page:06d}.html", _document(report, title, body, child=True))

    index_pages("failed", "失败的增删改请求", failed)
    for prefix, label in (("create", "新增明细"), ("delete", "删除明细"), ("modify", "修改明细")):
        index_pages(prefix, label, categories[prefix])
    for actor in report.get("actors", []):
        index_pages(_actor_prefix(actor["actor_key"]), "操作者：" + _text(actor.get("actor"), 120), actor_indices.get(str(actor["actor_key"]), []))
    actors = report.get("actors", [])
    actor_pages = _pages(actors)
    for page in range(1, actor_pages + 1):
        pagination = _pagination("actors", page, actor_pages)
        body = pagination + '<section><h2>全部操作者</h2>' + _actor_table(actors[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]) + '</section>' + pagination
        save(f"actors-{page:06d}.html", _document(report, "操作者汇总", body, child=True))
    for prefix, title, records in (("errors", "采集与解析问题", report["metadata"].get("errors", [])), ("unparsed", "未解析或隔离的证据", report.get("unparsed", []))):
        pages = _pages(records)
        for page in range(1, pages + 1):
            pagination = _pagination(prefix, page, pages)
            items = ''.join('<article class="error-item"><pre>' + _json(row) + '</pre></article>' for row in records[(page - 1) * PAGE_SIZE:page * PAGE_SIZE])
            body = pagination + f'<section><h2>{title}</h2><p>共 {len(records)} 项；长字段有界展示，完整内容保存在服务器归档。</p>' + (items or '<p class="empty">无此类记录。</p>') + '</section>' + pagination
            save(f"{prefix}-{page:06d}.html", _document(report, title, body, child=True))

    (directory / "rds-report.css").write_text(_css(), encoding="utf-8")
    main = directory / filename
    main.write_text(generate_overview(report), encoding="utf-8")
    art["manifest"] = files + [art["bundle_filename"]]
    report["artifacts"] = art
    # Keep complete normalized evidence as an archive, never an eager browser payload.
    with (directory / "daily-report.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, default=str)
        handle.write("\n")
    with ZipFile(directory / art["bundle_filename"], "w", compression=ZIP_DEFLATED, compresslevel=6) as bundle:
        for name in files:
            bundle.write(directory / name, arcname=name)
    return main
