"""Static summary pages containing user totals only."""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZipFile

PAGE_SIZE = 100
FORMAT_VERSION = "user-summary-v1"
EXTRA_CSS = """
.summary-table{table-layout:fixed;min-width:720px}.summary-table th,.summary-table td{vertical-align:middle}.summary-table th.number,.summary-table td.number{text-align:right;white-space:nowrap}.actor-label{width:32%}.actor-source{width:20%}.summary-number{width:9.6%}.source-label{width:24%}.pagination{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:16px 0}.pagination a{padding:8px 12px;background:#eaf1f9;border-radius:6px}.section-footer{margin:16px 0 0}
""".strip()


def _model():
    import rds_report
    return rds_report


def _e(value):
    return html.escape(str(value), quote=True)


def _href(path):
    return quote(str(path), safe="/-_.#")


def _filename(report):
    filename = str(report["metadata"]["report_filename"])
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}-rds操作审计(?:-自定义窗口)?\.html", filename):
        raise ValueError("unsafe report filename")
    return filename


def _css():
    return _model().CSS + "\n" + EXTRA_CSS + "\n"


def _summary_report(report):
    """Discard legacy evidence even if a caller passes an older report model."""
    allowed_actor = ("actor", "actor_key", "actor_type", "source_kind", "total", "failed", "counts", "attempted_counts", "anchor")
    metadata = {key: value for key, value in report["metadata"].items() if key != "errors"}
    metadata["summary_only"] = True
    metadata["errors"] = [{"scope": "summary_quality", "reason": "incomplete", "count": int(row.get("count", 1))}
                          for row in report["metadata"].get("errors", [])]
    coverage = {key: value for key, value in report.get("coverage", {}).items()
                if key in {"notes", "audit_cloudwatch_events", "general_log_events_not_counted", "duplicate_cloudwatch_events",
                           "filtered_management", "filtered_queries", "filtered_auxiliary", "unclassified", "unparsed_records",
                           "unknown_reasons", "collection_status"}}
    return {"metadata": metadata, "actors": [{key: row[key] for key in allowed_actor if key in row} for row in report.get("actors", [])],
            "by_source": report.get("by_source", {}), "coverage": coverage, "events": [], "unparsed": []}


def _artifacts(report):
    filename = _filename(report)
    payload = _summary_report(report)
    payload["metadata"] = {key: value for key, value in payload["metadata"].items() if key != "generated_at"}
    digest = hashlib.sha256((FORMAT_VERSION + _css()).encode())
    for chunk in json.JSONEncoder(ensure_ascii=False, sort_keys=True, default=str).iterencode(payload):
        digest.update(chunk.encode())
    return {"format": FORMAT_VERSION, "page_size": PAGE_SIZE,
            "detail_directory": filename[:-5] + "-summary-" + digest.hexdigest()[:12],
            "bundle_filename": filename[:-5] + "-汇总报告.zip", "detail_pages": 0}


def _document(report, title, body, *, child=False):
    meta, model = report["metadata"], _model()
    prefix = "../" if child else ""
    css = _css()
    css_hash = hashlib.sha256(css.encode()).hexdigest()[:12]
    status = "采集步骤完成" if meta.get("complete") else "采集或解析不完整"
    badges = f'<span class="badge{ " error" if not meta.get("complete") else ""}">{status}</span>'
    if meta.get("example_data"):
        badges += ' <span class="badge demo">虚构示例，非真实账号数据</span>'
    elif meta.get("offline"):
        badges += ' <span class="badge demo">离线输入，未向 AWS 验证</span>'
    back = f'<p><a href="{_href(prefix + _filename(report))}">← 返回报告总览</a></p>' if child else ""
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(meta['audit_date'])} {_e(title)}</title><link rel="stylesheet" href="{prefix}rds-report.css?v={css_hash}"><style>{css}</style></head>
<body><main>{back}<header><div class="topline"><div><h1>{_e(title)}</h1><div class="muted">{_e(meta.get('period_label', '北京时间日报'))} · 窗口结束日期 {_e(meta['audit_date'])} · AWS 账号 {_e(meta['account_id'])}</div></div><div>{badges}</div></div><p class="window">北京时间 {_e(model.local_time(meta['window_start_utc']))} 至 {_e(model.local_time(meta['window_end_utc_exclusive']))}（左闭右开）<br><small>生成于 {_e(model.local_time(meta['generated_at']))}（北京时间）</small></p></header>{body}</main></body></html>'''


def _actor_table(actors):
    rows = []
    for actor in actors:
        cells = "".join(f'<td class="number">{int(actor.get("counts", {}).get(category, 0))}</td>' for category in ("新增", "删除", "修改"))
        rows.append(f'<tr><td>{_e(actor.get("actor", ""))}<br><small>{_e(actor.get("actor_type", ""))}</small></td><td>{_e(_model().SOURCE_LABELS.get(actor.get("source_kind"), ""))}</td>{cells}<td class="number">{int(actor.get("failed", 0))}</td><td class="number">{int(actor.get("total", 0))}</td></tr>')
    columns = '<colgroup><col class="actor-label"><col class="actor-source">' + '<col class="summary-number">' * 5 + '</colgroup>'
    return '<div class="scroll"><table class="summary-table actor-summary">' + columns + '<thead><tr><th>操作者</th><th>来源</th><th class="number">新增</th><th class="number">删除</th><th class="number">修改</th><th class="number">失败</th><th class="number">请求总数</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>' if rows else '<p class="empty">当前未取得可汇总的增删改操作者。</p>'


def generate_overview(report):
    meta = report["metadata"]
    cards = []
    for category, css_class in (("新增", "create"), ("删除", "delete"), ("修改", "modify")):
        parts = [f"{_e(source.get('label', kind))} {int(source.get('counts', {}).get(category, 0))}" for kind, source in report.get("by_source", {}).items()]
        cards.append(f'<div class="card {css_class}"><span>{category}</span><strong>{int(meta.get("counts", {}).get(category, 0))}</strong><small>{" · ".join(parts)}</small></div>')
    body = '<div class="cards">' + "".join(cards) + '</div>'
    coverage = meta.get("source_cache")
    if coverage:
        missing = len(coverage.get("missing_segments", []))
        body += f'<div class="notice{ " error" if missing else ""}">本地分段覆盖 {int(coverage.get("selected_segments", 0))} / {int(coverage.get("expected_segments", 0))}；缺失 {missing} 段。缺失段不按零操作处理。{"本报告已按补采结果修订。" if coverage.get("revision") else ""}</div>'
    sources = []
    for kind, source in report.get("by_source", {}).items():
        cells = "".join(f'<td class="number">{int(source.get("counts", {}).get(category, 0))}</td>' for category in ("新增", "删除", "修改"))
        sources.append(f'<tr><td>{_e(source.get("label", kind))}</td>{cells}<td class="number">{int(source.get("failed", 0))}</td><td class="number">{int(source.get("total", 0))}</td></tr>')
    columns = '<colgroup><col class="source-label">' + '<col class="summary-number">' * 5 + '</colgroup>'
    body += '<section><h2>按来源汇总</h2><div class="scroll"><table class="summary-table source-summary">' + columns + '<thead><tr><th>来源</th><th class="number">新增</th><th class="number">删除</th><th class="number">修改</th><th class="number">失败</th><th class="number">请求总数</th></tr></thead><tbody>' + "".join(sources) + '</tbody></table></div></section>'
    actors = report.get("actors", [])
    more = f'<p class="section-footer"><a href="{_href(_artifacts(report)["detail_directory"] + "/actors-000001.html")}">更多操作者（共 {len(actors)} 位）</a></p>' if len(actors) > PAGE_SIZE else ""
    body += '<section><h2>按操作者汇总</h2>' + _actor_table(actors[:PAGE_SIZE]) + more + '</section>'
    unknown = int(report.get("coverage", {}).get("unparsed_records", 0))
    if unknown or not meta.get("complete"):
        body += f'<div class="notice error">当前汇总不完整；无法解析或分类的记录 {unknown} 条。请检查采集状态并补采，不能将缺失记录当作零操作。</div>'
    notes = "".join(f'<li>{_e(note)}</li>' for note in report.get("coverage", {}).get("notes", [])[:20])
    body += '<section><h2>统计口径</h2><ul class="coverage-list">' + notes + '</ul></section>'
    title = "RDS 操作审计报告" if meta.get("period_kind") == "custom" else "RDS 操作审计日报"
    return _document(report, title, body)


def _pagination(page, pages):
    links = []
    if page > 1:
        links.append(f'<a href="actors-{page - 1:06d}.html">上一页</a>')
    links.append(f'<span>第 {page} / {pages} 页 · 每页最多 {PAGE_SIZE} 位</span>')
    if page < pages:
        links.append(f'<a href="actors-{page + 1:06d}.html">下一页</a>')
    return '<nav class="pagination" aria-label="操作者分页">' + "".join(links) + '</nav>'


def write_paginated_report(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    compact = _summary_report(report)
    filename, art = _filename(compact), _artifacts(compact)
    files = [filename, "rds-report.css"]
    actors = compact.get("actors", [])
    if len(actors) > PAGE_SIZE:
        assets = directory / art["detail_directory"]
        if assets.is_symlink():
            raise ValueError("summary directory cannot be a symbolic link")
        assets.mkdir(exist_ok=True)
        pages = (len(actors) + PAGE_SIZE - 1) // PAGE_SIZE
        for page in range(1, pages + 1):
            navigation = _pagination(page, pages)
            body = navigation + '<section><h2>按操作者汇总</h2>' + _actor_table(actors[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]) + '</section>' + navigation
            name = f'actors-{page:06d}.html'
            (assets / name).write_text(_document(compact, "操作者汇总", body, child=True), encoding="utf-8")
            files.append(art["detail_directory"] + "/" + name)
    (directory / "rds-report.css").write_text(_css(), encoding="utf-8")
    target = directory / filename
    target.write_text(generate_overview(compact), encoding="utf-8")
    art["manifest"] = files + [art["bundle_filename"]]
    compact["artifacts"] = art
    report["artifacts"] = art
    (directory / "daily-report.json").write_text(json.dumps(compact, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    with ZipFile(directory / art["bundle_filename"], "w", compression=ZIP_DEFLATED, compresslevel=6) as bundle:
        for name in files:
            bundle.write(directory / name, arcname=name)
    return target
