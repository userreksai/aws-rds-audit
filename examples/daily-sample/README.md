此目录的账号、人员、IP、数据库和操作全部为虚构的离线示例，不代表真实 AWS 活动。

在项目根目录运行：

```bash
python rds_audit.py --input-dir examples/daily-sample --date 2026-10-29
```

生成 `2026-10-29-rds操作审计.html`、`rds-report.css` 和 `daily-report.json`。打开 HTML 时保留同目录 CSS。

示例包含成功和失败的管理 API、数据库增删改、无法推断内部行为的 CALL，以及不计入 SQL 语句数的辅助审计事件。
