# RDS MySQL / Aurora MySQL 操作记录采集

HTML 日报、Lark 汇总和 Linux 安装/定时服务的部署说明见 [README.md](README.md)。本文说明自定义时间窗口采集、SQL 审计配置与证据边界；下面不带 `--daily` 的命令保留原始时间窗口行为，并自动生成按该窗口汇总的 HTML。

`rds_audit.py` 是独立的只读采集脚本，使用 boto3 获取当前 AWS 账号可见的 RDS 管理操作、服务事件、审计配置和已有数据库日志。它不连接数据库，也不修改实例、参数组或日志配置。

## 能查到哪些记录

| 记录 | 数据来源 | 能回答的问题 | 范围限制 |
| --- | --- | --- | --- |
| RDS 管理操作 | CloudTrail `LookupEvents` | 谁在何时从哪个 IP 调用了创建、修改、删除、重启、快照等 RDS API，提交了哪些参数，调用是否报错 | 当前账号、所选区域、最近 90 天，包含读取和写入 API |
| RDS 服务事件 | RDS `DescribeEvents` | 备份、故障切换、维护等服务通知 | 最近 14 天，不能替代操作审计 |
| 数据库内部 SQL | 已存在的 audit / general 日志 | 日志记录的数据库用户、来源、时间、SQL 等 | 必须在当时已启用相应日志，且日志仍在保留期内 |
| 当前审计配置 | RDS 实例、集群、参数组、选项组 | 当前配置了哪些审计事件、用户过滤和日志导出 | 当前配置不能证明过去已经启用，也不能单独证明已在数据库运行时生效 |

CloudTrail 管理事件不包含普通 MySQL 客户端执行的 `INSERT`、`UPDATE`、`DELETE`。即使通过 Aurora Data API 执行 SQL，CloudTrail 的相关 API 记录也不会展示 SQL 正文；Data API 数据事件亦不由本脚本采集。参见 [CloudTrail 查询范围](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)、[RDS Data API 的 CloudTrail 记录](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/logging-using-cloudtrail-data-api.html)。

“所有操作”只能理解为指定范围内、服务实际记录且当前身份有权读取的全部可见记录。以前没开 SQL 审计、用户或事件被排除、SQL 被截断、日志已轮转删除的内容，脚本无法补录。超过 90 天的管理操作需要查询原先保存在 S3 Trail 或 CloudTrail Lake 的记录，本脚本不读取这些归档。

## 安装与身份

需要 Python 3.10 或更高版本。已有项目虚拟环境时直接复用：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Linux 使用：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

将同目录的 `iam-policy-rds-audit.json` 挂到用于采集的 IAM 角色或身份。该策略用于读取 CloudTrail、RDS 配置和日志，不提供修改数据库配置的权限。已有每日审计脚本的策略不包含全部 RDS 与 CloudWatch 读取权限，需要额外授权。SCP、权限边界、显式 Deny 仍可能阻止查询。

这是覆盖脚本所有可选功能的只读策略。显式指定区域时可以移除 `ec2:DescribeRegions`；不用下载实例文件时可以移除 `rds:DownloadDBLogFilePortion`；不用下载 CloudWatch SQL 正文时可以移除 `logs:FilterLogEvents`。可按实际账号、区域和实例进一步缩小资源范围。

本地可使用已配置的 AWS profile，例如 `audit`；EC2 IAM Role 等运行方式省略 `--profile`，使用 boto3 默认凭据链。无需把 Access Key、Secret Key 或数据库密码写进脚本，也无需在聊天里提供凭据。IAM 读取权限与数据库内执行 SQL 的权限是两套授权。

## 运行

先检查近 7 天管理操作、服务事件、当前审计配置和现存日志目录：

```powershell
.\.venv\Scripts\python.exe rds_audit.py --profile audit --regions ap-southeast-1 --days 7
```

同时导出已有 CloudWatch audit / general 日志：

```powershell
.\.venv\Scripts\python.exe rds_audit.py --profile audit --regions ap-southeast-1 --days 7 --download-sql-logs
```

自动发现当前 AWS 分区内所有已启用区域：

```powershell
.\.venv\Scripts\python.exe rds_audit.py --profile audit --regions all --download-sql-logs
```

Linux 将命令中的 Python 替换为 `.venv/bin/python`。`--regions` 默认 `all`；显式列出多个区域时用逗号分隔。自动发现区域需要 `ec2:DescribeRegions`，发现请求使用 `--discovery-region`、profile / 环境的默认区域或最后回退的 `us-east-1`。中国区或 GovCloud 等分区应指定本分区的发现区域，例如 `--discovery-region cn-north-1`。

需要精确时间窗口时，成对指定带时区的 ISO 8601 时间：

```powershell
.\.venv\Scripts\python.exe rds_audit.py --profile audit --regions ap-southeast-1 --start 2026-10-27T00:00:00+07:00 --end 2026-10-29T00:00:00+07:00 --download-sql-logs
```

这表示曼谷时间 10 月 27 日零点至 10 月 29 日零点，查询左闭右开，输出时间统一为 UTC。不要将不带时区的本地时间作为输入。`--days` 默认 7，必须大于 0 且小于 90；精确窗口使用 `--start` / `--end` 替代它。早于近 90 天范围的请求会被拒绝，边界保留 1 分钟余量；服务事件只查询该窗口与最近 14 天的交集，同样预留 1 分钟边界余量。CloudWatch 原始记录里的毫秒时间戳保持原样。

若没有 CloudWatch 日志，但数据库实例上仍有 audit / general 文件，可用备用下载方式：

```powershell
.\.venv\Scripts\python.exe rds_audit.py --profile audit --regions ap-southeast-1 --download-instance-logs
```

此方式下载当前 MySQL / Aurora MySQL 实例仍可见的相关文件，**下载整文件，不按上述时间窗口裁剪**。它会使用数据库实例资源，日志量大时优先使用 CloudWatch 导出方式。两种下载开关可以一起使用，可能包含重复的底层 SQL 记录。[AWS 的实例日志下载说明](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DownloadDBLogFilePortion.html)

## 输出与结果判断

默认在 `reports/rds/` 下为每次执行创建独立子目录，可通过 `--output-dir` 更改父目录：

```text
reports/rds/<AWS账号ID>/<本次运行目录>/
  report.json                  账号、时间窗口、各区域采集状态、配置、日志目录和错误
  management-events.jsonl       CloudTrail RDS 管理操作，逐行 JSON
  rds-events.jsonl              RDS 服务事件，逐行 JSON
  cloudwatch/*.jsonl            可选的 CloudWatch SQL 原始日志
  instance-logs/*.log           可选的实例原始日志
  daily-report.json            规范化统计、操作者与具体操作明细
  YYYY-MM-DD-rds操作审计-自定义窗口.html  自定义窗口 HTML 汇总
  rds-report.css               HTML 配套样式
```

所有实际采集命令都会自动生成 HTML。`--days`、`--start` / `--end` 或默认最近 7 天使用真实查询窗口，HTML 不会套用固定日报的 25 小时范围；定时 `--daily` 仍生成原有日报文件名。查看 HTML 时保留同目录 CSS。显式自定义窗口也可选用 `--send-lark` 与 `--publish-dir`；不提供这些开关就不会推送或发布。

已有下载目录可以直接生成 HTML，无需重新拉取。例如：

```bash
cd /usr/local/aws-rds-shenji
.venv/bin/python rds_audit.py --input-dir reports/ap-east-1-check/796973492024/20261029T093255Z-20ece9a5
```

不加 `--date` / `--daily` 时使用该目录 `report.json` 保存的完整原窗口；新元数据中的 `period_kind` 会保留，旧目录没有该字段时作为自定义窗口。上述目录的窗口为北京时间 2026-10-28 17:32:55 至 2026-10-29 17:32:55，不要求覆盖另一个 25 小时日报窗口。原始 JSONL 会保留，离线生成不连接 AWS。若显式加 `--date` 或 `--daily`，仍会检查原数据是否完整覆盖请求的固定日报窗口。

下载 40,510 条 CloudWatch 事件不代表发生 40,510 次增删改。汇总按解析后的操作记录分类；失败、辅助事件和不能可靠解析的内容按报告口径分别展示，解析失败会保留证据并标记采集或解析不完整。

默认不下载 SQL 正文，仅列出现有日志和审计配置。管理事件按 `rds.amazonaws.com` 查询，不要求资源仍存在，因此已删除实例的管理记录仍可收录。CloudWatch 日志目录也直接扫描现存的标准 RDS audit / general 日志组，涵盖已删除实例留下的日志，不只依赖当前导出开关。

CloudWatch 标准路径为 `/aws/rds/instance/<实例标识>/audit`、`/general`，Aurora 为 `/aws/rds/cluster/<集群标识>/audit`、`/general`，集群内各实例对应不同日志流。自定义转发目的地、S3 归档、其他账号和非标准路径不在该扫描范围。

脚本按分页继续读取，不因 CloudWatch 某一页为空而提前结束；不以 `INSERT` 等关键词过滤，以免漏掉多行语句、注释、预编译语句或其他日志格式。导出的 SQL 日志可能包含业务数据，请将输出目录放在受控位置，不要直接作为公开网页目录。

退出码：

- `0`：请求的采集步骤完成；不代表过去所有操作都有完整审计记录。
- `2`：存在区域、配置、日志读取或报告解析失败，已获取的结果仍保留；请检查 `report.json` 与 `daily-report.json`，不能把权限失败当作没有操作。
- `1`：参数或身份等运行前提失败，按终端提示修正。
- `3`：报告已生成，但所请求的 Lark 发送失败。
- `4`：报告已生成，但所请求的网页发布失败。

采集或解析不完整的退出码 `2` 优先于后续发布或通知错误。

查询结果为空还应检查账号、区域、时间范围、保留期、审计事件类别和用户过滤。日志发布存在延迟，刚发生的操作可稍后重查。

## MySQL 与 Aurora 的 SQL 审计区别

**普通 RDS MySQL** 使用 Option Group 中的 `MARIADB_AUDIT_PLUGIN`。检查 `SERVER_AUDIT_EVENTS` 是否包含目标操作、`SERVER_AUDIT_INCL_USERS` / `SERVER_AUDIT_EXCL_USERS` 是否排除了业务用户，以及选项组关联状态。只需记录写入语句时可评估 `QUERY_DML_NO_SELECT`；该项不包含 `SELECT`。需要结构或权限变更时还需考虑 DDL / DCL 事件。`SERVER_AUDIT_QUERY_LOG_LIMIT` 默认 1024，长 SQL 可能被截断。脚本仅检查配置，不自动添加或修改插件。[RDS MySQL 审计插件](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.MySQL.Options.AuditPlugin.html)

**Aurora MySQL** 使用 DB Cluster Parameter Group 中的 Advanced Auditing。`server_audit_logging` 需要开启，`server_audit_events` 也必须指定事件；`QUERY_DML` 包含 `SELECT`，不能照搬普通 RDS MySQL 的 `QUERY_DML_NO_SELECT`。还需检查用户过滤、参数关联状态和日志发布。Aurora 也支持通过 `server_audit_logs_upload` 配合日志角色上传审计日志，因此不能单凭 `EnabledCloudwatchLogsExports` 缺少 `audit` 就判定没有发布过日志。[Aurora MySQL Advanced Auditing](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html)

若使用 general 日志，检查 `general_log=1` 和 `log_output=FILE`，并配置对应日志导出。开启 CloudWatch 导出不等于自动启用了数据库内的审计或 general 日志。[RDS MySQL 日志导出](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.MySQLDB.PublishtoCloudWatchLogs.html)、[Aurora MySQL 日志导出](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Integrating.CloudWatch.html)

普通 RDS MySQL 如果已经使用 `log_output=TABLE`，general 日志可能位于 `mysql.general_log` 或轮转后的 `mysql.general_log_backup`，需要有权限的数据库连接查询；本脚本不会读取这些表。不要为了查看历史而先修改现有日志输出设置。慢查询日志也可能留有部分 SQL 线索，但本脚本只采集 audit / general 文件和对应 CloudWatch 日志，不采集慢日志或 Database Activity Streams 内容。[MySQL 日志输出与轮转](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.MySQL.LogFileSize.html)

拥有数据库读取权限时，可分别连接相关实例核实运行时变量；某些变量随引擎或插件有所不同，不存在的变量不会出现在结果中：

```sql
SHOW GLOBAL VARIABLES WHERE Variable_name IN (
  'server_audit_logging', 'server_audit_events',
  'server_audit_incl_users', 'server_audit_excl_users',
  'server_audit_query_log_limit', 'server_audit_logs_upload',
  'general_log', 'log_output',
  'log_bin', 'binlog_format', 'binlog_row_image'
);
```

这些查询反映当前运行状态，仍不能证明某个历史日期已启用审计。是否新增审计配置应结合实际版本、日志量和维护安排评估，脚本不会执行变更。

## 能否看到修改前后的数据

audit 日志通常回答“哪个数据库用户执行了什么 SQL”，不保证提供每一行的修改前值和修改后值。一般查询日志记录收到的语句，也不能据此认定事务最终提交成功。API 调用成功同样不代表异步资源变更已经完成。

若需要逐行变更内容，应另行评估已经保留的 ROW 格式 binlog / CDC；可获得的列和值取决于实际日志格式、row image、权限和保留设置。它与人员操作审计的用途不同，不能承诺补出未记录的内容。本脚本不解析 binlog。

数据库日志里的用户通常是数据库账号；多个应用或人员共用同一账号时，不能只靠它确定真实操作者。需要关联应用请求、登录身份和事务记录。脚本采集后应先确认日志实际内容和覆盖范围，再判断能否满足追责或逐行恢复要求。
