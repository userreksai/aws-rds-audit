# RDS MySQL / Aurora MySQL 用户变更汇总的数据源说明

本项目只回答“哪些 AWS 身份或数据库账号进行了新增、删除、修改，各多少次”。新采集、归档、HTML 和 Lark 不保存或展示 SQL 原文和逐条执行信息；详细部署和命令见 [README.md](README.md)。脚本通过 AWS 只读 API 获取现有记录，不连接数据库、不修改实例或审计配置。

## 简单接口能否直接获取汇总

| 接口或服务 | 是否可直接替代当前数据库用户汇总 |
| --- | --- |
| CloudTrail `LookupEvents` | 只能读取 RDS 管理 API 历史，不记录普通 MySQL 客户端执行的表内增删改；没有本项目所需的数据库用户计数 |
| RDS `DescribeEvents` | 备份、维护、故障切换等服务通知，不能说明哪个用户修改了数据 |
| RDS 配置、CloudWatch 常规指标 | 配置和性能指标，不能直接提供完整的数据库用户历史增删改次数 |
| Performance Insights / Database Insights | 性能负载、采样及 SQL 维度分析，不是完整的操作审计计数 |
| CloudWatch Logs Insights | 技术上可以 `parse` + `stats` 扫描审计日志返回聚合结果，但需要验证日志格式、复杂语句和未知记录处理，需要查询权限并产生扫描费用 |

用户选择先保留现有 30/60 分钟分段采集及每日本地汇总，每段流式解析后仅写用户计数。报告不再持有全部语句列表。语句数量很大时，AWS 源日志量、读取流量和处理耗时仍需容量规划；数据库行数不等于日志语句数量。

Logs Insights 可作为后续优化：云端扫描后仅回传汇总可降低下行数据量，但按扫描字节计费，单次查询有运行时限，也需处理未完成、失败、结果限制和迟到数据。一个 CloudWatch 消息可能包含多条审计记录；多行 SQL、注释、预编译调用、WITH 和截断记录不能凭简单正则安全分类。未经实际日志验证，本项目不会自动切换或把解析不到的结果当作 0。

参考官方文档：[CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)、[RDS 事件](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeEvents.html)、[Logs Insights StartQuery](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_StartQuery.html)、[GetQueryResults](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html)、[Logs Insights stats](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-Stats.html)。

## 统计与身份边界

新增、删除、修改统计的是可识别、未报错的 API 请求或审计语句条数，不是受影响行数。保留既有变更分类，包含可识别的 DDL、REPLACE 和 LOAD DATA 等；失败请求只进入失败汇总。SQL 返回码 0 不证明最终 COMMIT，API 未报错不证明异步变更最终成功。

数据库记录以 CloudWatch 事件时间归属分段和日报，同一事件内全部审计记录一起计入，避免跨边界的多记录消息漏计；管理 API 仍以 CloudTrail 事件时间筛选。

同名数据库账号跨实例和日志流合并，名称区分大小写；AWS 身份单独分组，不与同名数据库账号混合。多人共用数据库账号时只能识别该账号，无法推断真实人员。

CloudTrail 管理历史限当前账号、所选区域及近 90 天，超过范围需要事先保留的 S3/Lake 归档，本项目不读取该归档。普通 MySQL 客户端的 SQL 不在 CloudTrail 管理事件中。Aurora Data API 的 CloudTrail 记录也不提供 SQL 正文，其数据事件不由本项目采集。[Data API 的 CloudTrail 记录](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/logging-using-cloudtrail-data-api.html)

数据库内部变更依赖当时已启用且仍保留的 audit 日志。用户或事件过滤、截断、轮转、删除、延迟发布和权限失败都会影响覆盖；当前配置不能证明历史已生效，无法补录从未记录的历史。无日志不能认定无操作。

## 权限与日志发现

将 [iam-policy-rds-audit.json](iam-policy-rds-audit.json) 挂到采集身份。脚本通过标准 AWS 凭据链使用 profile、实例角色或其它工作负载身份；不要把 Access Key、数据库密码或 Lark Webhook 写进代码。IAM 日志读取权限与数据库内的 SQL 权限不同。

现有策略覆盖配置发现和日志读取。显式指定区域可移除 `ec2:DescribeRegions`。持续计算数据库用户汇总仍需要 `logs:FilterLogEvents`，不能因为本地不再保存 SQL 而移除该权限。实例原始文件下载不属于仅汇总模式，`rds:DownloadDBLogFilePortion` 无需用于定时汇总；可按实际功能、账号、区域和资源收紧策略。SCP、权限边界和显式 Deny 仍可能限制查询。

CloudWatch 发现以下标准日志组，包括已删除数据库留下的现存组：

```text
/aws/rds/instance/<实例标识>/audit
/aws/rds/instance/<实例标识>/general
/aws/rds/cluster/<集群标识>/audit
/aws/rds/cluster/<集群标识>/general
```

仅 audit 正文参与流式计算；general 正文不采集，避免大量查询与重复计数。自定义目的地、S3 归档、其它账号、非标准路径、数据库 TABLE 日志、慢日志、binlog 和 Database Activity Streams 不在本项目采集范围。

分页遇到空页仍按游标继续，不能只搜索 INSERT 等关键词，以免漏掉多行记录和复杂格式。确定的读取与辅助事件被过滤；无法识别的记录只保留计数与固定原因，标记质量不完整，不保存原文，也不混入成功数量。

## 审计配置

**普通 RDS MySQL** 使用 Option Group 中的 `MARIADB_AUDIT_PLUGIN`。管理员应检查 `SERVER_AUDIT_EVENTS`、用户包含/排除范围、选项组关联状态和日志导出。仅需写入时可评估 `QUERY_DML_NO_SELECT`，结构或权限变更还需考虑 DDL/DCL；应结合实际版本和负载决定，脚本不修改配置。[RDS MySQL 审计插件](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.MySQL.Options.AuditPlugin.html)

**Aurora MySQL** 使用集群参数组的 Advanced Auditing，需要核实 `server_audit_logging`、`server_audit_events`、用户过滤和参数关联状态。`QUERY_DML` 包含 SELECT，不能直接照搬普通 RDS MySQL 配置；还可能通过日志上传参数与角色导出，因此不能只凭当前导出开关推定历史无日志。[Aurora MySQL Advanced Auditing](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html)

开启 CloudWatch 导出不等于已在数据库内启用审计。[MySQL 日志导出](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.MySQLDB.PublishtoCloudWatchLogs.html)、[Aurora 日志导出](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Integrating.CloudWatch.html)

## 分段、质量与历史数据

保留原有分段缓存、重试、迟到复采、每日 25 小时窗口、共同进程锁和故障通知。源记录精确去重依赖事件身份，计算时不把所有 SQL 放入内存。成功段只保留汇总及必要元数据，日报合并用户计数；缺失或校验失败段进入修复队列，不以 0 代替。

未知记录或异常格式只保留质量计数与原因汇总，报告和质量告警标记不完整。质量恢复须由原问题段的健康快照确认，不能用其它空段覆盖原问题。更新后的新文件不再生成逐条 SQL 原文隔离证据；以前已保存的隔离文件不自动删除。

新报告模型 `daily-report.json` 与 `operation-summary.json` 无 SQL 原文，网页只提供用户汇总。旧目录通过 `--input-dir` 可流式重建为汇总报告，原始 JSONL 不修改。已有详情文件、旧告警队列和历史归档不自动清理；新运行不会继续投递逐 SQL 队列。应结合保留策略和磁盘容量另行处理历史文件。

安装升级后重跑 `install.sh`：旧 `AWS_RDS_SQL_ALERTS=1` 被迁移为 0；采集运行器即使读到旧环境也不再启用逐 SQL 告警。采集、质量、覆盖、进程和投递异常通知继续工作，日报发用户数量汇总及链接。
