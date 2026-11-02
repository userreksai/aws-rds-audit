# AWS RDS 用户增删改汇总日报

采集当前 AWS 账号可见的 RDS 管理变更与 MySQL / Aurora MySQL 数据库审计记录，只生成按用户汇总的报告：**用户、新增数、删除数、修改数和失败数**。AWS 身份与数据库账号分开统计；同名数据库账号跨实例合并，名称区分大小写，共用账号不能确定真实人员。

新采集和新报告不保存 SQL 原文、业务参数或逐条执行详情，不再发送逐 SQL 即时告警。旧缓存、历史报告和已发布的详情文件不会自动删除；应按既定保留策略另行处理。

## 接口评估与生产数据量

RDS、CloudTrail 和 Performance Insights 没有直接提供满足本项目口径的“历史窗口 × 数据库用户 × 增删改次数”现成预聚合接口。CloudTrail 只能提供 RDS 管理 API 记录，不能替代数据库内部审计；性能负载和采样指标也不能当作完整操作次数。

CloudWatch Logs Insights 技术上可以通过 `StartQuery` / `GetQueryResults` 在 AWS 侧解析日志并用 `stats` 返回汇总，降低下行数据量，但仍需扫描源日志并按扫描量计费，需要额外查询权限。一个 CloudWatch 事件可能包含多条或多行审计记录，复杂 SQL、注释、预编译调用和截断内容需要验证解析覆盖，简单关键词或正则可能漏算。用户已选择**先保留现有分段采集，只保存汇总**；本版不启用未经生产日志验证的云端查询方案。

默认每 **30 分钟**采集已结束分段，也支持 **60 分钟**。采集器每 5 分钟检查到期工作与失败重试，流式解析候选日志后只保存用户计数，日报只合并本地分段汇总。精确去重使用临时磁盘索引，不把全部 SQL 记录装入内存。生产表有亿级行不代表有亿级审计语句；如果语句数量也很大，源日志存储、AWS API 读取流量和处理耗时仍然存在，本地汇总不能消除源端成本。

日报固定为北京时间（Asia/Shanghai）**前一日 07:00 至当日 08:00，共 25 小时**，默认每天 **08:10** 执行，可改 08:05。窗口左闭右开，相邻日报有意重叠一小时，不能直接相加作为跨日去重统计。

## 统计口径

| 来源 | 统计内容 | 范围限制 |
| --- | --- | --- |
| CloudTrail RDS 管理事件 | 可明确归类的新增、删除、修改，按 AWS 身份汇总 | 排除读取和其它非增删改 API；近 90 天可查 |
| CloudWatch audit 日志 | 可明确归类的 SQL 变更，按数据库账号汇总；保留既有 DDL、REPLACE、LOAD DATA 等分类 | 排除 SELECT 等查询、连接和 TABLE 辅助事件；当时必须已启用审计 |
| general 日志及服务事件 | 配置或覆盖检查，不计入用户增删改 | 不重复统计 SQL，不导出逐条正文 |

新增、删除、修改按**未报错的请求或语句条数**统计，不是受影响行数。失败请求只计入失败汇总；SQL 返回码 0 不证明事务最终提交，API 未报错不证明异步变更最终完成。

数据库审计记录统一按 **CloudWatch 事件时间**归属分段和日报窗口，同一事件内的全部审计记录一起汇总，避免多记录跨边界造成漏计；管理 API 使用 CloudTrail 事件时间。

未知、异常或疑似截断记录仅保留质量计数与原因汇总，报告标记不完整，不保存 SQL 原文、不猜测为 0 条。权限失败、没有日志和缺失分段同样不能视作没有操作。详细权限与数据源边界见 [RDS_AUDIT.md](RDS_AUDIT.md)。

## 部署与更新

安装需要 Linux + systemd、Python 3.10+，使用项目 `.venv`。安装器可从发行版软件源安装缺少组件，检查运行用户、依赖和现有 AWS 读取权限；不会生成凭据、授予权限、开启数据库审计或修改 Nginx。

首次部署到新的源码目录：

```bash
git clone https://github.com/userreksai/aws-rds-audit.git /usr/local/aws-rds-shenji
cd /usr/local/aws-rds-shenji
cp lark-config.example.json lark-config.json
chmod 600 lark-config.json
```

将 [iam-policy-rds-audit.json](iam-policy-rds-audit.json) 配置给采集身份，并以服务用户配置 AWS profile `audit`。EC2 IAM Role 可省略 profile；填好服务器私有 `lark-config.json`，已有配置直接保留，勿提交凭据或 Webhook。

安装或升级后重新生成服务：

```bash
cd /usr/local/aws-rds-shenji
git pull --ff-only origin main
bash install.sh --user root --profile audit --regions all --minute 10 --interval-minutes 30 \
  --publish-dir /usr/local/aws-rds-shenji/index
systemctl start aws-rds-audit-collect.service
systemctl list-timers 'aws-rds-audit*' --no-pager
```

**只执行 git pull 不会更新已安装的服务配置。** 安装器保留私有 Lark、AWS 配置和虚拟环境，将旧 `AWS_RDS_SQL_ALERTS=1` 强制迁移为 `0`；运行器即使遇到未迁移的旧环境也始终关闭逐 SQL 通知。显式 `--sql-alerts` 和原始实例文件下载被拒绝。旧告警命令范围不再影响采集，待发逐 SQL 队列不继续投递。

| 参数 | 说明 |
| --- | --- |
| `--user USER` | 已存在的服务用户，应能读取其 AWS 配置和项目 |
| `--profile NAME` | AWS profile；实例角色方式省略 |
| `--regions all` 或逗号分隔列表 | 默认所有已启用区域 |
| `--interval-minutes 30\|60` | 分段长度，默认 30 分钟 |
| `--minute 05\|10` | 北京时间 08:05 或 08:10，默认 08:10 |
| `--publish-dir /绝对路径` | 默认项目下 `index/`，首页 `index.html` |
| `--no-sql-alerts` | 兼容旧参数；仅汇总模式始终关闭逐 SQL 告警 |
| `--no-enable` | 安装并预检，不主动启用定时器 |
| `--check-only` | 使用现有配置检查，不安装、不写文件、不启停服务 |

配置文件 `/etc/aws-rds-audit.env` 由 root 所有、权限 0600，保留标准 AWS 凭据链变量。服务使用指定用户的 HOME，不复制 root 的凭据。预检失败时保留文件并禁用两个定时器；修正后重跑安装器。

| 环境变量 | 默认值或用途 |
| --- | --- |
| `AWS_RDS_CACHE_DIR` | 项目下 `cache/` |
| `AWS_RDS_INTERVAL_MINUTES` | 30，支持 30 或 60 |
| `AWS_RDS_CACHE_LOOKBACK_HOURS` | 26，新分段回看范围 |
| `AWS_RDS_MAX_BUCKETS_PER_RUN` | 6，每轮处理上限 |
| `AWS_RDS_SQL_ALERTS` | 固定为 0，旧值不启用逐 SQL 通知 |
| `AWS_RDS_REGIONS` | all |
| `AWS_RDS_REPORT_ROOT` | 项目下 `reports/` |
| `AWS_RDS_LARK_CONFIG` | 项目私有 `lark-config.json` |
| `AWS_RDS_PUBLISH_DIR` | 项目下 `index/`；空值使用默认值 |
| `AWS_RDS_MINUTE` | 10；修改后重跑安装器同步 timer |

## 重试、覆盖与通知

`aws-rds-audit-collect.timer` 每 5 分钟检查工作，预留 5 分钟日志发布缓冲，不是每 5 分钟重拉整日。首次每轮最多处理 6 段，后续继续回填，启动一次不代表已补齐全部 25 小时。账号、profile、区域、分段长度和过滤版本隔离缓存。

失败段最多短重试 3 次，间隔 2、4 秒；仍失败则跨轮退避，由 5 分钟增长至最多 1 小时。已发现的旧失败或待采分段移出 26 小时回看范围后仍继续补采，最多近 89 天。成功段结束约 60 分钟后额外复采一次以补收迟到日志；更迟发布或已删除日志仍可能无法恢复。

日报只合并本地成功分段：25 小时需要 50 个半小时段或 25 个一小时段。缺失、失败、损坏和未知解析均标记不完整。质量问题按原问题快照跟踪，不因其它分段或空段成功而恢复。未知记录只保留计数和原因，历史隔离原文不会被删除。

采集失败、缺段、质量和发布/通知异常仍持久化告警并在恢复后通知。同一故障每小时最多提醒一次；通知失败保留待发状态并退避重试。systemd `OnFailure` 可通知进程超时或异常退出。正常采集不发例行消息，日报发用户增删改汇总与报告链接，不含 SQL 摘要。

当日日报因窗口内补采或迟到数据改变时自动修订，内容不变不重复推送；历史日期手工补报。采集和日报共用进程锁，日报遇忙持久化排队，失败请求由后续任务继续处理。缓存和历史文件不自动清理，应安排磁盘容量与保留策略。

```bash
journalctl -u aws-rds-audit-collect.service -n 100 --no-pager
journalctl -u aws-rds-audit.service -n 100 --no-pager
systemctl status aws-rds-audit-collect.timer aws-rds-audit.timer
```

定时器使用 `Asia/Shanghai`，无需改服务器时区。`Persistent=true` 在停机后补执行最近已结束窗口，不自动逐日报送停机期间所有历史。

## 手动运行

未安装服务时创建环境并预检；预检不发送 Lark：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python rds_audit.py --check-config --profile audit --regions all --send-lark --lark-config lark-config.json
```

采集到与服务相同的缓存，再从缓存汇总日报：

```bash
.venv/bin/python rds_audit.py --collect-incremental --profile audit --regions all \
  --cache-dir cache --interval-minutes 30 --cache-lookback-hours 26 --max-buckets-per-run 6 \
  --send-lark --lark-config lark-config.json

.venv/bin/python rds_audit.py --daily --from-cache --profile audit --regions all \
  --cache-dir cache --interval-minutes 30 --output-dir reports \
  --send-lark --lark-config lark-config.json
```

可加 `--date YYYY-MM-DD` 补报；显式补报会再次发送。缓存日报不连接 AWS，profile、regions、interval 和 cache-dir 须与采集相同。多个账号匹配时加 `--cache-account-id <账号ID>`。CLI 默认 cache-dir 为 `reports/cache`，安装器为项目下 `cache`，手工配合服务请明确指定。

一次性查询昨日北京时间 07:00 至当前时间，或指定明确窗口：

```bash
.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 \
  --since-yesterday-7 --output-dir reports/manual

.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 \
  --start '2026-10-28T07:00:00+08:00' --end now --output-dir reports/manual

.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 --days 1 \
  --download-sql-logs --output-dir reports/manual
```

这些命令仍读取源 audit 日志，解析后只保存汇总；兼容参数 `--download-sql-logs` 表示获取源日志进行计算，不再导出 SQL 原文。`--since-yesterday-7` 不与其它时间窗口、日报、离线和缓存模式混用。`--start` / `--end` 必须同时指定并带时区，`now` 使用命令启动时的时间。刚发生的操作可能尚未发布日志。仅 `--days` 未请求源 SQL 时不会建立数据库内部变更覆盖。

已有目录可离线重建为汇总报告：

```bash
.venv/bin/python rds_audit.py --input-dir /path/to/existing-run
```

离线重建不连接 AWS、不修改旧 JSONL；默认沿用原元数据窗口，不要为了重建任意历史目录而强加另一个日报日期。Windows 将 Python 替换为 `.\.venv\Scripts\python.exe`；实例角色省略 `--profile`。不通知时省略 `--send-lark`，不发布时加 `--no-publish`。

## 新输出与网页

```text
report.json                    账号、窗口、采集和覆盖状态
operation-summary.json         用户增删改/失败与质量计数，无 SQL 原文
daily-report.json              汇总报告模型，无逐条执行记录
YYYY-MM-DD-rds操作审计.html    用户汇总首页（自定义窗口带相应后缀）
rds-report.css                 网页样式
```

用户较多时可生成用户汇总分页，不生成逐条操作页或执行详情。新网页、Lark 和服务器归档均不提供 SQL、业务值、参数、IP、连接或事务执行信息。默认发布到 `/usr/local/aws-rds-shenji/index/index.html`；仅网页与必要静态资源发布，私有配置、缓存和汇总 JSON 不发布到站点。

Nginx 的 root/alias 由管理员指向发布目录，本项目不修改反向代理。发布目录 0755、文件 0644；项目内站点仅补项目根执行权限，不递归放宽缓存和私有配置。发布先复制资源，再原子更新首页。

退出码：0 请求步骤完成；1 参数或启动前提失败；2 采集/覆盖/质量不完整或有待处理告警；3 报告保留但 Lark 失败；4 报告保留但发布失败。不完整状态优先于投递错误。

```bash
.venv/bin/python -m unittest -v
```

测试使用模拟 AWS 响应，不访问真实凭据、不发送 Lark，不能替代目标服务器的真实权限、日志格式和定时任务验证。
