# AWS RDS 增删改审计日报

采集当前 AWS 账号可见的 RDS 管理变更与 MySQL / Aurora MySQL SQL 增删改，生成中文 HTML 报告，并向 Lark / 飞书发送数量汇总。先看新增、删除、修改，再按 AWS 身份或数据库账号查看操作；数据库账号不等于真实人员姓名。

推荐部署方式为**每 30 分钟分段采集、每天本地汇总**，避免每天重新拉取整个窗口。日报固定为北京时间（Asia/Shanghai）**前一日 07:00 至当日 08:00，共 25 小时**，每天 **08:10** 执行，可改 08:05。相邻日报有意重叠一小时，不能直接将多天数量相加作为去重统计。窗口左闭右开。

## 数据与统计口径

| 来源 | 保留内容 | 排除或限制 |
| --- | --- | --- |
| CloudTrail RDS 管理事件 | 可明确归类为新增、删除、修改的管理 API，包含失败请求 | 排除读取 API 和其他非增删改 API；近 90 天可查 |
| CloudWatch audit 日志 | 可明确归类的 SQL 变更，包含失败语句、DDL、REPLACE、LOAD DATA 等 | 排除 SELECT、SHOW、DESC、EXPLAIN 及连接、表访问等辅助事件；INSERT … SELECT 等写入仍保留 |
| general 日志 | 现存目录与配置 | 常规采集不下载正文，不重复计算 SQL |
| RDS 服务事件 | 原始归档中的服务通知与覆盖说明 | 不混入人员操作的增删改计数 |

增删改数量按**未报错的请求或语句条数**统计；失败的增删改保留在失败数和明细，不计入成功数量。它不是受影响行数；SQL 返回码 0 不证明事务最终提交，API 未报错不证明异步变更已经完成。

采集器逐页读取 audit 候选事件，**写入归档前过滤查询**；同一 CloudWatch 事件混有查询和变更时，只保存变更原文片段及原始记录位置。无法分类、格式异常或疑似截断的记录进入 `quarantine/sql-unclassified.jsonl`，不猜测为查询，不混入统计，报告标记不完整。过滤减少本地归档和报告体积；AWS 源日志量与候选事件下载流量仍取决于数据库审计配置。

CloudTrail 不记录普通 MySQL 客户端的表内增删改，必须当时已启用 audit 且日志仍在保留期内。未记录的历史不能补录。引擎配置、IAM 与证据边界见 [RDS_AUDIT.md](RDS_AUDIT.md)。

## 服务器部署与更新

安装器支持 Linux + systemd，使用项目 `.venv`。它检查运行用户、Python 3.10+、venv、pip、依赖模块、systemd 配置和现有 AWS 资源读取权限，可从系统软件源安装缺少组件。服务器需能访问系统源、Python 包源和 AWS API；脚本不会创建 AWS 凭据、授予 IAM 权限或开启数据库审计。

部署目录为 `/usr/local/aws-rds-shenji`。目录已创建且为空时拉取：

~~~bash
git clone https://github.com/userreksai/aws-rds-audit.git /usr/local/aws-rds-shenji
cd /usr/local/aws-rds-shenji
~~~

将 [iam-policy-rds-audit.json](iam-policy-rds-audit.json) 配置给采集身份，并以服务用户配置 AWS profile `audit`。EC2 IAM Role 可省略 profile，使用默认凭据链。不要将密钥写进代码。

仅首次创建 Lark 配置时执行，再填写自己的 Webhook 和可选签名密钥：

~~~bash
cp lark-config.example.json lark-config.json
chmod 600 lark-config.json
~~~

已有私有配置直接保留。`report_url_template` 支持 `{date}`、`{account_id}`、`{filename}`，没有报告网站时留空。私有配置被 Git 忽略，勿提交凭据或 Webhook。

安装或更新：

~~~bash
cd /usr/local/aws-rds-shenji
git pull --ff-only origin main
bash install.sh --user root --profile audit --regions all --minute 10 --interval-minutes 30
systemctl start aws-rds-audit-collect.service
systemctl list-timers 'aws-rds-audit*' --no-pager
~~~

**升级后须重跑 install.sh**，以创建增量定时器并将每日服务改为读取缓存；只执行 git pull 不会更新已安装的 systemd 单元。安装保留已有虚拟环境、AWS 配置及私有 Lark 配置。旧版 `WorkingDirectory= path is not absolute` 错误也通过重新生成单元修复。

首次每轮最多处理 6 段，随后每 5 分钟继续回填。立即启动采集不代表已补齐 25 小时；日报会显示缺段，不能把不完整状态当作没有操作。

| 安装参数 | 说明 |
| --- | --- |
| `--user USER` | 已存在的服务用户，应能读取其 AWS 配置和项目 |
| `--profile NAME` | AWS profile；实例角色方式省略 |
| `--regions all` 或逗号分隔列表 | 默认所有已启用区域 |
| `--interval-minutes 30\|60` | 分段长度，默认 30 分钟 |
| `--minute 05\|10` | 北京时间 08:05 或 08:10，默认 08:10 |
| `--sql-alerts` / `--no-sql-alerts` | 启用或关闭 SQL 变更即时告警，新安装默认启用 |
| `--sql-alert-commands DELETE,UPDATE,DROP,TRUNCATE,ALTER` | SQL 告警命令范围，默认全部五种，可选子集 |
| `--publish-dir /绝对路径` | 可选网页发布目录 |
| `--no-enable` | 安装并预检，不主动启用定时器 |
| `--check-only` | 检查现有配置，不安装、不写文件、不启停服务；不与配置修改参数混用 |

服务使用指定用户的 HOME，不会把 root 的凭据复制给其他用户。预检失败时保留安装结果并禁用两个定时器；修正后重跑。预检不保存业务日志、不发送 Lark，不能证明真实 Webhook 可用或未来资源权限充足。

配置文件 `/etc/aws-rds-audit.env` 由 root 所有、权限 0600，支持标准 AWS 凭据链变量。主要项目配置：

| 环境变量 | 默认值或用途 |
| --- | --- |
| `AWS_RDS_CACHE_DIR` | 项目下 cache，新建目录归服务用户、权限 0750 |
| `AWS_RDS_INTERVAL_MINUTES` | 30 |
| `AWS_RDS_CACHE_LOOKBACK_HOURS` | 26，新发现分段的回看小时数 |
| `AWS_RDS_MAX_BUCKETS_PER_RUN` | 6，每轮处理上限 |
| `AWS_RDS_SQL_ALERTS` | 1；设为 0 关闭 SQL 变更即时告警 |
| `AWS_RDS_SQL_ALERT_COMMANDS` | DELETE,UPDATE,DROP,TRUNCATE,ALTER；可选子集 |
| `AWS_RDS_REGIONS` | all |
| `AWS_RDS_REPORT_ROOT` | 项目下 reports |
| `AWS_RDS_LARK_CONFIG` | 项目私有 lark-config.json |
| `AWS_RDS_PUBLISH_DIR` | 可选发布目录 |
| `AWS_RDS_MINUTE` | 10；变更后重跑安装器同步 timer |

## 分段、重试与告警

`aws-rds-audit-collect.timer` 每 5 分钟检查到期工作，数据按 30 或 60 分钟已结束窗口采集，并留 5 分钟发布缓冲，**不是每 5 分钟重拉全部日志**。每段有 SQLite 检查点、独立尝试目录和内容校验，进程锁防止并发。账号、profile、区域、分段长度与过滤版本隔离，改变配置会使用不同缓存范围。

失败段最多立即尝试 3 次，间隔 2、4 秒；仍失败则保留状态，后续从 5 分钟起退避至最多 1 小时重试。已发现的失败或待采段即使超出 26 小时回看范围仍会补采，最多近 89 天安全范围。成功段通常不重复下载，但结束约 60 分钟后额外复采一次，以补收延迟日志。源日志已删除或更迟发布的内容仍可能无法恢复。

读取成功但含未知 SQL 时，保存快照和质量不完整标记，不因同一质量问题无限重复下载。日报校验状态和快照，缺失、失败、损坏段标记不完整并加入补采队列，**不能当作 0 条**。25 小时日报需要 50 个半小时段，或 25 个一小时段。

采集失败、日报缺段、解析质量、发布/通知失败记录持久化告警，向 Lark 提醒并在恢复后通知。同一故障每小时最多提醒一次；Webhook 失败留待发送记录并重试。进程异常退出或超时也有 systemd `OnFailure` 告警入口。网络超时可能表示已投递但未确认，重试有可能出现相同事件编号的重复通知。Webhook 不可用时先查看本地日志，恢复后继续投递。

SQL 质量告警按账号和当前成功快照中的未解决分段聚合，其他分段或空段成功不会触发恢复。首次发现问题通知一次，问题集合有变化时最多每小时更新一次；长期未变化的历史问题不反复提醒。只有原问题分段被通过质量检查的成功快照替换、且没有状态无法确认的分段时，才发送恢复通知。升级会从现有快照的小型 report.json 回填质量状态并取消旧逻辑尚未发送的恢复通知，不重新下载整日 SQL；历史隔离证据保留，问题未解决时报告仍标记不完整。

增量采集发现新的 `DELETE`、`UPDATE`、`DROP`、`TRUNCATE`、`ALTER` SQL 时，会向 Lark 发送数据库账号、SQL 摘要、北京时间、实例及执行结果；失败语句也会提示失败结果。SQL 摘要使用有界长度并应用既有凭据脱敏；它可能包含业务值，请确认通知群成员范围。读取查询、INSERT 和 AWS 管理 API 不触发这类 SQL 告警。正常无匹配数据时不发送例行消息，日报与采集异常通知继续按原逻辑运行。

这是分段采集后通知：默认每半小时窗口结束后留 5 分钟发布缓冲，再由采集器发现并告警，并非数据库执行时即时推送。首次启用只从最新可采集分段开始，历史回填不会集中补发；启用后的新数据、迟到数据和重试按原日志事件身份去重。告警分批发送、队列持久化，投递失败会退避重试；网络未确认时可能再次收到同一事件编号的消息。重新运行 `install.sh` 会补齐配置默认值并保留已设置的开关和命令范围。

每轮最多发送 5 批，每批最多 10 条且按消息字节数控制大小；SQL 摘要最多 500 字。超出发送上限的操作保留在待发队列，由后续定时任务继续投递，日志中的 sql_alerts 会显示剩余数量。某区域读取失败时，其他区域已经取得的有效 SQL 仍可告警。

每日 `aws-rds-audit.timer` 只汇总本地成功分段，不发起 25 小时 AWS 全量查询。已发送的当日日报若收到窗口内分段恢复或延迟数据，会自动修订并注明；内容未改变不会自动重复发送。当日 08:00 后的新分段不会无故修订已结束窗口。历史日期不自动逐日重发，可显式补报。

采集和汇总共用进程锁，避免同时更新检查点与日报。日报遇到采集占用会持久化排队，首次生成异常也会保留重试请求，由后续定时任务继续处理。缓存、失败尝试和历史报告不会自动删除；请按服务器容量安排受控归档与保留期，勿删除尚待补采或当日日报依赖的缓存。

~~~bash
journalctl -u aws-rds-audit-collect.service -n 100 --no-pager
journalctl -u aws-rds-audit.service -n 100 --no-pager
systemctl status aws-rds-audit-collect.timer aws-rds-audit.timer
~~~

定时器使用 Asia/Shanghai，无需改服务器时区。`Persistent=true` 在停机错过触发时补执行；日报选最近已结束窗口，更早日期手动补报。刚安装时 `LAST -`、`No entries` 通常表示正式服务还未执行。

## 手动运行

未安装服务时先创建虚拟环境并预检：

~~~bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python rds_audit.py --check-config --profile audit --regions all --send-lark --lark-config lark-config.json
~~~

手动采集到与安装器一致的 cache 目录：

~~~bash
.venv/bin/python rds_audit.py --collect-incremental --profile audit --regions all \
  --cache-dir cache --interval-minutes 30 --cache-lookback-hours 26 --max-buckets-per-run 6 \
  --send-lark --lark-config lark-config.json
~~~

从缓存生成日报；可加 `--date 2026-10-29` 补报指定结束日期：

~~~bash
.venv/bin/python rds_audit.py --daily --from-cache --profile audit --regions all \
  --cache-dir cache --interval-minutes 30 --output-dir reports \
  --send-lark --lark-config lark-config.json
~~~

缓存日报不连接 AWS；profile、regions、interval 必须与采集范围一致。匹配到多个账号时加 `--cache-account-id <账号ID>`。CLI 默认 cache-dir 是 reports/cache，安装器默认项目下 cache，与服务配合请显式指定。显式补报带 --send-lark 会再次发送。

一次性直接查询 AWS 仍可使用，采集后自动生成 HTML：

~~~bash
.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 --days 1 \
  --download-sql-logs --output-dir reports/ap-east-1-check
~~~

查询**昨日北京时间 07:00 至命令启动时当前时间**：

~~~bash
.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 \
  --since-yesterday-7 --output-dir reports/manual
~~~

指定任意带时区的起止时间，`--end now` 表示命令启动时的当前时间，也可填写明确结束时间：

~~~bash
.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 \
  --start '2026-10-28T07:00:00+08:00' --end now --output-dir reports/manual

.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 \
  --start '2026-10-28T07:00:00+08:00' --end '2026-10-29T21:00:00+08:00' \
  --output-dir reports/manual
~~~

快捷和显式起止查询会自动下载 audit SQL 并过滤增删改，直接读取 AWS，不复用半小时缓存，因此能查询到当前未结束的半小时；源日志发布延迟仍可能影响刚发生的操作。查询会生成 HTML；需要同时向 Lark 发送本次汇总时，加 `--send-lark --lark-config lark-config.json`。手工历史查询不触发后台 SQL 即时告警。`--since-yesterday-7` 不与 `--start`、`--end`、`--days`、日报、离线输入或缓存模式混用；显式时间必须带 `+08:00` 或 `Z`，不使用服务器本地时区推断。

`--daily` 不加 `--from-cache` 仍直接采集固定日报窗口，适合有意补采，不作为定时默认方式。`--days`、`--start` / `--end` 是自定义窗口；仅使用 `--days` 时需请求 `--download-sql-logs` 才下载 SQL 正文。`--download-instance-logs` 是显式原始取证选项，会下载整文件，可能含 SELECT 等查询，不用于定时增量采集。

EC2 IAM Role 省略 --profile audit；只生成不推送则省略 --send-lark。Windows Python 路径改为 `.\.venv\Scripts\python.exe`。

## 轻量 HTML 与已有数据

首页最多预览 20 条记录、100 位操作者；全部增删改、操作者、失败请求和质量问题分别分页，每页最多 100 条。长 SQL、大字段有展示上限，完整规范化字段保存在服务器 `daily-report.json`；浏览器不会自动读取整个 JSON 或原始日志。

本页每条记录可直接展开 SQL、身份及执行参数，无需跳转到其他文件；单独复制首页也能查看其已显示记录。更多记录入口位于明细表下方，查看其它页仍需保留分页目录。来源与操作者汇总使用固定列宽，数字标题和数量统一对齐，实例身份可折叠查看。

同名数据库账号跨实例和日志流合并为一行，点击账号查看合并后的全部明细，具体实例信息仍保留。数据库账号名称区分大小写，AWS 身份与数据库账号分别统计；合并显示不表示它们对应同一个自然人。

日报目录示意：

~~~text
reports/<账号>/<日报日期>/<运行目录>/
  report.json                         采集范围、分段覆盖、状态和错误
  management-events.jsonl              保留的管理变更记录
  cloudwatch/*.jsonl                   audit 变更原文片段与源位置
  quarantine/sql-unclassified.jsonl    可选，无法分类的证据
  daily-report.json                    完整规范化服务器归档
  YYYY-MM-DD-rds操作审计.html          轻量总览
  YYYY-MM-DD-rds操作审计-pages-<hash>/  按需打开的明细页
  YYYY-MM-DD-rds操作审计-完整报告.zip   总览、CSS 与明细页
  rds-report.css                       配套样式
~~~

自定义窗口目录没有日报日期层，HTML 文件名多 `-自定义窗口`。页面内置样式并保留外部 CSS 回退，单独复制首页也有样式；**查看明细必须保留分页文件夹，或下载并解压完整报告 ZIP**。ZIP 不包含完整 JSON 和原始日志，原始证据仍保存在服务器。不要直接公开归档目录。

`--publish-dir /var/www/rds-audit` 复制总览、CSS、明细页、ZIP 并更新 index.html，不发布原始 JSON/JSONL。项目不安装网站或修改反向代理。Lark 只发数量、状态、范围与已配置链接，不发送 SQL 正文。

已有 40,510 条 CloudWatch 事件的香港目录可离线重建为排除查询的分页报告：

~~~bash
cd /usr/local/aws-rds-shenji
.venv/bin/python rds_audit.py --input-dir reports/ap-east-1-check/796973492024/20261029T093255Z-20ece9a5
~~~

不连接 AWS、不重新下载、不修改原始 JSONL。该目录实际窗口为北京时间 2026-10-28 17:32:55 至 2026-10-29 17:32:55，请不要加 --daily 或 --date，否则会要求覆盖另一个完整 25 小时窗口。40,510 是候选事件量，不能代替增删改数量。离线输入表示本次未连接 AWS；只有元数据明确 example_data=true 才视为演示数据。

## 结果验证

没有日志、没有实例、权限不足、采集或解析失败，均不能证明没有数据库操作。请结合 report.json、分段覆盖、质量问题页和告警判断。

退出码：0 为请求步骤完成；1 为参数或启动前提失败；2 为采集、覆盖、解析不完整，或增量任务有失败/待投递告警；3 为报告保留但 Lark 失败；4 为报告保留但发布失败。不完整状态优先于后续投递错误。

~~~bash
.venv/bin/python -m unittest -v
~~~

测试使用模拟 AWS 响应，不需要真实凭据，不发送 Lark。仓库测试不能替代目标服务器权限、软件源、真实 Webhook 与定时服务验证。
