# AWS RDS 多账号来源 IP 审计邮件

在一个私有 JSON 中配置多个 AWS 账号，分段读取 RDS MySQL / Aurora MySQL 的 CloudWatch audit 日志，以**发起操作的来源 IP**汇总新增、删除、修改及失败次数。每个账号生成一份中文 PDF，所有启用账号的 PDF 作为附件放在同一封邮件中，支持收件人与抄送。

默认每 30 分钟形成一个数据分段，也可配置为 60 分钟；每天北京时间 08:10 发送**昨日 00:00 至今日 00:00**的自然日汇总。不是旧版前日 07:00 至今日 08:00 的 25 小时窗口。时区、发信时间、采集间隔和本地保留天数都在 JSON 中配置。

只保存来源 IP 汇总、覆盖状态和 PDF，不保存 SQL 原文、业务参数或逐条执行详情。数据库 SQL 与 RDS 管理 API 在 PDF 中分表，避免混成一种次数；同一账号内不同数据库用户的相同来源 IP 合并，AWS 账号之间始终隔离。

## 配置

推荐部署位置 `/usr/local/aws-rds-shenji`（标准路径为 `/usr/local`）。

```bash
git clone https://github.com/userreksai/aws-rds-audit.git /usr/local/aws-rds-shenji
cd /usr/local/aws-rds-shenji
cp rds-audit-config.example.json rds-audit-config.json
chmod 600 rds-audit-config.json
```

填写私有 `rds-audit-config.json`。示例中的 Key、SMTP、收件人和抄送均已留空，不包含真实凭据。将示例账号 ID 换成自己的 12 位 AWS 账号 ID，每个账号分别填 Key：

```json
{
  "OUTPUT_DIRECTORY": "output",
  "COLLECTION_INTERVAL_MINUTES": 30,
  "RETENTION_DAYS": 7,
  "TIMEZONE": "Asia/Shanghai",
  "DAILY_MAIL_TIME": "08:10",
  "MAIL_REPORT_MODE": "previous_day",
  "SMTP_HOST": "",
  "SMTP_PORT": 465,
  "SMTP_USERNAME": "",
  "SMTP_AUTH_CODE": "",
  "SMTP_SECURITY": "ssl",
  "SMTP_TIMEOUT": 30,
  "MAIL_RECIPIENTS": [],
  "MAIL_CC": [],
  "MAIL_SUBJECT": "AW-RDS审计报告",
  "MAIL_SENDER_NAME": "",
  "ACCOUNTS": [
    {
      "NAME": "production",
      "ACCOUNT_ID": "000000000001",
      "AWS_ACCESS_KEY_ID": "",
      "AWS_SECRET_ACCESS_KEY": "",
      "AWS_SESSION_TOKEN": "",
      "AWS_PROFILE": "",
      "REGIONS": "all",
      "ENABLED": true
    },
    {
      "NAME": "staging",
      "ACCOUNT_ID": "000000000002",
      "AWS_ACCESS_KEY_ID": "",
      "AWS_SECRET_ACCESS_KEY": "",
      "AWS_SESSION_TOKEN": "",
      "AWS_PROFILE": "",
      "REGIONS": ["ap-southeast-1", "us-east-1"],
      "ENABLED": true
    }
  ]
}
```

- `MAIL_RECIPIENTS` / `MAIL_CC` 使用邮箱数组，例如 `["audit@example.com", "ops@example.com"]`；CC 可为空。`SMTP_USERNAME` 同时作为发件邮箱。465 默认 SSL；需要 587 STARTTLS 时相应修改端口和 `SMTP_SECURITY`。
- `NAME` 是目录标签，只支持字母、数字、下划线和连字符；`NAME` 与 `ACCOUNT_ID` 各自不得重复。真正采集前使用 STS 核验 Key 对应的账号，账号不匹配不会采集。
- 每账号支持成对的 Access Key / Secret Key、临时凭据 Token，或 `AWS_PROFILE`；Key 与 profile 不可同时配置。均为空时使用该服务用户的标准 AWS 凭据链。`ENABLED: false` 暂停该账号采集和报告。
- `OUTPUT_DIRECTORY` 相对**配置文件所在目录**解析，所以默认输出为 `/usr/local/aws-rds-shenji/output/`；也可填写绝对路径。不要指向网页公开目录。
- 完整示例还包括 `MAX_BUCKETS_PER_ACCOUNT_PER_RUN`（默认 6）、`LOG_DELAY_MINUTES`（默认 5）、`REFRESH_DELAY_MINUTES`（默认 60）和 `PDF_FONT_PATH`（可选中文 TTF 字体）。
- 私有配置与 `output/` 已加入 Git 忽略规则。不要提交真实 Key 或 SMTP 授权码；源码更新不会替换私有配置。

每个账号使用 [iam-policy-rds-audit.json](iam-policy-rds-audit.json) 的读取权限。新模式主要使用 CloudTrail `LookupEvents`、CloudWatch `DescribeLogGroups` / `FilterLogEvents`；`REGIONS: "all"` 还需要 EC2 `DescribeRegions`。程序不修改数据库、审计设置、IAM 或 Nginx。数据库当时必须已经启用相应审计并导出到 CloudWatch；详细说明见 [RDS_AUDIT.md](RDS_AUDIT.md)。

## 安装与更新

Linux + systemd、Python 3.10+。配置填写完毕后：

```bash
cd /usr/local/aws-rds-shenji
sudo bash install.sh --config ./rds-audit-config.json --user root
systemctl start aws-rds-audit-collect.service
systemctl list-timers 'aws-rds-audit*' --no-pager
```

安装器建立/复用项目 `.venv`、安装依赖，检查配置和每个启用账号的身份/日志读取权限，使用 0600 私有配置和 0700 输出目录。预检不发送邮件、不全量采集、不生成日报。检查通过后停用旧两个同名定时器及其运行服务，替换为邮件模式并重新启用，避免 Lark 与邮件双跑。不修改 Nginx，也不删除旧版 `cache/`、`reports/` 或旧网页。

安装中文字体可提高 PDF 跨机器显示一致性，例如 Debian/Ubuntu 的 `fonts-wqy-zenhei`；程序也支持 `PDF_FONT_PATH` 指定字体，未找到字体时使用 ReportLab 中文 CID 字体。

```bash
# 更新源码后重新安装，保留填写好的私有 JSON
git pull --ff-only origin main
sudo bash install.sh --config ./rds-audit-config.json --user root

# 只检查已有部署；不安装、不写文件、不启停服务
sudo bash install.sh --config ./rds-audit-config.json --user root --check-only

# 完成安装和预检，暂不启用定时器
sudo bash install.sh --config ./rds-audit-config.json --user root --no-enable
```

两个定时器均每 5 分钟唤醒一次：采集任务仅处理配置的 30/60 分钟已结束分段及重试，不会每 5 分钟重拉整日；邮件任务读取配置中的时区和发送时间。修改 JSON 中的间隔、保留天数和发信时间后下一轮生效，无需重建定时器。改变区域、时区或分段长度会隔离为新缓存范围，并重新回填昨日与今日，不会混入旧口径。

首次部署从昨日零点开始逐段回填，每账号每轮最多处理 6 段；补齐昨日和今日可能需要多轮。采集预留 5 分钟日志发布缓冲；成功分段在结束 60 分钟后再采一次，使用新快照**替换**旧快照，不累加重复计数。失败分段以 5 分钟至 1 小时退避重试，在保留窗口内继续补采。更迟到达或已被源端删除的日志仍可能缺失。

账号失败不会阻止其它账号继续采集。全局进程锁避免采集、清理与发信互相覆盖；遇忙等待下一轮。邮件正文列出每个账号的覆盖状态；没有数据、缺段和解析失败不会伪装成完整的零操作。

## 本地存储与自动保留

```text
/usr/local/aws-rds-shenji/output/
  production-123456789012/
    .rds-audit-account
    2026-11-03/
      .rds-audit-day
      segments/<采集口径标识>/<分段UTC时间>.json
      collection-status.json
      ip-report.json
      production-123456789012-2026-11-03-RDS-IP审计.pdf
      combined-mail.json       # 合并投递凭据保存在最小账号ID对应目录
```

`RETENTION_DAYS: 7` 表示按配置时区保留**含当天在内的 7 个自然日**；改为 `3` 就保留当天和前两天。每轮采集/邮件任务清理过期日期目录，其中的分段、PDF、状态一并清理。最低 2 天，确保昨日数据能留到次日邮件发送。该设置仅控制本机文件，不修改 AWS CloudWatch 保留期。

只清理本程序带标记的账号/日期目录，不跟随符号链接或 junction；已有无标记目录拒绝收编。已移除或停用账号的旧标记目录也按同一保留天数过期。旧版 `cache/`、`reports/`、旧网页、未知文件和含链接的目录不会自动删除，避免误删；如有旧数据占用，请单独确认其保留策略。

## 邮件投递与手动命令

```bash
# 本地检查 JSON 与 SMTP 填写；不联网
.venv/bin/python rds_multi.py --config rds-audit-config.json --check-config
# 只核验 AWS 身份与日志权限；不发邮件
.venv/bin/python rds_multi.py --config rds-audit-config.json --verify-accounts
# 采集本轮到期分段
.venv/bin/python rds_multi.py --config rds-audit-config.json --collect
# 从本地分段生成昨日各账号 PDF，不连接 AWS、不发邮件
.venv/bin/python rds_multi.py --config rds-audit-config.json --report
# 指定日期生成 PDF，并将所有账号附件合并发送
.venv/bin/python rds_multi.py --config rds-audit-config.json --report --date 2026-11-03 --send-mail
```

指定今日时，仅统计到经过日志缓冲的最近完整分段；报告窗口在 PDF 中明确显示，不冒充完整全天。指定日期必须仍在保留范围内。定时邮件只发送最近一个昨日，不自动逐日补发停机期间的历史邮件。

SMTP 使用验证证书的 SSL / STARTTLS，To 与 CC 去重，所有账号 PDF 一次提交。服务器接受后记录投递状态，同样内容不重复发送。首次报告不完整时先发一份提示，补采仍不完整期间仅更新本地 PDF，恢复完整后发一份修订；完整报告的迟到数据、账号或收件人改变也会触发修订。明确的连接/认证失败 15 分钟后重试；部分收件人拒收、提交阶段断连或进程在提交期间退出会保留为 `uncertain` / `sending`，不会自动向所有人重发。核实实际投递后才手动加 `--force-resend`（需与 `--report --send-mail` 一起使用）。SMTP 接受不等于每个收件箱最终送达。

```bash
journalctl -u aws-rds-audit-collect.service -n 100 --no-pager
journalctl -u aws-rds-audit.service -n 100 --no-pager
.venv/bin/python -m unittest discover -v
```

退出码：0 请求步骤完成；1 配置/启动失败；2 采集或报告不完整；3 邮件失败、等待重试或需要核实投递。示例测试使用虚构数据和模拟 AWS/SMTP，不读取真实 Key、不发真实邮件。

## 统计边界

- 数据库 audit 的 `host` 是数据库观测到的来源，可能是应用、连接池、NAT 或代理地址；主机名与未知来源单独标记。不能据此保证识别真实人员或终端 IP。[AWS 审计字段](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html)
- 新增、删除、修改是可可靠分类的审计**语句次数**；一条 UPDATE 影响一万行仍计一次。保留既有 DDL、REPLACE、LOAD DATA 等分类；SELECT、连接和 TABLE 辅助记录不重复计入。失败单列，返回码 0 不证明事务最终 COMMIT。
- CloudTrail 来源 IP 用于 AWS 管理 API 调用审计，不能替代数据库内部 SQL；两种来源在 PDF 中分开。[CloudTrail 字段](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- 日志当时未启用、过滤、截断、过期、权限失败和延迟均可能造成缺失。本程序无法补出未记录的数据，也不会用 general 日志或性能采样冒充完整增删改审计。

旧单账号、按用户汇总的命令保留兼容，说明见 [LEGACY_USER_MODE.md](LEGACY_USER_MODE.md)。没有新 JSON 配置且未指定 `--config` 时，旧 `install.sh` 参数仍走旧部署流程；本次新方案请显式使用 `--config`。
