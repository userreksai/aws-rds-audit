# AWS RDS 操作审计日报

采集当前 AWS 账号可见的 RDS 操作，生成中文 HTML 日报：先看新增、删除、修改数量，再按操作者查看汇总和具体操作。报告区分 RDS 管理 API 与数据库内部 SQL，不会将数据库账号猜测为真实人员。可将数量汇总发送到 Lark / 飞书群机器人。

日报固定使用北京时间（Asia/Shanghai）：**前一日 07:00 至当日 08:00，共 25 小时**；每天 **08:10** 由 systemd timer 执行。相邻两天报告有意重叠 07:00 至 08:00 的一小时，不能直接将多天总数相加作为去重统计。查询使用左闭右开窗口，08:00 整的记录由之后覆盖该时刻的窗口收录。

## 记录与计数

| 数据来源 | 报告内容 | 计数边界 |
| --- | --- | --- |
| CloudTrail RDS 管理事件 | AWS 身份、角色会话、时间、来源 IP、API、请求参数及结果 | 查询近 90 天；读取 API 保留在其他操作，失败请求单列，不算成功返回的增删改 |
| MySQL / Aurora MySQL audit 日志 | 数据库账号、来源、数据库、SQL、返回码及日志位置 | 必须当时已开启审计且日志仍保留；按可可靠识别的语句归类 |
| general 日志与 RDS 服务事件 | 原始采集文件和覆盖范围说明 | 不与 audit 日志混在一起重复计算 SQL 变更 |

HTML 同时显示 API 与 SQL 分来源统计。它统计日志中的操作记录，不等于受影响行数；SQL 返回码为 0 不证明事务最终 COMMIT，API 调用成功也不证明异步资源变更已完成。CALL、复杂语句或不能可靠分类的内容保留在其他操作供核查。

CloudTrail 不包含普通 MySQL 客户端执行的表内增删改。普通 RDS MySQL 使用 MARIADB_AUDIT_PLUGIN，Aurora MySQL 使用 Advanced Auditing；没开过的审计、已删除的日志、被排除的用户或被截断的 SQL，不能事后补出完整历史。详细配置区别、原始采集参数与官方来源见 [RDS_AUDIT.md](RDS_AUDIT.md)。

## 部署前准备

安装脚本面向 Linux + systemd，使用独立 Python 虚拟环境。需要可访问操作系统软件源、Python 包源及 AWS API。脚本可安装缺少的系统包和 Python 模块，但不会生成 AWS 凭据、授予 IAM 权限、创建 Lark 机器人或自动启用数据库审计。

1. 下载代码到部署目录，例如 /opt/aws-rds-audit。
2. 将 [iam-policy-rds-audit.json](iam-policy-rds-audit.json) 挂到运行采集的 IAM 角色或身份。它仅包含本项目使用的读取权限，不允许修改 RDS 配置。
3. 以服务实际运行的操作系统用户配置 AWS 身份。EC2 IAM Role 推荐省略 profile；已有本地 profile 可使用 audit。不要把 Access Key 或数据库密码写进代码。
4. 在项目目录创建自己的 lark-config.json，配置目标群机器人 Webhook。实际文件被 Git 忽略，安装或更新不会覆盖已有配置。

Lark 配置示例：

~~~bash
cp lark-config.example.json lark-config.json
chmod 600 lark-config.json
~~~

仅首次创建时复制；已有配置请直接编辑。report_url_template 可填写实际可访问的报告地址，支持 {date}、{account_id}、{filename}；没有发布网站时留空。不要沿用其他项目的地址。Webhook 和签名密钥保留在本机私有文件，勿提交到 Git。

## 安装与定时服务

在项目目录执行：

~~~bash
sudo bash install.sh
~~~

使用名为 audit 的 AWS profile，并明确服务运行用户时：

~~~bash
sudo bash install.sh --user ubuntu --profile audit --regions all
~~~

将 ubuntu 替换为实际配置 AWS 身份的本机用户；直接以 root 安装且没有指定用户时使用 root，通过 sudo 安装时默认使用原调用用户。服务使用该用户的 HOME，不会自动将 root 的凭据复制给其他用户。

安装器会检查 Linux/systemd、Python 版本、venv、pip、依赖模块和运行用户，安装可从系统软件源获得的缺少组件，并通过主程序预检 AWS 访问及 Lark 配置。预检不发送消息；真实凭据、授权或配置缺失时会给出错误，保留安装结果，不启动未通过检查的定时任务。修正后重跑安装器即可。

如果旧版安装提示 `WorkingDirectory= path is not absolute` 且路径外带双引号，更新代码后直接重新执行安装命令即可重新生成服务文件，无需删除 `.venv` 或私有配置。例如部署目录为 `/usr/local/aws-rds-shenji` 时：

```bash
cd /usr/local/aws-rds-shenji
git pull --ff-only origin main
bash install.sh --user root --profile audit --regions all --minute 10
```

服务生成器分别处理 `WorkingDirectory` 路径标量与 `ExecStart` / `Environment` 的引用规则。普通路径及含内部空格、Unicode、百分号的路径受支持；包含 `$`、控制字符、引号、反斜线、通配符起始字符或以空白结尾的项目目录会明确拒绝，避免生成无法启动的服务。

| 安装参数 | 用途 |
| --- | --- |
| --user USER | 指定已有的服务运行用户 |
| --profile NAME | 设置 AWS profile；实例角色方式省略 |
| --regions all 或区域列表 | 默认所有已启用区域；多个区域用逗号分隔 |
| --publish-dir /绝对路径 | 可选的 HTML 网页副本目录；默认不发布网页 |
| --minute 05 或 10 | 北京时间 08:05 或 08:10；新安装默认 08:10 |
| --no-enable | 安装并预检，但不主动启用定时器；已有定时器不会因此被关闭 |
| --check-only | 检查已保存的部署配置，不安装、不写文件、不启停服务；不能同时指定 profile、regions、publish-dir 或 minute 修改项 |

服务配置保存为 /etc/aws-rds-audit.env，由 root 所有、权限 0600。配置缺失或预检失败时安装器退出 2 并禁用定时器；修正配置后再次运行安装命令。安装器保留已有私有配置，不删除现有虚拟环境。

环境文件使用单行 KEY="value" 格式，支持 AWS 标准凭据链配置，例如 AWS_PROFILE、AWS_DEFAULT_REGION、AWS_SHARED_CREDENTIALS_FILE；项目配置包括 AWS_RDS_REGIONS、AWS_RDS_REPORT_ROOT、AWS_RDS_LARK_CONFIG、AWS_RDS_PUBLISH_DIR、AWS_RDS_MINUTE。更改执行分钟应重跑安装器，以便同步生成的 timer。凭据文件仍须由服务用户可读，环境文件不会绕过 AWS 授权。

定时器使用明确的 Asia/Shanghai，无需更改服务器的系统时区。Persistent=true 会在停机错过执行时补触发；运行器选择最近已结束的日报窗口，避免北京时间 08:00 前查询尚未结束的当天窗口，并使用文件锁避免同一服务并发采集。

支持的安装参数以 bash install.sh --help 为准。部署后检查：

~~~bash
systemctl status aws-rds-audit.timer
systemctl list-timers aws-rds-audit.timer
journalctl -u aws-rds-audit.service -n 100 --no-pager
~~~

手动运行服务会进行真实 AWS 采集，并在启用通知时发送 Lark：

~~~bash
sudo systemctl start aws-rds-audit.service
~~~

运行器会跳过本机以相同运行配置成功完成的同一日报日期，防止重复通知；更换 profile、发布目录等配置后可以重新执行。若需要有意重跑、补采或再次通知，使用下方主程序的显式日期命令；重新加 --send-lark 会再次发送。停机多天后的持久化触发只补最近一个已结束窗口，不自动遍历所有缺失日期；更早日期需手动补跑。

## 手动运行与预检

在没有安装 systemd 服务的本地环境中，可以手动创建虚拟环境。需要 Python 3.10 或更高版本：

~~~bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
~~~

先做不发送消息的配置检查：

~~~bash
.venv/bin/python rds_audit.py --check-config --profile audit --regions all \
  --send-lark --lark-config lark-config.json
~~~

生成北京时间今天的日报并发送汇总：

~~~bash
.venv/bin/python rds_audit.py --daily --profile audit --regions all \
  --output-dir reports --send-lark --lark-config lark-config.json
~~~

EC2 IAM Role 省略 --profile audit。只生成报告时省略 --send-lark。Windows 将 Python 路径替换为 .\.venv\Scripts\python.exe。

--date 是窗口结束日期。例如下面采集北京时间 2026-10-28 07:00 至 2026-10-29 08:00：

~~~bash
.venv/bin/python rds_audit.py --daily --date 2026-10-29 --profile audit --regions ap-southeast-1
~~~

手动指定的窗口尚未结束时会拒绝，不会缩短窗口冒充完整日报。--daily 不能和原始采集模式的 --days、--start、--end 混用。日报会下载当前可见的标准 CloudWatch audit / general 日志；不会自动改变数据库的审计配置。

## HTML、归档与 Lark

每次采集使用独立运行目录，保留原始证据和日报。下面对应显式设置 --output-dir reports；未指定时父目录默认为 reports/rds：

~~~text
reports/<AWS账号ID>/<日报日期>/<运行目录>/
  report.json                         原始采集状态、范围、配置与错误
  management-events.jsonl              RDS 管理 API 原文
  rds-events.jsonl                     RDS 服务通知
  cloudwatch/*.jsonl                   已下载的 SQL 原始日志
  daily-report.json                   规范化日报、分来源计数和明细
  YYYY-MM-DD-rds操作审计.html          中文 HTML 日报
  rds-report.css                      报告样式
~~~

报告按“总览 → 操作者 → 具体操作”排列，包含北京时间、身份或数据库账号、增删改分类、操作内容、资源、区域、来源 IP 和结果。SQL 可能含业务值，报告应保存在受控位置。查看日期 HTML 时保留同目录的 rds-report.css。

已有 Web 服务时，可将最新报告副本写入它的文档目录：

~~~bash
.venv/bin/python rds_audit.py --daily --profile audit --regions all \
  --publish-dir /var/www/rds-audit --send-lark --lark-config lark-config.json
~~~

发布仅复制 HTML 和样式，并更新 index.html；原始 JSON 不复制到该目录。项目不会自动安装网站、开放端口或修改反向代理。需自行将 Web 服务映射到发布目录，并将真实地址填进 Lark 配置。报告使用独立 CSS，无内联脚本，适合现有同源资源策略。

Lark 复用项目的机器人通知模块，只发送日期、账号、北京时间范围、增删改数量、采集状态和已配置的详情链接，不发送 SQL 正文。未配置报告地址时应从服务器查看归档，不应把占位地址作为可用链接。预检只验证本地格式及 AWS 读取权限，不能证明远端机器人 token 有效；只有真实发送才能验证。

## 已发现日志组但尚未下载日志

安装器执行的是 `--check-config` 预检：它会打印匹配的 audit/general 日志组名称并验证读取接口，但不会下载或保存日志，也不能根据权限探针判断历史日志是否有内容。正式采集时才会输出窗口、每个日志组下载的 CloudWatch 事件数与文件位置；事件条数不等于 SQL 语句或受影响行数。

首次启用定时器后，如果 `systemctl list-timers` 显示 `LAST -`，且服务日志为 `No entries`，请先确认尚未执行正式采集。要立即生成日报并发送汇总，可执行 `systemctl start aws-rds-audit.service`。

例如香港区域的日志组 `/aws/rds/cluster/shenji/audit` 符合匹配规则；`error` 和 `RDSOSMetrics` 不属于 SQL audit/general，不纳入数据库增删改统计。单独检查香港近 24 小时的原始日志、且不发送 Lark：

```bash
cd /usr/local/aws-rds-shenji
.venv/bin/python rds_audit.py --profile audit --regions ap-east-1 --days 1 --download-sql-logs --output-dir reports/ap-east-1-check
```

检查输出目录中的 `report.json`（`sql_log_groups` 下的 `download.status`、`event_count`）以及 `cloudwatch/*.jsonl`。当天日报截至北京时间 08:00；当天 08:00 后才产生的日志不属于该份日报，应检查上述最近 24 小时窗口或后续日报。日志组存在不代表其中一定已有 SQL 事件。

## 已有采集结果与演示

已有运行目录可离线生成 HTML，使用该数据实际覆盖的日期与窗口：

~~~bash
.venv/bin/python rds_audit.py --input-dir reports/<账号>/<日报日期>/<运行目录> --date 2026-10-29
~~~

仓库演示数据不代表真实 AWS 活动：

~~~bash
.venv/bin/python rds_audit.py --input-dir examples/daily-sample --date 2026-10-29
~~~

从已有目录生成的报告标记为离线输入，表示本次未连接 AWS，不意味着归档数据是虚构样例。只有采集元数据明确设置 example_data=true 时才标记为演示数据；仓库自带样例属于这种情况，不能用样例中的数量或身份判断真实账号活动。

## 结果校验

采集或解析失败会在 JSON 与报告中标记不完整，已取得的数据仍保留。权限不足、某区域访问失败、空日志、日志轮转或尚未发布，都不能解释为“没有操作”。没有数据库 audit 日志时，API 部分仍可出报告，但不能据此断言内部没有 SQL 增删改。

主程序退出码：0 表示所请求步骤完成；1 表示参数、凭据或启动前提失败；2 表示采集或解析不完整；3 表示报告已保留但 Lark 发送失败；4 表示报告已保留但网页发布失败。采集不完整的退出码 2 优先于之后的发布或通知错误。

运行离线测试：

~~~bash
.venv/bin/python -m unittest -v
~~~

测试使用模拟 AWS 响应，不需要真实凭据，也不会发送 Lark。安装脚本的语法和模拟环境检查不能替代目标服务器上的软件源、身份权限和定时器验证。
