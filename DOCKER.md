# Docker 部署

Docker 使用与 systemd 相同的 `rds-audit-config.json`、分段采集、邮件正文、中文 PDF 和每日最多一封自动邮件规则。每 5 分钟分别检查采集与邮件任务，业务按 `COLLECTION_INTERVAL_MINUTES` 和 `DAILY_MAIL_TIME` 判断是否到期。新模板为北京时间 10:10 发信，统计昨日 10:00 至今日 10:00；已有配置不覆盖，未设置查询时刻的旧配置保留自然日窗口。

10:00 结束的末段在默认 5 分钟日志缓冲后，于 10:05 起可采集，10:10 再检查发信，给末段一次采集机会。采集积压、慢查询或失败仍可能产生明确标记的不完整报告；后续补采仅更新本地 PDF，不突破每日一封自动邮件额度。已有私有配置的发信时间保持原值。

## 安装

准备 Linux Docker Engine 和 Compose V2，使用完整源码目录构建：

```bash
git clone https://github.com/userreksai/aws-rds-audit.git /opt/aws-rds-audit-src
cd /opt/aws-rds-audit-src
sudo bash install-docker.sh
```

首次没有私有配置时，脚本复制完整七账号模板到 `/usr/local/aws-rds-shenji/rds-audit-config.json`，以 `0600` 保存后退出。填写账号、SMTP、收件人和可选抄送，再执行同一命令：

```bash
sudo nano /usr/local/aws-rds-shenji/rds-audit-config.json
sudo chmod 600 /usr/local/aws-rds-shenji/rds-audit-config.json
sudo bash install-docker.sh
```

已有私有配置按字节保留；不会把模板覆盖到已填写的文件。邮件配置、账号 `TAG`、正文示例和窗口字段见 [README](README.md#配置)。无需单独的 Docker 邮件配置。

使用原 systemd 安装目录中的配置，或其他数据目录时：

```bash
sudo bash install-docker.sh --config /usr/local/aws-rds-shenji/rds-audit-config.json
sudo bash install-docker.sh --data-dir /srv/rds-audit --config /srv/rds-audit/rds-audit-config.json
```

需要 AWS profile 时显式挂载配置所在目录；只使用 Access Key 时无需此参数：

```bash
sudo bash install-docker.sh --profile-dir /root/.aws
```

只查看部署计划，或先构建和检查、暂不启动：

```bash
bash install-docker.sh --dry-run
sudo bash install-docker.sh --no-start
```

安装器使用现有 Docker，不负责安装 Docker，也不修改或停止宿主 systemd、cron、Nginx。构建与配置预检不连接 AWS、SMTP 或 Lark。启动正常调度后会执行采集和到期邮件任务；需要先审核配置时使用 `--no-start`。

## 持久化与权限

| 内容 | 默认宿主路径 | 容器使用方式 |
| --- | --- | --- |
| 私有 JSON / JSONC | `/usr/local/aws-rds-shenji/rds-audit-config.json` | 只读挂载 |
| 分段、PDF、账号标记、锁、回执与每日额度 | `/usr/local/aws-rds-shenji/output` | 按 `OUTPUT_DIRECTORY` 解析并持久挂载 |
| Compose 运行参数 | `/usr/local/aws-rds-shenji/docker.env` | 保存路径与镜像信息，不包含凭据 |
| 可选 AWS profile | `--profile-dir` 指定目录 | `/root/.aws` 只读挂载 |
| 可选中文字体 | `PDF_FONT_PATH` 指定文件 | 按配置解析后只读挂载 |

相对 `OUTPUT_DIRECTORY` 以私有配置目录为起点；使用绝对路径时沿用配置解析出的目录。一个输出卷保留分段、报告、`.daily-mail-budget.json`、投递回执和业务锁，重建镜像不会重置邮件额度。定时窗口报告位于结束日期的 `manual/window-1000-1000/`，与旧自然日报告隔离。

私有配置保持 `0600`，数据目录使用 `0700`。容器以配置文件所有者的 UID/GID 运行；已有数据与 profile 须能由此用户读取。镜像包含 Python 运行环境、CA 证书、时区数据和中文字体。构建上下文和镜像 COPY 使用白名单，私有配置、`.aws`、输出文件及无关项目不进入镜像。容器不开放网站端口，根文件系统只读，仅输出卷和 `/tmp` 可写。

同一业务任务使用输出目录中的现有锁，采集和邮件可以同时进行，各自避免重叠。保留原 systemd 调度时须共用同一输出目录才能共用锁、回执和每日额度；独立输出目录会形成独立的邮件投递记录。

## 日志与手动执行

安装器使用 Compose 项目 `aws-rds-audit-docker` 和服务 `audit`，在数据目录生成 `docker.env`。安装后可在任意工作目录执行：

```bash
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env ps
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env logs --tail 100 -f audit
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env exec -T audit /app/.venv/bin/python /app/deploy/docker_runtime.py healthcheck
```

离线检查配置，或立即采集一轮到期分段：

```bash
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env run --rm --no-deps -T audit check-config
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env run --rm --no-deps -T audit collect
```

按新模板生成指定结束日的报告；未加 `--send-mail` 时不发正常日报：

```bash
# 统计 2026-11-05 10:00 至 2026-11-06 10:00，从本地分段生成 PDF
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env run --rm --no-deps -T audit report --date 2026-11-06
# 明确发送全部账号的合并邮件，PDF 作为附件
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env run --rm --no-deps -T audit report --date 2026-11-06 --send-mail
# 独立的昨日零点到当前查询及邮件
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env run --rm --no-deps -T audit since-yesterday --send-mail
```

手动明确发送属于额外投递，不受自动邮件每天一封的额度限制；同一报告已发送或投递不确定时，核实后才使用 `--force-resend`。`scheduled` 命令遵循配置时间和自动邮件额度，不会强制立即发信。

## 更新与停止

```bash
cd /opt/aws-rds-audit-src
git pull --ff-only origin main
sudo bash install-docker.sh
```

脚本先构建镜像并检查配置，通过后更新本项目服务；已有配置、输出、回执与额度保留。曾使用 `--config`、`--data-dir` 或 `--profile-dir` 时，更新仍传入相同参数。

修改 JSON 后重跑安装器，以重新校验并挂载配置。编辑器可能原子替换文件，直接修改文件后仅重启进程不一定更新已有绑定挂载；重跑安装器会重建容器。变更输出路径、profile 或字体时同样重跑安装器；不要在任务运行时迁移输出目录。

只停止 Docker 服务，保留数据和宿主服务：

```bash
sudo docker compose --env-file /usr/local/aws-rds-shenji/docker.env stop audit
```

手工构建时可使用 `docker build -t aws-rds-audit:local .`，再以 `docker compose -f compose.yaml config` 检查挂载。通常使用安装器可完成目录、权限和可选挂载的准备。实际采集与邮件投递仍需要容器访问 AWS API、SMTP 和已启用的 Lark/飞书地址。
