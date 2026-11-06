#!/usr/bin/env bash
# Install the multi-account JSON/PDF/SMTP mode without running a report.
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1
trap 'printf "[错误] 邮件模式安装中断（行 %s），请修正后重试。\n" "$LINENO" >&2' ERR

fail() { printf '[错误] %s\n' "$*" >&2; exit 1; }
log() { printf '[安装] %s\n' "$*"; }
usage() {
  cat <<'HELP'
用法：sudo bash install.sh --config ./rds-audit-config.json [选项]
  --config PATH    多账号和 SMTP JSON 配置；默认项目/rds-audit-config.json
  --user USER      已存在的服务运行用户；默认 root
  --no-enable      安装并预检，保持两个定时器禁用
  --check-only     只检查现有环境、配置与 AWS 读取权限，不安装/写文件/启停服务
  --help          显示帮助
采集和邮件定时器每5分钟唤醒；30/60分钟采集、每日邮件时间、保留天数均从JSON读取。
安装不发送邮件、不执行整日报告、不修改 Nginx、不删除历史数据。
HELP
}

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CONFIG_PATH="$PROJECT_ROOT/rds-audit-config.json"
RUN_USER=root
NO_ENABLE=0
CHECK_ONLY=0
ORIGINAL_ARGS=("$@")
while (($#)); do
  case "$1" in
    --config|--user)
      (($# >= 2)) || fail "$1 缺少值"
      [[ -n "$2" && "$2" != --* ]] || fail "$1 缺少值"
      if [[ "$1" == --config ]]; then CONFIG_PATH="$2"; else RUN_USER="$2"; fi
      shift 2 ;;
    --config=*) CONFIG_PATH="${1#--config=}"; [[ -n "$CONFIG_PATH" ]] || fail '--config 缺少值'; shift ;;
    --no-enable) NO_ENABLE=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "邮件模式未知参数：$1，请使用 --help。" ;;
  esac
done
[[ "$(uname -s)" == Linux ]] || fail '邮件模式服务安装需要 Linux。'
[[ -r /proc/1/comm && "$(cat /proc/1/comm)" == systemd ]] || fail 'PID 1 不是 systemd，请由 Linux 宿主机调度。'
command -v systemctl >/dev/null || fail '未找到 systemctl。'
if ((EUID != 0)); then
  command -v sudo >/dev/null || fail '请以 root 运行安装器。'
  exec sudo -- bash "$PROJECT_ROOT/install-mail.sh" "${ORIGINAL_ARGS[@]}"
fi
[[ "$RUN_USER" =~ ^[A-Za-z0-9_.-]+\$?$ ]] || fail '服务用户必须是本地系统用户名。'
id "$RUN_USER" >/dev/null 2>&1 || fail "服务用户不存在：$RUN_USER"
RUN_GROUP="$(id -gn "$RUN_USER")"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
[[ "$RUN_HOME" == /* && -d "$RUN_HOME" ]] || fail '服务用户必须有已存在的绝对 HOME 目录。'
for name in rds_multi.py rds_window.py rds_daily_mail.py rds_config.py rds_schedule.py rds_summary.py rds_report.py rds_mail.py rds_mail_summary.py rds_pdf.py rds_failure_alerts.py lark_notify.py requirements.txt deploy/render_mail_units.py; do
  [[ -f "$PROJECT_ROOT/$name" ]] || fail "项目缺少文件：$name，请下载完整项目。"
done
[[ -f "$CONFIG_PATH" && ! -L "$CONFIG_PATH" ]] || fail "配置必须是普通文件且不能是符号链接：$CONFIG_PATH；请先复制并填写 rds-audit-config.example.json。"

PKG_MANAGER=''
for candidate in apt-get dnf yum; do
  if command -v "$candidate" >/dev/null; then PKG_MANAGER="$candidate"; break; fi
done
pkg_install() {
  ((CHECK_ONLY == 0)) || fail '只检查模式发现缺少依赖，请正常运行安装器。'
  [[ -n "$PKG_MANAGER" ]] || fail '请先安装 Python >=3.10、venv、pip、ca-certificates 和 tzdata。'
  if [[ "$PKG_MANAGER" == apt-get ]]; then
    if [[ "${APT_UPDATED:-0}" != 1 ]]; then DEBIAN_FRONTEND=noninteractive apt-get update; APT_UPDATED=1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  else
    "$PKG_MANAGER" install -y "$@"
  fi
}
find_python() {
  local candidate
  for candidate in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null; then
      command -v "$candidate"; return 0
    fi
  done
  return 1
}
if ! PYTHON="$(find_python)"; then
  if [[ "$PKG_MANAGER" == apt-get ]]; then pkg_install python3 python3-venv python3-pip ca-certificates tzdata;
  else pkg_install python3 python3-pip ca-certificates tzdata; fi
  PYTHON="$(find_python)" || fail '系统软件源未提供 Python >=3.10，请升级发行版或安装受支持的 Python。'
fi
CONFIG_PATH="$("$PYTHON" -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$CONFIG_PATH")"
VENV="$PROJECT_ROOT/.venv"
if [[ ! -x "$VENV/bin/python" ]] || ! "$VENV/bin/python" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  [[ ! -e "$VENV" ]] || fail '现有 .venv 无效或版本低于3.10，请先备份并改名；安装器不会删除它。'
  ((CHECK_ONLY == 0)) || fail '缺少项目 .venv，请正常运行安装器。'
  if ! "$PYTHON" -m venv "$VENV"; then
    if [[ "$PKG_MANAGER" == apt-get ]]; then pkg_install python3-venv python3-pip;
    else pkg_install python3-pip; fi
    "$PYTHON" -m venv "$VENV" || fail '创建项目 venv 失败。'
  fi
fi
if ((CHECK_ONLY == 0)); then
  if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then "$VENV/bin/python" -m ensurepip --upgrade; fi
  PIP_ROOT_USER_ACTION=ignore "$VENV/bin/python" -m pip install --disable-pip-version-check -r "$PROJECT_ROOT/requirements.txt" || fail '依赖安装失败，请检查网络和软件源。'
fi
"$VENV/bin/python" -m pip check || fail '项目 Python 依赖冲突。'
if ! "$VENV/bin/python" -c 'import boto3, reportlab, ssl; from zoneinfo import ZoneInfo; ZoneInfo("Asia/Shanghai"); assert ssl.create_default_context().cert_store_stats().get("x509_ca", 0) > 0'; then
  pkg_install ca-certificates tzdata
  "$VENV/bin/python" -c 'import boto3, reportlab, ssl; from zoneinfo import ZoneInfo; ZoneInfo("Asia/Shanghai"); assert ssl.create_default_context().cert_store_stats().get("x509_ca", 0) > 0' || fail '项目依赖、时区数据或 CA 证书不可用。'
fi

run_as_user() {
  if [[ "$RUN_USER" == root ]]; then
    env HOME="$RUN_HOME" PYTHONDONTWRITEBYTECODE=1 "$@"
  elif command -v runuser >/dev/null; then
    runuser -u "$RUN_USER" -- env HOME="$RUN_HOME" PYTHONDONTWRITEBYTECODE=1 "$@"
  else
    command -v sudo >/dev/null || fail '非root服务用户预检需要 runuser 或 sudo。'
    sudo -u "$RUN_USER" -- env HOME="$RUN_HOME" PYTHONDONTWRITEBYTECODE=1 "$@"
  fi
}
if ((CHECK_ONLY == 0)); then
  # Never replace JSON contents; only tighten its owner and filesystem mode.
  chown "$RUN_USER:$RUN_GROUP" "$CONFIG_PATH"
  chmod 0600 "$CONFIG_PATH"
  chown "$RUN_USER:$RUN_GROUP" "$PROJECT_ROOT"
fi
log '检查 JSON、SMTP 填写完整性和 AWS 身份/日志读取权限（不发送邮件）。'
run_as_user "$VENV/bin/python" "$PROJECT_ROOT/rds_multi.py" --config "$CONFIG_PATH" --check-config || fail '配置预检失败，请填写配置后重试。'
run_as_user "$VENV/bin/python" "$PROJECT_ROOT/rds_multi.py" --config "$CONFIG_PATH" --verify-accounts || fail 'AWS账号、区域或日志读取权限预检失败，未启用新的定时器。'
OUTPUT_DIR="$("$VENV/bin/python" - "$PROJECT_ROOT" "$CONFIG_PATH" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from rds_config import load_config
print(load_config(sys.argv[2])["OUTPUT_DIRECTORY"])
PY
)"
[[ "$OUTPUT_DIR" == /* && "$OUTPUT_DIR" != / ]] || fail 'OUTPUT_DIRECTORY 必须解析为非根目录的绝对路径。'
if ((CHECK_ONLY)); then
  [[ "$(stat -c %a "$CONFIG_PATH")" == 600 ]] || fail '私有JSON配置权限必须为0600。'
  [[ "$(stat -c %U "$CONFIG_PATH")" == "$RUN_USER" ]] || fail '私有JSON配置所有者应为服务用户。'
  run_as_user test -r "$CONFIG_PATH" || fail '服务用户不能读取私有JSON配置。'
  run_as_user test -w "$OUTPUT_DIR" || fail '服务用户不能写入输出目录。'
  log '只检查完成：未安装依赖、写文件、发送邮件或启停服务。'
  exit 0
fi
install -d -m 0700 -o "$RUN_USER" -g "$RUN_GROUP" -- "$OUTPUT_DIR"
run_as_user test -w "$OUTPUT_DIR" || fail '输出目录不可写；请检查父目录访问权限。'

STAGING="$(mktemp -d /etc/systemd/system/.aws-rds-mail-units.XXXXXX)"
cleanup() {
  if [[ -n "${STAGING:-}" && "$STAGING" == /etc/systemd/system/.aws-rds-mail-units.* ]]; then
    for name in aws-rds-audit.service aws-rds-audit.timer aws-rds-audit-collect.service aws-rds-audit-collect.timer; do
      rm -f -- "$STAGING/$name"
    done
    rmdir -- "$STAGING"
  fi
}
trap cleanup EXIT
"$VENV/bin/python" - "$PROJECT_ROOT" "$STAGING" "$RUN_USER" "$RUN_GROUP" "$RUN_HOME" "$CONFIG_PATH" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/deploy")
from render_mail_units import write_units
write_units(sys.argv[2], sys.argv[1], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
PY
if command -v systemd-analyze >/dev/null; then
  systemd-analyze verify "$STAGING/aws-rds-audit.service" "$STAGING/aws-rds-audit.timer" "$STAGING/aws-rds-audit-collect.service" "$STAGING/aws-rds-audit-collect.timer" || fail '生成的 systemd 单元校验失败，未切换服务。'
fi
# Stop both old schedules and in-flight old runners before replacing their units.
for name in aws-rds-audit.timer aws-rds-audit-collect.timer; do
  if systemctl cat "$name" >/dev/null 2>&1; then systemctl disable --now "$name" || fail "停用旧定时器失败：$name"; fi
done
for name in aws-rds-audit.service aws-rds-audit-collect.service; do
  if systemctl cat "$name" >/dev/null 2>&1; then systemctl stop "$name" || fail "停止旧服务失败：$name"; fi
done
for name in aws-rds-audit.service aws-rds-audit.timer aws-rds-audit-collect.service aws-rds-audit-collect.timer; do
  install -m 0644 -- "$STAGING/$name" "/etc/systemd/system/.$name.mail-new"
  mv -f -- "/etc/systemd/system/.$name.mail-new" "/etc/systemd/system/$name"
done
systemctl daemon-reload || fail 'systemd daemon-reload失败，定时器保持禁用。'
if ((NO_ENABLE == 0)); then
  # Reset persistent stamps so installation itself does not catch up old runs.
  install -d -m 0755 /var/lib/systemd/timers
  touch /var/lib/systemd/timers/stamp-aws-rds-audit.timer /var/lib/systemd/timers/stamp-aws-rds-audit-collect.timer
  systemctl enable --now aws-rds-audit-collect.timer aws-rds-audit.timer || fail '启用邮件模式定时器失败。'
  systemctl is-enabled aws-rds-audit-collect.timer aws-rds-audit.timer >/dev/null || fail '定时器未成功启用。'
  systemctl is-active aws-rds-audit-collect.timer aws-rds-audit.timer >/dev/null || fail '定时器未成功启动。'
else
  log '已安装且预检通过；--no-enable 保持两个定时器禁用。'
fi
log "完成。私有配置：$CONFIG_PATH；输出目录：$OUTPUT_DIR；安装过程未发送邮件。"
