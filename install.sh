#!/usr/bin/env bash
# Deploy the already-downloaded project; never install into the system Python.
set -Eeuo pipefail
# --check-only must not create __pycache__ while importing deployment helpers.
export PYTHONDONTWRITEBYTECODE=1
trap 'printf "[错误] 安装中断（行 %s）；修正上方错误后可以重新运行。\n" "$LINENO" >&2' ERR

usage() {
  cat <<'HELP'
用法：sudo bash install.sh [选项]
  --user USER           服务运行用户；默认 sudo 原调用用户，直接 root 安装则使用 root
  --profile NAME        设置 AWS profile；省略时保留已有配置/使用默认凭据链或实例角色
  --regions REGIONS     all 或逗号分隔区域；新安装默认 all
  --publish-dir PATH    可选 HTML 网页副本目录；默认不发布网页
  --minute 05|10        北京时间执行分钟；新安装默认 10（08:10）
  --no-enable           安装并预检，但不启用定时器
  --check-only          只检查已部署环境和配置，不安装软件、不写文件、不启停服务
  --help                显示帮助
需要 Linux + systemd；支持 apt、dnf、yum 的系统发行版。
缺少 Python、venv、pip、CA/时区数据及 Python 依赖时会自动安装。
AWS 身份/权限和真实 Lark Webhook 必须由管理员提供；不生成或上传凭据。
HELP
}

fail() { printf '[错误] %s\n' "$*" >&2; exit 1; }
log() { printf '[安装] %s\n' "$*"; }
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
RUN_USER=''
PROFILE=''
REGIONS=''
PUBLISH_DIR=''
MINUTE=''
PROFILE_SET=0
REGIONS_SET=0
PUBLISH_SET=0
CHECK_ONLY=0
NO_ENABLE=0
ORIGINAL_ARGS=("$@")
while (($#)); do
  case "$1" in
    --user|--profile|--regions|--publish-dir|--minute)
      (($# >= 2)) || fail "$1 缺少值"
      [[ -n "$2" && "$2" != --* ]] || fail "$1 缺少值"
      case "$1" in
        --user) RUN_USER="$2" ;;
        --profile) PROFILE="$2"; PROFILE_SET=1 ;;
        --regions) REGIONS="$2"; REGIONS_SET=1 ;;
        --publish-dir) PUBLISH_DIR="$2"; PUBLISH_SET=1 ;;
        --minute) MINUTE="$2" ;;
      esac
      shift 2 ;;
    --no-enable) NO_ENABLE=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "未知参数：$1" ;;
  esac
done

if ((CHECK_ONLY && (PROFILE_SET || REGIONS_SET || PUBLISH_SET))) || [[ "$CHECK_ONLY" == 1 && -n "$MINUTE" ]]; then
  fail '--check-only 使用现有环境配置，不能同时指定 profile、regions、publish-dir 或 minute 修改项。'
fi

[[ "$(uname -s)" == Linux ]] || fail 'install.sh 只适用于 Linux；Windows 请使用 Python 脚本或 Linux 服务器部署。'
[[ -r /proc/1/comm && "$(cat /proc/1/comm)" == systemd ]] || fail '当前 PID 1 不是 systemd，不能安装 systemd 定时服务；容器内请由宿主机调度。'
command -v systemctl >/dev/null || fail '未找到 systemctl。'
if ((EUID != 0)); then
  command -v sudo >/dev/null || fail '安装系统软件和服务需要 root，请使用 root 或安装 sudo 后重试。'
  exec sudo -- bash "$PROJECT_ROOT/install.sh" "${ORIGINAL_ARGS[@]}"
fi
[[ "$PROJECT_ROOT" != *$'\n'* && "$PROJECT_ROOT" != *$'\r'* ]] || fail '项目路径不能包含换行。'
for name in rds_audit.py rds_report.py lark_notify.py lark-config.example.json requirements.txt deploy/run_daily.py deploy/render_units.py deploy/aws-rds-audit.service deploy/aws-rds-audit.timer; do
  [[ -f "$PROJECT_ROOT/$name" ]] || fail "项目缺少文件：$name，请先下载完整项目。"
done
ENV_FILE=/etc/aws-rds-audit.env
[[ ! -L "$ENV_FILE" ]] || fail "$ENV_FILE 是符号链接，请管理员确认后改为普通文件。"
if [[ -e "$ENV_FILE" ]]; then
  [[ "$(stat -c %u "$ENV_FILE")" == 0 ]] || fail "$ENV_FILE 必须由 root 所有。"
  [[ -z "$(find "$ENV_FILE" -maxdepth 0 -perm /022 -print)" ]] || fail "$ENV_FILE 不能允许组或其他用户写入。"
fi

PKG_MANAGER=''
for candidate in apt-get dnf yum; do
  if command -v "$candidate" >/dev/null; then PKG_MANAGER="$candidate"; break; fi
done
pkg_install() {
  ((CHECK_ONLY == 0)) || fail '只检查模式发现系统依赖缺失，请正常运行 install.sh 自动安装。'
  [[ -n "$PKG_MANAGER" ]] || fail '缺少依赖且未找到 apt-get/dnf/yum，请手动安装 Python >=3.10、venv、pip、ca-certificates 和 tzdata。'
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
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}
if ! PYTHON="$(find_python)"; then
  log '安装系统 Python 和基础模块。'
  if [[ "$PKG_MANAGER" == apt-get ]]; then
    pkg_install python3 python3-venv python3-pip ca-certificates tzdata
  else
    pkg_install python3 python3-pip ca-certificates tzdata
  fi
  if ! PYTHON="$(find_python)"; then
    for version in 3.13 3.12 3.11 3.10; do
      if pkg_install "python$version"; then
        if PYTHON="$(find_python)"; then break; fi
      fi
    done
  fi
fi
[[ -n "${PYTHON:-}" ]] || fail '系统软件源未提供 Python >=3.10；请升级发行版或配置可信的发行版软件源后重试。'
log "使用 Python：$PYTHON"
"$PYTHON" -c 'import ssl; from zoneinfo import ZoneInfo; assert ssl.create_default_context().cert_store_stats().get("x509_ca", 0) > 0; ZoneInfo("Asia/Shanghai")' >/dev/null 2>&1 || {
  pkg_install ca-certificates tzdata
  "$PYTHON" -c 'import ssl; from zoneinfo import ZoneInfo; assert ssl.create_default_context().cert_store_stats().get("x509_ca", 0) > 0; ZoneInfo("Asia/Shanghai")' || fail '系统 CA 证书或时区数据库仍不可用。'
}

VENV="$PROJECT_ROOT/.venv"
if [[ ! -x "$VENV/bin/python" ]] || ! "$VENV/bin/python" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  [[ ! -e "$VENV" ]] || fail '现有 .venv 无效或版本低于 3.10；请先备份并将它改名，再重试（安装器不会删除已有环境）。'
  ((CHECK_ONLY == 0)) || fail '缺少项目 .venv，请正常运行 install.sh 自动创建。'
  if ! "$PYTHON" -m venv "$VENV"; then
    package="$("$PYTHON" -c 'import sys; print("python%d.%d" % sys.version_info[:2])')"
    if [[ "$PKG_MANAGER" == apt-get ]]; then pkg_install "$package-venv"; else pkg_install "$package-pip"; fi
    "$PYTHON" -m venv "$VENV" || fail '创建 venv 失败，请检查发行版 venv/ensurepip 模块和目录权限。'
  fi
fi
if ((CHECK_ONLY == 0)); then
  if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then "$VENV/bin/python" -m ensurepip --upgrade; fi
  log '安装/检查项目依赖（仅写入项目 .venv）。'
  PIP_ROOT_USER_ACTION=ignore "$VENV/bin/python" -m pip install --disable-pip-version-check -r "$PROJECT_ROOT/requirements.txt" || fail '依赖下载失败；请检查 DNS、出站 HTTPS、代理及 PIP_INDEX_URL。'
fi
"$VENV/bin/python" -m pip check || fail 'Python 依赖冲突，请修复项目虚拟环境后重试。'
"$VENV/bin/python" -c 'import boto3, botocore, ssl; from zoneinfo import ZoneInfo; ZoneInfo("Asia/Shanghai"); ssl.create_default_context()' || fail '项目模块、CA 证书或北京时间时区数据不可用。'

if [[ -z "$RUN_USER" && -f "$ENV_FILE" ]]; then
  RUN_USER="$("$VENV/bin/python" - "$PROJECT_ROOT" "$ENV_FILE" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'deploy'))
from run_daily import load_environment
print(load_environment(Path(sys.argv[2])).get('AWS_RDS_RUN_USER', ''))
PY
)"
fi
RUN_USER="${RUN_USER:-${SUDO_USER:-root}}"
[[ "$RUN_USER" =~ ^[A-Za-z0-9_.-]+\$?$ ]] || fail '服务用户名称不适合 systemd；请使用本地系统用户。'
id "$RUN_USER" >/dev/null 2>&1 || fail "运行用户不存在：$RUN_USER"
RUN_GROUP="$(id -gn "$RUN_USER")"
[[ -z "$MINUTE" || "$MINUTE" == 05 || "$MINUTE" == 10 ]] || fail '--minute 只能是 05 或 10。'
if ((PUBLISH_SET)); then [[ "$PUBLISH_DIR" == /* ]] || fail '--publish-dir 必须是绝对路径。'; fi

if ((CHECK_ONLY)); then
  [[ -f "$ENV_FILE" ]] || fail '未找到部署环境配置，请先正常运行 install.sh。'
else
  log "配置服务用户 $RUN_USER；保留已有私有 Lark 配置。"
  if [[ ! -e "$PROJECT_ROOT/lark-config.json" ]]; then
    install -m 0600 -o "$RUN_USER" -g "$RUN_GROUP" "$PROJECT_ROOT/lark-config.example.json" "$PROJECT_ROOT/lark-config.json"
  fi
  install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$PROJECT_ROOT/reports"
  # Parse existing EnvironmentFile as data, retaining comments/private settings.
  "$VENV/bin/python" - "$PROJECT_ROOT" "$ENV_FILE" "$RUN_USER" "$RUN_GROUP" "$PROFILE_SET" "$PROFILE" "$REGIONS_SET" "$REGIONS" "$PUBLISH_SET" "$PUBLISH_DIR" "$MINUTE" <<'PY'
import json
import os
import pwd
import sys
import tempfile
from pathlib import Path

root, destination, username, group, profile_set, profile, regions_set, regions, publish_set, publish, minute = sys.argv[1:]
sys.path.insert(0, str(Path(root) / 'deploy'))
from run_daily import load_environment
from render_units import write_units
env_path = Path(destination)
existing = load_environment(env_path) if env_path.exists() else {}
updates = {'AWS_RDS_RUN_USER': username}
defaults = {
    'AWS_RDS_REGIONS': 'all', 'AWS_RDS_REPORT_ROOT': str(Path(root) / 'reports'),
    'AWS_RDS_LARK_CONFIG': str(Path(root) / 'lark-config.json'), 'AWS_RDS_MINUTE': '10',
}
for key, value in defaults.items():
    if key not in existing:
        updates[key] = value
if profile_set == '1': updates['AWS_PROFILE'] = profile
if regions_set == '1': updates['AWS_RDS_REGIONS'] = regions
if publish_set == '1': updates['AWS_RDS_PUBLISH_DIR'] = publish
if minute: updates['AWS_RDS_MINUTE'] = minute
content = env_path.read_text(encoding='utf-8-sig') if env_path.exists() else '# RDS audit service environment; single-line KEY="value" settings. Never source this file in a shell.\n'
lines = [line for line in content.splitlines() if line.partition('=')[0].strip() not in updates]
lines += [key + '=' + json.dumps(value, ensure_ascii=False) for key, value in updates.items()]
with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=env_path.parent, prefix='.aws-rds-audit-', delete=False) as handle:
    temporary = Path(handle.name)
    handle.write('\n'.join(lines) + '\n')
os.chmod(temporary, 0o600)
os.replace(temporary, env_path)
account = pwd.getpwnam(username)
effective = load_environment(env_path)
run_minute = effective.get('AWS_RDS_MINUTE', '10')
if run_minute not in {'05', '10'}:
    raise ValueError('AWS_RDS_MINUTE must be 05 or 10')
write_units(Path('/etc/systemd/system'), root, username, group, account.pw_dir, minute=run_minute)
PY
  systemd-analyze verify /etc/systemd/system/aws-rds-audit.service /etc/systemd/system/aws-rds-audit.timer || fail '生成的 systemd 服务校验失败。'
  systemctl daemon-reload
fi

log '检查系统时间和部署身份；不发送测试消息。'
date -u '+当前 UTC：%Y-%m-%d %H:%M:%S'
if command -v timedatectl >/dev/null && [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" != yes ]]; then
  printf '[提示] 系统未报告 NTP 已同步；请检查 timedatectl，时间偏差会影响 AWS 签名和日报窗口。\n' >&2
fi
if ! "$VENV/bin/python" "$PROJECT_ROOT/deploy/run_daily.py" --env-file "$ENV_FILE" --as-user "$RUN_USER" --check-config; then
  if ((CHECK_ONLY == 0)); then
    systemctl disable --now aws-rds-audit.timer || true
  fi
  printf '[待配置] 部署文件已保留，定时器未启用。请按上方提示配置服务用户的 AWS 身份、只读权限和真实 Lark Webhook，再重新运行 install.sh。\n' >&2
  printf 'Lark 配置：%s/lark-config.json；服务环境：%s（不要将私有配置提交到 Git）。\n' "$PROJECT_ROOT" "$ENV_FILE" >&2
  exit 2
fi
if ((CHECK_ONLY)); then
  log '预检通过；未修改文件、安装软件或启停服务。'
elif ((NO_ENABLE)); then
  log '安装和预检完成；按 --no-enable 要求未启用定时器。'
else
  systemctl enable --now aws-rds-audit.timer
  systemctl list-timers aws-rds-audit.timer --no-pager
  log '部署完成。定时器按 Asia/Shanghai 运行，服务器本地时区无需修改。'
fi
printf '查看日志：journalctl -u aws-rds-audit.service -n 100 --no-pager\n'
