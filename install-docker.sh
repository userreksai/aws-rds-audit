#!/usr/bin/env bash
# Independent Docker deployment; never changes host timers, cron or Nginx.
set -Eeuo pipefail
umask 077
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ORIGINAL_DIR=$PWD
DATA_DIR=/usr/local/aws-rds-shenji
CONTAINER_CONFIG=/usr/local/aws-rds-shenji/rds-audit-config.json
CONFIG_PATH=
PROFILE_DIR=
PROJECT=aws-rds-audit-docker
IMAGE=${AUDIT_IMAGE:-aws-rds-audit:local}
DRY_RUN=0
NO_START=0
WORK_LOG=
PLAN_FILE=
ENV_STAGE=
say() { printf '%s\n' "$*"; }
die() { printf 'RDS Docker 安装未完成：%s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "参数 $1 缺少值。"; }
usage() {
    cat <<'HELP'
Usage: bash install-docker.sh [options]
  --data-dir DIR     Default: /usr/local/aws-rds-shenji
  --config FILE      Existing JSON/JSONC; default DATA_DIR/rds-audit-config.json
  --profile-dir DIR  Existing AWS directory, read-only at /root/.aws
  --no-start         Build and check without starting/replacing the service
  --dry-run          Show the plan without Docker, network or writes
  --help            Show help
Requires Linux Docker Engine and Docker Compose V2+. Missing configuration is
initialized from the full template with mode 0600, then the installer stops.
Existing configuration bytes and OUTPUT_DIRECTORY state are preserved. This
installer never changes systemd, cron or Nginx. Startup immediately checks the
existing RDS collection/mail tasks, then wakes them every five minutes. The
business configuration controls mail time and the shared daily mail budget.
HELP
}
validate_path() {
    local value=$1
    [[ $value == /* && $value != //* && $value != *:* && $value != *,* && $value != *\\* \
        && ! $value =~ [[:cntrl:]] ]] || die '路径须为无控制字符、冒号或逗号的 Linux 绝对路径。'
    case $value/ in */../*|*/./*) die '部署路径不能包含 . 或 .. 路径段。' ;; esac
}
dedicated_directory() {
    case $1 in
        ''|/|/app|/bin|/sbin|/usr|/usr/local|/etc|/var|/var/lib|/tmp|/home|/root|/opt|/srv|/run|/proc|/dev|/sys|/lib|/lib64)
            die '请使用独立的应用数据子目录。' ;;
    esac
}
overlap() { [[ $1 == "$2" || $1 == "$2/"* || $2 == "$1/"* ]]; }
safe_output() {
    local directory=$1 protected
    dedicated_directory "$directory"
    for protected in /app /etc /root/.aws /bin /sbin /lib /lib64 /proc /sys /dev /boot /run \
        /usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/share /usr/local/bin /usr/local/sbin /usr/local/lib /var/run; do
        ! overlap "$directory" "$protected" || die '输出目录不能映射到系统敏感目录。'
    done
    ! overlap "$directory" "$CONFIG_PATH" || die '输出目录不能包含私有配置。'
    [[ -z $PROFILE_DIR ]] || ! overlap "$directory" "$PROFILE_DIR" || die '输出目录不能与 AWS profile 重叠。'
}
normalize_path() {
    local name=$1 value=${!1}
    [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
    validate_path "$value"
    value=$(realpath -m -- "$value") || die '无法解析部署路径。'
    validate_path "$value"
    printf -v "$name" '%s' "${value%/}"
}
cleanup() {
    local status=$?
    trap - EXIT
    [[ -z $WORK_LOG ]] || rm -f -- "$WORK_LOG"
    [[ -z $PLAN_FILE ]] || rm -f -- "$PLAN_FILE"
    [[ -z $ENV_STAGE ]] || rm -f -- "$ENV_STAGE"
    exit "$status"
}
run_logged() {
    local message=$1
    shift
    "$@" >"$WORK_LOG" 2>&1 || die "$message"
}
while (($#)); do
    case $1 in
        --data-dir) need_value "$@"; DATA_DIR=$2; shift 2 ;;
        --config) need_value "$@"; CONFIG_PATH=$2; shift 2 ;;
        --profile-dir) need_value "$@"; PROFILE_DIR=$2; shift 2 ;;
        --no-start) NO_START=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die '未知参数；请使用 --help。' ;;
    esac
done
[[ $IMAGE =~ ^[A-Za-z0-9][A-Za-z0-9._:/@-]*$ ]] || die 'Docker 镜像名称无效。'
[[ -n $CONFIG_PATH ]] || CONFIG_PATH=$DATA_DIR/rds-audit-config.json
if ((DRY_RUN)); then
    for value in "$DATA_DIR" "$CONFIG_PATH"; do
        [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
        validate_path "$value"
    done
    dedicated_directory "$DATA_DIR"
    if [[ -n $PROFILE_DIR ]]; then
        value=$PROFILE_DIR
        [[ $value == /* ]] || value=$ORIGINAL_DIR/$value
        validate_path "$value"
    fi
    say '【dry-run】未调用 Docker、未联网、未写入文件。'
    say "源码：$SOURCE_DIR；数据：$DATA_DIR"
    say "配置只读挂载到：$CONTAINER_CONFIG"
    say "Compose project：$PROJECT；service：audit；image：$IMAGE"
    say '无配置：复制完整模板为0600后退出。已有配置：build → 离线路径规划 → check-config → up。'
    say 'OUTPUT_DIRECTORY 整体持久化；分段/PDF/锁/邮件回执与每日额度保留。'
    say '启动即检查采集与邮件，每5分钟唤醒；发信时刻与每日最多一封规则沿用业务配置。'
    ((NO_START == 0)) || say '--no-start：只构建检查，不启动或替换容器。'
    exit 0
fi
[[ $(uname -s) == Linux ]] || die '实际安装只支持 Linux；其他系统可用 --dry-run。'
for required in realpath mkdir cat dirname chmod chown stat mktemp mv rm; do
    command -v "$required" >/dev/null 2>&1 || die "缺少必要命令：$required。"
done
validate_path "$SOURCE_DIR"
normalize_path DATA_DIR
[[ ! -L $CONFIG_PATH ]] || die '配置不能为符号链接。'
normalize_path CONFIG_PATH
dedicated_directory "$DATA_DIR"
if [[ ! -e $CONFIG_PATH ]]; then
    [[ -f $SOURCE_DIR/rds-audit-config.example.json ]] || die '缺少完整配置模板。'
    mkdir -p -- "$(dirname -- "$CONFIG_PATH")"
    (set -o noclobber; cat -- "$SOURCE_DIR/rds-audit-config.example.json" >"$CONFIG_PATH") \
        2>/dev/null || die '无法安全初始化配置。'
    chmod 0600 -- "$CONFIG_PATH"
    say "完整配置模板已保存为0600：$CONFIG_PATH"
    say '填写真实账号和邮件配置后重跑；本次未调用 Docker 或启动任务。'
    exit 2
fi
[[ -f $CONFIG_PATH && -r $CONFIG_PATH ]] || die '配置必须是可读普通文件。'
config_owner=$(stat -c '%u:%g' -- "$CONFIG_PATH")
[[ $config_owner =~ ^[0-9]+:[0-9]+$ ]] || die '无法读取配置所有者。'
export AUDIT_UID=${config_owner%:*} AUDIT_GID=${config_owner#*:}
if [[ -n $PROFILE_DIR ]]; then
    normalize_path PROFILE_DIR
    [[ -d $PROFILE_DIR && -r $PROFILE_DIR ]] || die '--profile-dir 必须是现有可读目录。'
fi
for asset in Dockerfile compose.yaml deploy/docker_config.py; do
    [[ -f $SOURCE_DIR/$asset ]] || die '缺少 Docker 部署文件，请使用完整源码。'
done
command -v docker >/dev/null 2>&1 || die '请先安装 Docker Engine 和 Docker Compose V2+。'
WORK_LOG=$(mktemp "${TMPDIR:-/tmp}/aws-rds-audit-docker-log.XXXXXXXX")
trap cleanup EXIT
PLAN_FILE=$(mktemp "${TMPDIR:-/tmp}/aws-rds-audit-docker-plan.XXXXXXXX")
run_logged '无法访问 Docker Engine。' docker info --format '{{.ServerVersion}}'
run_logged '需要 Docker Compose V2+。' docker compose version --short
compose_version=$(cat -- "$WORK_LOG")
[[ $compose_version =~ ^v?([0-9]{1,3})\. ]] && ((10#${BASH_REMATCH[1]} >= 2)) || die '需要 Docker Compose V2+。'
export AUDIT_CONFIG_PATH=$CONFIG_PATH AUDIT_OUTPUT_DIR=$DATA_DIR/output
export AUDIT_CONTAINER_OUTPUT_DIR=/usr/local/aws-rds-shenji/output
COMPOSE=(docker compose --project-name "$PROJECT" --project-directory "$SOURCE_DIR" -f "$SOURCE_DIR/compose.yaml")
if [[ -n $PROFILE_DIR ]]; then
    export AUDIT_AWS_DIR=$PROFILE_DIR
    COMPOSE+=(-f "$SOURCE_DIR/compose.aws-profile.yaml")
fi
say '正在构建独立 RDS 镜像；检查通过后更新本项目容器。'
run_logged '构建失败，未停止或更新容器。' "${COMPOSE[@]}" build audit
if ! docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --user "$AUDIT_UID:$AUDIT_GID" --mount "type=bind,src=$CONFIG_PATH,dst=$CONTAINER_CONFIG,readonly" \
    --entrypoint /app/.venv/bin/python "$IMAGE" /app/deploy/docker_config.py \
    --config "$CONTAINER_CONFIG" --host-config-path "$CONFIG_PATH" --format env >"$PLAN_FILE" 2>"$WORK_LOG"; then
    die '私有配置或路径预检失败；请检查JSONC、0600权限及目录冲突。'
fi
AUDIT_OUTPUT_DIR=
AUDIT_CONTAINER_OUTPUT_DIR=
AUDIT_REQUIRES_PROFILE=
AUDIT_FONT_SOURCE=
AUDIT_CONTAINER_FONT_PATH=
declare -A PLAN_KEYS=()
while IFS=$'\t' read -r key value extra || [[ -n ${key:-} ]]; do
    case $key in
        AUDIT_OUTPUT_DIR|AUDIT_CONTAINER_OUTPUT_DIR|AUDIT_REQUIRES_PROFILE|AUDIT_FONT_SOURCE|AUDIT_CONTAINER_FONT_PATH)
            [[ -n $value && -z ${extra:-} && -z ${PLAN_KEYS[$key]:-} ]] || die '路径计划格式无效。'
            printf -v "$key" '%s' "$value"; PLAN_KEYS[$key]=1 ;;
        *) die '路径计划包含未知字段。' ;;
    esac
done <"$PLAN_FILE"
[[ ( ${#PLAN_KEYS[@]} == 3 || ${#PLAN_KEYS[@]} == 5 ) && $AUDIT_REQUIRES_PROFILE =~ ^[01]$ ]] || die '路径计划不完整。'
for setting in AUDIT_OUTPUT_DIR AUDIT_CONTAINER_OUTPUT_DIR; do
    validate_path "${!setting}"
    dedicated_directory "${!setting}"
done
normalize_path AUDIT_OUTPUT_DIR
safe_output "$AUDIT_OUTPUT_DIR"
if [[ $AUDIT_REQUIRES_PROFILE == 1 && -z $PROFILE_DIR ]]; then
    die '账号使用 AWS_PROFILE，请加 --profile-dir /root/.aws（或真实目录）重跑。'
fi
if [[ -n $AUDIT_FONT_SOURCE || -n $AUDIT_CONTAINER_FONT_PATH ]]; then
    [[ -n $AUDIT_FONT_SOURCE && -n $AUDIT_CONTAINER_FONT_PATH ]] || die '字体路径计划不完整。'
    validate_path "$AUDIT_FONT_SOURCE"
    validate_path "$AUDIT_CONTAINER_FONT_PATH"
    [[ -f $AUDIT_FONT_SOURCE && -r $AUDIT_FONT_SOURCE && ! -L $AUDIT_FONT_SOURCE ]] || die '字体必须是可读非符号链接文件。'
    normalize_path AUDIT_FONT_SOURCE
    ! overlap "$AUDIT_FONT_SOURCE" "$AUDIT_OUTPUT_DIR" || die '字体不能位于可写输出目录内。'
    export AUDIT_FONT_SOURCE AUDIT_CONTAINER_FONT_PATH
    COMPOSE+=(-f "$SOURCE_DIR/compose.font.yaml")
fi
export AUDIT_OUTPUT_DIR AUDIT_CONTAINER_OUTPUT_DIR
if [[ -e $AUDIT_OUTPUT_DIR ]]; then
    [[ -d $AUDIT_OUTPUT_DIR && $(stat -c '%u' -- "$AUDIT_OUTPUT_DIR") == "$AUDIT_UID" ]] || die '现有输出目录须属于配置所有者；不会改写旧文件所有权。'
else
    mkdir -p -- "$AUDIT_OUTPUT_DIR"
    chown "$AUDIT_UID:$AUDIT_GID" -- "$AUDIT_OUTPUT_DIR"
fi
chmod 0700 -- "$AUDIT_OUTPUT_DIR"
run_logged 'Compose 配置检查失败，未更新容器。' "${COMPOSE[@]}" config --quiet
run_logged '容器配置检查失败，未更新容器。' "${COMPOSE[@]}" run --rm --no-deps -T audit check-config
ENV_FILE=$DATA_DIR/docker.env
[[ $ENV_FILE != "$CONFIG_PATH" && ! -L $ENV_FILE && ( ! -e $ENV_FILE || -f $ENV_FILE ) ]] || die 'docker.env 不能覆盖配置或符号链接。'
mkdir -p -- "$DATA_DIR"
ENV_STAGE=$(mktemp "$DATA_DIR/.docker.env.XXXXXXXX")
COMPOSE_FILE=$SOURCE_DIR/compose.yaml
[[ -z $PROFILE_DIR ]] || COMPOSE_FILE+=:$SOURCE_DIR/compose.aws-profile.yaml
[[ -z $AUDIT_FONT_SOURCE ]] || COMPOSE_FILE+=:$SOURCE_DIR/compose.font.yaml
COMPOSE_PROJECT_NAME=$PROJECT
AUDIT_IMAGE=$IMAGE
write_env() {
    local name=$1 value=${!1}
    value=${value//\'/\\\'}
    printf "%s='%s'\n" "$name" "$value" >>"$ENV_STAGE"
}
for setting in COMPOSE_PROJECT_NAME COMPOSE_FILE AUDIT_IMAGE AUDIT_UID AUDIT_GID AUDIT_CONFIG_PATH \
    AUDIT_OUTPUT_DIR AUDIT_CONTAINER_OUTPUT_DIR; do write_env "$setting"; done
[[ -z $PROFILE_DIR ]] || write_env AUDIT_AWS_DIR
if [[ -n $AUDIT_FONT_SOURCE ]]; then write_env AUDIT_FONT_SOURCE; write_env AUDIT_CONTAINER_FONT_PATH; fi
chmod 0600 -- "$ENV_STAGE"
mv -f -- "$ENV_STAGE" "$ENV_FILE"
ENV_STAGE=
say "部署环境已保存为0600：$ENV_FILE（不含凭据）。"
if ((NO_START)); then say '--no-start：构建和检查完成，未启动或替换容器。'; exit 0; fi
run_logged 'Docker服务启动失败，请检查本项目状态。' "${COMPOSE[@]}" up -d --no-deps --force-recreate audit
say 'RDS Docker 已启动：aws-rds-audit-docker / audit。配置和原有回执/额度保留。'
say '启动即检查现有采集和发信计划；未修改宿主 systemd、cron 或 Nginx。'
