#!/usr/bin/env python3
"""systemd entry point: select a completed Beijing window and prevent overlaps."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

PROJECT = Path(__file__).resolve().parent.parent
BEIJING = ZoneInfo("Asia/Shanghai")


def latest_completed_date(now: datetime | None = None) -> str:
    stamp = now or datetime.now(BEIJING)
    if stamp.tzinfo is None:
        raise ValueError("Scheduler time must have an explicit timezone")
    stamp = stamp.astimezone(BEIJING)
    day = stamp.date() if stamp.hour >= 8 else stamp.date() - timedelta(days=1)
    return day.isoformat()


def load_environment(path: Path) -> dict[str, str]:
    """Read the generated single-line EnvironmentFile subset without executing it."""
    if path.stat().st_size > 65536:
        raise ValueError("Environment file exceeds 64 KiB")
    result = {}
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"Invalid environment setting on line {number}")
        values = shlex.split(value, comments=False, posix=True)
        if len(values) > 1:
            raise ValueError(f"Quote environment values containing spaces on line {number}")
        result[key] = values[0] if values else ""
    return result


def drop_to_user(username: str) -> None:
    import pwd

    account = pwd.getpwnam(username)
    if os.geteuid() == 0:
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    elif os.geteuid() != account.pw_uid:
        raise PermissionError("Only root can select a different execution user")
    os.environ.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name)


def build_command(environment: dict[str, str], *, check=False, now=None) -> list[str]:
    command = [sys.executable, str(PROJECT / "rds_audit.py")]
    if check:
        command.append("--check-config")
    else:
        command.extend(["--daily", "--from-cache", "--date", latest_completed_date(now)])
    command.extend([
        "--regions", environment.get("AWS_RDS_REGIONS") or "all",
        "--output-dir", environment.get("AWS_RDS_REPORT_ROOT") or str(PROJECT / "reports"),
        "--send-lark", "--lark-config", environment.get("AWS_RDS_LARK_CONFIG") or str(PROJECT / "lark-config.json"),
        "--cache-dir", environment.get("AWS_RDS_CACHE_DIR") or str(PROJECT / "cache"),
        "--interval-minutes", environment.get("AWS_RDS_INTERVAL_MINUTES") or "30",
    ])
    if environment.get("AWS_PROFILE"):
        command.extend(["--profile", environment["AWS_PROFILE"]])
    command.extend(["--publish-dir", environment.get("AWS_RDS_PUBLISH_DIR") or str(PROJECT / "index")])
    return command


def run_locked(command: list[str], directory: Path, date: str) -> int:
    import fcntl

    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".daily.lock").open("a", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("已有 RDS 日报任务运行，本次跳过。", flush=True)
            return 0
        state = directory / ".daily-last-success.json"
        command_hash = hashlib.sha256(json.dumps(command, ensure_ascii=False).encode("utf-8")).hexdigest()
        if state.exists():
            try:
                previous = json.loads(state.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                previous = {}
            if previous.get("date") == date and previous.get("command_hash") == command_hash:
                print(f"北京时间 {date} 的日报已成功完成，本次定时调用跳过。", flush=True)
                return 0
        status = subprocess.run(command, cwd=PROJECT, check=False).returncode
        if status == 0:
            temporary = state.with_suffix(".tmp")
            temporary.write_text(json.dumps({"date": date, "command_hash": command_hash, "completed_at": datetime.now(BEIJING).isoformat()}) + "\n", encoding="utf-8")
            temporary.replace(state)
        return status


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="RDS 日报 systemd 运行器；安装预检不发送通知")
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--env-file", type=Path, help="仅供安装预检读取生成的 EnvironmentFile；不执行 Shell")
    parser.add_argument("--as-user", help="安装时读取环境文件后切换到实际服务用户")
    args = parser.parse_args(argv)
    try:
        if args.env_file:
            os.environ.update(load_environment(args.env_file))
        if args.as_user:
            drop_to_user(args.as_user)
        if not os.access(PROJECT, os.R_OK | os.X_OK) or not os.access(PROJECT / "rds_audit.py", os.R_OK):
            raise PermissionError("服务用户无法访问项目目录；请将项目放在 /opt 等可访问目录或修正目录权限")
        command = build_command(dict(os.environ), check=args.check_config)
        if args.check_config:
            return subprocess.run(command, cwd=PROJECT, check=False).returncode
        root = Path(os.environ.get("AWS_RDS_REPORT_ROOT") or PROJECT / "reports")
        return run_locked(command, root, latest_completed_date())
    except Exception as exc:
        print(f"RDS 日报运行器失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
