#!/usr/bin/env python3
"""Wake bounded interval work and retries, including one delayed refresh."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

try:
    from .run_daily import drop_to_user, load_environment
except ImportError:
    from run_daily import drop_to_user, load_environment

PROJECT = Path(__file__).resolve().parent.parent


def build_command(environment: dict[str, str]) -> list[str]:
    interval = environment.get("AWS_RDS_INTERVAL_MINUTES") or "30"
    if interval not in {"30", "60"}:
        raise ValueError("AWS_RDS_INTERVAL_MINUTES must be 30 or 60")
    lookback = environment.get("AWS_RDS_CACHE_LOOKBACK_HOURS") or "26"
    maximum = environment.get("AWS_RDS_MAX_BUCKETS_PER_RUN") or "6"
    if not lookback.isdecimal() or not 1 <= int(lookback) <= 2136:
        raise ValueError("AWS_RDS_CACHE_LOOKBACK_HOURS must be between 1 and 2136")
    if not maximum.isdecimal() or not 1 <= int(maximum) <= 100:
        raise ValueError("AWS_RDS_MAX_BUCKETS_PER_RUN must be between 1 and 100")
    command = [
        sys.executable, str(PROJECT / "rds_audit.py"), "--collect-incremental",
        "--regions", environment.get("AWS_RDS_REGIONS") or "all",
        "--cache-dir", environment.get("AWS_RDS_CACHE_DIR") or str(PROJECT / "cache"),
        "--interval-minutes", interval, "--cache-lookback-hours", lookback,
        "--max-buckets-per-run", maximum,
        "--output-dir", environment.get("AWS_RDS_REPORT_ROOT") or str(PROJECT / "reports"),
        "--send-lark", "--lark-config", environment.get("AWS_RDS_LARK_CONFIG") or str(PROJECT / "lark-config.json"),
    ]
    if environment.get("AWS_PROFILE"):
        command.extend(["--profile", environment["AWS_PROFILE"]])
    if environment.get("AWS_RDS_PUBLISH_DIR"):
        command.extend(["--publish-dir", environment["AWS_RDS_PUBLISH_DIR"]])
    return command


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Incremental RDS collector with persistent retry/checkpoint state")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--as-user")
    args = parser.parse_args(argv)
    try:
        if args.env_file:
            os.environ.update(load_environment(args.env_file))
        if args.as_user:
            drop_to_user(args.as_user)
        if not os.access(PROJECT, os.R_OK | os.X_OK) or not os.access(PROJECT / "rds_audit.py", os.R_OK):
            raise PermissionError("服务用户无法读取项目目录或采集脚本")
        # CacheStore owns the process lock and durable per-segment state.
        return subprocess.run(build_command(dict(os.environ)), cwd=PROJECT, check=False).returncode
    except Exception as exc:
        print(f"RDS 增量采集运行器失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
