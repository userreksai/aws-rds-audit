#!/usr/bin/env python3
"""Forward systemd crash/timeout alerts to the durable notifier, without AWS I/O."""
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
SOURCES = ("aws-rds-audit.service", "aws-rds-audit-collect.service")


def build_command(environment: dict[str, str], source_service: str) -> list[str]:
    if source_service not in SOURCES:
        raise ValueError("Unsupported source service for failure notification")
    interval = environment.get("AWS_RDS_INTERVAL_MINUTES") or "30"
    if interval not in {"30", "60"}:
        raise ValueError("AWS_RDS_INTERVAL_MINUTES must be 30 or 60")
    command = [
        sys.executable, str(PROJECT / "rds_audit.py"), "--notify-service-failure",
        "--source-service", source_service,
        "--cache-dir", environment.get("AWS_RDS_CACHE_DIR") or str(PROJECT / "cache"),
        "--interval-minutes", interval, "--regions", environment.get("AWS_RDS_REGIONS") or "all",
        "--send-lark", "--lark-config", environment.get("AWS_RDS_LARK_CONFIG") or str(PROJECT / "lark-config.json"),
    ]
    if environment.get("AWS_PROFILE"):
        command.extend(["--profile", environment["AWS_PROFILE"]])
    return command


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Persist and notify an RDS service crash or timeout")
    parser.add_argument("source_service", choices=SOURCES)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--as-user")
    args = parser.parse_args(argv)
    try:
        if args.env_file:
            os.environ.update(load_environment(args.env_file))
        if args.as_user:
            drop_to_user(args.as_user)
        return subprocess.run(build_command(dict(os.environ), args.source_service), cwd=PROJECT, check=False).returncode
    except Exception as exc:
        print(f"RDS 服务失败告警运行器失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
