#!/usr/bin/env python3
"""Wake the existing RDS collection and delivery tasks without host timers."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
from rds_cache import _exclusive
from rds_config import load_config
from rds_multi import atomic_json, safe_directory

DEFAULT_CONFIG = Path('/usr/local/aws-rds-shenji/rds-audit-config.json')
HEARTBEAT = '.docker-runtime-heartbeat.json'
INTERVAL_SECONDS = 300


def business_command(mode, config_path, *, day=None, send_mail=False, force=False):
    command = [sys.executable, str(PROJECT / 'rds_multi.py'), '--config', str(config_path), '--' + mode]
    if day:
        command.extend(['--date', day])
    if send_mail:
        command.append('--send-mail')
    if force:
        command.append('--force-resend')
    return command


def stop_children(children, *, grace=20):
    """Forward termination, then bound shutdown before Compose's 30s grace."""
    active = [child for child in children if child.poll() is None]
    for child in active:
        try:
            if os.name == 'posix':
                os.killpg(child.pid, signal.SIGTERM)
            else:
                child.terminate()
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + grace
    for child in active:
        try:
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                if os.name == 'posix':
                    os.killpg(child.pid, signal.SIGKILL)
                else:
                    child.kill()
            except ProcessLookupError:
                pass
            child.wait(timeout=2)


def run_schedule(config_path, *, stop=None, popen=None, monotonic=None, wait=None):
    """Collection and delivery may overlap; each mode has at most one child.

    The business module retains its output locks, daily mail budget, retries and
    timezone/window handling. No second scheduling or delivery ledger is added.
    """
    stop = stop or threading.Event()
    popen = popen or subprocess.Popen
    monotonic = monotonic or time.monotonic
    wait = wait or stop.wait
    settings = load_config(config_path, require_mail=False)
    output = safe_directory(settings['OUTPUT_DIRECTORY'])
    heartbeat = output / HEARTBEAT
    children, due = {}, {mode: 0 for mode in ('collect', 'scheduled')}
    with _exclusive(output / '.docker-runtime.lock') as acquired:
        if not acquired:
            raise ValueError('已有 Docker 调度器使用同一 OUTPUT_DIRECTORY。')
        try:
            while not stop.is_set():
                # Reject moving the live state volume; normal schedule/account
                # changes are loaded by each new business subprocess.
                current = load_config(config_path, require_mail=False)
                if Path(current['OUTPUT_DIRECTORY']).resolve() != output:
                    raise ValueError('OUTPUT_DIRECTORY 已变更，请重跑 Docker 安装器。')
                stamp = monotonic()
                for mode in due:
                    child = children.get(mode)
                    if child is not None and child.poll() is not None:
                        print(f'RDS Docker {mode} 本轮退出码：{child.returncode}', flush=True)
                        children.pop(mode)
                    if mode not in children and stamp >= due[mode]:
                        children[mode] = popen(business_command(mode, config_path),
                                              start_new_session=os.name == 'posix')
                        due[mode] = stamp + INTERVAL_SECONDS
                atomic_json(heartbeat, {'schema_version': 1, 'pid': os.getpid(),
                    'updated_at': datetime.now(timezone.utc).isoformat(),
                    'running': sorted(children)})
                wait(5)
        finally:
            stop_children(children.values())
            if heartbeat.exists():
                heartbeat.unlink()
    return 0


def healthcheck(config_path, *, now=None):
    settings = load_config(config_path, require_mail=False)
    path = Path(settings['OUTPUT_DIRECTORY']) / HEARTBEAT
    if path.is_symlink():
        return 1
    value = json.loads(path.read_text(encoding='utf-8'))
    now = now or datetime.now(timezone.utc)
    updated = datetime.fromisoformat(value['updated_at'])
    if (value.get('schema_version') != 1 or type(value.get('pid')) is not int
            or not 0 <= (now - updated).total_seconds() <= 90):
        return 1
    try:
        os.kill(value['pid'], 0)
    except (ProcessLookupError, PermissionError):
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('schedule', 'check-config', 'healthcheck', 'collect',
                                            'scheduled', 'report', 'since-yesterday'))
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--date')
    parser.add_argument('--send-mail', action='store_true')
    parser.add_argument('--force-resend', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'healthcheck':
            return healthcheck(args.config)
        if args.command != 'schedule':
            command = business_command(args.command, args.config, day=args.date,
                                       send_mail=args.send_mail, force=args.force_resend)
            os.execv(sys.executable, command)
        if args.date or args.send_mail or args.force_resend:
            raise ValueError('schedule 不接受手动报告参数。')
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: stop.set())
        return run_schedule(args.config, stop=stop)
    except Exception as exc:
        # Avoid copying provider/configuration values to Docker logs.
        print('RDS Docker 运行失败：' + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
