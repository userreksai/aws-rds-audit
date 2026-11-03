"""Render mail-mode units without shell interpolation or secret environment files."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import tempfile

UNIT_NAMES = ("aws-rds-audit.service", "aws-rds-audit.timer",
              "aws-rds-audit-collect.service", "aws-rds-audit-collect.timer")


def _value(value):
    if not isinstance(value, str) or not value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("Unit values must be non-empty and contain no control characters")
    return value


def _path(value):
    value = _value(value)
    if not PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
        raise ValueError("Unit paths must be absolute Linux paths without '..'")
    return value


def quote_word(value, *, executable_argument=False):
    """Systemd C quoting plus literal specifier and ExecStart dollar escaping."""
    value = _value(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if executable_argument:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def render_units(project_root, username, group, home, config_path):
    """Both timers wake every five minutes; JSON controls collection/mail cadence."""
    root = _path(project_root).rstrip("/") or "/"
    config_path = _path(config_path)
    for value in (username, group):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\$?", value):
            raise ValueError("Service user and group must be local account names")
    home = _path(home)
    # WorkingDirectory is deliberately a fixed scalar. Every execution argument
    # is absolute, so paths with quotes/spaces need no scalar-path unescaping.
    python = str(PurePosixPath(root) / ".venv/bin/python")
    runner = str(PurePosixPath(root) / "rds_multi.py")
    rendered = {}
    for name, mode, description in (
        ("aws-rds-audit", "--scheduled", "AWS RDS multi-account PDF email schedule"),
        ("aws-rds-audit-collect", "--collect", "AWS RDS multi-account source-IP interval collection"),
    ):
        command = " ".join(quote_word(item, executable_argument=True)
                           for item in (python, runner, "--config", config_path, mode))
        rendered[name + ".service"] = f"""[Unit]
Description={description}
Wants=network-online.target
After=network-online.target time-sync.target

[Service]
Type=oneshot
User={username}
Group={group}
WorkingDirectory=/
Environment={quote_word('HOME=' + home)}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONIOENCODING=utf-8
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart={command}
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
TimeoutStartSec=6h
"""
        rendered[name + ".timer"] = f"""[Unit]
Description=Wake {description.lower()} every five minutes

[Timer]
OnCalendar=*-*-* *:00/5:00 UTC
Persistent=true
AccuracySec=30s
Unit={name}.service

[Install]
WantedBy=timers.target
"""
    return rendered


def write_units(destination, project_root, username, group, home, config_path):
    """Replace each unit atomically after the caller stops the old timers."""
    destination = Path(destination)
    units = render_units(project_root, username, group, home, config_path)
    for name, content in units.items():
        handle, temporary = tempfile.mkstemp(prefix="." + name + ".", dir=destination)
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
            Path(temporary).chmod(0o644)
            os.replace(temporary, destination / name)
        finally:
            Path(temporary).unlink(missing_ok=True)
    return units
