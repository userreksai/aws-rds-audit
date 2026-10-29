"""Render the same systemd units in the installer and Linux regression tests."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re


def _validate(value: str) -> str:
    if not isinstance(value, str) or not value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("Unit values must be non-empty and contain no control characters")
    return value


def quote_word(value: str) -> str:
    """Environment/ExecStart items use systemd word quoting and C escapes."""
    value = _validate(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def working_directory(value: str) -> str:
    """WorkingDirectory is a scalar path: surrounding quotes become literal."""
    value = _validate(value)
    if not PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
        raise ValueError("Project root must be an absolute Linux path without '..'")
    if value != value.rstrip() or value.endswith("\\"):
        raise ValueError("Project root cannot end in whitespace or a backslash")
    if any(ch in value for ch in ("\\", "'", '"', "*", "?", "[")):
        raise ValueError("Project root contains characters unsupported in a systemd executable path")
    if "$" in value:
        raise ValueError("Project paths containing '$' are unsupported; choose a literal deployment path")
    return value.replace("%", "%%")


def _render_service(project_root, username, group, home, template, runner):
    for value in (username, group):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\$?", value):
            raise ValueError("Service user and group must be local account names")
    root = _validate(project_root).rstrip("/") or "/"
    scalar_path = working_directory(root)
    templates = Path(__file__).resolve().parent
    replacements = {
        "@RUN_USER@": username, "@RUN_GROUP@": group,
        "@PROJECT_ROOT@": scalar_path,
        "@HOME_ENV@": quote_word("HOME=" + home),
        "@PYTHON@": quote_word(str(PurePosixPath(root) / ".venv/bin/python")),
        "@RUNNER@": quote_word(str(PurePosixPath(root) / "deploy" / runner)),
    }
    service = (templates / template).read_text(encoding="utf-8")
    for key, value in replacements.items():
        service = service.replace(key, value)
    return service


def render_units(project_root: str, username: str, group: str, home: str, *, minute="10") -> tuple[str, str]:
    if minute not in {"05", "10"}:
        raise ValueError("Execution minute must be 05 or 10")
    templates = Path(__file__).resolve().parent
    service = _render_service(project_root, username, group, home, "aws-rds-audit.service", "run_daily.py")
    timer = (templates / "aws-rds-audit.timer").read_text(encoding="utf-8").replace("08:10", "08:" + minute)
    return service, timer


def render_collection_units(project_root: str, username: str, group: str, home: str) -> tuple[str, str]:
    service = _render_service(project_root, username, group, home, "aws-rds-audit-collect.service", "run_collect.py")
    timer = (Path(__file__).resolve().parent / "aws-rds-audit-collect.timer").read_text(encoding="utf-8")
    return service, timer


def render_failure_unit(project_root: str, username: str, group: str, home: str) -> str:
    # %i belongs to systemd's instance syntax; only substituted filesystem paths
    # are escaped, so the template can forward the actual failing unit name.
    return _render_service(project_root, username, group, home, "aws-rds-audit-failure@.service", "run_failure.py")


def write_units(destination: Path, project_root: str, username: str, group: str, home: str, *, minute="10"):
    service, timer = render_units(project_root, username, group, home, minute=minute)
    collect_service, collect_timer = render_collection_units(project_root, username, group, home)
    failure = render_failure_unit(project_root, username, group, home)
    for name, content in (("aws-rds-audit.service", service), ("aws-rds-audit.timer", timer),
                          ("aws-rds-audit-collect.service", collect_service), ("aws-rds-audit-collect.timer", collect_timer),
                          ("aws-rds-audit-failure@.service", failure)):
        path = Path(destination) / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o644)
