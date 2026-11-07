#!/usr/bin/env python3
"""Plan Docker bind mounts from the existing private JSONC without modifying it."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import sys
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rds_config import load_config
from rds_config import strip_json_comments


_CHECK_POSIX_PERMISSIONS = os.name == "posix"
_SYSTEM_TREES = (
    "/app", "/etc", "/root/.aws", "/bin", "/sbin", "/lib", "/lib64",
    "/proc", "/sys", "/dev", "/boot", "/run", "/usr/bin", "/usr/sbin",
    "/usr/lib", "/usr/lib64", "/usr/share", "/usr/local/bin", "/usr/local/sbin",
    "/usr/local/lib", "/var/run",
)
_SHARED_ROOTS = {"/", "/usr", "/usr/local", "/var", "/var/lib", "/opt",
                 "/home", "/root", "/tmp", "/mnt", "/media", "/srv"}
_ENV_KEYS = ("AUDIT_OUTPUT_DIR", "AUDIT_CONTAINER_OUTPUT_DIR", "AUDIT_REQUIRES_PROFILE")


class DockerConfigError(ValueError):
    """A field-only error safe to show without private configuration values."""


def _path_text(value, field):
    if (not isinstance(value, str) or not value.strip()
            or any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in value)
            or any(char in value for char in ",:\\") or value.strip().startswith("~")):
        raise DockerConfigError(field + " 必须为无控制字符、逗号和冒号的 Linux 路径。")
    return value.strip()


def _absolute(value, field):
    value = _path_text(value, field)
    if not value.startswith("/") or value.startswith("//"):
        raise DockerConfigError(field + " 必须为 Linux 绝对路径。")
    return posixpath.normpath(value)


def _overlap(first, second):
    return first == second or first.startswith(second.rstrip("/") + "/") or second.startswith(first.rstrip("/") + "/")


def _safe_path(path, config_path, field, *, font=False):
    if _overlap(path, config_path):
        raise DockerConfigError(field + " 不能包含或覆盖私有配置文件。")
    font_tree = font and path.startswith("/usr/share/fonts/")
    if (path in _SHARED_ROOTS
            or any(_overlap(path, protected) for protected in _SYSTEM_TREES
                   if not (font_tree and protected == "/usr/share"))):
        raise DockerConfigError(field + " 不能使用系统敏感目录或应用代码目录。")


def _mapped_paths(raw, key, default, host_config, container_config):
    value = _path_text(raw.get(key, default), key)
    if value.startswith("/"):
        source = target = _absolute(value, key)
    else:
        source = _absolute(str(PurePosixPath(host_config).parent / value), key)
        target = _absolute(str(PurePosixPath(container_config).parent / value), key)
    _safe_path(source, host_config, key, font=key == "PDF_FONT_PATH")
    _safe_path(target, container_config, key, font=key == "PDF_FONT_PATH")
    return source, target


def build_plan(raw, validated, *, host_config_path, container_config_path):
    """Return a secret-free POSIX mount plan from already validated settings."""
    host_config = _absolute(host_config_path, "--host-config-path")
    container_config = _absolute(container_config_path, "--config")
    output, container_output = _mapped_paths(raw, "OUTPUT_DIRECTORY", "output", host_config, container_config)
    plan = {"AUDIT_OUTPUT_DIR": output, "AUDIT_CONTAINER_OUTPUT_DIR": container_output,
            "AUDIT_REQUIRES_PROFILE": "1" if any(account.get("ENABLED", True) and account.get("AWS_PROFILE")
                                                  for account in validated["ACCOUNTS"]) else "0"}
    if raw.get("PDF_FONT_PATH", "").strip():
        source, target = _mapped_paths(raw, "PDF_FONT_PATH", "", host_config, container_config)
        if _overlap(source, output) or _overlap(target, container_output):
            raise DockerConfigError("PDF_FONT_PATH 不能与 OUTPUT_DIRECTORY 重叠。")
        plan.update(AUDIT_FONT_SOURCE=source, AUDIT_CONTAINER_FONT_PATH=target)
    return plan


def _private_file(source):
    if source.is_symlink():
        raise DockerConfigError("统一配置不能为符号链接。")
    info = source.stat()
    if not stat.S_ISREG(info.st_mode):
        raise DockerConfigError("统一配置必须为普通文件。")
    if _CHECK_POSIX_PERMISSIONS and (info.st_mode & 0o077 or not info.st_mode & stat.S_IRUSR):
        raise DockerConfigError("统一配置权限不安全；请手工执行 chmod 600 后重试。")


def create_plan(config_path, host_config_path, *, container_config_path=None):
    """Validate a private file locally and plan mounts without any network I/O.

    The optional logical container path lets local tests read a fixture while
    retaining Linux path semantics. The CLI uses its actual --config path.
    """
    source = Path(config_path)
    try:
        _private_file(source)
        validated = load_config(source, require_mail=False)
        raw = json.loads(strip_json_comments(source.read_text(encoding="utf-8-sig")))
        return build_plan(raw, validated, host_config_path=host_config_path,
                          container_config_path=(container_config_path if container_config_path is not None
                                                 else os.fspath(config_path)))
    except DockerConfigError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, RuntimeError):
        raise DockerConfigError("统一配置校验失败；请检查字段、语法、路径及读取权限。") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--host-config-path", required=True)
    parser.add_argument("--format", choices=("env", "json"), default="env")
    args = parser.parse_args(argv)
    try:
        plan = create_plan(args.config, args.host_config_path)
    except DockerConfigError as exc:
        print("Docker 配置规划失败：" + str(exc), file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(plan, ensure_ascii=False))
    else:
        for key in (*_ENV_KEYS, "AUDIT_FONT_SOURCE", "AUDIT_CONTAINER_FONT_PATH"):
            if key in plan:
                print(key + "\t" + plan[key])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
