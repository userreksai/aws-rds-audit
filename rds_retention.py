"""Prune only marked account/day directories without following links."""
from __future__ import annotations

from datetime import date, datetime, timedelta
import os
from pathlib import Path
import re
import shutil
import stat


DAY_MARKER = ".rds-audit-day"
_DAY_NAME = re.compile(r"\d{4}-\d{2}-\d{2}\Z")


def _is_link(path):
    """Windows junctions are reparse points even on Python before is_junction."""
    information = path.lstat()
    return stat.S_ISLNK(information.st_mode) or bool(
        getattr(information, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _contains_link(directory):
    for current, directories, files in os.walk(directory, followlinks=False):
        if _is_link(Path(current)):
            return True
        for name in directories + files:
            if _is_link(Path(current) / name):
                return True
    return False


def prune_account_days(account_directory: Path, today: date, retention_days: int) -> list[str]:
    """Keep today and its preceding N-1 dates; leave unknown/unmarked data alone.

    The caller holds its account/process lock. Symlinks and Windows junctions
    anywhere inside a candidate are refused rather than traversed or removed.
    """
    if not isinstance(today, date) or isinstance(today, datetime):
        raise ValueError("today must be a calendar date")
    if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days <= 0:
        raise ValueError("retention_days must be a positive integer")
    try:
        cutoff = today - timedelta(days=retention_days - 1)
    except OverflowError:
        raise ValueError("retention_days exceeds the calendar range") from None
    lexical_root = Path(account_directory).absolute()
    # Reject linked ancestors too: a configured output path must not silently
    # redirect retention into another tree.
    for component in (lexical_root, *lexical_root.parents):
        if component.exists() or component.is_symlink():
            if _is_link(component):
                raise ValueError("account_directory cannot contain linked path components")
    if not lexical_root.exists():
        return []
    if not lexical_root.is_dir():
        raise ValueError("account_directory must be a directory")
    root = lexical_root.resolve(strict=True)
    deleted = []
    for target in sorted(root.iterdir(), key=lambda path: path.name):
        if not _DAY_NAME.fullmatch(target.name):
            continue
        try:
            day = date.fromisoformat(target.name)
        except ValueError:
            continue
        if day >= cutoff or _is_link(target) or not target.is_dir():
            continue
        marker = target / DAY_MARKER
        if not marker.is_file() or _is_link(marker) or _contains_link(target):
            continue
        resolved = target.resolve(strict=True)
        if resolved == root or resolved.parent != root or not resolved.is_relative_to(root):
            raise ValueError("retention target leaves the account directory")
        # Recheck immediately before recursive deletion; only an exact, marked
        # child date directory inside this already-resolved root is eligible.
        if _is_link(target) or target.resolve(strict=True) != resolved:
            raise ValueError("retention target changed during validation")
        shutil.rmtree(resolved)
        deleted.append(target.name)
    return deleted
