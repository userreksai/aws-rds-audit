"""Calendar retention affects only marked day trees of a selected account."""
from datetime import date, datetime
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rds_retention import DAY_MARKER, prune_account_days


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.account = self.base / "account-a-123456789012"
        self.account.mkdir()

    def day(self, name, marked=True):
        target = self.account / name
        target.mkdir()
        if marked:
            (target / DAY_MARKER).write_text("{}", encoding="utf-8")
        (target / "segments").mkdir()
        (target / "segments" / "summary.json").write_text("{}")
        (target / "report.pdf").write_bytes(b"PDF")
        return target

    def test_three_days_includes_today_and_removes_old_day_everything(self):
        for day in ("2026-10-30", "2026-10-31", "2026-11-01", "2026-11-02", "2026-11-03", "2026-11-04"):
            self.day(day)
        removed = prune_account_days(self.account, date(2026, 11, 3), 3)
        self.assertEqual(removed, ["2026-10-30", "2026-10-31"])
        self.assertFalse((self.account / "2026-10-31").exists())
        self.assertTrue((self.account / "2026-11-01" / "segments" / "summary.json").is_file())
        self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 3), [])

    def test_seven_days_keeps_exact_boundary_and_other_accounts(self):
        self.day("2026-10-27")
        self.day("2026-10-28")
        self.day("2026-11-03")
        other = self.base / "account-b-210987654321" / "2026-10-01"
        other.mkdir(parents=True)
        (other / DAY_MARKER).touch()
        self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 7), ["2026-10-27"])
        self.assertTrue((self.account / "2026-10-28").is_dir())
        self.assertTrue(other.is_dir())

    def test_unmarked_invalid_and_nondaily_directories_are_never_deleted(self):
        names = ("cache", "reports", "legacy", "2026-01-01", "2026-02-30", "2026-1-01", "2026-01-01-backup")
        for name in names:
            self.day(name, marked=name != "2026-01-01")
        (self.account / "2026-01-02").write_text("not a directory")
        self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 3), [])
        self.assertTrue(all((self.account / name).exists() for name in names))

    def test_linked_day_cannot_delete_outside_account(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / DAY_MARKER).touch()
        (outside / "keep.txt").write_text("keep")
        try:
            (self.account / "2026-01-01").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("This host does not permit directory symlinks")
        self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 3), [])
        self.assertTrue((outside / "keep.txt").is_file())

    def test_nested_link_refuses_entire_day_without_following_it(self):
        target = self.day("2026-01-01")
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep")
        try:
            (target / "external").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("This host does not permit directory symlinks")
        self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 3), [])
        self.assertTrue((outside / "keep.txt").is_file())
        self.assertTrue(target.exists())

    def test_windows_reparse_marker_or_nested_tree_is_refused(self):
        target = self.day("2026-01-01")
        import rds_retention
        original = rds_retention._is_link
        for linked in (target, target / DAY_MARKER, target / "segments"):
            with self.subTest(linked=linked.name), patch("rds_retention._is_link", side_effect=lambda path: path == linked or original(path)):
                self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 3), [])
                self.assertTrue(target.is_dir())

    def test_root_and_retention_inputs_are_checked_before_delete(self):
        for retention in (0, -1, True, 3.5):
            with self.subTest(retention=retention), self.assertRaises(ValueError):
                prune_account_days(self.account, date(2026, 11, 3), retention)
        with self.assertRaises(ValueError):
            prune_account_days(self.account, datetime(2026, 11, 3), 3)
        self.assertEqual(prune_account_days(self.base / "missing", date(2026, 11, 3), 3), [])
        with patch("rds_retention._is_link", side_effect=lambda path: path == self.account):
            with self.assertRaises(ValueError):
                prune_account_days(self.account, date(2026, 11, 3), 3)

    def test_only_resolved_absolute_targets_inside_account_are_removed(self):
        target = self.day("2026-01-01")
        original = __import__("shutil").rmtree
        checked = []
        def remove(path):
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.is_relative_to(self.account.resolve()))
            self.assertEqual(path, target.resolve())
            checked.append(path)
            original(path)
        with patch("rds_retention.shutil.rmtree", side_effect=remove):
            self.assertEqual(prune_account_days(self.account, date(2026, 11, 3), 3), ["2026-01-01"])
        self.assertEqual(len(checked), 1)


if __name__ == "__main__":
    unittest.main()
