"""Private multi-account settings validation without AWS or SMTP calls."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from rds_config import load_config, validate_mail_config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "private.json"
        self.base = {
            "ACCOUNTS": [
                {"NAME": "production", "ACCOUNT_ID": "123456789012"},
                {"NAME": "staging", "ACCOUNT_ID": "210987654321", "ENABLED": False},
            ]
        }

    def load(self, settings=None, **kwargs):
        self.path.write_text(json.dumps(self.base if settings is None else settings), encoding="utf-8")
        return load_config(self.path, **kwargs)

    def test_defaults_and_relative_paths_are_beside_config(self):
        self.base["PDF_FONT_PATH"] = "fonts/chinese.ttf"
        result = self.load()
        self.assertEqual(result["OUTPUT_DIRECTORY"], str((self.path.parent / "output").resolve()))
        self.assertEqual(result["PDF_FONT_PATH"], str((self.path.parent / "fonts/chinese.ttf").resolve()))
        self.assertEqual(result["COLLECTION_INTERVAL_MINUTES"], 30)
        self.assertEqual(result["RETENTION_DAYS"], 7)
        self.assertEqual(result["MAIL_REPORT_MODE"], "previous_day")
        self.assertEqual(result["SMTP_PORT"], 465)
        self.assertEqual(result["MAIL_SUBJECT"], "AW-RDS审计报告")
        self.assertEqual(result["ACCOUNTS"][0]["AWS_ACCESS_KEY_ID"], "")
        self.assertFalse(result["ACCOUNTS"][1]["ENABLED"])

    def test_example_is_valid_and_does_not_contain_live_credentials(self):
        example = Path(__file__).with_name("rds-audit-config.example.json")
        result = load_config(example)
        self.assertEqual(len(result["ACCOUNTS"]), 2)
        for account in result["ACCOUNTS"]:
            for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
                self.assertEqual(account[key], "")
        for field in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE"):
            self.assertEqual(result[field], "")

    def test_explicit_keys_profile_default_chain_and_regions(self):
        self.base["ACCOUNTS"][0].update(AWS_ACCESS_KEY_ID="KEY", AWS_SECRET_ACCESS_KEY="SECRET", AWS_SESSION_TOKEN="TOKEN", REGIONS=["ap-east-1", "us-east-1", "ap-east-1"])
        self.base["ACCOUNTS"][1]["AWS_PROFILE"] = "audit-staging"
        result = self.load()
        self.assertEqual(result["ACCOUNTS"][0]["REGIONS"], "ap-east-1,us-east-1")
        self.assertEqual(result["ACCOUNTS"][1]["AWS_PROFILE"], "audit-staging")
        self.assertEqual(result["ACCOUNTS"][1]["REGIONS"], "all")

    def test_account_validation_does_not_echo_secrets(self):
        cases = [
            {"AWS_ACCESS_KEY_ID": "DO-NOT-ECHO-KEY"},
            {"AWS_SESSION_TOKEN": "DO-NOT-ECHO-TOKEN"},
            {"AWS_ACCESS_KEY_ID": "DO-NOT-ECHO-KEY", "AWS_SECRET_ACCESS_KEY": "DO-NOT-ECHO-SECRET", "AWS_PROFILE": "other"},
            {"NAME": "../escape"}, {"ACCOUNT_ID": "1234"}, {"ENABLED": "true"},
            {"REGIONS": ["all", "us-east-1"]}, {"REGIONS": "us-east-1,"},
        ]
        for update in cases:
            with self.subTest(update=list(update)):
                settings = deepcopy(self.base)
                settings["ACCOUNTS"][0].update(update)
                with self.assertRaises(ValueError) as raised:
                    self.load(settings)
                self.assertNotIn("DO-NOT-ECHO", str(raised.exception))

    def test_duplicate_ids_or_names_are_refused_including_case_alias(self):
        for field, value in (("NAME", "PRODUCTION"), ("ACCOUNT_ID", "123456789012")):
            settings = deepcopy(self.base)
            settings["ACCOUNTS"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(settings)

    def test_setting_ranges_and_types(self):
        bad_values = {
            "COLLECTION_INTERVAL_MINUTES": [True, 30.0, 15, "30"],
            "RETENTION_DAYS": [0, 1, -3, True, 3.0],
            "MAX_BUCKETS_PER_ACCOUNT_PER_RUN": [0, True],
            "LOG_DELAY_MINUTES": [-1, 0.5],
            "REFRESH_DELAY_MINUTES": [-1],
            "SMTP_PORT": [0, 65536, True],
            "SMTP_TIMEOUT": [0, 601, float("nan"), float("inf"), True],
            "SMTP_SECURITY": ["plain"],
            "TIMEZONE": ["Definitely/Missing-Timezone"],
            "DAILY_MAIL_TIME": ["8:10", "24:00", "08:60"],
            "MAIL_REPORT_MODE": ["old-25-hours"],
            "MAIL_SUBJECT": ["report\r\nBcc: other@example.com"],
            "ACCOUNTS": [[], "bad"],
        }
        for field, values in bad_values.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    settings = {**self.base, field: value}
                    with self.assertRaises(ValueError):
                        self.load(settings)
        result = self.load({**self.base, "RETENTION_DAYS": 3, "COLLECTION_INTERVAL_MINUTES": 60})
        self.assertEqual(result["RETENTION_DAYS"], 3)

    def test_complete_mail_config_and_recipients(self):
        settings = {**self.base, "SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "audit@example.com",
                    "SMTP_AUTH_CODE": "PRIVATE-AUTH-CODE", "MAIL_RECIPIENTS": ["to@example.com", "to@example.com"],
                    "MAIL_CC": ["cc@example.com"], "SMTP_SECURITY": "starttls"}
        result = self.load(settings, require_mail=True)
        self.assertEqual(result["MAIL_RECIPIENTS"], ["to@example.com"])
        self.assertEqual(result["MAIL_CC"], ["cc@example.com"])
        for field in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE", "MAIL_RECIPIENTS"):
            invalid = {**settings, field: [] if field == "MAIL_RECIPIENTS" else ""}
            with self.subTest(field=field), self.assertRaises(ValueError) as raised:
                self.load(invalid, require_mail=True)
            self.assertNotIn("PRIVATE-AUTH-CODE", str(raised.exception))
        for address in ("Display Name <to@example.com>", "to@example.com\nBcc: bad@example.com", "missing", "a@", "audit@localhost"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate_mail_config({**settings, "MAIL_RECIPIENTS": [address]})

    def test_malformed_config_never_echoes_pasted_secret(self):
        for content in ('{"SECRET": "DO-NOT-ECHO",', '{"ACCOUNTS": [], "ACCOUNTS": [{"key":"DO-NOT-ECHO"}]}', '["DO-NOT-ECHO"]'):
            self.path.write_text(content, encoding="utf-8")
            with self.subTest(content=content[:10]), self.assertRaises(ValueError) as raised:
                load_config(self.path)
            self.assertNotIn("DO-NOT-ECHO", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
