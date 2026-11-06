"""Private multi-account settings validation without AWS or SMTP calls."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from rds_config import DEFAULTS, load_config, strip_json_comments, validate_mail_config


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
        self.assertEqual(result["ACCOUNT_CONCURRENCY"], 7)
        self.assertEqual(result["AUTO_MAIL_MAX_PER_DAY"], 1)
        self.assertEqual(result["RETENTION_DAYS"], 7)
        self.assertEqual(result["MAIL_REPORT_MODE"], "previous_day")
        self.assertEqual(result["SMTP_PORT"], 465)
        self.assertEqual(result["MAIL_SUBJECT"], "AW-RDS审计报告")
        self.assertEqual(result["ACCOUNTS"][0]["AWS_ACCESS_KEY_ID"], "")
        self.assertFalse(result["ACCOUNTS"][1]["ENABLED"])
        self.assertFalse(result["LARK_ALERTS_ENABLED"])
        self.assertEqual(result["LARK_ALERT_AFTER_FAILURES"], 2)
        self.assertEqual(result["LARK_ALERT_REPEAT_MINUTES"], 60)
        self.assertEqual(result["LARK_NOTIFICATION_RETRY_MINUTES"], 5)

    def test_example_is_valid_and_does_not_contain_live_credentials(self):
        example = Path(__file__).with_name("rds-audit-config.example.json")
        result = load_config(example)
        self.assertEqual(len(result["ACCOUNTS"]), 7)
        self.assertEqual([account["ACCOUNT_ID"] for account in result["ACCOUNTS"]],
                         [f"{number:012d}" for number in range(1, 8)])
        self.assertEqual(result["ACCOUNT_CONCURRENCY"], 7)
        self.assertEqual(result["AUTO_MAIL_MAX_PER_DAY"], 1)
        documented = json.loads(strip_json_comments(example.read_text(encoding="utf-8")))
        self.assertEqual(set(documented), set(DEFAULTS) | {"ACCOUNTS"})
        self.assertIn("//", example.read_text(encoding="utf-8"))
        for account in result["ACCOUNTS"]:
            for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
                self.assertEqual(account[key], "")
        for field in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_AUTH_CODE"):
            self.assertEqual(result[field], "")
        self.assertFalse(result["LARK_ALERTS_ENABLED"])
        self.assertEqual(result["LARK_WEBHOOK_URL"], "")
        self.assertEqual(result["LARK_SIGNING_SECRET"], "")

    def test_explicit_keys_profile_default_chain_and_regions(self):
        self.base["ACCOUNTS"][0].update(AWS_ACCESS_KEY_ID="KEY", AWS_SECRET_ACCESS_KEY="SECRET", AWS_SESSION_TOKEN="TOKEN", REGIONS=["ap-east-1", "us-east-1", "ap-east-1"])
        self.base["ACCOUNTS"][1]["AWS_PROFILE"] = "audit-staging"
        result = self.load()
        self.assertEqual(result["ACCOUNTS"][0]["REGIONS"], "ap-east-1,us-east-1")
        self.assertEqual(result["ACCOUNTS"][1]["AWS_PROFILE"], "audit-staging")
        self.assertEqual(result["ACCOUNTS"][1]["REGIONS"], "all")

    def test_chinese_account_tags_are_optional_trimmed_and_do_not_change_directory_names(self):
        self.base["ACCOUNTS"][0]["TAG"] = "  测试账号  "
        result = self.load()
        self.assertEqual(result["ACCOUNTS"][0]["TAG"], "测试账号")
        self.assertEqual(result["ACCOUNTS"][0]["NAME"], "production")
        self.assertEqual(result["ACCOUNTS"][1]["TAG"], "")
        self.base["ACCOUNTS"][0]["TAG"] = "中" * 120
        self.assertEqual(self.load()["ACCOUNTS"][0]["TAG"], "中" * 120)

    def test_invalid_tags_are_refused_without_echoing_values(self):
        for value in (None, 42, ["private"], "PRIVATE" * 21, "PRIVATE\nTAG", "PRIVATE\x7f",
                      "PRIVATE\u202eTAG", "PRIVATE\u2028TAG", "PRIVATE\u2029TAG", "PRIVATE\ud800TAG"):
            with self.subTest(value=repr(value)):
                self.base["ACCOUNTS"][0]["TAG"] = value
                with self.assertRaisesRegex(ValueError, "TAG") as raised:
                    self.load()
                self.assertNotIn("PRIVATE", str(raised.exception))

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
            "ACCOUNT_CONCURRENCY": [0, 33, -1, True, 7.0, "7"],
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

    def test_concurrency_limits_do_not_limit_the_number_of_configured_accounts(self):
        settings = {"ACCOUNTS": [{"NAME": "account-" + str(number), "ACCOUNT_ID": f"{number:012d}"}
                                  for number in range(1, 11)]}
        for concurrency in (1, 7, 32):
            result = self.load({**settings, "ACCOUNT_CONCURRENCY": concurrency})
            self.assertEqual(len(result["ACCOUNTS"]), 10)
            self.assertEqual(result["ACCOUNT_CONCURRENCY"], concurrency)

    def test_auto_mail_daily_limit_defaults_to_one_and_accepts_only_zero_or_one_integers(self):
        # Existing private JSON files need no edit to get the one-mail default.
        self.assertEqual(self.load()["AUTO_MAIL_MAX_PER_DAY"], 1)
        for value in (0, 1):
            with self.subTest(value=value):
                self.assertEqual(self.load({**self.base, "AUTO_MAIL_MAX_PER_DAY": value})["AUTO_MAIL_MAX_PER_DAY"], value)
        for value in (False, True, -1, 2, 0.0, 1.0, "1", None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "AUTO_MAIL_MAX_PER_DAY"):
                self.load({**self.base, "AUTO_MAIL_MAX_PER_DAY": value})

    def test_comments_preserve_urls_literals_escaped_quotes_and_backslashes(self):
        expected = {
            "url": "https://host.example/path//literal?text=/*unchanged*/",
            "block": "literal /* not a comment */ and // not a comment",
            "quote": 'a "quoted // string" and \\"another /* string */"',
            "slashes": "a\\\\b\\\\",
            "controls": "one\r\ntwo\tthree",
            "中文": "配置字符串",
        }
        encoded = json.dumps(expected, ensure_ascii=False, indent=2)
        source = ("// 中文开头注释\r\n/* 多行注释\r\n保留行数\n*/\n"
                  + encoded.replace('{\n', '{ /* 对象开始 */\n', 1)
                  .replace('\n  "block"', '\n // 字段之间的注释\n  "block"')
                  + " // 文件末尾无换行注释")
        stripped = strip_json_comments(source)
        self.assertEqual(json.loads(stripped), expected)
        self.assertEqual(len(stripped), len(source))
        self.assertEqual([position for position, char in enumerate(stripped) if char in "\r\n"],
                         [position for position, char in enumerate(source) if char in "\r\n"])
        self.assertNotIn("多行注释", stripped)

    def test_jsonc_loads_without_changing_a_secret_containing_comment_markers(self):
        settings = {**self.base, "SMTP_AUTH_CODE": 'private://value/*keep*/with\\slash"quote'}
        encoded = json.dumps(settings, ensure_ascii=False, indent=2)
        content = "// 本机配置\n" + encoded.replace('"ACCOUNTS":', '"ACCOUNTS": /* 账号列表 */', 1) + "\n// end"
        self.path.write_text(content, encoding="utf-8-sig")
        result = load_config(self.path)
        self.assertEqual(result["SMTP_AUTH_CODE"], settings["SMTP_AUTH_CODE"])
        self.assertEqual(len(result["ACCOUNTS"]), 2)

    def test_jsonc_bad_syntax_duplicate_fields_and_unclosed_comments_are_refused(self):
        invalid = [
            '/* DO-NOT-ECHO unclosed comment',
            '{"ACCOUNTS": [], /* DO-NOT-ECHO */}',
            '{"ACCOUNTS": 1/* DO-NOT-ECHO */2}',
            '{"ACCOUNTS": [// DO-NOT-ECHO\n}',
            '{"SECRET": "DO-NOT-ECHO',
            '{"ACCOUNTS": [], /* separator */ "ACCOUNTS": []}',
            '{"ACCOUNTS": [{"NAME":"a", /* separator */ "NAME":"b"}]}',
            '{"ACCOUNTS": NaN}',
            '// DO-NOT-ECHO only comment',
        ]
        for content in invalid:
            self.path.write_text(content, encoding="utf-8")
            with self.subTest(content=content[:15]), self.assertRaisesRegex(ValueError, "JSON/JSONC") as raised:
                load_config(self.path)
            self.assertNotIn("DO-NOT-ECHO", str(raised.exception))
        with self.assertRaises(ValueError):
            strip_json_comments(None)
        with self.assertRaises(ValueError):
            strip_json_comments('"unterminated \\" still string')

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

    def test_enabled_lark_can_wait_for_configuration_during_collection(self):
        result = self.load({**self.base, "LARK_ALERTS_ENABLED": True})
        self.assertTrue(result["LARK_ALERTS_ENABLED"])
        self.assertEqual(result["LARK_WEBHOOK_URL"], "")
        self.assertEqual(result["SMTP_HOST"], "")
        with self.assertRaisesRegex(ValueError, "LARK_WEBHOOK_URL"):
            self.load({**self.base, "LARK_ALERTS_ENABLED": True}, require_mail=True)

    def test_disabled_lark_and_old_json_work_in_strict_mail_mode(self):
        settings = {**self.base, "SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "audit@example.com",
                    "SMTP_AUTH_CODE": "PRIVATE-AUTH-CODE", "MAIL_RECIPIENTS": ["to@example.com"]}
        old = self.load(settings, require_mail=True)
        self.assertFalse(old["LARK_ALERTS_ENABLED"])
        explicit_disabled = self.load({**settings, "LARK_ALERTS_ENABLED": False}, require_mail=True)
        self.assertEqual(explicit_disabled["LARK_WEBHOOK_URL"], "")
        settings.update(LARK_ALERTS_ENABLED=True,
                        LARK_WEBHOOK_URL="https://open.larksuite.com/open-apis/bot/v2/hook/unit-test-token",
                        LARK_SIGNING_SECRET="PRIVATE-LARK-SIGNING-SECRET")
        self.assertTrue(self.load(settings, require_mail=True)["LARK_ALERTS_ENABLED"])

    def test_lark_field_types_thresholds_and_positive_intervals(self):
        invalid = {
            "LARK_ALERTS_ENABLED": ["true", 1, None],
            "LARK_WEBHOOK_URL": [False, ["https://DO-NOT-ECHO"]],
            "LARK_SIGNING_SECRET": [True, "DO-NOT-ECHO\nsecret"],
            "LARK_ALERT_AFTER_FAILURES": [0, 1, True, 2.0, "2"],
            "LARK_ALERT_REPEAT_MINUTES": [0, -1, True, 1.5],
            "LARK_NOTIFICATION_RETRY_MINUTES": [0, -5, True, "5"],
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError) as raised:
                    self.load({**self.base, field: value})
                self.assertNotIn("DO-NOT-ECHO", str(raised.exception))
        result = self.load({**self.base, "LARK_ALERT_AFTER_FAILURES": 3,
                            "LARK_ALERT_REPEAT_MINUTES": 10, "LARK_NOTIFICATION_RETRY_MINUTES": 1})
        self.assertEqual(result["LARK_ALERT_AFTER_FAILURES"], 3)

    def test_lark_webhook_allowlist_applies_even_when_alerts_are_disabled(self):
        for domain in ("open.larksuite.com", "open.feishu.cn"):
            url = "https://" + domain + "/open-apis/bot/v2/hook/unit-test-token"
            self.assertEqual(self.load({**self.base, "LARK_WEBHOOK_URL": url})["LARK_WEBHOOK_URL"], url)
        invalid = [
            "http://open.larksuite.com/open-apis/bot/v2/hook/DO-NOT-ECHO",
            "https://open.larksuite.com.attacker.example/open-apis/bot/v2/hook/DO-NOT-ECHO",
            "https://attacker.example/open-apis/bot/v2/hook/DO-NOT-ECHO",
            "https://user:PRIVATE-LARK-SIGNING-SECRET@open.larksuite.com/open-apis/bot/v2/hook/DO-NOT-ECHO",
            "https://open.feishu.cn:8443/open-apis/bot/v2/hook/DO-NOT-ECHO",
            "https://open.feishu.cn/open-apis/bot/v2/hook/DO-NOT-ECHO?secret=PRIVATE-LARK-SIGNING-SECRET",
            "https://open.feishu.cn/open-apis/bot/v2/hook/REPLACE_WITH_YOUR_TOKEN",
        ]
        for url in invalid:
            with self.subTest(domain=url.split("/")[2]), self.assertRaises(ValueError) as raised:
                self.load({**self.base, "LARK_ALERTS_ENABLED": False, "LARK_WEBHOOK_URL": url,
                           "LARK_SIGNING_SECRET": "PRIVATE-LARK-SIGNING-SECRET"})
            self.assertNotIn("DO-NOT-ECHO", str(raised.exception))
            self.assertNotIn("PRIVATE-LARK-SIGNING-SECRET", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
