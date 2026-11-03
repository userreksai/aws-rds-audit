"""Validate mail-mode unit escaping, timer migration and preflight boundaries."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from deploy.render_mail_units import UNIT_NAMES, quote_word, render_units, write_units

ROOT = Path(__file__).resolve().parent


class MailUnitTests(unittest.TestCase):
    def test_collect_and_mail_read_same_private_config_without_environment_secrets(self):
        units = render_units("/usr/local/aws-rds-shenji", "root", "root", "/root", "/etc/rds-audit/config.json")
        self.assertEqual(set(units), set(UNIT_NAMES))
        for name, content in units.items():
            if name.endswith(".service"):
                self.assertIn('ExecStart="/usr/bin/env" "--" "/usr/local/aws-rds-shenji/.venv/bin/python"', content)
                self.assertIn('"/usr/local/aws-rds-shenji/rds_multi.py" "--config" "/etc/rds-audit/config.json"', content)
                self.assertIn("\nWorkingDirectory=/\n", content)
                self.assertIn("\nUMask=0077\n", content)
                self.assertIn('Environment="HOME=/root"', content)
                self.assertNotIn("EnvironmentFile", content)
                self.assertNotIn("OnFailure", content)
                self.assertNotIn("lark", content.lower())
            else:
                self.assertIn("OnCalendar=*-*-* *:00/5:00 UTC", content)
                self.assertIn("Persistent=true", content)
                self.assertNotIn("08:10", content)
        self.assertIn('"--collect"', units["aws-rds-audit-collect.service"])
        self.assertIn('"--scheduled"', units["aws-rds-audit.service"])
        self.assertNotIn('"--send-mail"', units["aws-rds-audit.service"])

    def test_spaces_quotes_specifiers_and_dollars_are_literal_arguments(self):
        config = '/etc/RDS 审计/config "quoted" %n ${TOKEN}.json'
        units = render_units('/opt/RDS "审计" %n', "audit", "audit", '/home/audit "name" %n', config)
        service = units["aws-rds-audit.service"]
        self.assertIn('ExecStart="/usr/bin/env" "--" "/opt/RDS \\"审计\\" %%n/.venv/bin/python"', service)
        self.assertIn('"/opt/RDS \\"审计\\" %%n/.venv/bin/python"', service)
        self.assertIn('"/etc/RDS 审计/config \\"quoted\\" %%n $${TOKEN}.json"', service)
        self.assertIn('Environment="HOME=/home/audit \\"name\\" %%n"', service)
        self.assertNotIn("WorkingDirectory=/opt", service)
        self.assertNotIn('ExecStart="/opt/', service)
        self.assertNotIn('/bin/sh', service)
        self.assertNotIn('/bin/bash', service)
        self.assertEqual(quote_word(r'/etc/a\b "c" %n $x', executable_argument=True),
                         '"/etc/a\\\\b \\"c\\" %%n $$x"')

    def test_invalid_control_characters_and_relative_paths_cannot_inject_units(self):
        for root, config in (("relative", "/etc/config"), ("/opt/rds", "relative/config"),
                             ("/opt/rds\n[Unit]", "/etc/config"), ("/opt/rds", "/etc/config\nExecStart=bad"),
                             ("/opt/../rds", "/etc/config"), ("/opt/rds", "/etc/../config")):
            with self.subTest(root=root, config=config), self.assertRaises(ValueError):
                render_units(root, "root", "root", "/root", config)
        with self.assertRaises(ValueError):
            render_units("/opt/rds", "root\n[Unit]", "root", "/root", "/etc/config")

    def test_atomic_writer_replaces_four_units_and_does_not_leave_temp_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            expected = write_units(destination, "/opt/rds", "root", "root", "/root", "/etc/first.json")
            self.assertEqual(set(path.name for path in destination.iterdir()), set(UNIT_NAMES))
            for name, content in expected.items():
                self.assertEqual((destination / name).read_text(encoding="utf-8"), content)
            write_units(destination, "/opt/rds", "root", "root", "/root", "/etc/second.json")
            self.assertNotIn("first.json", (destination / "aws-rds-audit.service").read_text(encoding="utf-8"))
            self.assertEqual(set(path.name for path in destination.iterdir()), set(UNIT_NAMES))


class MailInstallerContractTests(unittest.TestCase):
    def test_dispatch_preserves_legacy_without_json_and_selects_explicit_config(self):
        script = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("--config|--config=*", script)
        self.assertIn('[[ -f "$MAIL_INSTALL_ROOT/rds-audit-config.json" ]]', script)
        self.assertIn('exec bash "$MAIL_INSTALL_ROOT/install-mail.sh" "$@"', script)
        self.assertLess(script.index('exec bash "$MAIL_INSTALL_ROOT/install-mail.sh"'), script.index("usage()"))

    def test_prechecks_complete_before_migration_and_never_generate_or_send_report(self):
        script = (ROOT / "install-mail.sh").read_text(encoding="utf-8")
        migration = script.index('systemctl disable --now "$name"')
        self.assertLess(script.index('"$CONFIG_PATH" --check-config'), migration)
        self.assertLess(script.index('"$CONFIG_PATH" --verify-accounts'), migration)
        self.assertLess(script.index("systemd-analyze verify"), migration)
        self.assertLess(migration, script.index('mv -f -- "/etc/systemd/system/.$name.mail-new"'))
        self.assertIn('systemctl stop "$name"', script)
        self.assertNotIn("--send-mail", script)
        self.assertNotIn("--report", script)
        self.assertNotIn("systemctl start aws-rds-audit.service", script)
        self.assertNotIn("systemctl start aws-rds-audit-collect.service", script)
        self.assertNotIn("nginx", script.lower().replace("不修改 nginx", ""))
        self.assertNotIn("lark-config", script)

    def test_config_is_preserved_and_persistent_catchup_is_reset_before_enable(self):
        script = (ROOT / "install-mail.sh").read_text(encoding="utf-8")
        self.assertIn('chmod 0600 "$CONFIG_PATH"', script)
        self.assertIn('install -d -m 0700 -o "$RUN_USER" -g "$RUN_GROUP" -- "$OUTPUT_DIR"', script)
        self.assertIn('"$CONFIG_PATH" --check-config', script)
        self.assertNotIn('> "$CONFIG_PATH"', script)
        self.assertNotIn('cp "$PROJECT_ROOT/rds-audit-config.example.json"', script)
        self.assertLess(script.index("touch /var/lib/systemd/timers/stamp-aws-rds-audit.timer"),
                        script.index("systemctl enable --now aws-rds-audit-collect.timer"))
        self.assertIn("if ((NO_ENABLE == 0)); then", script)
        self.assertIn("if ((CHECK_ONLY)); then", script)
        self.assertIn("trap cleanup EXIT", script)
        self.assertNotIn("rm -rf", script)

    @unittest.skipUnless(shutil.which("bash"), "bash syntax check requires Bash")
    def test_bash_syntax(self):
        for name in ("install.sh", "install-mail.sh"):
            result = subprocess.run([shutil.which("bash"), "-n", str(ROOT / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("systemd-analyze"), "requires Linux systemd-analyze")
class MailSystemdIntegrationTests(unittest.TestCase):
    def test_generated_units_validate_for_real_paths_including_quotes(self):
        import grp
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("normal", 'RDS 审计 "quotes" %n'):
                with self.subTest(name=name):
                    root = Path(temporary) / name
                    (root / ".venv/bin").mkdir(parents=True)
                    (root / ".venv/bin/python").symlink_to(Path(sys.executable))
                    (root / "rds_multi.py").write_text("# validation only\n", encoding="utf-8")
                    units = root / "units"
                    units.mkdir()
                    write_units(units, str(root), user, group, str(Path.home()), str(root / 'config "quoted" %n ${LITERAL}.json'))
                    result = subprocess.run(["systemd-analyze", "verify", *[str(units / unit) for unit in UNIT_NAMES]], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
