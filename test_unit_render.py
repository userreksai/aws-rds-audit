"""Regression checks run the installer renderer, not hand-replaced templates."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from deploy.render_units import render_units, write_units, working_directory


class RenderingTests(unittest.TestCase):
    def test_reported_server_path_is_scalar_but_exec_arguments_stay_quoted(self):
        service, timer = render_units("/usr/local/aws-rds-shenji", "root", "root", "/root")
        self.assertIn("\nWorkingDirectory=/usr/local/aws-rds-shenji\n", service)
        self.assertNotIn('WorkingDirectory="', service)
        self.assertIn('ExecStart="/usr/local/aws-rds-shenji/.venv/bin/python" "/usr/local/aws-rds-shenji/deploy/run_daily.py"', service)
        self.assertIn('Environment="HOME=/root"', service)
        self.assertIn("08:10:00 Asia/Shanghai", timer)

    def test_spaces_percent_and_unicode_follow_each_directive_syntax(self):
        service, timer = render_units('/opt/审计 report %n', "audit", "audit", "/home/audit user", minute="05")
        self.assertIn('WorkingDirectory=/opt/审计 report %%n\n', service)
        self.assertIn('ExecStart="/opt/审计 report %%n/.venv/bin/python"', service)
        self.assertIn('Environment="HOME=/home/audit user"', service)
        self.assertIn("08:05:00 Asia/Shanghai", timer)

    def test_unsupported_paths_are_rejected_instead_of_generating_bad_units(self):
        for value in ("relative/path", "/opt/a\n[Service]", "/opt/end\\", "/opt/end ", "/opt/../tmp", "/opt/${MISSING}", '/opt/"quoted"', "/opt/'quoted'", "/opt/glob*", "/opt/question?", "/opt/bracket["):
            with self.subTest(value=value), self.assertRaises(ValueError):
                working_directory(value)

    def test_installer_calls_the_shared_renderer(self):
        script = (Path(__file__).parent / "install.sh").read_text(encoding="utf-8")
        self.assertIn("from render_units import write_units", script)
        self.assertIn("write_units(Path('/etc/systemd/system'), root", script)
        self.assertNotIn("'@PROJECT_ROOT@': quote(root)", script)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("systemd-analyze"), "requires Linux systemd-analyze")
class SystemdIntegrationTests(unittest.TestCase):
    def test_installer_generated_units_work_with_real_filesystem_paths(self):
        import grp
        import pwd
        username = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("aws-rds-shenji", 'RDS 审计 space %n'):
                with self.subTest(name=name):
                    root = Path(temporary) / name
                    (root / ".venv/bin").mkdir(parents=True)
                    (root / "deploy").mkdir()
                    (root / ".venv/bin/python").symlink_to(Path(sys.executable))
                    (root / "deploy/run_daily.py").write_text("# No AWS or Lark requests in unit validation\n", encoding="utf-8")
                    units = root / "units"
                    units.mkdir()
                    write_units(units, str(root), username, group, str(Path.home()))
                    command = ["systemd-analyze", "verify", str(units / "aws-rds-audit.service"), str(units / "aws-rds-audit.timer")]
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    # Demonstrate that the formerly generated outer quotes are rejected.
                    service_path = units / "aws-rds-audit.service"
                    service = service_path.read_text(encoding="utf-8")
                    scalar = working_directory(str(root))
                    service_path.write_text(service.replace("WorkingDirectory=" + scalar, 'WorkingDirectory="' + scalar + '"'), encoding="utf-8")
                    broken = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(broken.returncode, 0, "Regression setup must reproduce the original invalid unit")


if __name__ == "__main__":
    unittest.main()
