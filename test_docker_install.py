"""Exercise the Linux installer with fake Docker and real private file mounts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

PROJECT = Path(__file__).resolve().parent
BASH = shutil.which('bash')


@unittest.skipUnless(os.name == 'posix' and BASH, 'Linux Bash installer')
class DockerInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='rds-installer-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / 'private-data'
        self.log = self.root / 'docker-calls.jsonl'
        self.fake_bin = self.root / 'bin'
        self.fake_bin.mkdir()
        stub = self.fake_bin / 'docker'
        stub.write_text('#!' + sys.executable + '\n' + textwrap.dedent('''\
            import json, os, pathlib, sys
            sys.path.insert(0, os.environ['RDS_TEST_SOURCE'])
            args = sys.argv[1:]
            with open(os.environ['RDS_TEST_LOG'], 'a') as handle:
                handle.write(json.dumps(args) + '\\n')
            if args[:2] == ['compose', 'version']:
                print('v2.29.0')
            elif args[:1] == ['run']:
                from deploy.docker_config import create_plan
                mount = args[args.index('--mount') + 1]
                source = next(item[4:] for item in mount.split(',') if item.startswith('src='))
                for key, value in create_plan(source, source,
                    container_config_path='/usr/local/aws-rds-shenji/rds-audit-config.json').items():
                    print(key + '\\t' + value)
            elif 'check-config' in args:
                from rds_multi import main
                raise SystemExit(main(['--config', os.environ['AUDIT_CONFIG_PATH'], '--check-config']))
            elif 'build' in args and os.environ.get('RDS_TEST_BUILD_FAIL'):
                raise SystemExit(1)
            '''), encoding='utf-8')
        stub.chmod(0o700)
        self.env = {**os.environ, 'PATH': str(self.fake_bin) + os.pathsep + os.environ['PATH'],
                    'RDS_TEST_SOURCE': str(PROJECT), 'RDS_TEST_LOG': str(self.log),
                    'AWS_EC2_METADATA_DISABLED': 'true'}

    def run_installer(self, *extra):
        return subprocess.run([BASH, str(PROJECT / 'install-docker.sh'), '--data-dir', str(self.data), *extra],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def existing_config(self):
        self.data.mkdir()
        path = self.data / 'rds-audit-config.json'
        path.write_text('// Preserve original bytes\n' + json.dumps({
            'OUTPUT_DIRECTORY': 'existing-output', 'AUTO_MAIL_MAX_PER_DAY': 0,
            'ACCOUNTS': [{'NAME': 'offline', 'ACCOUNT_ID': '000000000001', 'REGIONS': 'us-east-1'}]}))
        path.chmod(0o600)
        output = self.data / 'existing-output'
        output.mkdir(mode=0o700)
        (output / '.daily-mail-budget.json').write_bytes(b'PERSISTENT-RECEIPT')
        return path, output

    def test_first_setup_creates_complete_private_template_without_docker(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 2, result.stderr)
        private = self.data / 'rds-audit-config.json'
        self.assertEqual(private.read_bytes(), (PROJECT / 'rds-audit-config.example.json').read_bytes())
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.calls(), [])

    def test_dry_run_performs_no_writes_or_docker_calls(self):
        result = self.run_installer('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.calls(), [])

    def test_no_start_preserves_config_and_receipts_and_exports_only_mount_settings(self):
        private, output = self.existing_config()
        before = private.read_bytes()
        result = self.run_installer('--no-start')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(private.read_bytes(), before)
        self.assertEqual((output / '.daily-mail-budget.json').read_bytes(), b'PERSISTENT-RECEIPT')
        deployment = (self.data / 'docker.env').read_text()
        self.assertIn(str(output), deployment)
        self.assertNotIn('000000000001', deployment)
        self.assertNotIn('SMTP_AUTH_CODE', deployment)
        self.assertEqual((self.data / 'docker.env').stat().st_mode & 0o777, 0o600)
        self.assertFalse(any('up' in call for call in self.calls()))
        self.assertTrue(any('check-config' in call for call in self.calls()))

    def test_build_failure_never_recreates_service_or_modifies_receipts(self):
        private, output = self.existing_config()
        self.env['RDS_TEST_BUILD_FAIL'] = '1'
        result = self.run_installer()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(any('up' in call for call in self.calls()))
        self.assertFalse((self.data / 'docker.env').exists())
        self.assertEqual((output / '.daily-mail-budget.json').read_bytes(), b'PERSISTENT-RECEIPT')


if __name__ == '__main__':
    unittest.main()
