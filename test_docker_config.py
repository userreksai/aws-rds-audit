"""Verify Docker mount plans without AWS, SMTP, secrets or Docker itself."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from deploy import docker_config as config


class MountPlanTests(unittest.TestCase):
    def setUp(self):
        self.raw = {'OUTPUT_DIRECTORY': 'output', 'SMTP_AUTH_CODE': 'PRIVATE-MUST-NOT-LEAK'}
        self.validated = {'ACCOUNTS': [{'ENABLED': True, 'AWS_PROFILE': ''}]}

    def plan(self, raw=None, accounts=None):
        validated = self.validated if accounts is None else {'ACCOUNTS': accounts}
        return config.build_plan(self.raw if raw is None else raw, validated,
            host_config_path='/srv/rds/private.json',
            container_config_path='/usr/local/aws-rds-shenji/rds-audit-config.json')

    def test_relative_output_and_font_preserve_private_config_and_all_state(self):
        self.raw['PDF_FONT_PATH'] = 'fonts/font.ttc'
        original = deepcopy(self.raw)
        plan = self.plan()
        self.assertEqual(plan['AUDIT_OUTPUT_DIR'], '/srv/rds/output')
        self.assertEqual(plan['AUDIT_CONTAINER_OUTPUT_DIR'], '/usr/local/aws-rds-shenji/output')
        self.assertEqual(plan['AUDIT_FONT_SOURCE'], '/srv/rds/fonts/font.ttc')
        self.assertEqual(self.raw, original)
        self.assertNotIn('PRIVATE-MUST-NOT-LEAK', json.dumps(plan))
        self.assertNotIn('AUDIT_STATE_DIR', plan)

    def test_absolute_output_is_reused_and_profiles_only_required_for_enabled_accounts(self):
        self.assertEqual(self.plan({'OUTPUT_DIRECTORY': '/srv/existing/output'})['AUDIT_CONTAINER_OUTPUT_DIR'],
                         '/srv/existing/output')
        self.assertEqual(self.plan(accounts=[{'ENABLED': True, 'AWS_PROFILE': 'audit'}])['AUDIT_REQUIRES_PROFILE'], '1')
        self.assertEqual(self.plan(accounts=[{'ENABLED': False, 'AWS_PROFILE': 'audit'}])['AUDIT_REQUIRES_PROFILE'], '0')

    def test_rejects_sensitive_or_overlapping_paths(self):
        for path in ('/', '/app/reports', '/etc/audit', '/root/.aws', '..', '/srv/rds', '/srv/rds/private.json',
                     '/srv/output,private', '/srv/output\nprivate'):
            with self.subTest(path=path), self.assertRaises(config.DockerConfigError):
                self.plan({'OUTPUT_DIRECTORY': path})
        with self.assertRaises(config.DockerConfigError):
            self.plan({'OUTPUT_DIRECTORY': 'output', 'PDF_FONT_PATH': 'output/font.ttf'})

    def test_jsonc_file_validation_is_read_only_and_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            raw = {'OUTPUT_DIRECTORY': 'output', 'AUTO_MAIL_MAX_PER_DAY': 0,
                   'ACCOUNTS': [{'NAME': 'offline', 'ACCOUNT_ID': '000000000001', 'REGIONS': 'us-east-1'}]}
            content = '// Existing private JSONC\n' + json.dumps(raw)
            path.write_text(content, encoding='utf-8')
            path.chmod(0o600)
            plan = config.create_plan(path, '/srv/rds/private.json',
                container_config_path='/usr/local/aws-rds-shenji/rds-audit-config.json')
            self.assertEqual(path.read_text(encoding='utf-8'), content)
            self.assertEqual(plan['AUDIT_OUTPUT_DIR'], '/srv/rds/output')


if __name__ == '__main__':
    unittest.main()
