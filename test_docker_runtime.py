"""Offline checks of the RDS container's two independent business workers."""
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from deploy import docker_runtime as runtime


class FakeChild:
    def __init__(self, code=None):
        self.pid = 123456789
        self.returncode = code

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = -15
        return self.returncode


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / 'output'
        self.config = self.root / 'private.json'
        self.raw = {'OUTPUT_DIRECTORY': 'output', 'AUTO_MAIL_MAX_PER_DAY': 0,
                    'ACCOUNTS': [{'NAME': 'offline', 'ACCOUNT_ID': '000000000001',
                                  'REGIONS': 'us-east-1'}]}
        self.config.write_text(json.dumps(self.raw), encoding='utf-8')

    def test_workers_overlap_but_the_same_mode_does_not(self):
        stop = threading.Event()
        children = [FakeChild() for _ in range(3)]
        popen = Mock(side_effect=children)
        ticks, now = 0, 0

        def wait(_seconds):
            nonlocal ticks, now
            ticks += 1
            if ticks == 1:
                # Both children still running: no overlap at the next due time.
                now = 300
            elif ticks == 2:
                children[1].returncode = 0
            else:
                stop.set()

        self.output.mkdir()
        receipt = self.output / '.daily-mail-budget.json'
        receipt.write_bytes(b'KEEP-EXISTING-DAILY-BUDGET')
        with patch.object(runtime, 'stop_children') as cleanup, redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.run_schedule(self.config, stop=stop, popen=popen,
                                                 monotonic=lambda: now, wait=wait), 0)
        self.assertEqual(popen.call_count, 3)
        self.assertIn('--collect', popen.call_args_list[0].args[0])
        self.assertIn('--scheduled', popen.call_args_list[1].args[0])
        self.assertIn('--scheduled', popen.call_args_list[2].args[0])
        cleanup.assert_called_once()
        self.assertEqual(receipt.read_bytes(), b'KEEP-EXISTING-DAILY-BUDGET')
        self.assertFalse((self.output / runtime.HEARTBEAT).exists())

    def test_healthy_heartbeat_updates_during_long_workers_and_stale_fails(self):
        stop = threading.Event()
        popen = Mock(side_effect=lambda *_args, **_kwargs: FakeChild())

        def wait(_seconds):
            path = self.output / runtime.HEARTBEAT
            self.assertEqual(runtime.healthcheck(self.config), 0)
            value = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(value['running'], ['collect', 'scheduled'])
            value['updated_at'] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
            path.write_text(json.dumps(value), encoding='utf-8')
            self.assertEqual(runtime.healthcheck(self.config), 1)
            stop.set()

        with patch.object(runtime, 'stop_children'):
            runtime.run_schedule(self.config, stop=stop, popen=popen, wait=wait)

    def test_output_move_is_rejected_and_children_are_cleaned_up(self):
        stop = threading.Event()
        popen = Mock(side_effect=lambda *_args, **_kwargs: FakeChild())

        def wait(_seconds):
            self.raw['OUTPUT_DIRECTORY'] = 'another-output'
            self.config.write_text(json.dumps(self.raw), encoding='utf-8')

        with patch.object(runtime, 'stop_children') as cleanup:
            with self.assertRaisesRegex(ValueError, 'OUTPUT_DIRECTORY'):
                runtime.run_schedule(self.config, stop=stop, popen=popen, wait=wait)
        cleanup.assert_called_once()
        self.assertFalse((self.output / runtime.HEARTBEAT).exists())

    def test_manual_commands_forward_business_options_without_new_mail_logic(self):
        command = runtime.business_command('report', self.config, day='2026-11-06', send_mail=True, force=True)
        self.assertEqual(command[-4:], ['--date', '2026-11-06', '--send-mail', '--force-resend'])
        self.assertEqual(Path(command[1]).name, 'rds_multi.py')

    @unittest.skipUnless(os.name == 'posix', 'Linux process-group shutdown')
    def test_shutdown_forwards_sigterm_then_kills_a_stuck_group(self):
        child = Mock(pid=321)
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('fake', 1), -9]
        with patch.object(runtime.os, 'killpg') as signaler:
            runtime.stop_children([child], grace=0)
        self.assertEqual([call.args[1] for call in signaler.call_args_list],
                         [runtime.signal.SIGTERM, runtime.signal.SIGKILL])


if __name__ == '__main__':
    unittest.main()
