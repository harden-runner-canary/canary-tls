import datetime as dt
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('secure-registry-community.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class TestFixture(unittest.TestCase):
    def test_actual_publish_time_and_boundary(self):
        now = dt.datetime(2026, 11, 15, tzinfo=dt.timezone.utc)
        metadata = {'versions': {'fresh': {}, 'old': {}, 'future': {}}, 'time': {
            'fresh': (now-dt.timedelta(hours=10)).isoformat(),
            'old': (now-dt.timedelta(hours=47)).isoformat(),
            'future': (now+dt.timedelta(hours=1)).isoformat()}}
        self.assertEqual(fixture.recent_version(metadata, now), 'fresh')
        del metadata['versions']['fresh']
        with self.assertRaisesRegex(RuntimeError, 'fixture unavailable'):
            fixture.recent_version(metadata, now)

    @patch.object(fixture.subprocess, 'run')
    def test_only_specific_policy_refusal_passes(self, run):
        for status, message, passes in [
            (1, '403 blocked by security policy with StepSecurity: known compromised package', True),
            (1, '404 not found', False),
            (1, '403 unauthorized', False),
            (1, 'network timeout', False),
            (0, 'chalk-5.6.1.tgz', False),
        ]:
            with self.subTest(message=message):
                run.return_value = subprocess.CompletedProcess([], status, '', message)
                if passes:
                    fixture.download('chalk', '5.6.1', 'compromised')
                else:
                    with self.assertRaises(RuntimeError): fixture.download('chalk', '5.6.1', 'compromised')
                self.assertIn('--ignore-scripts', run.call_args.args[0])
                self.assertIn('https://community.registry.stepsecurity.io/javascript/chalk/-/chalk-5.6.1.tgz', run.call_args.args[0])

if __name__ == '__main__': unittest.main()
