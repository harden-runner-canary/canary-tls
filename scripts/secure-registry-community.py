"""Exercise real downloads without extracting or executing package contents."""
import datetime as dt
import json
import re
import subprocess
import tempfile
import urllib.request

REGISTRY = 'https://community.registry.stepsecurity.io/javascript/'
# https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi
MALICIOUS = ('chalk', '5.6.1')


def recent_version(metadata, now):
    candidates = []
    for version, published in metadata['time'].items():
        if version not in metadata['versions'] or not re.fullmatch(r'[0-9A-Za-z.+-]+', version):
            continue
        timestamp = dt.datetime.fromisoformat(published.replace('Z', '+00:00'))
        # Leave an hour of margin before the 48-hour boundary.
        if dt.timedelta(0) <= now - timestamp < dt.timedelta(hours=47):
            candidates.append((timestamp, version))
    if not candidates:
        raise RuntimeError('No TypeScript release younger than 47 hours; cooldown fixture unavailable')
    return max(candidates)[1]


def download(name, version, reason=None):
    url = f'{REGISTRY}{name}/-/{name}-{version}.tgz'
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run(
            ['npm', 'pack', '--ignore-scripts', '--fetch-retries=0',
             '--fetch-timeout=30000', '--cache', directory + '/cache', url],
            cwd=directory, text=True, capture_output=True, timeout=90,
        )
        output = result.stdout + result.stderr
        if reason:
            if result.returncode == 0:
                raise RuntimeError(f'{name}@{version} unexpectedly downloaded')
            if '403' not in output or 'blocked by security policy with StepSecurity' not in output or reason not in output.lower():
                raise RuntimeError(f'{name}@{version} failed without the expected {reason} policy refusal: {output}')
        elif result.returncode:
            raise RuntimeError(f'Allowed control download failed: {output}')
        print(f'{name}@{version}: {reason or "allowed"}')


def main():
    registry = subprocess.check_output(['npm', 'config', 'get', 'registry'], text=True).strip()
    if registry != REGISTRY:
        raise RuntimeError(f'Expected community registry, got {registry}')
    # Only metadata is fetched from upstream. Archives always use Harden-Runner's
    # configured registry and npm-managed credentials; no public fallback.
    with urllib.request.urlopen('https://registry.npmjs.org/typescript', timeout=30) as response:
        metadata = json.load(response)
    version = recent_version(metadata, dt.datetime.now(dt.timezone.utc))
    print(f'Cooldown fixture: typescript@{version}, published {metadata["time"][version]}')
    download('is-number', '7.0.0')
    # Both requests are attempted even if one protection regresses.
    failures = []
    for name, selected, reason in [('typescript', version, 'cooldown'), (*MALICIOUS, 'compromised')]:
        try:
            download(name, selected, reason)
        except Exception as error:
            failures.append(str(error))
    if failures:
        raise RuntimeError('\n'.join(failures))


if __name__ == '__main__':
    main()
