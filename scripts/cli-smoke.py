#!/usr/bin/env python3
"""Test the shipped CLI inside the Docker demo; secrets enter through stdin."""
import json
import secrets
import subprocess

key = 'cli:' + secrets.token_hex(6)
values = [secrets.token_urlsafe(48), secrets.token_urlsafe(48)]
def run(operation, *args, data=''):
    result = subprocess.run(['docker', 'compose', '-f', 'compose.demo.yaml', 'exec', '-T', 'console', '/knox-management', '-config', '/config/config.json', operation, *args], input=data, text=True, capture_output=True)
    if result.returncode:
        raise SystemExit('CLI operation failed: ' + operation)
    if any(value in result.stdout or value in result.stderr for value in values):
        raise SystemExit('CLI disclosed a credential')
    return json.loads(result.stdout)

run('create', key, data=values[0])
assert key in run('list')
new_id = run('add-version', key, data=values[1])['version_id']
assert isinstance(new_id, str)
run('set-status', key, new_id, 'Primary')
run('set-acl', key, data=json.dumps([{'type':'User','id':'cli-reader','access':'Read'}]))
metadata = run('inspect', key)
assert all('data' not in version for version in metadata['versions'])
assert any(version['id'] == new_id and version['status'] == 'Primary' for version in metadata['versions'])
assert any(rule['id'] == 'cli-reader' and rule['access'] == 'Read' for rule in metadata['acl'])
print('PASS: packaged CLI create, list, add-version, promote, set-acl, and redacted inspect')
