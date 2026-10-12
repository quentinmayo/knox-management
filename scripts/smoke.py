#!/usr/bin/env python3
"""Test the Docker companion against its real-Knox demo backend."""
import json
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request

env = dict(line.split('=', 1) for line in (Path(__file__).resolve().parents[1] / '.env').read_text().splitlines() if '=' in line)
base = 'http://127.0.0.1:19100'
values = [secrets.token_urlsafe(48), secrets.token_urlsafe(48)]
key = 'smoke:' + secrets.token_hex(6)
def command(payload, token=None, expected=200):
    req = urllib.request.Request(base + '/api/command', data=json.dumps(payload).encode(), headers={'Content-Type':'application/json','Authorization':'Bearer ' + (token if token is not None else env['KNOX_MANAGEMENT_TOKEN'])})
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read()
    if response.status != expected:
        raise RuntimeError(f'Command {payload["operation"]} returned {response.status}; expected {expected}')
    if any(value.encode() in body for value in values + list(env.values())):
        raise SystemExit('Credential leaked in response')
    return json.loads(body)

for attempt in range(60):
    try:
        command({'operation':'list'})
        break
    except (OSError, urllib.error.URLError, RuntimeError):
        time.sleep(1)
else:
    raise SystemExit('Console did not become available')
command({'operation':'list'}, token=env['KNOX_DEMO_AUTH'], expected=401)
print('PASS: backend credential cannot administer console')
command({'operation':'create','key_id':key,'value':values[0]})
assert key in command({'operation':'list'})
print('PASS: create and list a real Knox key')
metadata = command({'operation':'inspect','key_id':key})
assert all('data' not in version for version in metadata['versions'])
assert all(isinstance(version['id'], str) for version in metadata['versions'])
print('PASS: metadata redaction and lossless version IDs')
version = command({'operation':'add-version','key_id':key,'value':values[1]})['version_id']
assert isinstance(version, str)
command({'operation':'set-status','key_id':key,'version_id':version,'status':'Primary'})
metadata = command({'operation':'inspect','key_id':key})
assert any(v['id'] == version and v['status'] == 'Primary' for v in metadata['versions'])
print('PASS: add Active version and promote to Primary')
command({'operation':'set-acl','key_id':key,'acl':[{'type':'User','id':'demo-reader','access':'Read'}]})
metadata = command({'operation':'inspect','key_id':key})
assert any(rule['id'] == 'demo-reader' and rule['access'] == 'Read' for rule in metadata['acl'])
print('PASS: apply and inspect Knox access rule')
