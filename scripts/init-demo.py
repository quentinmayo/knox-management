#!/usr/bin/env python3
import os
from pathlib import Path
import secrets

path = Path(__file__).resolve().parents[1] / '.env'
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print('Existing .env retained.')
else:
    with os.fdopen(fd, 'w') as stream:
        stream.write('KNOX_MANAGEMENT_TOKEN=' + secrets.token_urlsafe(48) + '\n')
        stream.write('KNOX_DEMO_AUTH=0u' + secrets.token_urlsafe(48) + '\n')
    print('Generated ignored .env with mode 0600. No credential values printed.')
