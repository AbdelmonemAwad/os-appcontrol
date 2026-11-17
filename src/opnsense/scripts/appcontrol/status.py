#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the page shows, as one JSON object: whether the classifier runs, what it found since it
started (classify.py's status.json), the applications with their category and table, the tables
and how many addresses pf holds in each, and the installed nDPI.

    status.py            the cards and the Applications tab
    status.py unknown    the Unknown tab: the connections nDPI did not name, latest first

Read only; it prints JSON and exits 0 whatever it could not read.
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

STATE = '/var/db/os-appcontrol'
STATUS = STATE + '/status.json'
UNKNOWN = STATE + '/unknown.json'
PIDFILE = '/var/run/appcontrol.pid'
PROJECT = '/usr/local/opnsense/scripts/xgs'


def load(path, default):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def running(pidfile=PIDFILE):
    """The classifier's pid when the pidfile names a live process running it; None otherwise."""
    try:
        with open(pidfile) as handle:
            pid = int(handle.read().split()[0])
        if pid <= 1:
            return None
        os.kill(pid, 0)
        args = subprocess.run(['ps', '-ww', '-o', 'args=', '-p', str(pid)], capture_output=True, text=True,
                              timeout=10).stdout
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None
    return pid if 'classify.py run' in args else None


def entries(pfctl=tables.PFCTL):
    """{table: addresses} of the appcontrol_ tables pf holds, from pfctl -vvs Tables."""
    try:
        text = subprocess.run([pfctl, '-vvs', 'Tables'], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    out, name = {}, None
    for line in text.splitlines():
        head = re.match(r'^[-a-zA-Z]{7}\s+(\S+)', line)
        if head:
            name = head.group(1) if head.group(1).startswith(tables.PREFIX) else None
            if name:
                out[name] = 0
            continue
        found = re.match(r'^\s+Addresses:\s+(\d+)', line)
        if found and name:
            out[name] = int(found.group(1))
    return out


def report(status_path=STATUS, config=tables.CONFIG, catalogue_path=tables.CATALOGUE, pidfile=PIDFILE,
           pfctl=tables.PFCTL, reader=ndpi.NDPIREADER):
    conf = tables.settings(config)
    found = load(status_path, {})
    catalogue = tables.load_catalogue(catalogue_path)
    aliases = tables.present(config)
    held = entries(pfctl)
    chosen = set(conf['apps'])
    apps = []
    for name, entry in sorted((found.get('apps') or {}).items()):
        table = tables.table_for_app(name, aliases) if name in chosen else None
        apps.append({'name': name, 'category': entry.get('category') or '', 'named': entry.get('named', 0),
                     'guessed': entry.get('guessed', 0), 'protocols': entry.get('protocols', []),
                     'last': entry.get('last'), 'chosen': name in chosen, 'table': table or '',
                     'entries': (held or {}).get(table) if table else None})
    for name in sorted(chosen - {a['name'] for a in apps}):
        table = tables.table_for_app(name, aliases)
        apps.append({'name': name, 'category': (catalogue.get('protocols') or {}).get(name, ''), 'named': 0,
                     'guessed': 0, 'protocols': [], 'last': None, 'chosen': True, 'table': table or '',
                     'entries': (held or {}).get(table) if table else None})
    categories = [{'table': t, 'name': a['name'], 'entries': (held or {}).get(t)}
                  for t, a in sorted(aliases.items()) if a['kind'] == 'category']
    pid = running(pidfile)
    return {
        'classify': conf['classify'], 'running': pid is not None, 'pid': pid, 'ttl': conf['ttl'],
        'installed': ndpi.installed(reader), 'version': catalogue.get('version'), 'reader': catalogue.get('reader'),
        'catalogue_errors': catalogue.get('errors', []),
        'since': found.get('since'), 'windows': found.get('windows', 0), 'window': found.get('window'),
        'totals': found.get('totals') or {}, 'last': found.get('last'), 'error': found.get('error'),
        'stopped': found.get('stopped'), 'capped_windows': found.get('capped_windows', 0),
        'interfaces': found.get('interfaces') or [], 'apps': apps, 'categories': categories,
        'tables': {'categories': len(categories), 'applications': sum(1 for a in aliases.values()
                                                                       if a['kind'] == 'application'),
                   'addresses': sum((held or {}).values()) if held is not None else None},
        'unknown': len(load(UNKNOWN, [])), 'project': os.path.isdir(PROJECT),
    }


def main(argv):
    if argv[1:2] == ['unknown']:
        rows = load(UNKNOWN, [])
        print(json.dumps({'rows': rows if isinstance(rows, list) else []}))
        return 0
    try:
        print(json.dumps(report()))
    except Exception as error:                                           # noqa: BLE001
        print(json.dumps({'error': 'status could not be read: %r' % error}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
