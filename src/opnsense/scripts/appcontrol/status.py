#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the page shows, as one JSON object: whether the classifier runs, what it found since it
started (classify.py's status.json), the applications with their category and table, the tables
and how many addresses pf holds in each, the installed nDPI, and what is blocked - each blocked
application's connections cut and the packets its block rule stopped, read from pf's own counters.

    status.py            the cards and the Applications tab
    status.py unknown    the Unknown tab: the connections nDPI did not name, latest first

Read only; it prints JSON and exits 0 whatever it could not read.
"""

import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

STATE = '/var/db/os-appcontrol'
STATUS = STATE + '/status.json'
UNKNOWN = STATE + '/unknown.json'
PIDFILE = '/var/run/appcontrol.pid'
PROJECT = '/usr/local/opnsense/scripts/xgs'
HWDROP = PROJECT + '/hwdrop.py'
# A block rule as plugins.inc.d/appcontrol.inc registers it, as pfctl -v -s rules prints it: block, in, quick,
# on no interface, to the table - which pfctl writes <name>, or <name:addresses> once verbose.
BLOCK_RULE = re.compile(r'^(?:@\d+\S*\s+)?block\b(?!.*\son\s).*\sin\s.*\bquick\b.*\bto <(' + tables.PREFIX
                        + r'[A-Za-z0-9_]+)(?::[0-9*-]+)?>')
PACKETS = re.compile(r'\bPackets:\s*(\d+)')


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


def stopped_packets(pfctl=tables.PFCTL):
    """{table: packets} the block rules of this plugin's tables stopped, from pf's counters (pfctl -v -s
    rules): a rule as plugins.inc.d/appcontrol.inc registers it, its IPv4 and IPv6 rules summed - an owner's
    rule of the very same form is summed with them. None when pf's rules could not be read."""
    try:
        done = subprocess.run([pfctl, '-v', '-s', 'rules'], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    out, table = {}, None
    for line in done.stdout.splitlines():
        if line and not line[0].isspace():
            found = BLOCK_RULE.match(line)
            table = found.group(1) if found else None
            continue
        counted = PACKETS.search(line)
        if counted and table:
            out[table] = out.get(table, 0) + int(counted.group(1))
            table = None
    return out


def hardware(config=tables.CONFIG, hwdrop=HWDROP):
    """os-xgs-npu's cut in hardware, as a cut uses it: None where its hwdrop.py is not installed; else
    {'cut_in_hardware': XGS: Settings' "Cut in hardware", on unless switched off}."""
    if not os.path.isfile(hwdrop):
        return None
    try:
        text = ET.parse(config).getroot().findtext('OPNsense/XGS/general/cut_in_hardware')
    except (OSError, ET.ParseError):
        text = None
    return {'cut_in_hardware': (text or '1').strip() != '0'}


def report(status_path=STATUS, config=tables.CONFIG, catalogue_path=tables.CATALOGUE, pidfile=PIDFILE,
           pfctl=tables.PFCTL, reader=ndpi.NDPIREADER, hwdrop=HWDROP):
    conf = tables.settings(config)
    found = load(status_path, {})
    catalogue = tables.load_catalogue(catalogue_path)
    aliases = tables.present(config)
    held = entries(pfctl)
    chosen = set(conf['apps'])
    asked = set(conf['blocked'])
    blocked = tables.blocked(conf, aliases)
    stopped = (stopped_packets(pfctl) or {}) if blocked else {}

    def row(name, entry):
        table = tables.table_for_app(name, aliases) if name in chosen | asked else None
        return {'name': name, 'category': entry.get('category') or (catalogue.get('protocols') or {}).get(name, ''),
                'named': entry.get('named', 0), 'guessed': entry.get('guessed', 0),
                'protocols': entry.get('protocols', []), 'last': entry.get('last'), 'chosen': name in chosen,
                'table': table or '', 'entries': (held or {}).get(table) if table else None,
                'blocked': name in blocked, 'block_pending': name in asked and name not in blocked,
                'cut': entry.get('cut', 0), 'packets': stopped.get(blocked[name], 0) if name in blocked else None}

    apps = [row(name, entry) for name, entry in sorted((found.get('apps') or {}).items())]
    for name in sorted((chosen | asked) - {a['name'] for a in apps}):
        apps.append(row(name, {}))
    categories = [{'table': t, 'name': a['name'], 'entries': (held or {}).get(t)}
                  for t, a in sorted(aliases.items()) if a['kind'] == 'category']
    pid = running(pidfile)
    totals = found.get('totals') or {}
    return {
        'classify': conf['classify'], 'running': pid is not None, 'pid': pid, 'ttl': conf['ttl'],
        'installed': ndpi.installed(reader), 'version': catalogue.get('version'), 'reader': catalogue.get('reader'),
        'catalogue_errors': catalogue.get('errors', []), 'catalogue_read_at': catalogue.get('read_at'),
        'since': found.get('since'), 'windows': found.get('windows', 0), 'window': found.get('window'),
        'totals': found.get('totals') or {}, 'last': found.get('last'), 'error': found.get('error'),
        'stopped': found.get('stopped'), 'capped_windows': found.get('capped_windows', 0),
        'dropped_windows': found.get('dropped_windows', 0),
        'interfaces': found.get('interfaces') or [], 'apps': apps, 'categories': categories,
        'tables': {'categories': len(categories), 'applications': sum(1 for a in aliases.values()
                                                                       if a['kind'] == 'application'),
                   'addresses': sum((held or {}).values()) if held is not None else None},
        'unknown': len(load(UNKNOWN, [])), 'project': os.path.isdir(PROJECT),
        'blocking': {'apps': sorted(blocked), 'pending': sorted(asked - set(blocked)), 'log': conf['block_log'],
                     'cut': totals.get('cut', 0), 'states': totals.get('cut_states', 0),
                     'dropped': totals.get('cut_dropped', 0), 'packets': sum(stopped.values()),
                     'last_cut': found.get('last_cut'), 'hardware': hardware(config, hwdrop)},
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
