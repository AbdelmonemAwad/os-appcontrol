#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the page shows, as one JSON object: whether the classifier runs, what it found since it
started (classify.py's status.json), the applications with their category and table, the tables
and how many addresses pf holds in each, the installed nDPI, and what is blocked - each blocked
application's connections cut and the packets its block rule stopped, read from pf's own counters,
which start again at 0 whenever the firewall's rules are loaded (OPNsense keeps them only with its
own keep-counters option).

    status.py            the cards and the Applications tab
    status.py unknown    the Unknown tab: the connections nDPI did not name, latest first
    status.py rules      the Rules tab: what each rule does now - its state, the connections cut for it,
                         its Suricata lines or why it has none - and the Intrusion Detection's state

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
SURICATA = STATE + '/suricata.json'
PIDFILE = '/var/run/appcontrol.pid'
SURICATA_PIDFILE = '/var/run/suricata.pid'
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


def running(pidfile=PIDFILE, runs='classify.py run'):
    """The pid when the pidfile names a live process whose command line holds `runs` - the classifier's, by
    default; None otherwise."""
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
    return pid if runs in args else None


def ids(config=tables.CONFIG, pidfile=SURICATA_PIDFILE):
    """OPNsense's Intrusion Detection, as the Suricata rules of the Rules tab meet it: switched on, its mode - IPS
    (netmap, divert), where a drop drops, or IDS (pcap), where it alerts - the interfaces it reads, by their names
    too, those of them that are internal - where Suricata sees a device's own address, before NAT - and whether
    Suricata runs."""
    try:
        general = ET.parse(config).getroot().find('OPNsense/IDS/general')
    except (OSError, ET.ParseError):
        general = None

    def text(tag, default=''):
        return ((general.findtext(tag) if general is not None else None) or default).strip()

    reads = [i for i in text('interfaces').split(',') if i]
    names = tables.interface_names(config)
    internal = {key for key, _dev in tables.interfaces([], config)}
    return {'enabled': text('enabled', '0') == '1', 'mode': 'ips' if text('mode', 'pcap') in ('netmap', 'divert') else 'ids',
            'interfaces': reads, 'names': [names.get(i, i.upper()) for i in reads],
            'internal': [i for i in reads if i in internal], 'running': running(pidfile, 'suricata') is not None}


def rule_state(rule, conf, applied, said, known, table):
    """What a rule of the Rules tab does now (rules())."""
    key = rule['uuid'] or str(rule['number'])
    if not conf['classify']:
        return 'off'
    if applied is not None:
        before = applied.get(key)
        was_on = before is not None and before['enabled']
        if tables.digest(rule) != (tables.digest(before) if before is not None else None) and (rule['enabled'] or was_on):
            return 'changed'
    if not rule['enabled']:
        return 'disabled'
    if known and rule['app'] not in known:
        return 'unknown_app'
    if not table:
        return 'pending'
    unread = said.get('unread') if isinstance(said.get('unread'), list) else []
    if unread and (rule['not'] or set(unread) >= set(rule['source'])):
        return 'unread'
    if said.get('empty') is True:
        return 'empty'
    return 'active'


def rules(config=tables.CONFIG, status_path=STATUS, suricata_path=SURICATA, catalogue_path=tables.CATALOGUE,
          ids_pidfile=SURICATA_PIDFILE):
    """The Rules tab: {'rules': {uuid: {'state', 'table', 'cut', 'suricata'}}, 'gone', 'ids': ids(), 'suricata': when
    the rules file was last written and its lines}. A rule's state, against what the last Apply put in force -
    the rules suricata_rules.py kept as it applied them, with their digests (tables.digest()): 'off' - classifying
    off; 'changed' - saved since and not applied yet: pf, the cut and Suricata still act as before; 'disabled' -
    switched off; 'unknown_app' - an application the installed nDPI does not know; 'pending' - its application's
    table not made, Apply needed; 'unread' - its source cannot be read now, inverted or every element of it, so
    it acts on no device; 'empty' - its source holds no device's address now; 'active'. gone: the rules applied
    and switched on that are deleted since - they act until Apply. cut: the connections cut for it since the
    classifier started; suricata: what suricata_rules.py last wrote for it - its lines, or why none."""
    conf = tables.settings(config)
    aliases = tables.present(config)
    known = (tables.load_catalogue(catalogue_path).get('protocols') or {})
    cut = (load(status_path, {}) or {}).get('rule_cut') or {}
    written = load(suricata_path, {}) or {}
    said = written.get('rules') or {}
    applied = None
    kept = written.get('applied')
    if isinstance(kept, dict) and isinstance(kept.get('rules'), list):
        applied = {}
        for rule in kept['rules']:
            try:
                applied[rule['uuid'] or str(rule['number'])] = rule
                tables.digest(rule)
            except (KeyError, TypeError):
                applied = None
                break
    out = {}
    for rule in conf['rules']:
        key = rule['uuid'] or str(rule['number'])
        table = tables.table_for_app(rule['app'], aliases) if rule['app'] else None
        found = said.get(key) if isinstance(said.get(key), dict) else None
        out[key] = {'number': rule['number'], 'state': rule_state(rule, conf, applied, found or {}, known, table),
                    'table': table or '', 'cut': cut.get(key, 0) if isinstance(cut.get(key, 0), int) else 0,
                    'suricata': found}
    gone = sum(1 for key, rule in (applied or {}).items() if key not in out and rule['enabled']) \
        if conf['classify'] and applied is not None and kept.get('classify') is True else 0
    return {'rules': out, 'gone': gone, 'ids': ids(config, ids_pidfile),
            'suricata': {'at': written.get('at'), 'lines': written.get('lines', 0), 'errors': written.get('errors') or []}}


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
    {'cut_in_hardware': XGS: Settings' "Cut in hardware", on unless switched off; 'too_old': its hwdrop.py
    has no release_addresses() - an os-xgs-npu before 2026-11-17, its last release among them, whose
    drop_ends() takes no protocol: cut.py asks it nothing (cut.py's hardware())}."""
    if not os.path.isfile(hwdrop):
        return None
    try:
        text = ET.parse(config).getroot().findtext('OPNsense/XGS/general/cut_in_hardware')
    except (OSError, ET.ParseError):
        text = None
    try:
        with open(hwdrop, encoding='utf-8', errors='replace') as handle:
            too_old = 'def release_addresses(' not in handle.read()
    except OSError:
        too_old = True
    return {'cut_in_hardware': (text or '1').strip() != '0', 'too_old': too_old}


def report(status_path=STATUS, config=tables.CONFIG, catalogue_path=tables.CATALOGUE, pidfile=PIDFILE,
           pfctl=tables.PFCTL, reader=ndpi.NDPIREADER, hwdrop=HWDROP):
    conf = tables.settings(config)
    found = load(status_path, {})
    catalogue = tables.load_catalogue(catalogue_path)
    aliases = tables.present(config)
    held = entries(pfctl)
    chosen = set(conf['apps'])
    asked = set(conf['blocked'])
    ruled = tables.ruled(conf)
    policy = tables.policy(conf, aliases)
    # blocked for every device, by Blocked applications; the others of policy are blocked by rules alone
    blocked = {app: block['table'] for app, block in policy.items() if block['everyone']}
    stopped = (stopped_packets(pfctl) or {}) if policy else {}

    def row(name, entry):
        table = tables.table_for_app(name, aliases) if name in chosen | asked | ruled else None
        block = policy.get(name)
        return {'name': name, 'category': entry.get('category') or (catalogue.get('protocols') or {}).get(name, ''),
                'named': entry.get('named', 0), 'guessed': entry.get('guessed', 0),
                'protocols': entry.get('protocols', []), 'last': entry.get('last'), 'chosen': name in chosen,
                'ruled': name in ruled, 'table': table or '', 'entries': (held or {}).get(table) if table else None,
                'blocked': name in blocked, 'block_pending': name in asked and name not in blocked,
                'rules': len(block['rules']) if block else 0,
                'cut': entry.get('cut', 0), 'packets': stopped.get(block['table'], 0) if block else None}

    apps = [row(name, entry) for name, entry in sorted((found.get('apps') or {}).items())]
    for name in sorted((chosen | asked | ruled) - {a['name'] for a in apps}):
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
                     'rules': sum(len(block['rules']) for block in policy.values()),
                     'cut': totals.get('cut', 0), 'states': totals.get('cut_states', 0),
                     'dropped': totals.get('cut_dropped', 0), 'packets': sum(stopped.values()),
                     'last_cut': found.get('last_cut'), 'hardware': hardware(config, hwdrop)},
    }


def main(argv):
    if argv[1:2] == ['unknown']:
        rows = load(UNKNOWN, [])
        print(json.dumps({'rows': rows if isinstance(rows, list) else []}))
        return 0
    if argv[1:2] == ['rules']:
        try:
            print(json.dumps(rules()))
        except Exception as error:                                       # noqa: BLE001
            print(json.dumps({'error': 'the rules could not be read: %r' % error}))
        return 0
    try:
        print(json.dumps(report()))
    except Exception as error:                                           # noqa: BLE001
        print(json.dumps({'error': 'status could not be read: %r' % error}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
