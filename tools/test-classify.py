#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""What the classifier reads of nDPI, and its tables, with stand-ins for what only a firewall has:
ndpiReader and pfctl.

- ndpiReader's CSV as phase 0's lab read it on an XGS 3300 (OPNsense 26.7.9, ndpi-6.0.d20260909,1):
  tools/fixtures/lab-*.csv are those files with every address made a documentation one; the rows
  and names found must be the lab's. The catalogue's two outputs, -a 1 and -H, are in the format of
  the source of nDPI de5c784 (tools/fixtures/ndpiReader-*.txt, written for the test, not read on a box).
- tables.py: the alias names and the 31-character rule, the tables the settings ask for, and an
  address added when new and refreshed when seen again.

    python3 tools/test-classify.py"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'appcontrol')
FIX = os.path.join(HERE, 'fixtures')
sys.path.insert(0, HERE)
sys.path.insert(0, SCRIPTS)

import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402
import apps                                                              # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def labels(rows):
    out = {}
    for row in rows.values():
        out[row['name']] = out.get(row['name'], 0) + 1
    return out


# ---------------------------------------------------------------- ndpiReader's CSV, as the lab had it
rows, bad = ndpi.read_csv(os.path.join(FIX, 'lab-tls13.csv'))
check('lab, tls13: the 41 connections named, as the lab counted them', (len(rows), bad), (41, 0))
check('lab, tls13: their names', labels(rows), {'TLS.Wikipedia': 11, 'TLS.Cloudflare': 11, 'DNS': 8, 'TLS.Mozilla': 11})
rows, bad = ndpi.read_csv(os.path.join(FIX, 'lab-video.csv'))
check('lab, video pages: 59, by name', (len(rows), labels(rows)),
      (59, {'TLS.YouTube': 12, 'TLS.Twitch': 12, 'TLS.NetFlix': 11, 'DNS': 23, 'TLS': 1}))
rows, _ = ndpi.read_csv(os.path.join(FIX, 'lab-tls12.csv'))
check('lab, tls12: TLS 12 and DNS 4', labels(rows), {'TLS': 12, 'DNS': 4})
rows, _ = ndpi.read_csv(os.path.join(FIX, 'lab-update.csv'))
check('lab, update: HTTP.Canonical 20 and DNS 7', labels(rows), {'HTTP.Canonical': 20, 'DNS': 7})
rows, _ = ndpi.read_csv(os.path.join(FIX, 'lab-smtp.csv'))
check('lab, a server-first banner: SMTP 5', labels(rows), {'SMTP': 5})
some = sorted(rows.values(), key=lambda r: r['sport'])[0]
check('lab, SMTP: the row read - ends, name, server name', (some['proto'], some['dst'], some['dport'], some['server_name']),
      (6, some['dst'], 25, 'mail.example'))
rows, bad = ndpi.read_csv(os.path.join(FIX, 'lab-header-only.csv'))
check('lab: a CSV of the header only (ndpiReader with -v) - no row, nothing wrong', (rows, bad), ({}, 0))
check('a CSV that is not there: no row', ndpi.read_csv(os.path.join(FIX, 'none.csv')), ({}, 0))

with tempfile.TemporaryDirectory() as tmp:
    head = open(os.path.join(FIX, 'lab-update.csv'), encoding='utf-8').readline()
    line = open(os.path.join(FIX, 'lab-update.csv'), encoding='utf-8').read().split('\n')[1]
    path = os.path.join(tmp, 'x.csv')
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(head + line + ' | with a bar\n' + '1|6|x|short\n' + '\n')
    rows, bad = ndpi.read_csv(path)
    check('a row with a "|" in its last column, the user agent: read; a short row counted, not read', (len(rows), bad), (1, 1))
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write('flow_id|protocol\n1|6\n')
    check('a file whose first line is no header: nothing read, said', ndpi.read_csv(path), ({}, 1))

check('the run with guessing: -q, the window file, -C, 8 packets a connection; no -d',
      ndpi.command('/w.pcap', '/w.csv', True, '/r'),
      ['/r', '-q', '-i', '/w.pcap', '-C', '/w.csv', '--cfg=NULL,packets_limit_per_flow,8'])
check('the run by DPI alone: -d', ndpi.command('/w.pcap', '/w.csv', False, '/r')[-1], '-d')
check('a name split: TLS.YouTube is TLS carrying YouTube, DNS its own', (ndpi.split_name('TLS.YouTube'),
      ndpi.split_name('DNS')), (('TLS', 'YouTube'), ('DNS', 'DNS')))
check('carried only: TLS, QUIC, HTTP alone; not TLS.YouTube, not DNS',
      [ndpi.carried_only(n) for n in ('TLS', 'QUIC', 'HTTP', 'TLS.YouTube', 'DNS')], [True, True, True, False, False])

# ------------------------------------------------------------------------ the installed nDPI's catalogue
cats = ndpi.parse_categories(open(os.path.join(FIX, 'ndpiReader-a1.txt'), encoding='utf-8').read())
committed = apps.committed()
check('-a 1: every category of the file, by id', (len(cats), cats[5], cats[160]), (93, 'Web', 'Children'))
check('categories.json: the same ids and names', committed == cats, True)
check('-a 1: a category with no name left out', ndpi.parse_categories('<Option20 value="20"></Option20>' +
                                                                      '<Option5 value="5">Web</Option5>'), {5: 'Web'})
check('categories.json: every name an alias can carry', all(len(tables.alias_name(tables.CATEGORY_PREFIX, n)) <= 31
                                                             for n in committed.values()), True)
protos = ndpi.parse_protocols(open(os.path.join(FIX, 'ndpiReader-H.txt'), encoding='utf-8').read(), cats)
check('-H: a protocol with an empty layer 4 and the X column', protos.get('ICMP'), 'Network')
check('-H: an application, a long category', (protos.get('YouTube'), protos.get('Example_Env')),
      ('Media', 'Environmental_Services'))
check('-H: the header, Unknown (category 0) and what follows the table, a protocol-shaped line among it: not taken',
      ('Protocol' in protos, 'Unknown' in protos, 'XSS' in protos, 'After_Risks' in protos, len(protos)),
      (False, False, False, False, 16))

with tempfile.TemporaryDirectory() as tmp:
    fake = os.path.join(tmp, 'ndpiReader')
    with open(fake, 'w') as handle:
        handle.write('#!/bin/sh\ncase "$1" in -a) cat %s ;; -H) cat %s ;; esac\n'
                     % (os.path.join(FIX, 'ndpiReader-a1.txt'), os.path.join(FIX, 'ndpiReader-H.txt')))
    os.chmod(fake, 0o755)
    pkg = os.path.join(tmp, 'pkg')
    with open(pkg, 'w') as handle:
        handle.write('#!/bin/sh\necho 6.0.d20260909,1\n')
    os.chmod(pkg, 0o755)
    out = apps.refresh(fake, os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    saved = json.load(open(os.path.join(tmp, 'ndpi.json')))
    check('apps.py refresh: the categories from -a 1, the protocols from -H, the version from pkg',
          (out['categories_from'], len(saved['categories']), len(saved['protocols']), saved['version'], saved['reader'],
           out['errors']), ('ndpiReader -a 1', 93, 16, '6.0.d20260909,1', '6.0.0', []))
    with open(fake, 'w') as handle:
        handle.write('#!/bin/sh\nexit 1\n')
    out = apps.refresh(fake, os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    check('apps.py refresh, nDPI answering nothing: categories.json stands in, and it is said',
          (out['categories_from'], len(out['categories']), len(out['errors'])), ('categories.json', 93, 2))
    out = apps.refresh(os.path.join(tmp, 'none'), os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    check('apps.py refresh, nDPI not installed: said, no protocol', (out['installed'], out['protocols']), (False, {}))
    check('apps.py list: name to name, for the field', apps.options({'protocols': {'b': 'Web', 'A': 'Web'}}),
          {'A': 'A', 'b': 'b'})

# --------------------------------------------------------------------------------------- the names
check('a short name: appcontrol_ and the name', tables.alias_name(tables.PREFIX, 'YouTube'), 'appcontrol_YouTube')
check('a name with a hyphen: an underscore', tables.alias_name(tables.CATEGORY_PREFIX, 'IoT-Scada'), 'appcontrol_cat_IoT_Scada')
long_name = tables.alias_name(tables.CATEGORY_PREFIX, 'Environmental_Services')
check('a name too long: 31 characters, cut, with a suffix of its own',
      (len(long_name), long_name.startswith('appcontrol_cat_Environm'), long_name[-5] == '_'), (31, True, True))
everything = [tables.alias_name(tables.CATEGORY_PREFIX, n) for n in committed.values()]
check('every category: a name of its own', len(set(everything)), len(everything))
two = [tables.alias_name(tables.CATEGORY_PREFIX, n) for n in ('Environmental_Services_A', 'Environmental_Services_B')]
check('two names cut alike: still two', two[0] != two[1], True)
cat = {'categories': {'5': 'Web', '14': 'Network', '26': 'Video'}, 'protocols': {'YouTube': 'Media', 'DNS': 'Network'}}
check('wanted, classifying off: no alias', tables.wanted({'classify': False, 'apps': ['YouTube']}, cat), {})
w = tables.wanted({'classify': True, 'apps': ['YouTube', 'NotInNdpi']}, cat)
check('wanted: a table for every category, and one for each application chosen that nDPI knows', sorted(w),
      ['appcontrol_YouTube', 'appcontrol_cat_Network', 'appcontrol_cat_Video', 'appcontrol_cat_Web'])
check('wanted: described as the plugin\'s, nDPI\'s name kept', w['appcontrol_cat_Web']['description'],
      'Application Control: category Web')
w = tables.wanted({'classify': True, 'apps': ['Apple-Music', 'Apple_Music']},
                  {'categories': {}, 'protocols': {'Apple-Music': 'Music', 'Apple_Music': 'Music'}})
check('two applications that meet in one name: two aliases', len(w), 2)

with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases>'
                     '<alias uuid="1"><enabled>1</enabled><name>appcontrol_cat_Web</name><type>external</type>'
                     '<description>Application Control: category Web</description></alias>'
                     '<alias uuid="2"><enabled>0</enabled><name>appcontrol_cat_Video</name><type>external</type>'
                     '<description>Application Control: category Video</description></alias>'
                     '<alias uuid="3"><enabled>1</enabled><name>appcontrol_mine</name><type>host</type>'
                     '<description>my own</description></alias>'
                     '<alias uuid="5"><enabled>1</enabled><name>appcontrol_list</name><type>external</type>'
                     '<description>my own table</description></alias>'
                     '<alias uuid="4"><enabled>1</enabled><name>appcontrol_YouTube</name><type>external</type>'
                     '<description>Application Control: YouTube</description></alias>'
                     '</aliases></Alias></Firewall><AppControl><general><classify>0</classify><apps>YouTube,DNS</apps>'
                     '<ttl>120</ttl></general></AppControl></OPNsense></opnsense>')
    found = tables.present(config)
    check('present: the plugin\'s aliases switched on; one switched off, and the owner\'s - External too - not', found,
          {'appcontrol_cat_Web': {'kind': 'category', 'name': 'Web'},
           'appcontrol_YouTube': {'kind': 'application', 'name': 'YouTube'}})
    check('settings: off, the applications, the expiry', (lambda s: (s['classify'], s['apps'], s['ttl']))(
        tables.settings(config)), (False, ['YouTube', 'DNS'], 120))
    check('settings: no element of the plugin\'s - on, 3600', (lambda s: (s['classify'], s['ttl']))(
        tables.settings(os.path.join(tmp, 'none.xml'))), (True, 3600))
    check('the table of a category whose alias is there; of one whose alias is not, none',
          (tables.table_for_category('Web', found), tables.table_for_category('Video', found)), ('appcontrol_cat_Web', None))


# --------------------------------------------------------------------------------- pfctl's tables
class FakePf:
    """pfctl -t T -T show|add|zero|flush, and -v -s Tables, on tables held here."""

    def __init__(self, held=None, fail=()):
        self.held = {k: set(v) for k, v in (held or {}).items()}
        self.calls = []
        self.fail = set(fail)

    def __call__(self, args):
        self.calls.append(list(args))
        if args[:3] == ['-v', '-s', 'Tables']:
            return 0, ''.join('-pa-%s--\t%s\n' % ('r' if t.endswith('_used') else '-', t) for t in sorted(self.held))
        table, verb, addrs = args[1], args[3], args[4:]
        if verb in self.fail:
            return 1, 'pfctl: Operation not permitted'
        if verb == 'show':
            if table not in self.held:
                return 1, 'pfctl: Table does not exist.'
            return 0, ''.join('   %s\n' % a for a in sorted(self.held[table]))
        if verb == 'add':
            self.held.setdefault(table, set()).update(addrs)
        if verb == 'flush':
            self.held[table] = set()
        return 0, '%d/%d addresses %s.' % (len(addrs), len(addrs), verb)


fake = FakePf({'appcontrol_cat_Web': {'198.51.100.1'}})
pf = tables.Pf(run=fake)
check('an address new to a table added, one there refreshed', pf.update('appcontrol_cat_Web', ['198.51.100.1', '198.51.100.2']),
      (1, 1))
check('pfctl as asked: show, add the new, zero the one there', [c[3:] for c in fake.calls],
      [['show'], ['add', '198.51.100.2'], ['zero', '198.51.100.1']])
fake = FakePf()
many = ['198.51.100.%d' % i for i in range(1, 151)]
tables.Pf(run=fake).update('appcontrol_cat_Web', many)
check('150 addresses: added 64 at a time', [len(c) - 4 for c in fake.calls if c[3] == 'add'], [64, 64, 22])
fake = FakePf(fail=['add'])
pf = tables.Pf(run=fake)
check('pfctl refusing: no exception, said', (pf.update('appcontrol_cat_Web', ['198.51.100.9']), len(pf.errors)), ((1, 0), 1))
check('nothing to put: pfctl not asked', (tables.Pf(run=fake).update('appcontrol_cat_Web', []), len(fake.calls)), ((0, 0), 2))
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases><alias><name>appcontrol_cat_Web</name></alias>'
                     '</aliases></Alias></Firewall></OPNsense></opnsense>')
    fake = FakePf({'appcontrol_cat_Web': {'198.51.100.1'}, 'appcontrol_cat_Gone': {'198.51.100.2'},
                   'appcontrol_cat_Gone_used': {'198.51.100.3'}, 'bogons': {'192.0.2.0/24'}})
    check('flush-gone: only a table of the plugin\'s whose alias is gone and no rule uses',
          tables.flush_gone(tables.Pf(run=fake), config), ['appcontrol_cat_Gone'])



print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
