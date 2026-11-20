#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The classifier, run with stand-ins for what only a firewall has: ndpiReader, tcpdump and pfctl.

- ndpiReader's CSV as phase 0's lab read it on an XGS 3300 (OPNsense 26.7.9, ndpi-6.0.d20260909,1):
  tools/fixtures/lab-*.csv are those files with every address made a documentation one; the rows
  and names found must be the lab's. The catalogue's two outputs, -a 1 and -H, are in the format of
  the source of nDPI de5c784 (tools/fixtures/ndpiReader-*.txt, written for the test, not read on a box).
- capture.py on packets built byte by byte (tools/pcapgen.py): the pcap stream in chunks, the
  connections and their server, what is kept for nDPI and in which window, and a ClientHello read -
  the JA4 of FoxIO's own example.
- tables.py: the alias names and the 31-character rule, the tables the settings ask for, and an
  address added when new and refreshed when seen again.
- classify.py: each connection named, guessed or unknown, what goes into a table and what never
  does, the Unknown list kept to its latest 500, status.json - and one whole run of the service, its
  tcpdump and ndpiReader stand-in programs, that ends when it is asked to.

    python3 tools/test-classify.py"""
import json
import os
import select
import stat
import struct
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'appcontrol')
FIX = os.path.join(HERE, 'fixtures')
sys.path.insert(0, HERE)
sys.path.insert(0, SCRIPTS)

import pcapgen                                                           # noqa: E402
import capture                                                           # noqa: E402
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402
import apps                                                              # noqa: E402
import classify                                                          # noqa: E402

# Every address here is a documentation one, which Python's ipaddress does not take for the internet's: they
# stand for it here, as servers out there - but for 203.0.113.0/24, which stands for a site the firewall
# reaches over a VPN or a route, its addresses private ones.
INTERNET = ('192.0.2.0/24', '198.51.100.0/24', '2001:db8::/32')
classify.ALSO_GLOBAL = tuple(classify.ipaddress.ip_network(n) for n in INTERNET)

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def program(path, text):
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def mounted(tmp, lines=None):
    """A stand-in mount: mount -p listing tmp/work as a tmpfs, or the lines given."""
    table = os.path.join(tmp, 'mounts.txt')
    with open(table, 'w') as handle:
        handle.write(''.join(line + '\n' for line in (lines if lines is not None else [
            'tmpfs %s tmpfs rw,size=167772160,mode=0750 0 0' % os.path.join(tmp, 'work')])))
    program(os.path.join(tmp, 'mount'), '#!/bin/sh\n[ "$1" = -p ] && cat %s\n' % table)
    return os.path.join(tmp, 'mount')


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
check('lab, SMTP: the key is the two ends in one order', capture.flow_key(6, some['dst'], 25, some['src'], some['sport'])
      in rows, True)
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
check('-H believed: TLS in Web and DNS in Network', ndpi.protocols_problem(protos), None)
check('-H not believed: empty, or TLS or DNS in another category or none - said which',
      [ndpi.protocols_problem(p) for p in ({}, dict(protos, TLS='Media'), {k: v for k, v in protos.items() if k != 'DNS'})],
      ['ndpiReader -H gave no protocol', 'ndpiReader -H was not read as nDPI writes it: TLS in Media, not Web',
       'ndpiReader -H was not read as nDPI writes it: DNS in no category, not Network'])

ids = ndpi.parse_protocol_ids(open(os.path.join(FIX, 'ndpiReader-H.txt'), encoding='utf-8').read())
check('-H: each protocol\'s id, Unknown\'s 0 too, before the table of risks - After_Risks, id 3 after it, not taken for '
      'SMTP\'s 3', (len(ids), ids[0], ids[124], ids[3], ids[188]), (17, 'Unknown', 'YouTube', 'SMTP', 'QUIC'))
hosts = ndpi.parse_hosts(open(os.path.join(FIX, 'ndpiReader-protos-dump-1.txt'), encoding='utf-8').read(), ids)
check('--protos-dump 1: the names nDPI knows each application by, by the id -H gives it, each once, in order',
      (hosts['YouTube'], hosts['NetFlix'], sorted(hosts)),
      (['googlevideo.com', 'youtu.be', 'youtube-nocookie.', 'youtube-ui.l.google.com', 'youtube.', 'youtubeeducation.com',
        'youtubei.googleapis.com', 'yt3.ggpht.com', 'ytimg.com'],
       ['-nflxext.example', '-nflxtest.', 'netflix.com', 'nflxso-', 'nflxvideo.net'],
       ['Canonical', 'Cloudflare', 'Dropbox', 'Mozilla', 'NetFlix', 'Twitch', 'Wikipedia', 'YouTube']))
check('--protos-dump 1: a name in capitals lower case; the header, a line that is no name and an id, a name of other '
      'characters, an empty one and one of an id -H does not list, left out',
      hosts['Dropbox'], ['dropbox.com', 'dropboxstatic.com'])

with tempfile.TemporaryDirectory() as tmp:
    fake = os.path.join(tmp, 'ndpiReader')
    with open(fake, 'w') as handle:
        handle.write('#!/bin/sh\ncase "$1" in -a) cat %s ;; -H) cat %s ;; --protos-dump) [ "$2" = 1 ] && cat %s ;; esac\n'
                     % (os.path.join(FIX, 'ndpiReader-a1.txt'), os.path.join(FIX, 'ndpiReader-H.txt'),
                        os.path.join(FIX, 'ndpiReader-protos-dump-1.txt')))
    os.chmod(fake, 0o755)
    pkg = os.path.join(tmp, 'pkg')
    with open(pkg, 'w') as handle:
        handle.write('#!/bin/sh\necho 6.0.d20260909,1\n')
    os.chmod(pkg, 0o755)
    out = apps.refresh(fake, os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    saved = json.load(open(os.path.join(tmp, 'ndpi.json')))
    check('apps.py refresh: the categories from -a 1, the protocols from -H, the names of the host table from '
          '--protos-dump 1, the version from pkg',
          (out['categories_from'], len(saved['categories']), len(saved['protocols']), len(saved['hosts']['YouTube']),
           saved['version'], saved['reader'], out['errors']), ('ndpiReader -a 1', 93, 16, 9, '6.0.d20260909,1', '6.0.0', []))
    shifted = os.path.join(tmp, 'H.txt')
    with open(shifted, 'w') as handle:
        handle.write(open(os.path.join(FIX, 'ndpiReader-H.txt'), encoding='utf-8').read().replace(
            'Safe                  Web', 'Safe                  Media', 1))
    program(os.path.join(tmp, 'shifted'), '#!/bin/sh\ncase "$1" in -a) cat %s ;; -H) cat %s ;; --protos-dump) cat %s ;; esac\n'
            % (os.path.join(FIX, 'ndpiReader-a1.txt'), shifted, os.path.join(FIX, 'ndpiReader-protos-dump-1.txt')))
    out = apps.refresh(os.path.join(tmp, 'shifted'), os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    check('apps.py refresh, -H giving TLS another category: said, for the page', out['errors'],
          ['ndpiReader -H was not read as nDPI writes it: TLS in Media, not Web'])
    program(os.path.join(tmp, 'no-dump'), '#!/bin/sh\ncase "$1" in -a) cat %s ;; -H) cat %s ;; esac\n'
            % (os.path.join(FIX, 'ndpiReader-a1.txt'), os.path.join(FIX, 'ndpiReader-H.txt')))
    out = apps.refresh(os.path.join(tmp, 'no-dump'), os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    check('apps.py refresh, --protos-dump 1 giving no name: said - a Suricata rule then matches a protocol alone',
          (out['errors'], json.load(open(os.path.join(tmp, 'ndpi.json')))['hosts']),
          (['ndpiReader --protos-dump 1 gave no name: a Suricata rule matches a protocol alone'], {}))
    with open(fake, 'w') as handle:
        handle.write('#!/bin/sh\nexit 1\n')
    out = apps.refresh(fake, os.path.join(tmp, 'ndpi.json'), pkg=pkg)
    check('apps.py refresh, nDPI answering nothing: categories.json stands in, and it is said - and that it gave no name',
          (out['categories_from'], len(out['categories']), len(out['errors'])), ('categories.json', 93, 3))
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
        if verb == 'delete':
            self.held.get(table, set()).difference_update(addrs)
        if verb == 'kill':
            self.held.pop(table, None)
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
    check('flush-gone: that table taken out of pf (killed), not only emptied; the others kept',
          sorted(fake.held), ['appcontrol_cat_Gone_used', 'appcontrol_cat_Web', 'bogons'])

    # the reload still loading: a table whose alias is gone is a rule's for the first two reads, then not -
    # flush-gone reads pf again a second at a time and takes it out once no rule uses it (2026-11-20: left in pf)
    class LatePf(FakePf):
        reads = 0

        def __call__(self, args):
            if args[:3] == ['-v', '-s', 'Tables']:
                LatePf.reads += 1
                return 0, ''.join('-pa-%s--\t%s\n' % ('r' if t.endswith('_late') and LatePf.reads <= 2 else '-', t)
                                  for t in sorted(self.held))
            return FakePf.__call__(self, args)
    fake = LatePf({'appcontrol_cat_Gone_late': {'198.51.100.4'}, 'appcontrol_cat_Web': {'198.51.100.1'}})
    slept = []
    check('flush-gone: a table a rule lets go of within the wait is taken out, after two seconds\' wait',
          (tables.flush_gone(tables.Pf(run=fake), config, sleep=slept.append), len(slept)),
          (['appcontrol_cat_Gone_late'], 2))
    fake = FakePf({'appcontrol_cat_Gone_used': {'198.51.100.3'}})
    slept = []
    check('flush-gone: one a rule goes on using is left, after the wait (3 s here)',
          (tables.flush_gone(tables.Pf(run=fake), config, wait=3, sleep=slept.append), len(slept)), ([], 3))


# --------------------------------------------------------------------------------- the capture
def stream_of(packets, chunk=None, linktype=1):
    data = pcapgen.capture(packets, linktype)
    stream = capture.Stream()
    out = []
    step = chunk or len(data)
    for i in range(0, len(data), step):
        out.extend(stream.feed(data[i:i + step]))
    return stream, out


T0 = 1794926400.0       # 2026-11-17, in a window of its own whatever its length here
hello = pcapgen.client_hello(padding=1700)
conn = pcapgen.tcp_connection(T0 + 1, '192.0.2.10', 50001, '198.51.100.10', 443, hello, server_data=b'\x16\x03\x03' + b'x' * 40)
stream, packets = stream_of(conn, chunk=7)
check('a capture fed 7 bytes at a time: every packet, its time, its link type',
      (len(packets), stream.linktype, round(packets[0][0], 3)), (len(conn), 1, T0 + 1))
check('the ClientHello in two TCP segments: the handshake, two segments, the answer', len(conn), 6)
flows = capture.Flows('lan', 60, T0)
for ts, rec, wire in packets:
    flows.packet(stream.linktype, ts, rec, wire)
f = list(flows.table.values())[0]
check('one connection: client, server, begun here, its window', (f.client, f.server, f.started, f.window),
      (('192.0.2.10', 50001), ('198.51.100.10', 443), True, int((T0 + 1) // 60)))
check('its ClientHello put together from two segments: server name, ALPN, the JA4 of FoxIO\'s example',
      (f.sni, f.alpn, f.ja4), ('www.example.com', 'h2', pcapgen.CHROME_JA4))
check('its key: the same as a CSV row\'s for its ends', f.key, capture.flow_key(6, '198.51.100.10', 443, '192.0.2.10', 50001))

# the segments out of order, and the first one only after the second
mixed = conn[:3] + [conn[4], conn[3]] + conn[5:]
mixed = [(T0 + 1 + i * 0.001, fr) for i, (_, fr) in enumerate(mixed)]
stream, packets = stream_of(mixed)
flows = capture.Flows('lan', 60, T0)
for ts, rec, wire in packets:
    flows.packet(stream.linktype, ts, rec, wire)
check('the ClientHello\'s segments the other way round: the same JA4', list(flows.table.values())[0].ja4, pcapgen.CHROME_JA4)


def one(packets, since=T0, seconds=60, linktype=1):
    stream, got = stream_of(packets, linktype=linktype)
    flows = capture.Flows('lan', seconds, since)
    for ts, rec, wire in got:
        flows.packet(stream.linktype, ts, rec, wire)
    return flows


for name, kwargs, want in (
        ('no server name: i, and the count of extensions without it', {'sni': None}, 't13i1515h2'),
        ('no ALPN: 00', {'alpn': ()}, 't13d151500'),
        ('an ALPN beginning and ending in no letter or digit: the hex digits', {'alpn': (b'\xab\x01',)}, 't13d1516a1'),
        ('TLS 1.2 alone, no supported_versions', {'versions': (), 'extensions': [e for e in pcapgen.CHROME_EXTENSIONS
                                                                                if e != 0x002b]}, 't12d1515h2')):
    hello2 = pcapgen.client_hello(**kwargs)
    fl = one(pcapgen.tcp_connection(T0 + 2, '192.0.2.10', 50002, '198.51.100.10', 443, hello2))
    check('JA4, ' + name, list(fl.table.values())[0].ja4[:10], want)
fl = one(pcapgen.tcp_connection(T0 + 2, '192.0.2.10', 50003, '198.51.100.10', 80, data=b'GET / HTTP/1.1\r\n\r\n'))
check('a client that does not begin with a TLS handshake: no JA4, no server name', (lambda x: (x.ja4, x.sni))(
    list(fl.table.values())[0]), (None, None))

fl = one(pcapgen.tcp_connection(T0 + 2, '192.0.2.10', 50004, '198.51.100.10', 443, hello)[1:])
check('a SYN and ACK seen first: the server is the end that sent it', list(fl.table.values())[0].server,
      ('198.51.100.10', 443))
fl = one(pcapgen.tcp_connection(T0 + 2, '192.0.2.10', 50005, '198.51.100.10', 8080, syn=False, data=b'x' * 100))
check('a TCP connection with no SYN: not taken as begun here', list(fl.table.values())[0].started, False)
dns = [(T0 + 5, pcapgen.frame('192.0.2.10', '198.51.100.53', 17, pcapgen.udp(53000, 53, pcapgen.dns_query()))),
       (T0 + 5.01, pcapgen.frame('198.51.100.53', '192.0.2.10', 17, pcapgen.udp(53, 53000, b'\0' * 40), to_server=False))]
fl = one(dns)
check('UDP: the server is where the first packet went; begun, the capture well under way', (lambda x: (x.server, x.started))(
    list(fl.table.values())[0]), (('198.51.100.53', 53), True))
fl = one(dns, since=T0 + 4)
check('UDP in the capture\'s first seconds: maybe going already, not taken as begun', list(fl.table.values())[0].started, False)
v6 = pcapgen.tcp_connection(T0 + 2, '2001:db8::10', 50007, '2001:db8::443', 443, hello, vlan=12)
fl = one(v6)
check('IPv6 behind a VLAN tag: its ends spelt as a CSV row spells them, and its JA4', (lambda x: (x.server, x.ja4))(
    list(fl.table.values())[0]), (('2001:db8::443', 443), pcapgen.CHROME_JA4))
check('an address spelt as ndpi.canonical() spells it', (capture.address(bytes(16)), ndpi.canonical('2001:DB8:0::1')),
      ('::', '2001:db8::1'))
ext = struct.pack('!BB6x', 6, 0)                     # a hop-by-hop header before TCP
packet = pcapgen.ether(pcapgen.ip6('2001:db8::10', '2001:db8::443', 0, pcapgen.tcp(50008, 443, 1, 0, 0x02), ext), 0x86dd)
check('IPv6 with an extension header: the ports behind it', capture.decode(1, struct.pack('<IIII', 0, 0, len(packet),
      len(packet)) + packet)[:5], (6, bytes.fromhex('20010db8000000000000000000000010'), 50008,
                                   bytes.fromhex('20010db8000000000000000000000443'), 443))
small = pcapgen.frame('192.0.2.10', '198.51.100.10', 6, pcapgen.tcp(50009, 443, 5, 6, 0x10))
d = capture.decode(1, struct.pack('<IIII', 0, 0, len(small), len(small)) + small)
check('an Ethernet frame padded to 60 bytes: the padding is no payload', d[8] - d[7], 0)
frag = pcapgen.ether(pcapgen.ip4('192.0.2.10', '198.51.100.10', 17, b'\x01' * 20, frag=185), 0x0800)
check('a later IPv4 fragment: no port read from it', capture.decode(1, struct.pack('<IIII', 0, 0, len(frag), len(frag)) +
                                                                     frag)[2], 0)
loop = struct.pack('>I', 2) + pcapgen.ip4('192.0.2.10', '198.51.100.10', 17, pcapgen.udp(1, 2, b''))
null_be = struct.pack('>I', 2) + pcapgen.ip4('192.0.2.10', '198.51.100.10', 17, pcapgen.udp(1, 2, b''))
null_le = struct.pack('<I', 2) + pcapgen.ip4('192.0.2.10', '198.51.100.10', 17, pcapgen.udp(1, 2, b''))
check('a tunnel\'s capture (loopback and null link types, either byte order): IPv4 read',
      [capture.decode(lt, struct.pack('<IIII', 0, 0, len(p), len(p)) + p)[2] for lt, p in
       ((108, loop), (0, null_be), (0, null_le))], [1, 1, 1])
check('ARP and a link type not known here: nothing read', (capture.decode(1, bytes(16) + pcapgen.ether(b'\0' * 28, 0x0806)),
                                                          capture.decode(147, bytes(16) + b'\0' * 40)), (None, None))
try:
    capture.Stream().feed(b'\0' * 24)
    refused = False
except capture.StreamError:
    refused = True
check('bytes that are not pcap: refused', refused, True)
big = pcapgen.capture([(T0, pcapgen.frame('192.0.2.10', '198.51.100.10', 17, pcapgen.udp(1, 2, b'')))])
big = big[:24] + struct.pack('<IIII', 0, 0, capture.MAX_RECORD + 1, 0)
try:
    capture.Stream().feed(big)
    refused = False
except capture.StreamError:
    refused = True
check('a record larger than tcpdump writes: refused', refused, True)

# what is kept: the first KEEP packets of a connection, in the window it began in
long_conn = pcapgen.tcp_connection(T0 + 50, '192.0.2.10', 50010, '198.51.100.10', 443, hello)
long_conn += [(T0 + 51 + i, pcapgen.frame('198.51.100.10', '192.0.2.10', 6,
                                         pcapgen.tcp(443, 50010, 60000 + i * 100, 9999, 0x10, b'y' * 100), to_server=False))
              for i in range(40)]
stream, got = stream_of(long_conn)
fl = capture.Flows('lan', 60, T0)
for ts, rec, wire in got:
    fl.packet(stream.linktype, ts, rec, wire)
index = fl.window_of(T0 + 50)
check('a connection longer than its window: its first 16 packets kept in the window it began in, the rest counted',
      (len(fl.windows[index].records), list(fl.table.values())[0].packets, sorted(fl.windows)), (16, len(long_conn), [index]))
win = fl.close(index)
check('a window closed: its records and its connection handed over, and gone from the capture',
      (len(win.records), len(win.flows), index in fl.windows), (16, 1, False))
late = [(T0 + 52, pcapgen.frame('192.0.2.11', '198.51.100.11', 17, pcapgen.udp(1, 2, b'')))]
stream, got = stream_of(late)
for ts, rec, wire in got:
    fl.packet(stream.linktype, ts, rec, wire)
check('a connection begun in a window already closed: not followed, counted late', (fl.late, len(fl.table)), (1, 1))
fl.MAX_WINDOW_FLOWS = 2
stream, got = stream_of([(T0 + 121 + i, pcapgen.frame('192.0.2.%d' % (20 + i), '198.51.100.10', 17,
                                                      pcapgen.udp(1000 + i, 53, b'q'))) for i in range(4)])
for ts, rec, wire in got:
    fl.packet(stream.linktype, ts, rec, wire)
check('a window past its number of connections: the rest not followed, the window marked',
      (len(fl.windows[fl.window_of(T0 + 121)].flows), fl.windows[fl.window_of(T0 + 121)].capped, fl.not_followed), (2, True, 2))
check('a connection not heard from for 180 s: forgotten', fl.forget(T0 + 50 + 40 + 181) >= 1, True)
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, 'w.pcap')
    capture.pcap_file(path, stream.header, [r for _, r, _ in got[:2]])
    again = capture.Stream()
    check('a window\'s file: the stream\'s own header and its records, read back as they were',
          [r for _, r, _ in again.feed(open(path, 'rb').read())], [r for _, r, _ in got[:2]])


def feed(flows, packets):
    stream, got = stream_of(packets)
    for ts, rec, wire in got:
        flows.packet(stream.linktype, ts, rec, wire)


def only(flows):
    return list(flows.table.values())[0]


# a window's bytes, checked before each packet is kept: a UDP record here is 16 + 42 + 200 bytes
fl = capture.Flows('lan', 60, T0)
fl.MAX_WINDOW_BYTES = 600
feed(fl, [(T0 + 70 + i * 0.01, pcapgen.frame('192.0.2.10', '198.51.100.30', 17, pcapgen.udp(40000, 9000, b'b' * 200)))
          for i in range(6)])
w, f = fl.windows[fl.window_of(T0 + 70)], only(fl)
check('a window\'s bytes checked before each packet: never past them, the window marked, the connection cut and counted',
      (w.kept_bytes <= 600, len(w.records), w.capped, f.keep, f.cut, f.kept, f.packets), (True, 2, True, False, True, 2, 6))
check('a connection cut short that nDPI did not name: not judged, not called unknown', classify.judge({f.key: f}, {}, {}),
      ([], 1))
cut_row = {'proto': 17, 'src': '192.0.2.10', 'sport': 40000, 'dst': '198.51.100.30', 'dport': 9000, 'name': 'IPsec',
           'by_ip': '', 'server_name': '', 'packets': 2}
check('a connection cut short that nDPI named from what it kept: named', [r[0] for r in classify.judge(
    {f.key: f}, {f.key: cut_row}, {f.key: cut_row})[0]], ['named'])

# what a ClientHello put together, let go: at the connection's 16th packet, and when its window closes
f = only(one(pcapgen.tcp_connection(T0 + 3, '192.0.2.10', 50020, '198.51.100.10', 443, hello, mss=100)))
check('a ClientHello longer than 16 packets: what was put together let go at the 16th, no JA4',
      (f.kept, f.segments, f.hello_done, f.ja4), (16, None, True, None))
fl = one(pcapgen.tcp_connection(T0 + 4, '192.0.2.10', 50021, '198.51.100.10', 443, hello)[:4])
f = only(fl)
waiting = f.segments is not None
fl.close(fl.window_of(T0 + 4))
check('a ClientHello not whole when its window closes: let go then', (waiting, f.segments, f.hello_done), (True, None, True))

# the same two ends again
fl = capture.Flows('lan', 60, T0)
feed(fl, pcapgen.tcp_connection(T0 + 5, '192.0.2.10', 50030, '198.51.100.10', 443, data=b'a' * 10))
old = only(fl)
fl.close(fl.window_of(T0 + 5))
feed(fl, pcapgen.tcp_connection(T0 + 65, '192.0.2.10', 50030, '198.51.100.10', 443, data=b'b' * 10))
new = only(fl)
check('a SYN on the same ends, the old connection\'s window closed: a new connection, begun, in the window it began in',
      (new is not old, new.started, new.window, [x is new for x in getattr(fl.windows.get(fl.window_of(T0 + 65)), 'flows', [])]),
      (True, True, fl.window_of(T0 + 65), [True]))
fl.close(fl.window_of(T0 + 65))
synack = pcapgen.frame('198.51.100.10', '192.0.2.10', 6, pcapgen.tcp(443, 50030, 50000, 1001, 0x12), to_server=False)
feed(fl, [(T0 + 125, synack)])
check('a SYN and ACK sent again by the server after its window closed: no new connection', only(fl) is new, True)
fl = capture.Flows('lan', 60, T0)
fin = [(T0 + 10.5, pcapgen.frame('192.0.2.10', '198.51.100.10', 6, pcapgen.tcp(50031, 80, 2000, 50001, 0x11)))]
feed(fl, pcapgen.tcp_connection(T0 + 10, '192.0.2.10', 50031, '198.51.100.10', 80, data=b'x') + fin)
old = only(fl)
feed(fl, pcapgen.tcp_connection(T0 + 11, '192.0.2.10', 50031, '198.51.100.10', 80, data=b'y'))
check('a FIN seen, then a SYN on the same ends in the same window: a new connection', (old.ended, only(fl) is not old,
                                                                                      only(fl).started), (True, True, True))
fl = capture.Flows('lan', 60, T0)
syn = pcapgen.frame('192.0.2.10', '198.51.100.10', 6, pcapgen.tcp(50032, 443, 1000, 0, 0x02))
feed(fl, [(T0 + 12, syn), (T0 + 13, syn)])
check('a SYN sent again, its connection open in its window: the same connection', (len(fl.table), only(fl).packets), (1, 2))
fl = capture.Flows('lan', 60, T0)
udp_k = pcapgen.frame('192.0.2.10', '198.51.100.40', 17, pcapgen.udp(40001, 4500, b'k'))
feed(fl, [(T0 + 20, udp_k)])
first = only(fl)
fl.forget(T0 + 20 + 181)
feed(fl, [(T0 + 220, udp_k)])
check('a UDP connection forgotten as idle, heard from again: not taken as begun here', (first.started, only(fl) is not first,
                                                                                      only(fl).started), (True, True, False))
fl.forget(T0 + 220 + 181)
fl.forget(T0 + 220 + 181 + 3601)
feed(fl, [(T0 + 220 + 181 + 3602, udp_k)])
check('the same ends an hour after they were forgotten: a connection begun', (only(fl).started, len(fl.gone)), (True, 0))
fl = capture.Flows('lan', 60, T0)
check('the reader\'s offset to start with: the wall clock less the monotonic one, now', abs(
    fl.offset - (time.time() - time.monotonic())) < 5, True)
fl.offset = 1000.0
feed(fl, pcapgen.tcp_connection(T0 + 5, '192.0.2.10', 50090, '198.51.100.10', 443, data=b'x'))
before_step = only(fl)
fl.offset = 1030.0          # the wall clock stepped 30 s forward
feed(fl, pcapgen.tcp_connection(T0 + 40, '192.0.2.10', 50091, '198.51.100.10', 443, data=b'x'))
after_step = [f for f in fl.table.values() if f is not before_step][0]
check('a connection\'s first packet on the monotonic clock beside the wall clock\'s: its time less the offset the reader '
      'saw - a clock stepped 30 s forward between two connections 35 s apart leaves them 5 s apart there, as pf counts',
      (before_step.first, before_step.began, after_step.began - before_step.began), (T0 + 5, T0 + 5 - 1000.0, 5.0))


# ------------------------------------------------------------------- judged, and what follows from it
class F:
    """A connection as capture.Flow gives it, for the records."""

    def __init__(self, server, started=True, sni=None, ja4=None, proto=6, client=('192.0.2.10', 50000), iface='lan',
                 ended=False, first=None, packets=10):
        self.server, self.client, self.started, self.sni, self.ja4, self.proto, self.iface = (
            server, client, started, sni, ja4, proto, iface)
        self.cut = False
        self.ended = ended
        self.packets = packets
        self.first = T0 + 1 if first is None else first
        self.began = self.first                     # the monotonic clock's, standing in
        self.key = capture.flow_key(proto, client[0], client[1], server[0], server[1])


def row(flow, name, server_name=''):
    return {'proto': flow.proto, 'src': flow.client[0], 'sport': flow.client[1], 'dst': flow.server[0],
            'dport': flow.server[1], 'name': name, 'by_ip': '', 'server_name': server_name, 'packets': 8}


named = F(('198.51.100.10', 443), sni='www.youtube.com', ja4=pcapgen.CHROME_JA4)
plain_tls = F(('198.51.100.20', 443), client=('192.0.2.10', 50002), sni='api.example.com', ja4=pcapgen.CHROME_JA4)
dns_flow = F(('198.51.100.53', 53), client=('192.0.2.10', 53000), proto=17)
guessed = F(('203.0.113.7', 443), client=('192.0.2.10', 50005))
unknown = F(('203.0.113.5', 5201), client=('192.0.2.10', 50004))
midway = F(('203.0.113.9', 8080), client=('192.0.2.10', 50006), started=False)
mid_named = F(('203.0.113.10', 80), client=('192.0.2.10', 50011), started=False)
flows = {f.key: f for f in (named, plain_tls, dns_flow, guessed, unknown, midway, mid_named)}
rows_dpi = {named.key: row(named, 'TLS.YouTube', 'www.youtube.com'), plain_tls.key: row(plain_tls, 'TLS', 'api.example.com'),
            dns_flow.key: row(dns_flow, 'DNS', 'www.example.com'), mid_named.key: row(mid_named, 'HTTP.Canonical')}
rows_any = dict(rows_dpi)
rows_any[guessed.key] = row(guessed, 'TLS')
orphan = F(('203.0.113.20', 443), client=('192.0.2.30', 40000))
rows_dpi[orphan.key] = rows_any[orphan.key] = row(orphan, 'TLS.NetFlix')
records, not_judged = classify.judge(flows, rows_any, rows_dpi)
check('judged: named by DPI, guessed only with guessing on, unknown when begun here and named in neither',
      sorted((r[0], r[1]) for r in records),
      sorted([('named', 'TLS.YouTube'), ('named', 'TLS'), ('named', 'DNS'), ('guessed', 'TLS'), ('unknown', None),
              ('named', 'HTTP.Canonical'), ('named', 'TLS.NetFlix')]))
check('a connection not begun here and named by neither run: not judged', not_judged, 1)
check('a row no capture matched: named all the same, its ends from the row', [r[2] for r in records if r[1] == 'TLS.NetFlix'],
      [None])

catalogue = {'categories': {'5': 'Web', '14': 'Network', '1': 'Media', '26': 'Video', '19': 'SoftwareUpdate'},
             'protocols': {'YouTube': 'Media', 'TLS': 'Web', 'DNS': 'Network', 'NetFlix': 'Video',
                           'Canonical': 'SoftwareUpdate', 'HTTP': 'Web'}}
aliases = {tables.alias_name(tables.CATEGORY_PREFIX, c): {'kind': 'category', 'name': c}
           for c in catalogue['categories'].values()}
aliases['appcontrol_YouTube'] = {'kind': 'application', 'name': 'YouTube'}
aliases['appcontrol_DNS'] = {'kind': 'application', 'name': 'DNS'}
# ifconfig -a as FreeBSD writes it: the WAN, two internal interfaces (a CARP address on one, the other
# written /25), the loopback and a point-to-point link
IFCONFIG_TEXT = '''em0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tether 02:00:00:00:00:10
\tinet 203.0.113.2 netmask 0xffffff00 broadcast 203.0.113.255
\tinet6 fe80::10%em0 prefixlen 64 scopeid 0x1
em1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tether 02:00:00:00:00:11
\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255
\tinet 192.0.2.3 netmask 0xffffff00 broadcast 192.0.2.255 vhid 1
\tinet6 fe80::11%em1 prefixlen 64 scopeid 0x2
\tinet6 2001:db8:1::1 prefixlen 64
em2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 198.51.100.129/25 broadcast 198.51.100.255
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
pppoe0: flags=88d1<UP,POINTOPOINT,RUNNING,NOARP,SIMPLEX,MULTICAST> metric 0 mtu 1492
\tinet 203.0.113.50 --> 203.0.113.1 netmask 0xffffffff
'''
NET = classify.Network(IFCONFIG_TEXT, {'em1', 'em2'})
state = classify.State(T0, catalogue, {'apps': ['YouTube', 'DNS', 'TLS']}, [('lan', 'em1')])
state.network = NET
fake = FakePf()
counts = classify.apply(state, records, tables.Pf(run=fake), aliases, T0 + 70)
check('into the tables: each server named by DPI and begun here, in its category\'s table and its chosen application\'s',
      {t: sorted(a) for t, a in fake.held.items()},
      {'appcontrol_cat_Media': ['198.51.100.10'], 'appcontrol_YouTube': ['198.51.100.10'],
       'appcontrol_cat_Web': ['198.51.100.20'], 'appcontrol_cat_Network': ['198.51.100.53'],
       'appcontrol_DNS': ['198.51.100.53']})
check('never into a table: a guess, an unknown connection, one not begun here, one no capture matched',
      any(a in v for v in fake.held.values() for a in ('203.0.113.7', '203.0.113.5', '203.0.113.10', '203.0.113.20')), False)
check('TLS chosen, but no table of it in config.xml: none written', 'appcontrol_TLS' in fake.held, False)
check('the counts of the window', {k: counts[k] for k in ('flows', 'named', 'guessed', 'unknown', 'no_app', 'added')},
      {'flows': 7, 'named': 5, 'guessed': 1, 'unknown': 1, 'no_app': 1, 'added': 5})
rows_u = {(r['kind'], r['server']): r for r in state.unknown.values()}
check('the Unknown list: not named, guessed (with nDPI\'s guess), and TLS alone (with its server name and JA4)',
      sorted(rows_u), sorted([('unknown', '203.0.113.5'), ('guess', '203.0.113.7'), ('no_app', '198.51.100.20')]))
check('Unknown: TLS alone keeps what its client sent first', (rows_u[('no_app', '198.51.100.20')]['server_name'],
                                                              rows_u[('no_app', '198.51.100.20')]['ja4']),
      ('api.example.com', pcapgen.CHROME_JA4))
check('Unknown: a guess keeps nDPI\'s guess', rows_u[('guess', '203.0.113.7')]['name'], 'TLS')
check('Applications: YouTube named once, its category, carried by TLS', (lambda a: (a['named'], a['category'], a['protocols']))(
    state.apps['YouTube']), (1, 'Media', ['TLS']))
check('Applications: TLS named once and guessed once', (state.apps['TLS']['named'], state.apps['TLS']['guessed']), (1, 1))
counts = classify.apply(state, records, tables.Pf(run=fake), aliases, T0 + 130)
check('the same servers again: refreshed, not added', (counts['added'], counts['refreshed']), (0, 5))
check('the same unknown connection again: one row, two connections', rows_u[('unknown', '203.0.113.5')]['connections'], 2)
for i in range(600):
    classify._unknown(state, 'unknown', None, 6, ('203.0.113.%d' % (i % 250), 1000 + i), '', '', 'lan', T0 + 200 + i)
classify.apply(state, [], tables.Pf(run=fake), aliases, T0 + 900)
kinds = {}
for r in state.unknown.values():
    kinds.setdefault(r['kind'], []).append(r['last'])
check('the Unknown list: the latest 500 of each kind kept - 600 more not named push none of the others out',
      {k: (len(v), min(v)) for k, v in kinds.items()}, {'unknown': (500, T0 + 300), 'guess': (1, T0 + 130),
                                                       'no_app': (1, T0 + 130)})
check('the Unknown list as written: all of it, latest first', [r['last'] for r in state.unknown_rows()][:2] + [
    len(state.unknown_rows())], [T0 + 799, T0 + 798, 502])
status = state.status()
check('status.json: what the page reads', sorted(status), sorted(['since', 'windows', 'window', 'totals', 'apps', 'last', 'error',
                                                                  'capped_windows', 'dropped_windows', 'stopped', 'interfaces',
                                                                  'engine', 'blocking', 'remembered', 'waiting_cut',
                                                                  'last_cut', 'rule_cut', 'unread_sources']))
check('status.json: the totals', {k: status['totals'][k] for k in ('named', 'guessed', 'unknown', 'no_app', 'added', 'refreshed')},
      {'named': 10, 'guessed': 2, 'unknown': 2, 'no_app': 2, 'added': 5, 'refreshed': 5})

# never into a table: the firewall, its internal networks, an address that is no server's, ICMP
check('ifconfig -a read: the firewall\'s own addresses, in every way ifconfig writes them', sorted(str(a) for a in NET.own),
      sorted(['203.0.113.2', 'fe80::10', '192.0.2.1', '192.0.2.3', 'fe80::11', '2001:db8:1::1', '198.51.100.129', '127.0.0.1',
              '::1', '203.0.113.50']))
check('ifconfig -a read: the networks of the internal interfaces, and those alone', sorted(str(n) for n in NET.networks),
      ['192.0.2.0/24', '198.51.100.128/25', '2001:db8:1::/64', 'fe80::/64'])
cases = [(6, '198.51.100.10', None), (6, '203.0.113.7', None), (1, '198.51.100.10', 'icmp'), (58, '2001:db8::443', 'icmp'),
         (17, '224.0.0.251', 'address'), (17, 'ff02::fb', 'address'), (17, '255.255.255.255', 'address'),
         (17, '203.0.113.255', 'address'), (17, '192.0.2.255', 'address'), (6, '169.254.10.1', 'address'),
         (6, 'fe80::2', 'address'), (6, '127.0.0.1', 'address'), (6, '::1', 'address'), (6, '0.0.0.0', 'address'),
         (6, '::', 'address'), (6, '192.0.2.1', 'own'), (6, '192.0.2.3', 'own'), (6, '203.0.113.2', 'own'),
         (6, '203.0.113.50', 'own'), (6, '2001:db8:1::1', 'own'), (6, '192.0.2.50', 'lan'), (6, '2001:db8:1::50', 'lan'),
         (6, '198.51.100.130', 'lan')]
check('why a server goes into no table: ICMP; multicast, broadcast, link-local, loopback, unspecified; the firewall\'s own; '
      'a host of an internal network - and a server out there, or on the WAN\'s network, goes in',
      [NET.why_not(p, s) for p, s, _ in cases], [w for _, _, w in cases])
check('the firewall\'s addresses not read: nothing goes into a table', classify.Network('', {'em1'}).why_not(6, '198.51.100.10'),
      'unread')
lan_host = F(('192.0.2.50', 443), client=('203.0.113.99', 40001))
firewall = F(('192.0.2.1', 53), client=('192.0.2.10', 40002), proto=17)
mdns = F(('224.0.0.251', 5353), client=('192.0.2.10', 5353), proto=17)
ping = F(('198.51.100.10', 0), client=('192.0.2.10', 0), proto=1)
tls_midway = F(('198.51.100.21', 443), client=('192.0.2.10', 50040), started=False)
special = [('named', 'TLS.YouTube', lan_host, row(lan_host, 'TLS.YouTube')), ('named', 'DNS', firewall, row(firewall, 'DNS')),
           ('named', 'MDNS', mdns, row(mdns, 'MDNS')), ('named', 'ICMP', ping, row(ping, 'ICMP')),
           ('named', 'TLS', tls_midway, row(tls_midway, 'TLS')), ('named', 'TLS', None, row(tls_midway, 'TLS'))]
state = classify.State(T0, catalogue, {'apps': ['YouTube', 'DNS']}, [('lan', 'em1')])
state.network = NET
fake = FakePf()
counts = classify.apply(state, special, tables.Pf(run=fake), aliases, T0 + 70)
check('a LAN host, the firewall, a multicast address and ICMP, named: counted as named, in no table, the reason kept',
      (counts['named'], counts['not_tabled'], fake.held, state.not_tabled),
      (6, 4, {}, {'icmp': 1, 'address': 1, 'own': 1, 'lan': 1, 'unread': 0}))
check('TLS alone, on a connection not begun here or matched by no capture: no "no application" row, not counted',
      (counts['no_app'], [r['kind'] for r in state.unknown.values()]), (0, []))
check('status.json: the connections named and put in no table, and why', (lambda t: (t['not_tabled'], t['not_tabled_why']['lan']))(
    state.status()['totals']), (4, 1))

# ------------------------------------------------------------- a packet the reader cannot make sense of
pipe_r, pipe_w = os.pipe()
reader = classify.Capture('lan', 'em1', T0)
reader.proc = type('Proc', (), {'stdout': os.fdopen(pipe_r, 'rb')})()
reader.flows.offset = 0.0   # as seen before a clock step
os.write(pipe_w, pcapgen.capture(dns))
os.close(pipe_w)
real_decode = capture.decode


def broken(linktype, record):
    raise IndexError('a packet like no other')


capture.decode = broken
try:
    alive = reader.read(T0 + 6)
finally:
    capture.decode = real_decode
check('a packet the reader cannot make sense of: counted, and the capture goes on', (alive, reader.flows.unread), (True, 2))
check('each read takes the wall clock less the monotonic one again, for the packets it hands over',
      abs(reader.flows.offset - (time.time() - time.monotonic())) < 5, True)
reader.proc.stdout.close()


# ------------------------------------------------------------------------------- the interfaces watched
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><interfaces>'
                     '<wan><enable>1</enable><if>em0</if><ipaddr>203.0.113.2</ipaddr></wan>'
                     '<lan><enable>1</enable><if>em1</if><ipaddr>192.168.1.1</ipaddr></lan>'
                     '<opt6><enable>1</enable><if>em6</if><ipaddr>dhcp</ipaddr></opt6>'
                     '<opt1><enable>1</enable><if>em2</if><ipaddr>10.0.0.1</ipaddr><gateway>GW2</gateway></opt1>'
                     '<opt2><if>em3</if><ipaddr>172.16.0.1</ipaddr></opt2>'
                     '<opt3><enable>1</enable><if>em4</if><ipaddr>none</ipaddr><ipaddrv6>track6</ipaddrv6></opt3>'
                     '<opt4><enable>1</enable><if>wg0</if><ipaddr>none</ipaddr></opt4>'
                     '<opt5><enable>1</enable><if>em5</if><ipaddrv6>dhcp6</ipaddrv6><ipaddr>192.0.2.1</ipaddr></opt5>'
                     '<lo0><internal_dynamic>1</internal_dynamic><enable>1</enable><if>lo0</if><ipaddr>127.0.0.1</ipaddr></lo0>'
                     '</interfaces></opnsense>')
    check('none chosen: the internal ones - not the WAN, static or not; no gateway; switched on; an address of its own, '
          'not from upstream',
          classify.interfaces({'interfaces': []}, config), [('lan', 'em1'), ('opt3', 'em4')])
    check('chosen: those, switched on', classify.interfaces({'interfaces': ['opt4', 'opt2', 'wan']}, config),
          [('wan', 'em0'), ('opt4', 'wg0')])
    check('the internal networks, for the tables: those of the interfaces internal by default, whatever Settings chose, '
          'and those watched', classify.lan_devices([('opt4', 'wg0')], config), {'em1', 'em4', 'wg0'})
    text = open(config).read().replace('</interfaces>', '</interfaces><gateways><gateway_item><interface>opt3</interface>'
                                                        '<name>GW_OPT3</name></gateway_item></gateways>')
    with open(config, 'w') as handle:
        handle.write(text)
    check('none chosen: not one System: Gateways gives a gateway', classify.interfaces({'interfaces': []}, config),
          [('lan', 'em1')])


# ------------------------------------------------------------- a capture that stops: tried again, said once
with tempfile.TemporaryDirectory() as tmp:
    quitter, writer = os.path.join(tmp, 'quits'), os.path.join(tmp, 'writes')
    program(quitter, '#!/bin/sh\nexit 1\n')
    program(writer, '#!/usr/bin/env python3\nimport sys, time\nsys.path.insert(0, %r)\nimport pcapgen\n'
            'sys.stdout.buffer.write(pcapgen.header())\nsys.stdout.buffer.flush()\ntime.sleep(30)\n' % HERE)
    said = []
    real_log = classify.log
    classify.log = said.append
    try:
        state = classify.State(T0, catalogue, {'apps': []}, [('opt9', 'em9')])
        cap = classify.Capture('opt9', 'em9', T0, tcpdump=quitter)
        t, waits = T0, []
        for _ in range(7):
            if cap.start(t):
                cap.proc.wait()
                cap.read(t)
            cap.trouble(state, t)
            waits.append(cap.retry_at - t)
            t = cap.retry_at
        check('a capture stopping again and again - its device gone: started again after 30 s, the wait doubled each time '
              'to 10 minutes, said once', (waits, said), ([30, 60, 120, 240, 480, 600, 600],
                                                          ['tcpdump stopped on em9: there is no such device']))
        cap.tcpdump = writer
        cap.start(t)
        deadline = time.time() + 10
        while cap.stream.header is None and time.time() < deadline:
            select.select([cap], [], [], 0.5)
            cap.read(t)
        check('the capture reading again: said, and its wait back to 30 s', (said[1:], cap.delay, cap.failing),
              (['Application Control: capturing again on opt9 (em9)'], 30, False))
        cap.stop()
    finally:
        classify.log = real_log


# ------------------------------------------------------------- the window files' directory, in memory
with tempfile.TemporaryDirectory() as tmp:
    work = os.path.join(tmp, 'work')
    os.makedirs(work)
    tables_seen = [(['/dev/ada0p2 / ufs rw 1 1', 'tmpfs %s tmpfs rw,size=167772160,mode=0750 0 0' % work], True),
                   (['/dev/md3 %s ufs rw 0 0' % work], True),
                   (['/dev/ada0p2 / ufs rw 1 1'], False),
                   (['tmpfs %s tmpfs rw 0 0' % work, '/dev/ada0p3 %s ufs rw 0 0' % work], False)]
    check('the work directory in memory: a tmpfs or an md(4) there; not when nothing is mounted there, or a disk on top',
          [classify.in_memory(work, mounted(tmp, lines)) for lines, _ in tables_seen], [want for _, want in tables_seen])
    check('the work directory, mount not to be run: not taken as in memory', classify.in_memory(work, os.path.join(tmp, 'none')),
          False)


# ------------------------------------------------------------- one run of the service, with stand-ins
HEADER = open(os.path.join(FIX, 'lab-update.csv'), encoding='utf-8').readline()


def csv_rows(pairs):
    """The CSV ndpiReader writes, with the lab's header: a row for each (flow, name), the columns not
    read here left empty."""
    head = HEADER.lstrip('#').rstrip('\n').split('|')
    out = [HEADER.rstrip('\n')]
    for i, (fl, name, sni) in enumerate(pairs):
        cells = [''] * len(head)
        for k, v in (('flow_id', i), ('protocol', fl[0]), ('src_ip', fl[1]), ('src_port', fl[2]), ('dst_ip', fl[3]),
                     ('dst_port', fl[4]), ('ndpi_proto', name), ('server_name_sni', sni), ('c_to_s_pkts', 4),
                     ('s_to_c_pkts', 4), ('proto_by_ip', 'Unknown')):
            cells[head.index(k)] = str(v)
        out.append('|'.join(cells))
    return '\n'.join(out) + '\n'


with tempfile.TemporaryDirectory() as tmp:
    named_flow = (6, '192.0.2.10', 50001, '198.51.100.10', 443)
    tls_only = (6, '192.0.2.10', 50002, '198.51.100.20', 443)
    dns_one = (17, '192.0.2.10', 53000, '198.51.100.53', 53)
    guess_one = (6, '192.0.2.10', 50005, '203.0.113.7', 443)
    v6_one = (6, '2001:db8::10', 50007, '2001:db8::443', 443)
    with open(os.path.join(tmp, 'any.csv'), 'w') as handle:
        handle.write(csv_rows([(named_flow, 'TLS.YouTube', 'www.example.com'), (tls_only, 'TLS', 'www.example.com'),
                               (dns_one, 'DNS', 'www.example.com'), (guess_one, 'TLS', ''),
                               (v6_one, 'TLS.NetFlix', 'www.example.com')]))
    with open(os.path.join(tmp, 'dpi.csv'), 'w') as handle:
        handle.write(csv_rows([(named_flow, 'TLS.YouTube', 'www.example.com'), (tls_only, 'TLS', 'www.example.com'),
                               (dns_one, 'DNS', 'www.example.com'), (v6_one, 'TLS.NetFlix', 'www.example.com')]))
    calls = os.path.join(tmp, 'calls')
    # ndpiReader: the CSV of the run asked for, and how it was asked
    program(os.path.join(tmp, 'ndpiReader'), '#!/usr/bin/env python3\nimport shutil, sys\n'
            'open(%r, "a").write("ndpiReader " + " ".join(sys.argv[1:]) + "\\n")\n'
            'a = sys.argv\ncsv = a[a.index("-C") + 1]\n'
            'shutil.copy(%r if "-d" in a else %r, csv)\n'
            % (calls, os.path.join(tmp, 'dpi.csv'), os.path.join(tmp, 'any.csv')))
    # tcpdump: a capture of these connections, stamped now, written to the pipe; then it waits
    program(os.path.join(tmp, 'tcpdump'), '#!/usr/bin/env python3\nimport os, sys, time\nsys.path.insert(0, %r)\n'
            'import pcapgen\n'
            'open(%r, "a").write("tcpdump " + " ".join(sys.argv[1:]) + "\\n")\n'
            'open(%r, "w").write(str(os.getpid()))\n'
            't = time.time()\nhello = pcapgen.client_hello(padding=1700)\n'
            'p = pcapgen.tcp_connection(t, "192.0.2.10", 50001, "198.51.100.10", 443, hello)\n'
            'p += pcapgen.tcp_connection(t, "192.0.2.10", 50002, "198.51.100.20", 443, pcapgen.client_hello(sni="api.example.com"))\n'
            'p += [(t, pcapgen.frame("192.0.2.10", "198.51.100.53", 17, pcapgen.udp(53000, 53, pcapgen.dns_query())))]\n'
            'p += pcapgen.tcp_connection(t, "192.0.2.10", 50004, "203.0.113.5", 5201, data=b"z" * 300)\n'
            'p += pcapgen.tcp_connection(t, "192.0.2.10", 50005, "203.0.113.7", 443, data=b"\\x00" * 64)\n'
            'p += pcapgen.tcp_connection(t, "192.0.2.10", 50006, "203.0.113.9", 8080, syn=False, data=b"m" * 64)\n'
            'p += pcapgen.tcp_connection(t, "2001:db8::10", 50007, "2001:db8::443", 443, hello)\n'
            'sys.stdout.buffer.write(pcapgen.capture(p))\nsys.stdout.buffer.flush()\n'
            'while True:\n    time.sleep(1)\n' % (HERE, calls, os.path.join(tmp, 'tcpdump.pid')))
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><interfaces><lan><enable>1</enable><if>em1</if><ipaddr>192.0.2.1</ipaddr></lan>'
                     '<wan><enable>1</enable><if>em0</if><ipaddr>dhcp</ipaddr></wan></interfaces>'
                     '<OPNsense><Firewall><Alias><aliases>' + ''.join(
                         '<alias><enabled>1</enabled><name>%s</name><type>external</type><description>Application Control: %s'
                         '</description></alias>' % (n, d) for n, d in (
                             ('appcontrol_cat_Media', 'category Media'), ('appcontrol_cat_Web', 'category Web'),
                             ('appcontrol_cat_Network', 'category Network'), ('appcontrol_cat_Video', 'category Video'),
                             ('appcontrol_YouTube', 'YouTube'))) +
                     '</aliases></Alias></Firewall><AppControl><general><classify>1</classify><apps>YouTube</apps>'
                     '</general></AppControl></OPNsense></opnsense>')
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump(catalogue, handle)
    with open(os.path.join(tmp, 'ifconfig.txt'), 'w') as handle:
        handle.write(IFCONFIG_TEXT)
    program(os.path.join(tmp, 'ifconfig'), '#!/bin/sh\necho "ifconfig $*" >> %s\ncat %s\n' % (calls, os.path.join(tmp, 'ifconfig.txt')))
    classify.WINDOW, classify.GRACE = 2.0, 1.0
    capture.Flows.SETTLE = 0.0
    fake = FakePf()
    started = time.time()
    state = classify.serve(stop_after=2, reader=os.path.join(tmp, 'ndpiReader'), tcpdump=os.path.join(tmp, 'tcpdump'),
                           pf=tables.Pf(run=fake), config=config, catalogue_path=os.path.join(tmp, 'ndpi.json'),
                           status=os.path.join(tmp, 'status.json'), unknown=os.path.join(tmp, 'unknown.json'),
                           work=os.path.join(tmp, 'work'), refresh=False, ifconfig=os.path.join(tmp, 'ifconfig'),
                           mount=mounted(tmp))
    took = time.time() - started
    asked = open(calls).read().splitlines()
    check('the service: the firewall\'s addresses read at its start and again at each window\'s close',
          [line for line in asked if line.startswith('ifconfig')], ['ifconfig -a'] * 3)
    dump = [line for line in asked if line.startswith('tcpdump')]
    check('the service: tcpdump on the internal interface alone, -p (no promiscuous port), each packet as it comes, whole, to its pipe',
          dump, ['tcpdump -p -n -U -i em1 -s 0 -w - ip or ip6'])
    readers = [line for line in asked if line.startswith('ndpiReader')]
    check('the service: ndpiReader twice over the window\'s file, once with guessing off',
          (len(readers), sum(1 for line in readers if line.endswith(' -d'))), (2, 1))
    check('the service: the tables', {t: sorted(a) for t, a in fake.held.items()},
          {'appcontrol_cat_Media': ['198.51.100.10'], 'appcontrol_YouTube': ['198.51.100.10'],
           'appcontrol_cat_Web': ['198.51.100.20'], 'appcontrol_cat_Network': ['198.51.100.53'],
           'appcontrol_cat_Video': ['2001:db8::443']})
    saved = json.load(open(os.path.join(tmp, 'status.json')))
    check('the service: status.json - named, guessed, unknown, TLS alone, not judged',
          {k: saved['totals'][k] for k in ('named', 'guessed', 'unknown', 'no_app', 'not_judged')},
          {'named': 4, 'guessed': 1, 'unknown': 1, 'no_app': 1, 'not_judged': 1})
    unknown_rows = json.load(open(os.path.join(tmp, 'unknown.json')))
    check('the service: unknown.json - TLS alone with the server name and JA4 its client sent, a guess, one not named',
          sorted((r['kind'], r['server'], r['server_name'], r['ja4'][:10]) for r in unknown_rows),
          [('guess', '203.0.113.7', '', ''), ('no_app', '198.51.100.20', 'www.example.com', 't13d1516h2'),
           ('unknown', '203.0.113.5', '', '')])
    check('the service: the window\'s files removed', os.listdir(os.path.join(tmp, 'work')), [])
    pid = int(open(os.path.join(tmp, 'tcpdump.pid')).read())
    try:
        os.kill(pid, 0)
        alive = True
    except OSError:
        alive = False
    check('the service: tcpdump stopped with it, and the service said when', (alive, saved['stopped'] is not None),
          (False, True))
    check('the service: two windows of 2 s and 1 s of grace took well under 20 s', took < 20, True)


# ------------------------------------------------------------- a window's ndpiReader runs, one interface at a time
def windows_of(keys):
    """{key: (header, window)}: one window on each interface key, a TLS connection begun in it."""
    out = {}
    for i, key in enumerate(keys):
        stream, got = stream_of(pcapgen.tcp_connection(T0 + 1, '192.0.2.%d' % (20 + i), 50100 + i, '198.51.100.10', 443,
                                                       hello))
        fl = capture.Flows(key, 60, T0)
        for ts, rec, wire in got:
            fl.packet(stream.linktype, ts, rec, wire)
        out[key] = (stream.header, fl.close(fl.window_of(T0 + 1)))
    return out


with tempfile.TemporaryDirectory() as tmp:
    work = os.path.join(tmp, 'work')
    os.makedirs(work)
    log_path = os.path.join(tmp, 'runs')
    good = os.path.join(tmp, 'good.csv')
    with open(good, 'w') as handle:
        handle.write(csv_rows([((6, '192.0.2.20', 50100, '198.51.100.10', 443), 'TLS.YouTube', 'www.example.com')]))
    # ndpiReader: says when it begins and ends and what the work directory holds; on opt1 the DPI run fails,
    # on opt2 no CSV is written, on slow it does not end
    program(os.path.join(tmp, 'ndpiReader'), '#!/usr/bin/env python3\nimport os, shutil, sys, time\n'
            'a = sys.argv\npcap, csv = a[a.index("-i") + 1], a[a.index("-C") + 1]\nname = os.path.basename(pcap)\n'
            'log = open(%r, "a")\nlog.write("begin %%s %%s %%r\\n" %% (name, "-d" in a, sorted(os.listdir(%r))))\nlog.flush()\n'
            'if "slow" in name:\n    time.sleep(30)\n'
            'time.sleep(0.3)\n'
            'if "opt2" not in name:\n    shutil.copy(%r, csv)\n'
            'log.write("end %%s %%s\\n" %% (name, "-d" in a))\n'
            'sys.exit(3 if "opt1" in name and "-d" in a else 0)\n' % (log_path, work, good))
    found = windows_of(['lan', 'opt1', 'opt2'])
    job = classify.Job(7, [(k, h, w) for k, (h, w) in found.items()], os.path.join(tmp, 'ndpiReader'), work)
    while not job.poll():
        time.sleep(0.05)
    flows, rows_any, rows_dpi, problems, skipped = job.results()
    runs = open(log_path).read().splitlines()
    at_once, most = 0, 0
    for line in runs:
        at_once += 1 if line.startswith('begin') else -1
        most = max(most, at_once)
    check('ndpiReader: one interface\'s file at a time, its two runs together - never more than two at once',
          (most, [line.split()[1] for line in runs if line.startswith('begin')]),
          (2, ['7-lan.pcap', '7-lan.pcap', '7-opt1.pcap', '7-opt1.pcap', '7-opt2.pcap', '7-opt2.pcap']))
    listings = [line.split(' ', 3)[3] for line in runs if line.startswith('begin')]
    check('ndpiReader: the work directory holds one interface\'s file when its runs begin',
          [(listing.count('.pcap'), "'7-%s.pcap'" % k in listing) for k, listing in zip(('lan', 'lan', 'opt1', 'opt1', 'opt2', 'opt2'),
                                                                                         listings)], [(1, True)] * 6)
    check('ndpiReader failing on one interface, writing no CSV on another: their connections not judged, the reasons said',
          (sorted(f.iface for f in flows.values()), len(rows_dpi), skipped, problems),
          (['lan'], 1, 2, ['ndpiReader ended with status 3 on opt1', 'ndpiReader wrote no CSV on opt2']))
    check('ndpiReader: every file removed once read', os.listdir(work), [])
    found = windows_of(['slow', 'lan'])
    job = classify.Job(8, [(k, h, w) for k, (h, w) in found.items()], os.path.join(tmp, 'ndpiReader'), work)
    time.sleep(0.5)
    still = job.poll()
    job.kill()
    flows, rows_any, rows_dpi, problems, skipped = job.results()
    check('ndpiReader past its time: stopped, the next interface never run, neither judged, the files removed',
          (still, flows, skipped, problems, os.listdir(work)),
          (False, {}, 2, ['ndpiReader stopped after 120 s on slow', 'ndpiReader not run on lan: the window ran out of its 120 s'],
           []))


SERVICE_CONFIG = ('<opnsense><interfaces><lan><enable>1</enable><if>em1</if><ipaddr>192.0.2.1</ipaddr></lan>'
                  '<wan><enable>1</enable><if>em0</if><ipaddr>dhcp</ipaddr></wan>%s</interfaces>'
                  '<OPNsense><Firewall><Alias><aliases>' + ''.join(
                      '<alias><enabled>1</enabled><name>%s</name><type>external</type><description>Application Control: %s'
                      '</description></alias>' % (n, d) for n, d in (
                          ('appcontrol_cat_Media', 'category Media'), ('appcontrol_cat_Web', 'category Web'),
                          ('appcontrol_cat_Network', 'category Network'), ('appcontrol_YouTube', 'YouTube'))) +
                  '</aliases></Alias></Firewall><AppControl><general><classify>1</classify><apps>YouTube</apps>'
                  '</general></AppControl></OPNsense></opnsense>')
COPY_READER = ('#!/usr/bin/env python3\nimport shutil, sys\nopen(%r, "a").write("ndpiReader " + " ".join(sys.argv[1:]) + "\\n")\n'
               'a = sys.argv\nshutil.copy(%r if "-d" in a else %r, a[a.index("-C") + 1])\n')


def service(tmp, packets, any_rows, dpi_rows, reader=COPY_READER, stop_after=2, cat=None, more_interfaces='',
            timeout=40, change=None, **kwargs):
    """One run of the service with stand-ins, in tmp: tcpdump writing what the Python in packets puts in p
    (t its start, pcapgen there) and then waiting; ndpiReader (reader, %-formatted with the calls file and
    the two CSVs) - COPY_READER copies the CSV of the run asked for; ifconfig and a stand-in pfctl. Two
    windows judged by default: tcpdump's packets can fall in the window after the one the service began
    in. Stopped after timeout s whatever happens. (state, status.json, unknown.json, the programs' calls,
    pfctl's tables)."""
    calls = os.path.join(tmp, 'calls')
    any_csv, dpi_csv = os.path.join(tmp, 'any.csv'), os.path.join(tmp, 'dpi.csv')
    for path, pairs in ((any_csv, any_rows), (dpi_csv, dpi_rows)):
        with open(path, 'w') as handle:
            handle.write(csv_rows(pairs))
    program(os.path.join(tmp, 'ndpiReader'), reader % (calls, dpi_csv, any_csv) if '%r' in reader else reader)
    program(os.path.join(tmp, 'tcpdump'), '#!/usr/bin/env python3\nimport os, sys, time\nsys.path.insert(0, %r)\n'
            'import pcapgen\nopen(%r, "a").write("tcpdump " + " ".join(sys.argv[1:]) + " pid=%%d\\n" %% os.getpid())\n'
            't = time.time()\nhello = pcapgen.client_hello(padding=1700)\np = []\n%s\n'
            'sys.stdout.buffer.write(pcapgen.capture(p))\nsys.stdout.buffer.flush()\n'
            'time.sleep(120)\n' % (HERE, calls, packets))
    with open(os.path.join(tmp, 'ifconfig.txt'), 'w') as handle:
        handle.write(IFCONFIG_TEXT)
    program(os.path.join(tmp, 'ifconfig'), '#!/bin/sh\necho "ifconfig $*" >> %s\ncat %s\n' % (calls, os.path.join(tmp, 'ifconfig.txt')))
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write((change or str)(SERVICE_CONFIG % more_interfaces))
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump(cat or catalogue, handle)
    fake = FakePf()
    if 'mount' not in kwargs:
        kwargs['mount'] = mounted(tmp)
    timer = threading.Timer(timeout, lambda: setattr(classify, 'running', False))
    timer.start()
    try:
        state = classify.serve(stop_after=stop_after, reader=os.path.join(tmp, 'ndpiReader'), tcpdump=os.path.join(tmp, 'tcpdump'),
                               pf=tables.Pf(run=fake), config=config, catalogue_path=os.path.join(tmp, 'ndpi.json'),
                               status=os.path.join(tmp, 'status.json'), unknown=os.path.join(tmp, 'unknown.json'),
                               work=os.path.join(tmp, 'work'), refresh=False, ifconfig=os.path.join(tmp, 'ifconfig'), **kwargs)
    finally:
        timer.cancel()
        classify.running = True
    asked = open(calls).read().splitlines() if os.path.exists(calls) else []
    return (state, json.load(open(os.path.join(tmp, 'status.json'))), json.load(open(os.path.join(tmp, 'unknown.json'))),
            asked, {t: sorted(a) for t, a in fake.held.items()})


TWO = ('p += pcapgen.tcp_connection(t, "192.0.2.10", 50001, "198.51.100.10", 443, hello)\n'
       'p += pcapgen.tcp_connection(t, "192.0.2.10", 50004, "203.0.113.5", 5201, data=b"z" * 300)')
YOUTUBE = [((6, '192.0.2.10', 50001, '198.51.100.10', 443), 'TLS.YouTube', 'www.example.com')]

with tempfile.TemporaryDirectory() as tmp:
    failing = ('#!/bin/sh\ncase "$*" in *" -d"*) exit 1 ;; esac\n'
               'while [ $# -gt 0 ]; do [ "$1" = -C ] && cp %s "$2"; shift; done\n' % os.path.join(tmp, 'any.csv'))
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, reader=failing)
    check('the service, ndpiReader failing on the interface: its connections counted as not judged - none unknown, none '
          'named, no table', ({k: saved['totals'][k] for k in ('named', 'unknown', 'not_judged')}, rows, held,
                              saved['error']['message']),
          ({'named': 0, 'unknown': 0, 'not_judged': 2}, [], {}, 'ndpiReader ended with status 1 on lan'))
with tempfile.TemporaryDirectory() as tmp:
    no_dns = dict(catalogue, protocols={k: v for k, v in catalogue['protocols'].items() if k != 'DNS'})
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, cat=no_dns)
    check('the service, nDPI\'s protocols not to be believed: said, no category table filled, the chosen application\'s still',
          ((saved['error'] or {}).get('message'), held, saved['engine']['protocols']),
          ('the protocols of the installed nDPI cannot be believed (ndpiReader -H was not read as nDPI writes it: DNS in no '
           'category, not Network): no server goes into a category table', {'appcontrol_YouTube': ['198.51.100.10']}, 0))


# ------------------------------------------------------------------------------------------- the clock stepped
fl = capture.Flows('lan', 60, T0 + 590)
feed(fl, pcapgen.tcp_connection(T0 + 600, '192.0.2.10', 50050, '198.51.100.10', 443, data=b'q'))
fl.close(fl.window_of(T0 + 540))
going = only(fl)
back = T0 + 60                                      # the clock set back nine minutes
feed(fl, pcapgen.tcp_connection(back, '192.0.2.10', 50051, '198.51.100.10', 443, data=b'r'))
late = fl.late
dropped = fl.restart(back + 1)
feed(fl, pcapgen.tcp_connection(back + 2, '192.0.2.10', 50052, '198.51.100.10', 443, data=b's'))
check('the clock set back: a connection begun then is late until the windows start again; then kept in the window now, the '
      'window still open dropped, the connection already followed keeping nothing more',
      (late, dropped, sorted(fl.windows), [f.client[1] for f in getattr(fl.windows.get(fl.window_of(back + 2)), 'flows', [])],
       going.keep),
      (4, 1, [fl.window_of(back + 2)], [50052], False))
check('the clock set back: a connection followed is forgotten in the clock\'s new time', (going.last, fl.forget(back + 1 + 181) >= 1),
      (back + 1, True))
feed(fl, [(back + 3, pcapgen.frame('192.0.2.10', '198.51.100.53', 17, pcapgen.udp(53001, 53, pcapgen.dns_query())))])
check('the clock set back before the capture began: a UDP connection begun now is taken as begun',
      [f.started for f in fl.table.values() if f.proto == 17], [True])


class Clock:
    """time.time(), moved by step seconds from its call after the given one on."""

    def __init__(self, step, after):
        self.calls, self.step, self.after = 0, step, after

    def __call__(self):
        self.calls += 1
        return time.time() + (self.step if self.calls > self.after else 0)


with tempfile.TemporaryDirectory() as tmp:
    began = time.time()
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, now=Clock(1000, 3), timeout=20)
    check('the clock gone forward 1000 s: the windows between dropped, not closed one by one - the one judged is one of now',
          (state.last['window'] >= int((began + 1000) // classify.WINDOW), saved['dropped_windows'] >= 499,
           time.time() - began < 15), (True, True, True))
with tempfile.TemporaryDirectory() as tmp:
    began = time.time()
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, now=Clock(-1000, 3), timeout=15, stop_after=1)
    check('the clock gone back 1000 s: windows close again at once, in the clock\'s new time',
          (state.windows, state.last and state.last['window'] < int(began // classify.WINDOW)), (1, True))


# ------------------------------------------------------------- the interfaces, read again at each window's close
def rewrite_later(tmp, change, after=0.3):
    """config.xml changed after a moment, while the service runs."""
    def later():
        path = os.path.join(tmp, 'config.xml')
        try:
            text = change(open(path).read())
            with open(path + '.new', 'w') as handle:
                handle.write(text)
            os.replace(path + '.new', path)
        except OSError:
            pass                                    # the run is over already
    timer = threading.Timer(after, later)
    timer.start()
    return timer


with tempfile.TemporaryDirectory() as tmp:
    opt1 = '<opt1><enable>1</enable><if>em2</if><ipaddr>198.51.100.129</ipaddr></opt1>'
    rewrite_later(tmp, lambda text: text.replace('<lan><enable>1</enable>', '<lan>').replace('</interfaces>', opt1 + '</interfaces>'))
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, stop_after=2)
    alive = []
    for line in asked:
        if line.startswith('tcpdump'):
            try:
                os.kill(int(line.rsplit('pid=', 1)[1]), 0)
                alive.append(line.split(' -i ')[1].split()[0])
            except OSError:
                pass
    check('the interfaces read again at a window\'s close: one switched off since stopped, one assigned since started',
          ([line.split(' -i ')[1].split()[0] for line in asked if line.startswith('tcpdump')],
           [(i['key'], i['device']) for i in saved['interfaces']], alive), (['em1', 'em2'], [('opt1', 'em2')], []))
with tempfile.TemporaryDirectory() as tmp:
    rewrite_later(tmp, lambda text: text.replace('<lan>', '<lan><enable>1</enable>'))
    said = []
    real_log = classify.log
    classify.log = said.append
    try:
        state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, stop_after=3,
                                                  change=lambda text: text.replace('<lan><enable>1</enable>', '<lan>'))
    finally:
        classify.log = real_log
    check('no interface to watch when the service began: said, and the one switched on since followed at a window\'s close',
          ([m for m in said if 'no interface' in m], [line.split(' -i ')[1].split()[0] for line in asked if line.startswith('tcpdump')]),
          (['no interface to watch: none is internal, and none is chosen in Settings'], ['em1']))

# --------------------------------------------------------------------------- what the page reads
import status                                                            # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases>'
                     '<alias><enabled>1</enabled><name>appcontrol_cat_Web</name><type>external</type>'
                     '<description>Application Control: category Web</description></alias>'
                     '<alias><enabled>1</enabled><name>appcontrol_YouTube</name><type>external</type>'
                     '<description>Application Control: YouTube</description></alias>'
                     '</aliases></Alias></Firewall><AppControl><general><classify>1</classify>'
                     '<apps>YouTube,Dropbox</apps></general></AppControl></OPNsense></opnsense>')
    with open(os.path.join(tmp, 'status.json'), 'w') as handle:
        json.dump({'since': T0, 'windows': 3, 'totals': {'named': 4}, 'error': None,
                   'apps': {'YouTube': {'category': 'Media', 'named': 3, 'guessed': 0, 'protocols': ['TLS', 'QUIC'],
                                        'last': T0 + 10},
                            'TLS': {'category': 'Web', 'named': 1, 'guessed': 2, 'protocols': ['TLS'], 'last': T0 + 9}}}, handle)
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump({'version': '6.0.d20260909,1', 'protocols': {'Dropbox': 'Cloud', 'YouTube': 'Media'}, 'read_at': T0 - 5,
                   'errors': ['ndpiReader -H was not read as nDPI writes it: TLS in Media, not Web']}, handle)
    pfctl = os.path.join(tmp, 'pfctl')
    # pfctl -vvs Tables, as status.py reads it: a table's flags and name, then its counters
    with open(os.path.join(tmp, 'tables.txt'), 'w') as handle:
        handle.write('-pa-r--\tappcontrol_cat_Web\n\tAddresses:   7\n-pa----\tappcontrol_YouTube\n\tAddresses:   2\n'
                     '-pa----\tbogons\n\tAddresses:   9\n')
    program(pfctl, '#!/bin/sh\ncat %s\n' % os.path.join(tmp, 'tables.txt'))
    report = status.report(os.path.join(tmp, 'status.json'), config, os.path.join(tmp, 'ndpi.json'),
                           os.path.join(tmp, 'none.pid'), pfctl, os.path.join(tmp, 'none'))
    apps_seen = {a['name']: a for a in report['apps']}
    check('status.py: an application named and chosen - its table and the addresses pf holds in it',
          (apps_seen['YouTube']['table'], apps_seen['YouTube']['entries'], apps_seen['YouTube']['protocols']),
          ('appcontrol_YouTube', 2, ['TLS', 'QUIC']))
    check('status.py: one chosen and not seen yet - listed, no table until Apply made it',
          (apps_seen['Dropbox']['named'], apps_seen['Dropbox']['category'], apps_seen['Dropbox']['table']), (0, 'Cloud', ''))
    check('status.py: one seen and not chosen - no table', (apps_seen['TLS']['chosen'], apps_seen['TLS']['table']), (False, ''))
    check('status.py: the category tables and their addresses; tables not of the plugin not counted',
          (report['categories'], report['tables']), ([{'table': 'appcontrol_cat_Web', 'name': 'Web', 'entries': 7}],
                                                     {'categories': 1, 'applications': 1, 'addresses': 9}))
    check('status.py: no pidfile - not running; nDPI not there - said', (report['running'], report['installed'],
                                                                          report['classify']), (False, False, True))
    check('status.py: what reading nDPI\'s catalogue found wrong, and when, for the page\'s Last error',
          (report.get('catalogue_errors'), report.get('catalogue_read_at')),
          (['ndpiReader -H was not read as nDPI writes it: TLS in Media, not Web'], T0 - 5))
    with open(os.path.join(tmp, 'mine.pid'), 'w') as handle:
        handle.write(str(os.getpid()))
    check('status.py: a pidfile naming a live process that is not the classifier - not running',
          status.running(os.path.join(tmp, 'mine.pid')), None)


# ------------------------------------------------------------- the service with nothing it can do
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><AppControl><general><classify>1</classify></general></AppControl></OPNsense></opnsense>')
    state = classify.serve(stop_after=0, reader=os.path.join(tmp, 'none'), config=config,
                           catalogue_path=os.path.join(tmp, 'ndpi.json'), status=os.path.join(tmp, 'status.json'),
                           unknown=os.path.join(tmp, 'unknown.json'), work=os.path.join(tmp, 'work'), refresh=False)
    saved = json.load(open(os.path.join(tmp, 'status.json')))
    check('nDPI not installed: the service waits, and says so in status.json', 'nDPI is not installed' in saved['error']['message'],
          True)
with tempfile.TemporaryDirectory() as tmp:
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, mount=mounted(tmp, ['/dev/ada0p2 / ufs rw 1 1']))
    check('the work directory not in memory: no capture started, no window written, and why said in status.json',
          ((saved['error'] or {}).get('message'), [line for line in asked if line.startswith(('tcpdump', 'ndpiReader'))],
           os.listdir(os.path.join(tmp, 'work'))),
          ('%s is not in memory - the rc script mounts a tmpfs there: no window is written to the disk, so nothing is classified'
           % os.path.join(tmp, 'work'), [], []))

# ================================================================ phase 2: an application blocked, its connections cut
# ---------------------------------------------------------------------------- the settings and the tables
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><AppControl><general><classify>1</classify><apps>DNS</apps>'
                     '<blocked>YouTube,TikTok</blocked><block_log>1</block_log></general></AppControl></OPNsense></opnsense>')
    conf = tables.settings(config)
    check('settings: the applications blocked, and whether what is blocked is logged', (conf['blocked'], conf['block_log']),
          (['YouTube', 'TikTok'], True))
    check('settings: none blocked and nothing logged when config.xml says nothing', (lambda s: (s['blocked'], s['block_log']))(
        tables.settings(os.path.join(tmp, 'none.xml'))), ([], False))
cat2 = {'categories': {'5': 'Web'}, 'protocols': {'YouTube': 'Media', 'DNS': 'Network', 'TikTok': 'SocialNetwork'}}
w = tables.wanted({'classify': True, 'apps': ['DNS'], 'blocked': ['YouTube', 'NotInNdpi']}, cat2)
check('wanted: a table for an application blocked as for one of Application tables; none for one nDPI does not know',
      sorted(w), ['appcontrol_DNS', 'appcontrol_YouTube', 'appcontrol_cat_Web'])
check('tabled: the applications of Application tables and of Blocked applications',
      tables.tabled({'apps': ['DNS'], 'blocked': ['YouTube', 'DNS']}), {'DNS', 'YouTube'})
present_now = {'appcontrol_YouTube': {'kind': 'application', 'name': 'YouTube'},
               'appcontrol_cat_Web': {'kind': 'category', 'name': 'Web'}}
check('blocked: an application chosen whose alias is there, with its table; one whose alias is not made yet, none',
      tables.blocked({'classify': True, 'blocked': ['YouTube', 'TikTok']}, present_now), {'YouTube': 'appcontrol_YouTube'})
check('blocked: nothing while classifying is off, whatever is chosen',
      tables.blocked({'classify': False, 'blocked': ['YouTube']}, present_now), {})

# --------------------------------------------------------------------- what a window queues to cut, and remembers
yt = F(('198.51.100.10', 443), client=('192.0.2.10', 51001), first=T0 + 2)
yt_guess = F(('198.51.100.11', 443), client=('192.0.2.10', 51002))
yt_midway = F(('198.51.100.12', 443), client=('192.0.2.10', 51003), started=False)
yt_lan = F(('192.0.2.50', 443), client=('203.0.113.99', 51004))
dns_named = F(('198.51.100.53', 53), client=('192.0.2.10', 51005), proto=17, packets=4)
dns_ended = F(('198.51.100.54', 53), client=('192.0.2.10', 51006), ended=True)
dns_exchange = F(('198.51.100.55', 53), client=('192.0.2.10', 51008), proto=17, packets=2)
nf = F(('198.51.100.70', 443), client=('192.0.2.10', 51007))
block_records = [('named', 'TLS.YouTube', yt, row(yt, 'TLS.YouTube', 'www.youtube.example')),
                 ('guessed', 'TLS.YouTube', yt_guess, row(yt_guess, 'TLS')),
                 ('named', 'TLS.YouTube', yt_midway, row(yt_midway, 'TLS.YouTube')),
                 ('named', 'TLS.YouTube', yt_lan, row(yt_lan, 'TLS.YouTube')), ('named', 'DNS', dns_named, row(dns_named, 'DNS')),
                 ('named', 'DNS', dns_ended, row(dns_ended, 'DNS')), ('named', 'DNS', dns_exchange, row(dns_exchange, 'DNS')),
                 ('named', 'TLS.NetFlix', nf, row(nf, 'TLS.NetFlix', 'www.netflix.example'))]
NETFLIX = dict(aliases, appcontrol_NetFlix={'kind': 'application', 'name': 'NetFlix'})


def blocking_state(blocked, apps=('YouTube', 'DNS')):
    state = classify.State(T0, catalogue, {'classify': True, 'apps': list(apps), 'blocked': list(blocked)}, [('lan', 'em1')])
    state.network = NET
    return state


state = blocking_state(['YouTube'])
# YouTube in Application tables before it was blocked: its table took servers on their names alone
fake = FakePf({'appcontrol_YouTube': {'198.51.100.53'}})
counts = classify.apply(state, block_records, tables.Pf(run=fake), aliases, T0 + 70, T0 + 70)
check('a window, YouTube blocked: its connection named by its packets, begun here, to an address of the internet - queued '
      'to be cut, with its two ends, when it began and the name it carried; a guess, one not begun here and one to a LAN '
      'host never',
      ([(c['app'], c['name'], c['client'], c['server'], c['proto'], c['began'], c['host'], c['alone']) for c in state.to_cut],
       counts['to_cut']),
      ([('YouTube', 'TLS.YouTube', ['192.0.2.10', 51001], ['198.51.100.10', 443], 6, T0 + 2, 'www.youtube.example', False)], 1))
check('YouTube blocked since the last look: its table emptied - what went in on a name alone leaves it - and no server put '
      'in it here, cut.py putting one there once the resolver vouches for it; its category\'s table as before',
      (fake.held.get('appcontrol_YouTube'), sorted(fake.held.get('appcontrol_cat_Media', ()))), (set(), ['198.51.100.10']))
check('the others remembered for when their application is blocked, with the name each carried: DNS of four packets and '
      'NetFlix, named and begun; not one seen to end, a UDP question and its answer - over by now - nor the YouTube '
      'connection being cut',
      sorted((v[0], classify.unpacked(k)[2][0], v[2]) for k, v in state.remembered.items()),
      [('DNS', '198.51.100.53', ''), ('TLS.NetFlix', '198.51.100.70', 'www.netflix.example')])
check('status.json: the applications blocked, what is remembered, what waits for a cut',
      (lambda s: (s['blocking'], s['remembered'], s['waiting_cut'], s['totals']['to_cut']))(state.status()),
      (['YouTube'], 2, 1, 1))
fake = FakePf({'appcontrol_YouTube': {'198.51.100.53'}})
classify.apply(state, [], tables.Pf(run=fake), aliases, T0 + 130, T0 + 130)
check('blocked still at the next window: its table left as it is', fake.held.get('appcontrol_YouTube'), {'198.51.100.53'})
state = blocking_state(['TLS'])
classify.apply(state, block_records, tables.Pf(run=FakePf()), dict(aliases, appcontrol_TLS={'kind': 'application', 'name': 'TLS'}),
               T0 + 70, T0 + 70)
check('the protocol carrying it blocked - TLS: TLS.YouTube and TLS.NetFlix cut, as TLS', sorted((c['name'], c['app'])
                                                                                          for c in state.to_cut),
      [('TLS.NetFlix', 'TLS'), ('TLS.YouTube', 'TLS')])
state = blocking_state(['NetFlix'])
classify.apply(state, block_records, tables.Pf(run=FakePf()), aliases, T0 + 70, T0 + 70)
check('chosen to be blocked, its alias not made yet - not applied: nothing cut, its connection remembered',
      (state.to_cut, sorted(v[0] for v in state.remembered.values()), state.blocking),
      ([], ['DNS', 'TLS.NetFlix', 'TLS.YouTube'], {}))

# a newly blocked application: what is remembered of it, cut at once - cut.py putting its servers in its table - and its
# table given back to be emptied
state.conf = dict(state.conf, blocked=['NetFlix'])
blocked_now = classify.block(state, NETFLIX, T0 + 70)
check('blocked since the last look: its remembered connection queued to be cut, with the name it carried, forgotten here; '
      'its table given back to be emptied',
      (blocked_now, [(c['app'], c['server'], c['host']) for c in state.to_cut], sorted(v[0] for v in state.remembered.values())),
      (({'NetFlix': 'appcontrol_NetFlix'}, ['appcontrol_NetFlix']), [('NetFlix', ['198.51.100.70', 443], 'www.netflix.example')],
       ['DNS', 'TLS.YouTube']))
state.to_cut = []
check('blocked still, looked at again: nothing more queued, nothing emptied', (classify.block(state, NETFLIX, T0 + 70)[1],
                                                                               state.to_cut), ([], []))
fake = FakePf()
added_before = state.totals['added']
check('put: the servers into pf, counted', (classify.put(state, tables.Pf(run=fake), {'appcontrol_cat_Video': {'198.51.100.70'}}),
                                            fake.held, state.totals['added'] - added_before),
      ((1, 0), {'appcontrol_cat_Video': {'198.51.100.70'}}, 1))

# blocked when the service last ran, and still: a restart does not take it for blocked since
with tempfile.TemporaryDirectory() as tmp:
    before = os.path.join(tmp, 'status.json')
    with open(before, 'w') as handle:
        json.dump({'blocking': ['YouTube', 'NetFlix'], 'since': T0}, handle)
    check('the applications blocked when the service last wrote status.json, and blocked still - NetFlix no longer is',
          classify.was_blocking(before, {'classify': True, 'blocked': ['YouTube']}, aliases), {'YouTube': 'appcontrol_YouTube'})
    with open(before, 'w') as handle:
        handle.write('{"error": ')
    check('no status.json, or one not to be read: none', (classify.was_blocking(os.path.join(tmp, 'none.json'), {
        'classify': True, 'blocked': ['YouTube']}, aliases), classify.was_blocking(before, {'classify': True, 'blocked': [
            'YouTube']}, aliases)), ({}, {}))
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases><alias><enabled>1</enabled><name>appcontrol_YouTube'
                     '</name><type>external</type><description>Application Control: YouTube</description></alias>'
                     '</aliases></Alias></Firewall><AppControl><general><classify>1</classify><blocked>YouTube</blocked>'
                     '</general></AppControl></OPNsense></opnsense>')
    with open(before, 'w') as handle:
        json.dump({'blocking': ['YouTube']}, handle)
    started = classify.start_state(lambda: T0, os.path.join(tmp, 'none'), config, os.path.join(tmp, 'ndpi.json'), False,
                                   mounted(tmp), os.path.join(tmp, 'work'), before)
    check('the service started again: the applications blocked when it last wrote status.json, and still, taken as '
          'blocked before', started.blocking, {'YouTube': 'appcontrol_YouTube'})
    fake = FakePf({'appcontrol_YouTube': {'198.51.100.10'}})
    started.network = NET
    classify.apply(started, [], tables.Pf(run=fake), aliases, T0 + 70, T0 + 70)
    check('started again, YouTube blocked before and still: its table not emptied', fake.held['appcontrol_YouTube'],
          {'198.51.100.10'})

# a name a device writes: one UDP packet named QUIC.YouTube, sent to the resolver the office uses
forged = F(('198.51.100.53', 443), client=('192.0.2.30', 51301), proto=17, packets=1)
state = blocking_state(['YouTube'])
fake = FakePf()
classify.apply(state, [('named', 'QUIC.YouTube', forged, row(forged, 'QUIC.YouTube', 'www.youtube.example'))],
               tables.Pf(run=fake), aliases, T0 + 70, T0 + 70)
check('a QUIC Initial a device sends naming www.youtube.example to another server: that address put in no blocked table '
      'here - cut.py asks the firewall\'s own resolver first - and the device\'s own connection queued to be cut, with the '
      'name it carried', (fake.held.get('appcontrol_YouTube'), [(c['server'][0], c['host']) for c in state.to_cut]),
      (set(), [('198.51.100.53', 'www.youtube.example')]))

# a server shared with an application not blocked: its connection cut alone
gm = F(('198.51.100.10', 443), client=('192.0.2.20', 51101))
gm_record = ('named', 'TLS.GMail', gm, row(gm, 'TLS.GMail', 'mail.example'))
yt_record = ('named', 'TLS.YouTube', yt, row(yt, 'TLS.YouTube', 'www.youtube.example'))
state = blocking_state(['YouTube'])
classify.apply(state, [gm_record], tables.Pf(run=FakePf()), aliases, T0 + 10, T0 + 10)
classify.apply(state, [yt_record], tables.Pf(run=FakePf()), aliases, T0 + 70, T0 + 70)
check('a server nDPI named as GMail, not blocked, within the address expiry: YouTube\'s connection to it cut alone - its '
      'server for no blocked table, whatever the resolver says', [c['alone'] for c in state.to_cut], [True])
state = blocking_state(['YouTube'])
classify.apply(state, [yt_record, gm_record], tables.Pf(run=FakePf()), aliases, T0 + 70, T0 + 70)
check('GMail named in the same window, after YouTube: the same - the order of a window does not matter',
      [c['alone'] for c in state.to_cut], [True])
state = blocking_state(['YouTube'])
classify.apply(state, [gm_record], tables.Pf(run=FakePf()), aliases, T0 + 10, T0 + 10)
classify.apply(state, [yt_record], tables.Pf(run=FakePf()), aliases, T0 + 10 + 3601, T0 + 10 + 3601)
check('GMail named there longer ago than the address expiry: not shared', [c['alone'] for c in state.to_cut], [False])
tls_alone = F(('198.51.100.10', 443), client=('192.0.2.22', 51103))
yt_too = F(('198.51.100.10', 443), client=('192.0.2.23', 51104))
state = blocking_state(['YouTube'])
classify.apply(state, [('named', 'TLS', tls_alone, row(tls_alone, 'TLS')), ('named', 'TLS.YouTube', yt_too, row(
    yt_too, 'TLS.YouTube')), yt_record], tables.Pf(run=FakePf()), aliases, T0 + 70, T0 + 70)
check('a protocol named alone there, or the blocked application itself from another device: not shared',
      [c['alone'] for c in state.to_cut], [False, False])
kept_most = classify.NAMES_MOST
classify.NAMES_MOST = 2
try:
    state = blocking_state(['YouTube'])
    for i in range(4):
        classify.note(state, '198.51.100.%d' % i, 'TLS.GMail', T0 + i)
    check('the names of the latest NAMES_MOST servers kept, the oldest gone first', list(state.names_at),
          ['198.51.100.2', '198.51.100.3'])
finally:
    classify.NAMES_MOST = kept_most
state = blocking_state(['YouTube'])
for i, name in enumerate(('TLS.A', 'TLS.B', 'TLS.C', 'TLS.D', 'TLS.E', 'TLS.B')):
    classify.note(state, '198.51.100.10', name, T0 + i)
check('the latest NAMES_EACH names of a server kept, one named again the latest', list(state.names_at['198.51.100.10']),
      ['TLS.C', 'TLS.D', 'TLS.E', 'TLS.B'])

# a server in a blocked table named since as an application not blocked: taken out of it
quic_gmail = F(('198.51.100.10', 443), client=('192.0.2.21', 51102), proto=17)
state = blocking_state(['YouTube'])
state.blocking = {'YouTube': 'appcontrol_YouTube'}
fake = FakePf({'appcontrol_YouTube': {'198.51.100.10', '198.51.100.11'}})
counts = classify.apply(state, [('named', 'QUIC.GMail', quic_gmail, row(quic_gmail, 'QUIC.GMail', 'mail.example'))],
                        tables.Pf(run=fake), aliases, T0 + 70, T0 + 70)
check('a server in YouTube\'s table named as GMail - a QUIC Initial, which nDPI names from its first packet though the rule '
      'drops it: taken out of the table, it serves GMail too', (sorted(fake.held['appcontrol_YouTube']), counts['untabled'],
                                                                state.totals['untabled']), (['198.51.100.11'], 1, 1))

# an address not on the internet: a host at a VPN's other end, behind a route, on a DMZ
RDP = dict(aliases, appcontrol_RDP={'kind': 'application', 'name': 'RDP'})
site = F(('203.0.113.5', 3389), client=('192.0.2.10', 51201))
out_there = F(('198.51.100.80', 3389), client=('192.0.2.10', 51202))
state = blocking_state(['RDP'])
fake = FakePf()
counts = classify.apply(state, [('named', 'RDP', site, row(site, 'RDP')), ('named', 'RDP', out_there, row(out_there, 'RDP'))],
                        tables.Pf(run=fake), RDP, T0 + 70, T0 + 70)
check('RDP blocked: a session to the remote office\'s server - an address not on the internet - neither cut nor put in a '
      'table, counted; one to a server out there cut', ([c['server'][0] for c in state.to_cut], fake.held.get('appcontrol_RDP'),
                                                        counts['not_internet'], state.totals['not_internet']),
      (['198.51.100.80'], set(), 1, 1))
state = blocking_state([])
classify.apply(state, [('named', 'RDP', site, row(site, 'RDP'))], tables.Pf(run=FakePf()), RDP, T0 + 70, T0 + 70)
state.conf = dict(state.conf, blocked=['RDP'])
classify.block(state, RDP, T0 + 80)
check('RDP blocked later: the session it remembered to an address not on the internet not cut, counted',
      (state.to_cut, state.totals['not_internet'], len(state.remembered)), ([], 1, 0))
kept_also = classify.ALSO_GLOBAL
classify.ALSO_GLOBAL = ()
try:
    check('internet(): a documentation address is not the internet\'s, as Python\'s ipaddress has it, nor what is no '
          'address', [classify.internet(a) for a in ('198.51.100.10', '2001:db8::1', '203.0.113.5', 'not an address')],
          [False] * 4)
finally:
    classify.ALSO_GLOBAL = kept_also

# an application unblocked while its connections wait for cut.py: dropped, never cut after
state = blocking_state(['YouTube'])
classify.apply(state, block_records, tables.Pf(run=FakePf()), aliases, T0 + 70, T0 + 70)
waiting_before = len(state.to_cut)
state.conf = dict(state.conf, blocked=[])
classify.apply(state, [], tables.Pf(run=FakePf()), aliases, T0 + 130, T0 + 130)
check('YouTube unblocked at the next window, its connection still waiting for cut.py: dropped from the queue, counted',
      (waiting_before, state.to_cut, state.totals['cut_unblocked'], state.blocking), (1, [], 1, {}))
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    blocked_config = ('<opnsense><OPNsense><Firewall><Alias><aliases><alias><enabled>1</enabled><name>appcontrol_YouTube</name>'
                      '<type>external</type><description>Application Control: YouTube</description></alias></aliases></Alias>'
                      '</Firewall><AppControl><general><classify>1</classify><apps>YouTube</apps><blocked>%s</blocked>'
                      '</general></AppControl></OPNsense></opnsense>')
    with open(config, 'w') as handle:
        handle.write(blocked_config % 'YouTube')
    state = blocking_state(['YouTube'])
    classify.reread(state, config, os.path.join(tmp, 'ndpi.json'))
    classify.apply(state, block_records, tables.Pf(run=FakePf()), aliases, T0 + 70, T0 + 70)
    with open(config, 'w') as handle:
        handle.write(blocked_config % '')
    emptied = classify.reread(state, config, os.path.join(tmp, 'ndpi.json'))
    check('read again (SIGHUP), YouTube unblocked: what waited for its cut dropped, nothing to empty',
          (state.to_cut, state.blocking, emptied, state.totals['cut_unblocked']), ([], {}, [], 1))
    with open(config, 'w') as handle:
        handle.write(blocked_config % 'YouTube')
    check('read again, YouTube blocked since: its table given back to be emptied', classify.reread(
        state, config, os.path.join(tmp, 'ndpi.json')), ['appcontrol_YouTube'])

# what is remembered: its two ends packed, the latest REMEMBER, for REMEMBER_FOR seconds
pk4, pk6 = classify.packed(6, ('192.0.2.10', 51001), ('198.51.100.10', 443)), classify.packed(
    17, ('2001:db8::10', 51002), ('2001:db8::443', 443))
check('remembered as its two ends packed - 13 bytes for IPv4, 37 for IPv6 - and read back as they were',
      (len(pk4), len(pk6), classify.unpacked(pk4), classify.unpacked(pk6)),
      (13, 37, (6, ('192.0.2.10', 51001), ('198.51.100.10', 443)), (17, ('2001:db8::10', 51002), ('2001:db8::443', 443))))
kept_most, kept_for = classify.REMEMBER, classify.REMEMBER_FOR
classify.REMEMBER, classify.REMEMBER_FOR = 3, 600
try:
    state = blocking_state([])
    many = [F(('198.51.100.%d' % (100 + i), 443), client=('192.0.2.10', 52000 + i), first=T0 + i) for i in range(5)]
    classify.apply(state, [('named', 'TLS.YouTube', f, row(f, 'TLS.YouTube')) for f in many], tables.Pf(run=FakePf()), aliases,
                   T0 + 70, T0 + 70)
    check('remembered: the latest 3 of 5, the oldest gone first', [classify.unpacked(k)[2][0] for k in state.remembered],
          ['198.51.100.102', '198.51.100.103', '198.51.100.104'])
    classify.forget_remembered(state, T0 + 3 + 600)
    check('remembered: none past its time', [classify.unpacked(k)[2][0] for k in state.remembered],
          ['198.51.100.103', '198.51.100.104'])
    again = F(('198.51.100.103', 443), client=('192.0.2.10', 52003), first=T0 + 900)
    classify.remember(state, again, 'TLS.YouTube')
    check('remembered again: the latest, at the end', [v[1] for v in state.remembered.values()], [T0 + 4, T0 + 900])
finally:
    classify.REMEMBER, classify.REMEMBER_FOR = kept_most, kept_for

# what waits for cut.py: kept to CUT_WAITING, the oldest left uncut, counted and said
kept_waiting = classify.CUT_WAITING
classify.CUT_WAITING = 3
said = []
real_log = classify.log
classify.log = said.append
try:
    state = blocking_state(['YouTube'])
    for i in range(5):
        classify.queue_cut(state, ('k', i), 'TLS.YouTube', ('192.0.2.10', 53000 + i), ('198.51.100.10', 443), 6, T0, 'YouTube')
    classify.trim_cut(state, T0)
    check('more waiting for cut.py than it takes: the latest kept, the oldest left uncut, counted, said',
          ([c['client'][1] for c in state.to_cut], state.totals['cut_skipped'], said),
          ([53002, 53003, 53004], 2, ['2 connection(s) of a blocked application left uncut: more were waiting for cut.py than 3']))
finally:
    classify.CUT_WAITING = kept_waiting
    classify.log = real_log

# what a cut did not reach: queued again, first, each connection given CUT_TRIES runs
said = []
real_log = classify.log
classify.log = said.append
try:
    state = blocking_state(['YouTube'])
    state.to_cut = [{'client': ['192.0.2.10', 53100], 'app': 'YouTube'}]
    again = classify.requeue(state, [{'client': ['192.0.2.10', 53101], 'app': 'YouTube'},
                                     {'client': ['192.0.2.10', 53102], 'app': 'YouTube', 'tries': 2}, 'not a connection'],
                             T0, 'cut.py stopped at 120 s')
    check('a cut\'s connections not reached: queued again before those waiting, a second run each; one that had its '
          'second left uncut, counted, said', (again, [(c['client'][1], c.get('tries')) for c in state.to_cut],
                                               state.totals['cut_skipped'], said),
          (1, [(53101, 2), (53100, None)], 1,
           ['1 connection(s) of a blocked application left uncut: cut.py stopped at 120 s, 2 times']))
finally:
    classify.log = real_log

# ---------------------------------------------------------------------------- cut.py run beside the capture
with tempfile.TemporaryDirectory() as tmp:
    work = os.path.join(tmp, 'work')
    os.makedirs(work)
    asked_file = os.path.join(tmp, 'asked')
    stand_in = os.path.join(tmp, 'cut.py')
    program(stand_in, '#!/usr/bin/env python3\nimport json, os, sys, time\n'
            'conns = json.load(open(sys.argv[2]))\nopen(%r, "a").write(json.dumps([sys.argv[1], conns]) + "\\n")\n'
            'mode = open(%r).read().strip() if os.path.exists(%r) else ""\n'
            'if mode == "slow":\n    time.sleep(30)\n'
            'if mode == "garbled":\n    print("not json")\n    sys.exit(0)\n'
            'left = conns[1:] if mode == "left" else []\nconns = conns[:1] if mode == "left" else conns\n'
            'apps = {}\nfor c in conns:\n    apps[c["app"]] = apps.get(c["app"], 0) + 1\n'
            'print(json.dumps({"connections": len(conns), "cut": len(conns), "states": 2 * len(conns), "dropped": 1, '
            '"tabled": 1, "alone": len(conns) - 1, "hardware": "ready", "left": left, '
            '"apps": apps, "errors": ["a state pfctl would not kill"] if mode == "said" else []}))\n'
            % (asked_file, os.path.join(tmp, 'mode'), os.path.join(tmp, 'mode')))

    def run_cutter(cutter, state, wait=10):
        cutter.start(state, T0)
        until = time.time() + wait
        while cutter.poll(state, T0) and time.time() < until:
            time.sleep(0.05)

    state = blocking_state(['YouTube'])
    state.apps['YouTube'] = {'category': 'Media', 'named': 1, 'guessed': 0, 'protocols': ['TLS'], 'last': T0}
    one_cut = {'proto': 6, 'client': ['192.0.2.10', 51001], 'server': ['198.51.100.10', 443], 'name': 'TLS.YouTube',
               'app': 'YouTube', 'began': T0, 'host': 'www.youtube.example', 'alone': False}
    state.to_cut = [dict(one_cut)]
    cutter = classify.Cutter(work, stand_in)
    run_cutter(cutter, state)
    asked = [json.loads(line) for line in open(asked_file)]
    check('cut.py: run with "cut" and a file holding the connections, as classify.py hands them over',
          asked, [['cut', [one_cut]]])
    check('its answer counted: connections cut, states killed, dropped in hardware, servers put in their tables and '
          'connections cut alone, each application\'s, the last cut',
          ({k: state.totals[k] for k in ('cut', 'cut_states', 'cut_dropped', 'cut_tabled', 'cut_alone')},
           state.apps['YouTube'].get('cut'), state.last_cut, state.to_cut, os.listdir(work)),
          ({'cut': 1, 'cut_states': 2, 'cut_dropped': 1, 'cut_tabled': 1, 'cut_alone': 0}, 1,
           {'at': T0, 'asked': 1, 'cut': 1, 'states': 2, 'tabled': 1, 'alone': 0, 'dropped': 1, 'hardware': 'ready'}, [], []))
    state.to_cut = [dict(one_cut, client=['192.0.2.10', 51000 + i]) for i in range(7)]
    kept_most = classify.CUT_MOST
    classify.CUT_MOST = 5
    try:
        cutter.start(state, T0)
        check('at most CUT_MOST a run, the rest waiting; one run at a time', (len(state.to_cut), cutter.start(state, T0),
                                                                              len(state.to_cut)), (2, None, 2))
        until = time.time() + 10
        while cutter.poll(state, T0) and time.time() < until:
            time.sleep(0.05)
        run_cutter(cutter, state)
        check('the rest in the next run', ([len(json.loads(line)[1]) for line in open(asked_file)][-2:], state.to_cut), ([5, 2], []))
    finally:
        classify.CUT_MOST = kept_most
    with open(os.path.join(tmp, 'mode'), 'w') as handle:
        handle.write('left')
    state.to_cut = [dict(one_cut, client=['192.0.2.10', 51200 + i]) for i in range(3)]
    run_cutter(cutter, state)
    check('cut.py out of its own time before some: those it gives back queued again, a second run each',
          [(c['client'][1], c.get('tries')) for c in state.to_cut], [(51201, 2), (51202, 2)])
    run_cutter(cutter, state)
    check('given back again on their second run: left uncut, counted', (state.to_cut, state.totals['cut_skipped']), ([], 1))
    with open(os.path.join(tmp, 'mode'), 'w') as handle:
        handle.write('said')
    said = []
    real_log = classify.log
    classify.log = said.append
    try:
        state.to_cut = [dict(one_cut)]
        run_cutter(cutter, state)
        check('what cut.py could not do: said, as the Last error', said[-1:], ['the cut: a state pfctl would not kill'])
        with open(os.path.join(tmp, 'mode'), 'w') as handle:
            handle.write('garbled')
        state.to_cut = [dict(one_cut)]
        before = state.totals['cut']
        run_cutter(cutter, state)
        check('an answer that cannot be read: said, nothing counted', (said[-1], state.totals['cut'] - before),
              ('cut.py said nothing that could be read: 1 connection(s) of a blocked application may not be cut', 0))
        with open(os.path.join(tmp, 'mode'), 'w') as handle:
            handle.write('slow')
        kept_timeout = classify.CUT_TIMEOUT
        classify.CUT_TIMEOUT = 1
        state.to_cut = [dict(one_cut)]
        began = time.time()
        run_cutter(cutter, state)
        check('cut.py past its time: stopped, said, its file removed, its connections queued again for a second run',
              (time.time() - began < 10, said[-1], cutter.proc, os.listdir(work), [c.get('tries') for c in state.to_cut]),
              (True, 'cut.py took longer than 1 s: 1 connection(s) of a blocked application queued again', None, [], [2]))
        run_cutter(cutter, state)
        classify.CUT_TIMEOUT = kept_timeout
        check('past its time again, on their second run: left uncut, said', (state.to_cut, said[-1]),
              ([], '1 connection(s) of a blocked application left uncut: cut.py stopped at 1 s, 2 times'))
        missing = classify.Cutter(work, os.path.join(tmp, 'none.py'))
        state.to_cut = [dict(one_cut)]
        missing.start(state, T0)
        check('cut.py not to be run: said, nothing left behind', (said[-1].startswith('1 connection(s) of a blocked application '
                                                                                     'not cut: cut.py could not be run'),
                                                                  missing.proc, os.listdir(work)), (True, None, []))
    finally:
        classify.log = real_log
    check('the cut beside classify.py is cut.py, in the same directory', classify.CUT,
          os.path.join(SCRIPTS, 'cut.py'))

# ------------------------------------------------------------- the service: a blocked application's connection cut
CUT_STAND_IN = ('#!/usr/bin/env python3\nimport json, sys\nconns = json.load(open(sys.argv[2]))\n'
                'open(%r, "a").write(json.dumps(conns) + "\\n")\napps = {}\n'
                'for c in conns:\n    apps[c["app"]] = apps.get(c["app"], 0) + 1\n'
                'print(json.dumps({"connections": len(conns), "cut": len(conns), "states": 2 * len(conns), "dropped": None, '
                '"apps": apps, "errors": []}))\n')

with tempfile.TemporaryDirectory() as tmp:
    cuts_file = os.path.join(tmp, 'cuts')
    program(os.path.join(tmp, 'cut.py'), CUT_STAND_IN % cuts_file)
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, cut=os.path.join(tmp, 'cut.py'),
                                              change=lambda text: text.replace('<apps>YouTube</apps>',
                                                                               '<apps></apps><blocked>YouTube</blocked>'))
    handed = [c for line in open(cuts_file) for c in json.loads(line)] if os.path.exists(cuts_file) else []
    check('the service, YouTube blocked: its table emptied as it became blocked, nothing put in it by the classifier, '
          'and its connection handed to cut.py with its two ends and the name it carried - cut.py putting the server in '
          'the table once the resolver vouches for it',
          (held.get('appcontrol_YouTube'), [(c['app'], c['client'], c['server'], c['host']) for c in handed]),
          ([], [('YouTube', ['192.0.2.10', 50001], ['198.51.100.10', 443], 'www.example.com')]))
    check('the service: the connection\'s first packet on the monotonic clock, as pf\'s age of a state is - not the wall '
          'clock\'s', [abs(c['began'] - time.monotonic()) < 120 for c in handed], [True])
    check('the service: what cut.py said, in status.json - the totals, YouTube\'s, the applications blocked',
          ({k: saved['totals'][k] for k in ('to_cut', 'cut', 'cut_states')}, saved['apps']['YouTube'].get('cut'), saved['blocking']),
          ({'to_cut': 1, 'cut': 1, 'cut_states': 2}, 1, ['YouTube']))

# ------------------------------------------------------- the service keeps the Suricata rules of the Rules tab current
SURICATA_STAND_IN = ('#!/usr/bin/env python3\nimport json, sys\nopen(%r, "a").write(sys.argv[1] + "\\n")\n'
                     'print(json.dumps({"status": "ok", "changed": False, "errors": ["a test problem"] '
                     'if sys.argv[1] == "refresh" else []}))\n')
with tempfile.TemporaryDirectory() as tmp:
    verbs_file = os.path.join(tmp, 'verbs')
    program(os.path.join(tmp, 'suricata_rules.py'), SURICATA_STAND_IN % verbs_file)
    kept_every = classify.SURICATA_EVERY
    classify.SURICATA_EVERY = 1.5
    try:
        state, saved, rows, asked, held = service(
            tmp, TWO, YOUTUBE, YOUTUBE, suricata=os.path.join(tmp, 'suricata_rules.py'), stop_after=2,
            change=lambda text: text.replace('</AppControl>', '<rules><rule uuid="cccccccc-0000-4000-8000-000000000001">'
                                             '<enabled>1</enabled><action>alert</action><source>lan</source>'
                                             '<source_not>0</source_not><app>YouTube</app><description/></rule></rules>'
                                             '</AppControl>'))
        verbs = open(verbs_file).read().split() if os.path.exists(verbs_file) else []
        said = [e for e in [saved.get('error') or {}] if e]
        check('the service with a rule of the Rules tab: suricata_rules.py start as it starts - the rules written as the '
              'settings say - then refresh every SURICATA_EVERY seconds, its answer\'s problems the last error',
              (verbs[:1], len(verbs) >= 2 and set(verbs[1:]) == {'refresh'},
               any('the Suricata rules of the Rules tab: a test problem' in e.get('message', '') for e in said)),
              (['start'], True, True))
        os.remove(verbs_file)
        state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, suricata=os.path.join(tmp, 'suricata_rules.py'),
                                                  stop_after=1)
        check('the service with no rule switched on: suricata_rules.py never run - Apply took the file away',
              os.path.exists(verbs_file), False)
    finally:
        classify.SURICATA_EVERY = kept_every

# ------------------------------------------------------- the settings read again (SIGHUP): an application blocked since
with tempfile.TemporaryDirectory() as tmp:
    cuts_file = os.path.join(tmp, 'cuts')
    program(os.path.join(tmp, 'cut.py'), CUT_STAND_IN % cuts_file)
    real_apply = classify.apply
    seen = {}

    def apply_then_block(state, records, pf, aliases_now, now):
        """The window that named the YouTube connection judged, nothing blocked; then YouTube blocked in config.xml and
        a SIGHUP, as Apply does."""
        out = real_apply(state, records, pf, aliases_now, now)
        if not seen and state.remembered:
            seen['remembered'] = sorted(v[0] for v in state.remembered.values())
            seen['since'] = state.since
            path = os.path.join(tmp, 'config.xml')
            with open(path) as handle:
                text = handle.read()
            with open(path + '.new', 'w') as handle:
                handle.write(text.replace('<apps>YouTube</apps>', '<apps>YouTube</apps><blocked>YouTube</blocked>'))
            os.replace(path + '.new', path)
            classify.reload_asked = True
        return out

    classify.apply = apply_then_block
    try:
        state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, cut=os.path.join(tmp, 'cut.py'), stop_after=3)
    finally:
        classify.apply = real_apply
        classify.reload_asked = False
    handed = [c for line in open(cuts_file) for c in json.loads(line)] if os.path.exists(cuts_file) else []
    check('read again, YouTube blocked since: the YouTube connection it remembered cut at once, without a restart - one '
          'service all along, tcpdump started once',
          (seen.get('remembered'), [(c['app'], c['client']) for c in handed], state.since == seen.get('since'),
           len([line for line in asked if line.startswith('tcpdump')])),
          (['TLS.YouTube'], [('YouTube', ['192.0.2.10', 50001])], True, 1))
    check('read again: YouTube blocked, its connection forgotten as it is cut', (saved['blocking'], state.remembered.get(
        classify.packed(6, ('192.0.2.10', 50001), ('198.51.100.10', 443)))), (['YouTube'], None))

# ---------------------------------------------------- SIGHUP's handler, set before anything else is loaded
source = open(os.path.join(SCRIPTS, 'classify.py'), encoding='utf-8').read()
check('SIGHUP\'s handler set as classify.py is loaded, before its other imports: a reload in the service\'s first moments '
      'is not taken for its end', (classify.signal.getsignal(classify.signal.SIGHUP) is classify.read_again,
                                   source.index('signal.signal(signal.SIGHUP, read_again)') < source.index('import errno')),
      (True, True))

# ---------------------------------------------------- nothing it can do at the start: looked at again at a SIGHUP
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><AppControl><general><classify>0</classify></general></AppControl></OPNsense></opnsense>')
    looked = []
    real_start = classify.start_state

    def counted_start(*args):
        looked.append(1)
        if len(looked) == 1:
            threading.Timer(0.3, lambda: setattr(classify, 'reload_asked', True)).start()
        elif len(looked) == 2:
            classify.running = False
        return real_start(*args)

    classify.start_state = counted_start
    try:
        classify.serve(reader=os.path.join(tmp, 'none'), config=config, catalogue_path=os.path.join(tmp, 'ndpi.json'),
                       status=os.path.join(tmp, 'status.json'), unknown=os.path.join(tmp, 'unknown.json'),
                       work=os.path.join(tmp, 'work'), refresh=False)
    finally:
        classify.start_state = real_start
        classify.running = True
        classify.reload_asked = False
    check('classifying off at the start: the service waits, saying why, and looks again at a SIGHUP', (len(looked), json.load(
        open(os.path.join(tmp, 'status.json')))['error']['message']), (2, 'classification is off in Settings'))

# ------------------------------------------------------------------------------- what the page reads of the blocking
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases>'
                     '<alias><enabled>1</enabled><name>appcontrol_YouTube</name><type>external</type>'
                     '<description>Application Control: YouTube</description></alias>'
                     '<alias><enabled>1</enabled><name>appcontrol_cat_Media</name><type>external</type>'
                     '<description>Application Control: category Media</description></alias>'
                     '</aliases></Alias></Firewall><XGS><general><cut_in_hardware>0</cut_in_hardware></general></XGS>'
                     '<AppControl><general><classify>1</classify><apps></apps><blocked>YouTube,TikTok</blocked>'
                     '<block_log>1</block_log></general></AppControl></OPNsense></opnsense>')
    with open(os.path.join(tmp, 'status.json'), 'w') as handle:
        json.dump({'since': T0, 'totals': {'named': 4, 'cut': 3, 'cut_states': 5, 'cut_dropped': 2},
                   'last_cut': {'at': T0 + 70, 'asked': 3, 'cut': 3, 'states': 5, 'dropped': 2},
                   'apps': {'YouTube': {'category': 'Media', 'named': 3, 'guessed': 0, 'protocols': ['TLS'], 'last': T0 + 10,
                                        'cut': 3}}}, handle)
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump({'protocols': {'YouTube': 'Media', 'TikTok': 'SocialNetwork'}}, handle)
    # pfctl -v -s rules as FreeBSD writes it: each rule, then its counters; and -vvs Tables
    with open(os.path.join(tmp, 'rules.txt'), 'w') as handle:
        handle.write('scrub on em0 all fragment reassemble\n'
                     '  [ Evaluations: 100       Packets: 50        Bytes: 5000        States: 0     ]\n'
                     '  [ Inserted: uid 0 pid 123 State Creations: 0     ]\n'
                     'block drop in quick inet from any to <appcontrol_YouTube:3> label "0123456789abcdef0123456789abcdef"\n'
                     '  [ Evaluations: 900       Packets: 12        Bytes: 720         States: 0     ]\n'
                     '  [ Source Nodes: 0      Limit: 0      NAT/RDR: 0      Route: 0      ]\n'
                     '  [ Inserted: uid 0 pid 123 State Creations: 0     ]\n'
                     'block drop in log quick inet6 from any to <appcontrol_YouTube:*> label "fedcba9876543210fedcba9876543210"\n'
                     '  [ Evaluations: 900       Packets: 3         Bytes: 240         States: 0     ]\n'
                     'block drop in quick on em1 inet from any to <appcontrol_YouTube:3> label "11111111111111111111111111111111"\n'
                     '  [ Evaluations: 10        Packets: 100       Bytes: 6000        States: 0     ]\n'
                     'pass in quick inet from any to <appcontrol_YouTube:3> flags S/SA keep state label "2222"\n'
                     '  [ Evaluations: 10        Packets: 1000      Bytes: 60000       States: 4     ]\n'
                     'block drop out quick inet from any to <appcontrol_YouTube> label "3333"\n'
                     '  [ Evaluations: 10        Packets: 77        Bytes: 600         States: 0     ]\n')
    with open(os.path.join(tmp, 'tables.txt'), 'w') as handle:
        handle.write('-pa----\tappcontrol_YouTube\n\tAddresses:   3\n-pa----\tappcontrol_cat_Media\n\tAddresses:   9\n')
    program(os.path.join(tmp, 'pfctl'), '#!/bin/sh\ncase "$*" in "-v -s rules") cat %s ;; *) cat %s ;; esac\n'
            % (os.path.join(tmp, 'rules.txt'), os.path.join(tmp, 'tables.txt')))
    hw = os.path.join(tmp, 'hwdrop.py')
    report = status.report(os.path.join(tmp, 'status.json'), config, os.path.join(tmp, 'ndpi.json'), os.path.join(tmp, 'none.pid'),
                           os.path.join(tmp, 'pfctl'), os.path.join(tmp, 'none'), hw)
    apps_seen = {a['name']: a for a in report['apps']}
    check('status.py: YouTube blocked - its table, the connections cut, the packets its two block rules stopped; an '
          'owner\'s rule on an interface, a pass rule and an outbound rule not counted',
          {k: apps_seen['YouTube'][k] for k in ('blocked', 'block_pending', 'table', 'entries', 'cut', 'packets')},
          {'blocked': True, 'block_pending': False, 'table': 'appcontrol_YouTube', 'entries': 3, 'cut': 3, 'packets': 15})
    check('status.py: TikTok chosen, its alias not made - not applied yet, listed with its category',
          {k: apps_seen['TikTok'][k] for k in ('blocked', 'block_pending', 'table', 'category', 'packets')},
          {'blocked': False, 'block_pending': True, 'table': '', 'category': 'SocialNetwork', 'packets': None})
    check('status.py: the blocking for the page - blocked, not applied yet, logged, the totals; no os-xgs-npu, no hardware',
          {k: report['blocking'][k] for k in ('apps', 'pending', 'log', 'cut', 'states', 'dropped', 'packets', 'hardware')},
          {'apps': ['YouTube'], 'pending': ['TikTok'], 'log': True, 'cut': 3, 'states': 5, 'dropped': 2, 'packets': 15,
           'hardware': None})
    with open(hw, 'w') as handle:
        handle.write('# os-xgs-npu\ndef drop_ends(groups, path=None):\n    return 0\n\n\n'
                     'def release_addresses(contains):\n    return 0\n')
    check('status.py: os-xgs-npu\'s hwdrop.py there, Cut in hardware off in XGS: Settings - said',
          status.hardware(config, hw), {'cut_in_hardware': False, 'too_old': False})
    check('status.py: Cut in hardware not in config.xml - on, as os-xgs-npu has it by default',
          status.hardware(os.path.join(tmp, 'none.xml'), hw), {'cut_in_hardware': True, 'too_old': False})
    with open(hw, 'w') as handle:
        handle.write('# os-xgs-npu of 2026-11-08\ndef drop_ends(groups, path=None):\n    return 0\n')
    check('status.py: an os-xgs-npu whose hwdrop.py has no release_addresses() - its release of 2026-11-08 - too old for '
          'the cut in hardware, said', status.hardware(config, hw), {'cut_in_hardware': False, 'too_old': True})
    check('status.py: pf\'s rules not to be read - none counted', status.stopped_packets(os.path.join(tmp, 'none')), None)

# ================================================================ phase 3: the rules of the Rules tab
# ------------------------------------------------------------------------------------ the rules read
RULES_XML = ('<rules>'
             '<rule uuid="aaaaaaaa-0000-4000-8000-000000000001"><enabled>1</enabled><action>block</action><source>opt2</source>'
             '<source_not>0</source_not><app>YouTube</app><description>no video for guests</description></rule>'
             '<rule uuid="aaaaaaaa-0000-4000-8000-000000000002"><enabled>1</enabled><action>alert</action><source>any</source>'
             '<source_not>0</source_not><app>NetFlix</app><description/></rule>'
             '<rule uuid="aaaaaaaa-0000-4000-8000-000000000003"><enabled>0</enabled><action>block</action><source>lan</source>'
             '<source_not>0</source_not><app>TikTok</app><description/></rule>'
             '<rule uuid="aaaaaaaa-0000-4000-8000-000000000004"><enabled>1</enabled><action>block</action>'
             '<source>Teachers</source><source_not>1</source_not><app>TLS</app><description/></rule>'
             '<rule uuid="aaaaaaaa-0000-4000-8000-000000000005"><enabled>1</enabled><action>pass</action><source>lan</source>'
             '<source_not>0</source_not><app>DNS</app><description/></rule>'
             '<rule uuid="aaaaaaaa-0000-4000-8000-000000000006"><enabled>1</enabled><action>block</action><source></source>'
             '<source_not>0</source_not><app>DNS</app><description/></rule>'
             '</rules>')
R1, R2, R3, R4 = ('aaaaaaaa-0000-4000-8000-00000000000%d' % n for n in (1, 2, 3, 4))
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><AppControl><general><classify>1</classify><blocked>NetFlix</blocked></general>'
                     + RULES_XML + '</AppControl></OPNsense></opnsense>')
    conf = tables.settings(config)
    check('settings: the rules of the Rules tab, in their order, numbered from 1, each with its uuid, action, application, '
          'source split, inverted or not, description',
          [(r['number'], r['uuid'][-1], r['enabled'], r['action'], r['app'], r['source'], r['not'], r['description'])
           for r in conf['rules']],
          [(1, '1', True, 'block', 'YouTube', ['opt2'], False, 'no video for guests'),
           (2, '2', True, 'alert', 'NetFlix', ['any'], False, ''), (3, '3', False, 'block', 'TikTok', ['lan'], False, ''),
           (4, '4', True, 'block', 'TLS', ['Teachers'], True, ''), (5, '5', False, 'pass', 'DNS', ['lan'], False, ''),
           (6, '6', False, 'block', 'DNS', [], False, '')])
    check('settings: no rules in config.xml - none', tables.settings(os.path.join(tmp, 'none.xml'))['rules'], [])
cat3 = {'categories': {'5': 'Web'}, 'protocols': {'YouTube': 'Media', 'NetFlix': 'Video', 'TikTok': 'SocialNetwork',
                                                    'TLS': 'Web', 'DNS': 'Network'}}
check('wanted: a table for the application of each rule switched on - Block or Alert - none for one switched off',
      sorted(tables.wanted(dict(conf, blocked=[]), cat3)), ['appcontrol_NetFlix', 'appcontrol_TLS', 'appcontrol_YouTube',
                                                            'appcontrol_cat_Web'])
check('ruled and tabled: the applications of the rules switched on, with those of the settings',
      (sorted(tables.ruled(conf)), sorted(tables.tabled(dict(conf, apps=['DNS'])))),
      (['NetFlix', 'TLS', 'YouTube'], ['DNS', 'NetFlix', 'TLS', 'YouTube']))
ALL3 = {'appcontrol_%s' % a: {'kind': 'application', 'name': a} for a in ('YouTube', 'NetFlix', 'TikTok', 'TLS', 'DNS')}
found = tables.policy(conf, ALL3)
check('policy: NetFlix blocked for every device (Blocked applications) - its Alert rule no block; YouTube from opt2; TLS '
      'from every device but Teachers; the rule switched off, one of another action and one with no source, none',
      {app: (f['everyone'], [(r['uuid'][-1], r['source'], r['not']) for r in f['rules']]) for app, f in found.items()},
      {'NetFlix': (True, []), 'YouTube': (False, [('1', ['opt2'], False)]), 'TLS': (False, [('4', ['Teachers'], True)])})
check('policy: an application whose table is not made yet - not applied - nothing; classifying off, nothing',
      (sorted(tables.policy(conf, {k: v for k, v in ALL3.items() if k != 'appcontrol_YouTube'})),
       tables.policy(dict(conf, classify=False), ALL3)), (['NetFlix', 'TLS'], {}))
check('blocked: every application blocked, for every device or by a rule, with its table', tables.blocked(conf, ALL3),
      {'NetFlix': 'appcontrol_NetFlix', 'YouTube': 'appcontrol_YouTube', 'TLS': 'appcontrol_TLS'})
check('scope: every device; the elements of the rules\' sources; a rule from any is every device',
      (tables.scope(found['NetFlix']), tables.scope(found['YouTube']), tables.scope(
          {'everyone': False, 'rules': [{'source': ['any'], 'not': False}]}), tables.scope(None)),
      (tables.EVERYONE, frozenset({('opt2', False)}), tables.EVERYONE, frozenset()))
check('covers: every device covers anything; a wider set of sources a narrower one; not the other way, nor every device by '
      'a set, nor another name for the same devices',
      [tables.covers(tables.EVERYONE, frozenset({('opt2', False)})), tables.covers(frozenset({('opt2', False), ('lan', False)}),
                                                                                  frozenset({('opt2', False)})),
       tables.covers(frozenset({('opt2', False)}), frozenset({('opt2', False), ('lan', False)})),
       tables.covers(frozenset({('opt2', False)}), tables.EVERYONE), tables.covers(frozenset({('Guests', False)}),
                                                                                    frozenset({('opt2', False)})),
       tables.covers(frozenset(), frozenset({('opt2', False)}))], [True, True, False, False, False, False])

# ------------------------------------------------------------------------------------ where a source's devices are
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><interfaces><wan><if>em0</if></wan><lan><if>em1</if></lan><opt2><if>em2</if></opt2>'
                     '<opt3><descr>none</descr></opt3></interfaces></opnsense>')
    DEVICES = tables.interface_devices(config)
    check('the interfaces of config.xml and their devices; one with no device left out', DEVICES,
          {'wan': 'em0', 'lan': 'em1', 'opt2': 'em2'})
BY_DEV = tables.device_networks(IFCONFIG_TEXT)
check('ifconfig -a: each device\'s networks, link-local left out, each once',
      {d: [str(n) for n in nets] for d, nets in BY_DEV.items()},
      {'em0': ['203.0.113.0/24'], 'em1': ['192.0.2.0/24', '2001:db8:1::/64'], 'em2': ['198.51.100.128/25'],
       'lo0': ['127.0.0.0/8', '::1/128'], 'pppoe0': ['203.0.113.50/32']})
src_pf = FakePf({'Teachers': {'192.0.2.40', '192.0.2.41'}, 'Wing': {'192.0.2.0/25', '!192.0.2.64/26', '192.0.2.70'}})
RESOLVED = {e: tables.resolve(e, DEVICES, BY_DEV, tables.Pf(run=src_pf))
            for e in ('any', 'lan', 'opt2', '198.51.100.7', '2001:db8:9::/48', 'Teachers', 'Gone', '(self)', 'lanip')}
check('a source\'s element resolved: any; an interface\'s networks from ifconfig; an address or a network as written; an '
      'alias as pf holds its table; an alias pf holds no table for, the firewall itself and an address of its own - unread',
      {e: (k, [str(n) + ('!' if inv else '') for n, inv in v] if isinstance(v, list) else v) for e, (k, v) in RESOLVED.items()},
      {'any': ('any', None), 'lan': ('nets', ['192.0.2.0/24', '2001:db8:1::/64']), 'opt2': ('nets', ['198.51.100.128/25']),
       '198.51.100.7': ('nets', ['198.51.100.7/32']), '2001:db8:9::/48': ('nets', ['2001:db8:9::/48']),
       'Teachers': ('nets', ['192.0.2.40/32', '192.0.2.41/32']), 'Gone': ('unread', 'pf holds no table Gone'),
       '(self)': ('unread', '(self) is the firewall itself'), 'lanip': ('unread', 'lanip is the firewall itself')})
wing = tables.Pf(run=src_pf).entries('Wing')
held = tables.Held(wing)
check('a table with an entry written with !: an address in it when the most specific entry holding it is not inverted - '
      '192.0.2.70 in the hole and in again, 192.0.2.65 in the hole, 192.0.2.10 and nothing else',
      [a in held for a in ('192.0.2.10', '192.0.2.65', '192.0.2.70', '192.0.2.200', '2001:db8::1', 'no address')],
      [True, False, True, False, False, False])
check('flatten: the same addresses written without !, collapsed, IPv4 first',
      [str(n) for n in tables.flatten(wing + [(tables.ipaddress.ip_network('2001:db8::/64'), False),
                                              (tables.ipaddress.ip_network('203.0.113.0/24'), True)])],
      ['192.0.2.0/26', '192.0.2.70/32', '2001:db8::/64'])
check('flatten: a hole inside a hole already taken out, and a wider one first, change nothing more',
      [str(n) for n in tables.flatten([(tables.ipaddress.ip_network('192.0.2.0/24'), False),
                                       (tables.ipaddress.ip_network('192.0.2.0/28'), True),
                                       (tables.ipaddress.ip_network('192.0.2.0/25'), True)])], ['192.0.2.128/25'])

# ------------------------------------------------------------------------- the classifier's sources
where = classify.Where()
POLICY3 = {'YouTube': {'table': 'appcontrol_YouTube', 'everyone': False,
                       'rules': [{'uuid': R1, 'number': 1, 'source': ['opt2'], 'not': False}]},
           'TLS': {'table': 'appcontrol_TLS', 'everyone': False,
                   'rules': [{'uuid': R4, 'number': 4, 'source': ['Teachers'], 'not': True}]},
           'DNS': {'table': 'appcontrol_DNS', 'everyone': False,
                   'rules': [{'uuid': 'u-gone', 'number': 7, 'source': ['Gone'], 'not': False},
                             {'uuid': 'u-gone-not', 'number': 8, 'source': ['Gone'], 'not': True}]}}
where.refresh(POLICY3, DEVICES, BY_DEV, tables.Pf(run=src_pf))
check('where: a device in the source\'s network; one outside it; inverted - every device but the alias\'s; an alias that '
      'cannot be read holds no device, inverted or not',
      [where.holds(POLICY3['YouTube']['rules'][0], a) for a in ('198.51.100.130', '192.0.2.10')] +
      [where.holds(POLICY3['TLS']['rules'][0], a) for a in ('192.0.2.40', '192.0.2.10')] +
      [where.holds(r, '192.0.2.10') for r in POLICY3['DNS']['rules']], [True, False, False, True, False, False])
check('where: what could not be read, and why', where.unread, {'Gone': 'pf holds no table Gone'})


# ------------------------------------------------------------------------------------ a window under the rules
def rules_state(rules=(), blocked=(), apps=()):
    """A state whose settings hold the rules given, its addresses those of IFCONFIG_TEXT (em2, 198.51.100.128/25, is the
    guest network opt2), its interfaces DEVICES."""
    state = classify.State(T0, catalogue, {'classify': True, 'apps': list(apps), 'blocked': list(blocked),
                                           'rules': [dict({'number': i + 1, 'enabled': True, 'action': 'block', 'not': False,
                                                           'description': ''}, **r) for i, r in enumerate(rules)]},
                           [('lan', 'em1'), ('opt2', 'em2')])
    state.network = NET
    state.devices = DEVICES
    # as the service's first look does, before any window is judged
    state.where.refresh({}, DEVICES, BY_DEV, tables.Pf(run=FakePf()))
    return state


GUEST_YT = [{'uuid': R1, 'app': 'YouTube', 'source': ['opt2']}]
RULE_ALIASES = dict(aliases, appcontrol_NetFlix={'kind': 'application', 'name': 'NetFlix'},
                    appcontrol_TLS={'kind': 'application', 'name': 'TLS'})
guest = F(('198.51.100.10', 443), client=('198.51.100.130', 51401), iface='opt2')
staff = F(('198.51.100.11', 443), client=('192.0.2.10', 51402))
state = rules_state(GUEST_YT)
fake = FakePf()
counts = classify.apply(state, [('named', 'TLS.YouTube', guest, row(guest, 'TLS.YouTube', 'www.youtube.example')),
                                ('named', 'TLS.YouTube', staff, row(staff, 'TLS.YouTube', 'www.youtube.example'))],
                        tables.Pf(run=fake), RULE_ALIASES, T0 + 70, T0 + 70)
check('YouTube blocked from the guest network by a rule: a guest\'s connection queued to be cut, for that rule; a LAN '
      'device\'s not - remembered for when it is',
      ([(c['client'][0], c['app'], c['rule']) for c in state.to_cut], [classify.unpacked(k)[1][0] for k in state.remembered]),
      ([('198.51.100.130', 'YouTube', R1)], ['192.0.2.10']))
check('a table with a block rule from a source takes a server by cut.py alone, as one blocked for every device',
      fake.held.get('appcontrol_YouTube'), set())
check('status.json: the applications blocked - by a rule too', state.status()['blocking'], ['YouTube'])
state = rules_state([{'uuid': R4, 'app': 'TLS', 'source': ['Teachers'], 'not': True}])
teacher = F(('198.51.100.12', 443), client=('192.0.2.40', 51403))
classify.apply(state, [('named', 'TLS.YouTube', teacher, row(teacher, 'TLS.YouTube')),
                       ('named', 'TLS.YouTube', staff, row(staff, 'TLS.YouTube'))],
               tables.Pf(run=src_pf), RULE_ALIASES, T0 + 70, T0 + 70)
check('TLS blocked for every device but the alias Teachers: a teacher\'s connection let through, another\'s cut - as TLS, '
      'the protocol carrying it, by that rule', [(c['client'][0], c['app'], c['rule']) for c in state.to_cut],
      [('192.0.2.10', 'TLS', R4)])
state = rules_state([{'uuid': 'u-gone', 'app': 'YouTube', 'source': ['Gone']}])
said = []
real_log = classify.log
classify.log = said.append
try:
    classify.apply(state, [('named', 'TLS.YouTube', staff, row(staff, 'TLS.YouTube'))], tables.Pf(run=src_pf), RULE_ALIASES,
                   T0 + 70, T0 + 70)
    classify.say_unread(state, T0 + 70)
    classify.say_unread(state, T0 + 130)
finally:
    classify.log = real_log
check('a rule whose source cannot be read - an alias pf holds no table for: nothing cut, said once as the last error',
      (state.to_cut, said, state.status()['unread_sources']),
      ([], ['a block rule\'s source cannot be read, so nothing of its devices is cut: pf holds no table Gone'],
       {'Gone': 'pf holds no table Gone'}))
state = rules_state(GUEST_YT, blocked=['YouTube'])
classify.apply(state, [('named', 'TLS.YouTube', staff, row(staff, 'TLS.YouTube'))], tables.Pf(run=FakePf()), RULE_ALIASES,
               T0 + 70, T0 + 70)
check('blocked for every device as well (Blocked applications): any device\'s connection cut, for no rule',
      [(c['client'][0], c['rule']) for c in state.to_cut], [('192.0.2.10', '')])
state = rules_state(GUEST_YT + [{'uuid': R4, 'app': 'TLS', 'source': ['opt2']}])
classify.apply(state, [('named', 'TLS.YouTube', guest, row(guest, 'TLS.YouTube'))], tables.Pf(run=FakePf()), RULE_ALIASES,
               T0 + 70, T0 + 70)
check('YouTube and TLS, the protocol carrying it, both blocked from the guests by two rules: cut as YouTube, by its rule - '
      'nDPI\'s application before the protocol, as Blocked applications has it', [(c['app'], c['rule']) for c in state.to_cut],
      [('YouTube', R1)])

# a server two applications share, blocked for different devices
gm_lan = F(('198.51.100.10', 443), client=('192.0.2.20', 51404))
gm_rec = ('named', 'TLS.GMail', gm_lan, row(gm_lan, 'TLS.GMail', 'mail.example'))
guest_rec = ('named', 'TLS.YouTube', guest, row(guest, 'TLS.YouTube', 'www.youtube.example'))
GMAIL = dict(RULE_ALIASES, appcontrol_GMail={'kind': 'application', 'name': 'GMail'})
for gmail_rule, want, what in (
        (None, True, 'GMail not blocked at all'),
        ({'uuid': 'u-gm', 'app': 'GMail', 'source': ['lan']}, True, 'GMail blocked for the LAN alone'),
        ({'uuid': 'u-gm', 'app': 'GMail', 'source': ['lan', 'opt2']}, False, 'GMail blocked for the LAN and the guests'),
        ({'uuid': 'u-gm', 'app': 'GMail', 'source': ['any']}, False, 'GMail blocked for every device')):
    state = rules_state(GUEST_YT + ([gmail_rule] if gmail_rule else []))
    classify.apply(state, [gm_rec, guest_rec], tables.Pf(run=FakePf()), GMAIL, T0 + 70, T0 + 70)
    check('YouTube blocked from the guests, its server named GMail as well, %s: the guest\'s connection cut %s' % (
        what, 'alone - its server for no table, it would stop GMail for guests it lets through' if want else
        'and its server for the table - GMail is blocked for every guest anyway'),
        [(c['app'], c['alone']) for c in state.to_cut if c['client'][0] == '198.51.100.130'], [('YouTube', want)])
state = rules_state(GUEST_YT)
state.blocking = {'YouTube': 'appcontrol_YouTube'}       # blocked before: its table not emptied
fake = FakePf({'appcontrol_YouTube': {'198.51.100.10', '198.51.100.11'}})
counts = classify.apply(state, [gm_rec], tables.Pf(run=fake), GMAIL, T0 + 70, T0 + 70)
check('a server in a table blocked from the guests, named GMail - not blocked for them: taken out of it',
      (sorted(fake.held['appcontrol_YouTube']), counts['untabled']), (['198.51.100.11'], 1))
state = rules_state(GUEST_YT + [{'uuid': 'u-gm', 'app': 'GMail', 'source': ['opt2']}])
state.blocking = {'YouTube': 'appcontrol_YouTube', 'GMail': 'appcontrol_GMail'}
fake = FakePf({'appcontrol_YouTube': {'198.51.100.10'}})
classify.apply(state, [gm_rec], tables.Pf(run=fake), GMAIL, T0 + 70, T0 + 70)
check('the same, GMail blocked from the guests too: left in it', fake.held['appcontrol_YouTube'], {'198.51.100.10'})
state = rules_state(GUEST_YT + [{'uuid': 'u-gm', 'app': 'GMail', 'source': ['lan']}])
state.blocking = {'YouTube': 'appcontrol_YouTube', 'GMail': 'appcontrol_GMail'}
fake = FakePf({'appcontrol_YouTube': {'198.51.100.10'}})
classify.apply(state, [gm_rec], tables.Pf(run=fake), GMAIL, T0 + 70, T0 + 70)
check('the same, GMail blocked for the LAN alone - let through for the guests: taken out', fake.held['appcontrol_YouTube'],
      set())

# the rules change: what waits for a cut, and what is remembered, looked at again
state = rules_state(GUEST_YT)
classify.apply(state, [guest_rec, ('named', 'TLS.YouTube', staff, row(staff, 'TLS.YouTube'))], tables.Pf(run=FakePf()),
               RULE_ALIASES, T0 + 70, T0 + 70)
state.conf = dict(state.conf, rules=[dict(state.conf['rules'][0], source=['lan'])])
classify.block(state, RULE_ALIASES, T0 + 80, tables.Pf(run=FakePf()))
check('the rule\'s source changed from the guests to the LAN: the guest\'s connection waiting dropped, counted; the LAN '
      'device\'s, remembered, queued now for the rule', ([(c['client'][0], c['rule']) for c in state.to_cut],
                                                        state.totals['cut_unblocked'], len(state.remembered)),
      ([('192.0.2.10', R1)], 1, 0))
state = rules_state([])
classify.apply(state, [guest_rec, ('named', 'TLS.YouTube', staff, row(staff, 'TLS.YouTube'))], tables.Pf(run=FakePf()),
               RULE_ALIASES, T0 + 70, T0 + 70)
state.conf = dict(state.conf, rules=[dict(GUEST_YT[0], number=1, enabled=True, action='block', **{'not': False},
                                          description='')])
emptied = classify.block(state, RULE_ALIASES, T0 + 80, tables.Pf(run=FakePf()))[1]
check('a block rule added: the guests\' connection it remembered cut at once, the LAN device\'s left remembered; the '
      'application\'s table, blocked since, given back to be emptied',
      ([c['client'][0] for c in state.to_cut], [classify.unpacked(k)[1][0] for k in state.remembered], emptied),
      (['198.51.100.130'], ['192.0.2.10'], ['appcontrol_YouTube']))
state.to_cut = []
classify.block(state, RULE_ALIASES, T0 + 90, tables.Pf(run=FakePf()))
check('the same rules looked at again: nothing more queued', state.to_cut, [])

# what cut.py says, for each rule
state = rules_state(GUEST_YT)
classify.count_cut(state, {'cut': 3, 'apps': {'YouTube': 3}, 'rules': {R1: 2, '': 1}}, 3, T0)
classify.count_cut(state, {'cut': 1, 'rules': {R1: 1, 'bad': 'x'}}, 1, T0)
check('cut.py\'s answer for each rule counted - \'\' for Blocked applications - and in status.json',
      (state.rule_cut, state.status()['rule_cut']), ({R1: 3, '': 1, 'bad': 0}, {R1: 3, '': 1, 'bad': 0}))

# read again (SIGHUP): the rules and their sources read again
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><interfaces><lan><if>em1</if></lan><opt2><if>em2</if></opt2></interfaces><OPNsense><Firewall>'
                     '<Alias><aliases><alias><enabled>1</enabled><name>appcontrol_YouTube</name><type>external</type>'
                     '<description>Application Control: YouTube</description></alias></aliases></Alias></Firewall>'
                     '<AppControl><general><classify>1</classify></general><rules><rule uuid="%s"><enabled>1</enabled>'
                     '<action>block</action><source>opt2</source><source_not>0</source_not><app>YouTube</app></rule></rules>'
                     '</AppControl></OPNsense></opnsense>' % R1)
    state = rules_state([])
    state.network.by_dev = BY_DEV
    classify.apply(state, [guest_rec], tables.Pf(run=FakePf()), RULE_ALIASES, T0 + 70, T0 + 70)
    emptied = classify.reread(state, config, os.path.join(tmp, 'ndpi.json'), tables.Pf(run=FakePf()))
    check('read again, a block rule of the guests there since: its remembered guest connection cut at once, its table '
          'given back to be emptied', ([(c['client'][0], c['rule']) for c in state.to_cut], emptied, state.devices),
          ([('198.51.100.130', R1)], ['appcontrol_YouTube'], {'lan': 'em1', 'opt2': 'em2'}))

# --------------------------------------------------------------------------- what the page reads of the rules
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases>' + ''.join(
            '<alias><enabled>1</enabled><name>appcontrol_%s</name><type>external</type><description>Application Control: %s'
            '</description></alias>' % (a, a) for a in ('YouTube', 'NetFlix')) + '</aliases></Alias></Firewall>'
            '<IDS><general><enabled>1</enabled><mode>netmap</mode><interfaces>lan,opt2</interfaces></general></IDS>'
            '<AppControl><general><classify>1</classify></general>' + RULES_XML + '</AppControl></OPNsense></opnsense>')
    with open(os.path.join(tmp, 'status.json'), 'w') as handle:
        json.dump({'rule_cut': {R1: 4}}, handle)
    with open(os.path.join(tmp, 'suricata.json'), 'w') as handle:
        json.dump({'at': T0, 'lines': 37, 'rules': {R1: {'lines': 37, 'reason': None}, R4: {'lines': 0, 'reason': 'unread'}},
                   'errors': []}, handle)
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump({'protocols': {'YouTube': 'Media', 'NetFlix': 'Video', 'TikTok': 'SocialNetwork', 'DNS': 'Network'}}, handle)
    found = status.rules(config, os.path.join(tmp, 'status.json'), os.path.join(tmp, 'suricata.json'),
                         os.path.join(tmp, 'ndpi.json'), os.path.join(tmp, 'none.pid'))
    check('status.py rules: each rule\'s state - acting, its table there; switched off; one the installed nDPI does not know; '
          'not applied yet - and the connections cut for it, what its Suricata lines are',
          {k[-1]: (v['state'], v['table'], v['cut'], (v['suricata'] or {}).get('lines'), (v['suricata'] or {}).get('reason'))
           for k, v in found['rules'].items()},
          {'1': ('active', 'appcontrol_YouTube', 4, 37, None), '2': ('active', 'appcontrol_NetFlix', 0, None, None),
           '3': ('disabled', '', 0, None, None), '4': ('unknown_app', '', 0, 0, 'unread'), '5': ('disabled', '', 0, None, None),
           '6': ('disabled', '', 0, None, None)})
    check('status.py rules: the Intrusion Detection - on, IPS (netmap), its interfaces and their names, none of them internal '
          'here, Suricata not running; the rules file\'s lines', (found['ids'], found['suricata']['lines']),
          ({'enabled': True, 'mode': 'ips', 'interfaces': ['lan', 'opt2'], 'names': ['LAN', 'OPT2'], 'internal': [],
            'running': False}, 37))
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump({'protocols': {'YouTube': 'Media', 'NetFlix': 'Video', 'TLS': 'Web'}}, handle)
    found = status.rules(config, os.path.join(tmp, 'none.json'), os.path.join(tmp, 'none.json'), os.path.join(tmp, 'ndpi.json'),
                         os.path.join(tmp, 'none.pid'))
    check('status.py rules: an application nDPI knows, its table not made yet - not applied yet; nothing cut nor written yet',
          (found['rules'][R4]['state'], found['rules'][R4]['cut'], found['rules'][R4]['suricata'], found['suricata']['lines']),
          ('pending', 0, None, 0))
    check('status.py rules: the Intrusion Detection off, or IDS mode (pcap) - said', [status.ids(c, os.path.join(tmp, 'none.pid'))
                                                                                       for c in (os.path.join(tmp, 'none.xml'),)],
          [{'enabled': False, 'mode': 'ids', 'interfaces': [], 'names': [], 'internal': [], 'running': False}])

    # against what the last Apply put in force: the rules suricata_rules.py kept as it applied them
    now_rules = tables.settings(config)['rules']
    kept_rules = [dict(r) for r in now_rules if r['number'] != 2]       # rule 2, NetFlix, added since
    kept_rules[0]['source'] = ['lan']                                   # rule 1 applied from the LAN, changed since
    kept_rules[1]['enabled'] = True                                     # rule 3 applied switched on, off since
    kept_rules.append(dict(kept_rules[0], uuid='aaaaaaaa-0000-4000-8000-000000000009', number=9))   # deleted since
    with open(os.path.join(tmp, 'suricata.json'), 'w') as handle:
        json.dump({'at': T0, 'lines': 0, 'rules': {}, 'applied': {'classify': True, 'rules': kept_rules}, 'errors': []},
                  handle)
    found = status.rules(config, os.path.join(tmp, 'none.json'), os.path.join(tmp, 'suricata.json'),
                         os.path.join(tmp, 'ndpi.json'), os.path.join(tmp, 'none.pid'))
    check('status.py rules, against what was applied: a rule\'s source changed, a rule added, one switched off since - '
          'changed, not applied yet, pf and Suricata acting as before; one applied as it is - as it was; one switched off '
          'then and now - switched off; and the rule deleted since, still acting until Apply, counted',
          ({k[-1]: v['state'] for k, v in found['rules'].items()}, found['gone']),
          ({'1': 'changed', '2': 'changed', '3': 'changed', '4': 'pending', '5': 'disabled', '6': 'disabled'}, 1))
    with open(os.path.join(tmp, 'suricata.json'), 'w') as handle:
        json.dump({'rules': {R1: {'lines': 0, 'reason': 'unread', 'unread': ['opt2'], 'empty': False},
                             R2: {'lines': 0, 'reason': 'empty', 'unread': [], 'empty': True}},
                   'applied': {'classify': True, 'rules': now_rules}}, handle)
    found = status.rules(config, os.path.join(tmp, 'none.json'), os.path.join(tmp, 'suricata.json'),
                         os.path.join(tmp, 'ndpi.json'), os.path.join(tmp, 'none.pid'))
    check('status.py rules: a rule in force whose source cannot be read now - an alias gone - acts on no device; one whose '
          'source holds no device\'s address now - an interface without one - neither; nothing deleted since',
          (found['rules'][R1]['state'], found['rules'][R2]['state'], found['gone']), ('unread', 'empty', 0))
    youtube_rule = now_rules[0]
    check('status.py rules: part of a source not read - the rest acts; inverted, one element not read - it acts on none',
          [status.rule_state(dict(youtube_rule, source=s, **{'not': n}), {'classify': True}, None, {'unread': u},
                             {'YouTube': 'Media'}, 'appcontrol_YouTube')
           for s, n, u in ((['opt2', 'Kids'], False, ['Kids']), (['Kids'], True, ['Kids']), (['opt2', 'Kids'], False, []))],
          ['active', 'unread', 'active'])
    ids_on = []
    for reads in ('wan', 'lan,opt2'):
        with open(config, 'w') as handle:
            handle.write('<opnsense><interfaces><wan><enable>1</enable><if>em0</if><descr>WAN</descr><ipaddr>dhcp</ipaddr>'
                         '</wan><lan><enable>1</enable><if>em1</if><ipaddr>192.0.2.1</ipaddr></lan><opt2><enable>1</enable>'
                         '<if>em2</if><descr>GUEST</descr><ipaddr>198.51.100.129</ipaddr></opt2></interfaces><OPNsense><IDS>'
                         '<general><enabled>1</enabled><mode>pcap</mode><interfaces>%s</interfaces></general></IDS></OPNsense>'
                         '</opnsense>' % reads)
        found = status.ids(config, os.path.join(tmp, 'none.pid'))
        ids_on.append((found['names'], found['internal']))
    check('status.py rules: the Intrusion Detection on the WAN alone - by its name, no internal interface among them, where '
          'Suricata sees no device\'s own address after NAT; on the LAN and the guests - both internal',
          ids_on, [(['WAN'], []), (['LAN', 'GUEST'], ['lan', 'opt2'])])
    with open(os.path.join(tmp, 'suricata.pid'), 'w') as handle:
        handle.write(str(os.getpid()))
    check('status.py rules: a pidfile naming a live process that is not Suricata - not running',
          status.ids(config, os.path.join(tmp, 'suricata.pid'))['running'], False)
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><AppControl><general><classify>0</classify></general>' + RULES_XML +
                     '</AppControl></OPNsense></opnsense>')
    check('status.py rules: classifying off - every rule off', sorted({v['state'] for v in status.rules(
        config, os.path.join(tmp, 'none.json'), os.path.join(tmp, 'none.json'), os.path.join(tmp, 'ndpi.json'),
        os.path.join(tmp, 'none.pid'))['rules'].values()}), ['off'])
    with open(config, 'w') as handle:
        handle.write('<opnsense><OPNsense><Firewall><Alias><aliases><alias><enabled>1</enabled><name>appcontrol_YouTube</name>'
                     '<type>external</type><description>Application Control: YouTube</description></alias></aliases></Alias>'
                     '</Firewall><AppControl><general><classify>1</classify></general>' + RULES_XML +
                     '</AppControl></OPNsense></opnsense>')
    with open(os.path.join(tmp, 'status.json'), 'w') as handle:
        json.dump({'totals': {'cut': 4}, 'apps': {'YouTube': {'category': 'Media', 'named': 5, 'cut': 4}}}, handle)
    # pfctl -v -s rules: the rule of the guests' block, from their network
    with open(os.path.join(tmp, 'rules.txt'), 'w') as handle:
        handle.write('block drop in quick inet from (em2:network) to <appcontrol_YouTube:3> label "x"\n'
                     '  [ Evaluations: 9         Packets: 6         Bytes: 360         States: 0     ]\n')
    program(os.path.join(tmp, 'pfctl'), '#!/bin/sh\ncase "$*" in "-v -s rules") cat %s ;; esac\n'
            % os.path.join(tmp, 'rules.txt'))
    report = status.report(os.path.join(tmp, 'status.json'), config, os.path.join(tmp, 'ndpi.json'), os.path.join(tmp, 'none.pid'),
                           os.path.join(tmp, 'pfctl'), os.path.join(tmp, 'none'), os.path.join(tmp, 'none.py'))
    rows3 = {a['name']: a for a in report['apps']}
    check('status.py: YouTube blocked by a rule alone - not for every device - its table, its block rules, the packets they '
          'stopped; NetFlix of an Alert rule, its table not made yet',
          ({k: rows3['YouTube'][k] for k in ('blocked', 'rules', 'ruled', 'table', 'packets', 'cut')},
           {k: rows3['NetFlix'][k] for k in ('blocked', 'rules', 'ruled', 'table')}),
          ({'blocked': False, 'rules': 1, 'ruled': True, 'table': 'appcontrol_YouTube', 'packets': 6, 'cut': 4},
           {'blocked': False, 'rules': 0, 'ruled': True, 'table': ''}))
    check('status.py: the blocking line - nothing blocked for every device, one block rule acting, its packets',
          {k: report['blocking'][k] for k in ('apps', 'rules', 'packets')}, {'apps': [], 'rules': 1, 'packets': 6})

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
