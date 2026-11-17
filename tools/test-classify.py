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


# ------------------------------------------------------------------- judged, and what follows from it
class F:
    """A connection as capture.Flow gives it, for the records."""

    def __init__(self, server, started=True, sni=None, ja4=None, proto=6, client=('192.0.2.10', 50000), iface='lan'):
        self.server, self.client, self.started, self.sni, self.ja4, self.proto, self.iface = (
            server, client, started, sni, ja4, proto, iface)
        self.cut = False
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
                                                                  'engine']))
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


# ------------------------------------------------------------- one run of the service, with stand-ins
def program(path, text):
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


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
                           work=os.path.join(tmp, 'work'), refresh=False, ifconfig=os.path.join(tmp, 'ifconfig'))
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


def service(tmp, packets, any_rows, dpi_rows, reader=COPY_READER, stop_after=1, cat=None, more_interfaces='',
            timeout=40, **kwargs):
    """One run of the service with stand-ins, in tmp: tcpdump writing what the Python in packets puts in p
    (t its start, pcapgen there) and then waiting; ndpiReader (reader, %-formatted with the calls file and
    the two CSVs) - COPY_READER copies the CSV of the run asked for; ifconfig and a stand-in pfctl. Stopped
    after timeout s whatever happens. (state, status.json, unknown.json, the programs' calls, pfctl's tables)."""
    calls = os.path.join(tmp, 'calls')
    any_csv, dpi_csv = os.path.join(tmp, 'any.csv'), os.path.join(tmp, 'dpi.csv')
    for path, pairs in ((any_csv, any_rows), (dpi_csv, dpi_rows)):
        with open(path, 'w') as handle:
            handle.write(csv_rows(pairs))
    program(os.path.join(tmp, 'ndpiReader'), reader % (calls, dpi_csv, any_csv) if '%r' in reader else reader)
    program(os.path.join(tmp, 'tcpdump'), '#!/usr/bin/env python3\nimport os, sys, time\nsys.path.insert(0, %r)\n'
            'import pcapgen\nopen(%r, "a").write("tcpdump " + " ".join(sys.argv[1:]) + "\\n")\n'
            't = time.time()\nhello = pcapgen.client_hello(padding=1700)\np = []\n%s\n'
            'sys.stdout.buffer.write(pcapgen.capture(p))\nsys.stdout.buffer.flush()\n'
            'while True:\n    time.sleep(1)\n' % (HERE, calls, packets))
    with open(os.path.join(tmp, 'ifconfig.txt'), 'w') as handle:
        handle.write(IFCONFIG_TEXT)
    program(os.path.join(tmp, 'ifconfig'), '#!/bin/sh\necho "ifconfig $*" >> %s\ncat %s\n' % (calls, os.path.join(tmp, 'ifconfig.txt')))
    config = os.path.join(tmp, 'config.xml')
    with open(config, 'w') as handle:
        handle.write(SERVICE_CONFIG % more_interfaces)
    with open(os.path.join(tmp, 'ndpi.json'), 'w') as handle:
        json.dump(cat or catalogue, handle)
    fake = FakePf()
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
    state, saved, rows, asked, held = service(tmp, TWO, YOUTUBE, YOUTUBE, now=Clock(-1000, 3), timeout=15)
    check('the clock gone back 1000 s: windows close again at once, in the clock\'s new time',
          (state.windows, state.last and state.last['window'] < int(began // classify.WINDOW)), (1, True))

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
        json.dump({'version': '6.0.d20260909,1', 'protocols': {'Dropbox': 'Cloud', 'YouTube': 'Media'}}, handle)
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

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
