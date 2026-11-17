#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""What the classifier reads - nDPI's answers and the packets themselves - and its tables, with
stand-ins for what only a firewall has: ndpiReader and pfctl.

- ndpiReader's CSV as phase 0's lab read it on an XGS 3300 (OPNsense 26.7.9, ndpi-6.0.d20260909,1):
  tools/fixtures/lab-*.csv are those files with every address made a documentation one; the rows
  and names found must be the lab's. The catalogue's two outputs, -a 1 and -H, are in the format of
  the source of nDPI de5c784 (tools/fixtures/ndpiReader-*.txt, written for the test, not read on a box).
- capture.py on packets built byte by byte (tools/pcapgen.py): the pcap stream in chunks, the
  connections and their server, what is kept for nDPI and in which window, and a ClientHello read -
  the JA4 of FoxIO's own example.
- tables.py: the alias names and the 31-character rule, the tables the settings ask for, and an
  address added when new and refreshed when seen again.

    python3 tools/test-classify.py"""
import json
import os
import struct
import sys
import tempfile

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



print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
