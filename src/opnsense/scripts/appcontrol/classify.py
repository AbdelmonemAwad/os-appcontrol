#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Application Control's classifier: which application each connection belongs to, by nDPI, and the
pf tables that follow from it.

    classify.py run       the service (rc.d/appcontrol runs it under daemon(8))

It reads the traffic and never stands in its way. On each interface it watches - the internal ones,
those without a gateway, unless Settings names others - tcpdump -p copies what the host sees through
BPF, the port left as it was (no promiscuous mode, which on an XGS front port is a request to the
switch's agent). capture.py keeps the first packets of each connection, in the window of WINDOW
seconds it began in; GRACE seconds after a window ends its packets go to ndpiReader as a file, once
as it is and once with guessing off (ndpi.py), and each connection is then:

  named        nDPI named it by its packets: the server's address goes into the table of its
               category, and into the table of its application when that one is chosen;
  guessed      named only with guessing on - by its port or its address: shown as a guess, never put
               in a table;
  unknown      not named at all, its beginning seen here: listed in Unknown with its server, and the
               server name and JA4 its TLS client gave, if any. A TLS, QUIC or HTTP connection begun
               here that nDPI named by that protocol alone - no application on top - is listed there
               too. Each kind keeps its latest UNKNOWN_KEEP rows.

A connection whose beginning was not seen - already open when the capture began - is not judged
unknown, and does not go into a table; one named by nDPI is counted. Nor does a server go into a table
that is the firewall itself or a host of its internal networks (Network, from ifconfig -a at each
window's close), an address that is no server's - multicast, broadcast, link-local, loopback,
unspecified - or the other end of an ICMP connection: those are counted in status.json as named and
not put in a table, with the reason.

A clock that steps - back, or forward past windows not yet closed - drops the windows still open, and
the windows begin again with the one now; status.json counts the windows dropped.

BLOCKING (phase 2). An application chosen in Blocked applications whose table is in config.xml is
blocked (tables.blocked()): plugins.inc.d/appcontrol.inc gives its table a block rule, and here a
connection nDPI names as it - by its packets, begun here, its server one that goes into a table - is
handed to cut.py once its window is judged, with its two ends, after its server went into the table:
its pf states killed by those ends, the coprocessor dropping it first where os-xgs-npu is installed.
cut.py runs beside the capture, one run at a time, so the capture is never held up. A guess, a
connection whose beginning was not seen, and one whose server goes into no table - the firewall, a host
of its internal networks, ICMP - are never cut, as they are never put in a table.

The connections named here that could be cut are remembered - the latest REMEMBER, for REMEMBER_FOR
seconds at most, one seen to end (FIN or RST) not at all - and when an application becomes blocked,
those remembered as it are cut at once and their servers put in its table, so its block rule holds
them before a new connection to them has to be named. SIGHUP has the settings read again (rc.d
appcontrol reload, the page's Apply): the blocked applications among them, the interfaces at the next
window's close, the installed nDPI's catalogue as aliases.php last read it - without a restart, which
would forget what is remembered.

What it found goes to /var/db/os-appcontrol: status.json (the page's cards and Applications) and
unknown.json (the page's Unknown), written after every window. Nothing is held on the firewall: no
connection waits for its classification, and an allowed one goes into hardware on os-xgs-npu's own
schedule. Errors are written there and to the system log, and the service goes on: it never fails its
caller.
"""

import errno
import fcntl
import ipaddress
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import syslog
import time
import xml.etree.ElementTree as ET
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apps                                                              # noqa: E402
import capture                                                           # noqa: E402
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

STATE = '/var/db/os-appcontrol'
WORK = STATE + '/work'      # a tmpfs rc.d/appcontrol mounts: a window's files never go to the disk
STATUS = STATE + '/status.json'
UNKNOWN = STATE + '/unknown.json'
CONFIG = '/conf/config.xml'
TCPDUMP = '/usr/sbin/tcpdump'
IFCONFIG = '/sbin/ifconfig'
MOUNT = '/sbin/mount'

WINDOW = 60.0               # seconds a window gathers new connections
GRACE = 10.0                # seconds a window stays open after it ends, for its connections' later packets
PACKETS_PER_WINDOW = 2000000  # packets one interface is read for in a window; past it, the rest waits
UNKNOWN_KEEP = 500          # rows the Unknown list keeps of each kind, the latest
RETRY = 30.0                # seconds before a capture that stopped is started again, doubled each time
RETRY_MOST = 600.0          # it stops again, up to this
BEHIND = 2                  # windows past their close with none being judged that mean the clock stepped
                            # forward: a window judged past TIMEOUT leaves at most two behind
CUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cut.py')
CUT_TIMEOUT = 120           # seconds a cut may take: pf's states read, the hardware step's 5 s, the kills
CUT_MOST = 5000             # connections one cut takes; the rest wait for the next
CUT_WAITING = 20000         # connections waiting for a cut at most; past it the oldest are left uncut, and said
REMEMBER = 50000            # connections named here remembered, for a cut when their application is blocked
REMEMBER_FOR = 86400        # seconds: pf keeps an established TCP connection a day without a packet

DYNAMIC_V4 = ('dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp')
DYNAMIC_V6 = ('dhcp6', 'slaac', '6rd', '6to4', 'pppoe')
NOT_WATCHED = ('lo', 'enc', 'pflog', 'pfsync')

running = True
reload_asked = False


def log(message):
    syslog.syslog(syslog.LOG_NOTICE, message)


def write_json(path, data):
    """Written whole and put in place in one step, so a reader never sees half of it."""
    tmp = path + '.new'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(data, handle)
    os.replace(tmp, path)


def interfaces(conf, path=CONFIG):
    """[(key, device)] watched: the interfaces chosen in Settings that are switched on; with none chosen,
    every internal one - switched on, not the WAN, no gateway of its own nor one in System: Gateways, an
    address of its own that is not obtained from upstream. Read again at each window's close."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    found = root.find('interfaces')
    routed = {(g.findtext('interface') or '').strip() for g in root.findall('gateways/gateway_item')}
    out = []
    for node in (list(found) if found is not None else []):
        key, dev = node.tag, (node.findtext('if') or '').strip()
        if not dev or node.find('enable') is None or dev.startswith(NOT_WATCHED):
            continue
        if conf['interfaces']:
            if key in conf['interfaces']:
                out.append((key, dev))
            continue
        if key == 'wan' or key in routed or node.find('internal_dynamic') is not None:
            continue
        if (node.findtext('gateway') or '').strip() or (node.findtext('gatewayv6') or '').strip():
            continue
        v4, v6 = (node.findtext('ipaddr') or '').strip(), (node.findtext('ipaddrv6') or '').strip()
        if v4 in DYNAMIC_V4 or v6 in DYNAMIC_V6:
            continue
        if _is_address(v4) or _is_address(v6) or v6 == 'track6':
            out.append((key, dev))
    return out


def _is_address(text):
    try:
        ndpi.ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def lan_devices(watched, path=CONFIG):
    """The devices whose networks are the firewall's internal ones: those internal by default, whatever
    Settings chose, and those watched."""
    return {dev for _, dev in interfaces({'interfaces': []}, path)} | {dev for _, dev in watched}


class Network:
    """The firewall's own addresses, and the networks of the interfaces given - its internal ones and
    those watched - as ifconfig -a lists them. A server nDPI named goes into no table when it is one of
    them, when its address is no server's (multicast, broadcast, link-local, loopback, unspecified), or
    when the connection is ICMP; and while the addresses have not been read, none does."""

    REASONS = ('icmp', 'address', 'own', 'lan', 'unread')
    HEAD = re.compile(r'^(\S+?):\s+flags=')
    LIMITED = ipaddress.ip_address('255.255.255.255')

    def __init__(self, text='', lan=()):
        self.own, self.networks, self.broadcast = set(), set(), {self.LIMITED}
        dev = None
        for line in text.splitlines():
            head = self.HEAD.match(line)
            if head:
                dev = head.group(1)
                continue
            words = line.split()
            if dev is None or len(words) < 2 or words[0] not in ('inet', 'inet6'):
                continue
            found = _interface(words)
            if found is None:
                continue
            self.own.add(found.ip)
            if found.version == 4 and 'broadcast' in words[:-1]:
                try:
                    self.broadcast.add(ipaddress.ip_address(words[words.index('broadcast') + 1]))
                except ValueError:
                    pass
            if dev in lan and found.network.prefixlen < found.max_prefixlen:
                self.networks.add(found.network)
                if found.version == 4 and found.network.prefixlen <= 30:
                    self.broadcast.add(found.network.broadcast_address)
        self.read = bool(self.own)

    def why_not(self, proto, server):
        """Why the server of a connection nDPI named goes into no table - one of REASONS - or None."""
        if proto in (capture.ICMP, capture.ICMP6):
            return 'icmp'
        try:
            address = ipaddress.ip_address(server)
        except ValueError:
            return 'address'
        if (address.is_multicast or address.is_link_local or address.is_loopback or address.is_unspecified
                or address in self.broadcast):
            return 'address'
        if not self.read:
            return 'unread'
        if address in self.own:
            return 'own'
        if any(address in net for net in self.networks if net.version == address.version):
            return 'lan'
        return None


def _interface(words):
    """The address and its network of one inet or inet6 line of ifconfig, in any of the ways it writes
    them - 'inet 192.0.2.1 netmask 0xffffff00', 'inet 192.0.2.1/24', 'inet6 fe80::1%em0 prefixlen 64';
    None for a line read as none of them."""
    text, prefix = words[1], None
    if '/' in text:
        text, prefix = text.rsplit('/', 1)
    text = text.split('%')[0]
    for i, word in enumerate(words[2:-1], 2):
        if word == 'netmask':
            try:
                mask = words[i + 1]
                prefix = bin(int(mask, 16) if mask.startswith('0x') else int(ipaddress.IPv4Address(mask))).count('1')
            except ValueError:
                return None
        elif word == 'prefixlen':
            prefix = words[i + 1]
    try:
        return ipaddress.ip_interface(text if prefix is None else '%s/%s' % (text, prefix))
    except ValueError:
        return None


def in_memory(path, mount=MOUNT):
    """True when path is where a file system in memory is mounted - tmpfs, or md(4)'s - as mount -p
    lists the mounts, the one on top last."""
    try:
        done = subprocess.run([mount, '-p'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    paths = {os.path.normpath(path), os.path.realpath(path)}
    found = False
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in paths:
            found = parts[2] in ('tmpfs', 'mfs') or parts[0].startswith('/dev/md')
    return found


def network(lan, before, ifconfig=IFCONFIG):
    """The firewall's addresses read again (ifconfig -a); the last read kept when this one gives none."""
    try:
        done = subprocess.run([ifconfig, '-a'], capture_output=True, text=True, timeout=30)
        text = done.stdout if done.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        text = ''
    found = Network(text, lan)
    return found if found.read or not before.read else before


class State:
    """What has been found since the service started, written for the page after every window."""

    def __init__(self, now, catalogue, conf, watched):
        self.since = now
        self.catalogue = catalogue
        self.conf = conf
        self.watched = watched
        self.windows = 0
        self.totals = {'flows': 0, 'named': 0, 'guessed': 0, 'unknown': 0, 'no_app': 0, 'not_judged': 0,
                       'not_tabled': 0, 'added': 0, 'refreshed': 0, 'to_cut': 0, 'cut': 0, 'cut_states': 0,
                       'cut_dropped': 0}
        self.not_tabled = dict.fromkeys(Network.REASONS, 0)
        self.network = Network()
        self.apps = {}
        self.unknown = {}
        self.last = None
        self.error = None
        self.capped = 0
        self.dropped = 0                # windows dropped as the clock stepped
        self.stopped = None
        self.blocking = {}              # {application: its table}, as last read (tables.blocked())
        self.remembered = OrderedDict()  # flow key -> (name, client, server, proto, first packet's time)
        self.to_cut = []                # connections waiting for cut.py
        self.last_cut = None

    def fail(self, message, now=None):
        self.error = {'at': now or time.time(), 'message': message}
        log(message)

    def status(self, captures=()):
        return {
            'since': self.since, 'windows': self.windows, 'window': WINDOW,
            'totals': dict(self.totals, not_tabled_why=dict(self.not_tabled)),
            'apps': self.apps, 'last': self.last, 'error': self.error, 'capped_windows': self.capped,
            'dropped_windows': self.dropped, 'stopped': self.stopped,
            'interfaces': [{'key': c.key, 'device': c.dev, 'capturing': c.proc is not None,
                            'packets': c.flows.packets, 'late': c.flows.late, 'unread': c.flows.unread,
                            'error': c.error} for c in captures],
            'engine': {'version': self.catalogue.get('version'), 'reader': self.catalogue.get('reader'),
                       'categories': len(self.catalogue.get('categories') or {}),
                       'protocols': len(self.catalogue.get('protocols') or {})},
            'blocking': sorted(self.blocking), 'remembered': len(self.remembered),
            'waiting_cut': len(self.to_cut), 'last_cut': self.last_cut,
        }

    def unknown_rows(self):
        """The Unknown list, latest first: apply() keeps each kind to its latest UNKNOWN_KEEP."""
        return sorted(self.unknown.values(), key=lambda r: r['last'], reverse=True)


def judge(flows, rows_any, rows_dpi):
    """[record] of one window: each connection begun in it (capture.Flow, by key) against the two CSVs,
    and the rows nDPI named that no capture matched - its keys and ours did not meet - with their ends
    from the row. A record: kind (named, guessed, unknown), nDPI's name, the flow or None, the row.
    A connection nDPI did not name is unknown only when its beginning was seen here and its first
    packets were all kept; else it is counted, not judged."""
    out = []
    rows_dpi = dict(rows_dpi)
    rows_any = dict(rows_any)
    not_judged = 0
    for key, flow in flows.items():
        dpi = rows_dpi.pop(key, None)
        any_row = rows_any.pop(key, None)
        if dpi is not None:
            out.append(('named', dpi['name'], flow, dpi))
        elif any_row is not None:
            out.append(('guessed', any_row['name'], flow, any_row))
        elif flow.started and not flow.cut:
            out.append(('unknown', None, flow, None))
        else:
            not_judged += 1
    for key, row in rows_dpi.items():
        out.append(('named', row['name'], None, row))
        rows_any.pop(key, None)
    for key, row in rows_any.items():
        out.append(('guessed', row['name'], None, row))
    return out, not_judged


def remember(state, flow, name):
    """A connection named here that could be cut, remembered: the latest REMEMBER, for REMEMBER_FOR seconds."""
    state.remembered.pop(flow.key, None)
    state.remembered[flow.key] = (name, flow.client, flow.server, flow.proto, flow.first)
    while len(state.remembered) > REMEMBER:
        state.remembered.popitem(last=False)


def forget_remembered(state, now):
    """The connections remembered for longer than REMEMBER_FOR, forgotten - the oldest first."""
    horizon = now - REMEMBER_FOR
    while state.remembered:
        key, entry = next(iter(state.remembered.items()))
        if entry[4] >= horizon:
            break
        state.remembered.pop(key)


def queue_cut(state, key, name, client, server, proto, first, app):
    """A connection of a blocked application, for cut.py: forgotten here, as it is being cut."""
    state.remembered.pop(key, None)
    state.to_cut.append({'proto': proto, 'client': list(client), 'server': list(server), 'name': name, 'app': app,
                         'first': first})


def trim_cut(state, now):
    """The connections waiting for cut.py kept to CUT_WAITING, the oldest left uncut - counted, and said."""
    over = len(state.to_cut) - CUT_WAITING
    if over > 0:
        del state.to_cut[:over]
        state.totals['cut_skipped'] = state.totals.get('cut_skipped', 0) + over
        state.fail('%d connection(s) of a blocked application left uncut: more were waiting for cut.py than %d'
                   % (over, CUT_WAITING), now)


def block(state, aliases, puts):
    """The applications blocked now (tables.blocked()). For one blocked since the last look, every connection
    remembered as it is queued to be cut, and its server put in the application's table - puts, for the
    caller - so the block rule holds it before a new connection to it has to be named. {application: table}."""
    blocked = tables.blocked(state.conf, aliases)
    newly = {app: table for app, table in blocked.items() if state.blocking.get(app) != table}
    if newly:
        for key, (name, client, server, proto, first) in list(state.remembered.items()):
            master, app = ndpi.split_name(name)
            hit = app if app in newly else master if master in newly else None
            if hit is not None:
                puts.setdefault(newly[hit], set()).add(server[0])
                queue_cut(state, key, name, client, server, proto, first, hit)
    state.blocking = blocked
    return blocked


def put(state, pf, puts):
    """puts - {table: addresses} - into pf: (added, refreshed), counted in the totals."""
    added = refreshed = 0
    for table in sorted(puts):
        a, r = pf.update(table, puts[table])
        added += a
        refreshed += r
    state.totals['added'] += added
    state.totals['refreshed'] += refreshed
    return added, refreshed


def apply(state, records, pf, aliases, now):
    """The records of a window into the state and the tables: the servers of connections nDPI named,
    begun here, into their category's table and their chosen application's - unless state.network
    says why not, which is counted; guesses and unknown connections into the Unknown list, never into
    a table, and those named by a protocol alone when they were begun here. A connection put in a table
    whose application - or the protocol carrying it - is blocked is queued to be cut (state.to_cut);
    one that is not, and was not seen to end, is remembered for when it is."""
    protocols = state.catalogue.get('protocols') or {}
    chosen = tables.tabled(state.conf)
    puts = {}
    waiting = len(state.to_cut)
    forget_remembered(state, now)
    blocked = block(state, aliases, puts)
    counts = {'flows': 0, 'named': 0, 'guessed': 0, 'unknown': 0, 'no_app': 0, 'not_tabled': 0}
    for kind, name, flow, row in records:
        counts['flows'] += 1
        if flow is not None:
            server, proto = flow.server, flow.proto
            server_name = (row or {}).get('server_name') or flow.sni or ''
            ja4, iface = flow.ja4 or '', flow.iface
        else:
            server, proto = (row['dst'], row['dport']), row['proto']
            server_name, ja4, iface = row.get('server_name') or '', '', ''
        if kind == 'named':
            counts['named'] += 1
            master, app = ndpi.split_name(name)
            category = protocols.get(app) or protocols.get(master)
            entry = state.apps.setdefault(app, {'category': category, 'named': 0, 'guessed': 0,
                                                'protocols': [], 'last': 0})
            entry['named'] += 1
            entry['category'] = category or entry['category']
            entry['last'] = now
            if master not in entry['protocols']:
                entry['protocols'].append(master)
            begun = flow is not None and flow.started
            why = state.network.why_not(proto, server[0]) if begun else None
            if why:
                counts['not_tabled'] += 1
                state.not_tabled[why] += 1
            elif begun:
                targets = []
                if category:
                    targets.append(tables.table_for_category(category, aliases))
                for each in {master, app} & chosen:
                    targets.append(tables.table_for_app(each, aliases))
                for table in targets:
                    if table:
                        puts.setdefault(table, set()).add(server[0])
                hit = app if app in blocked else master if master in blocked else None
                if hit is not None:
                    queue_cut(state, flow.key, name, flow.client, flow.server, flow.proto, flow.first, hit)
                elif not flow.ended:
                    remember(state, flow, name)
            if begun and ndpi.carried_only(name):
                counts['no_app'] += 1
                _unknown(state, 'no_app', name, proto, server, server_name, ja4, iface, now)
        elif kind == 'guessed':
            counts['guessed'] += 1
            master, app = ndpi.split_name(name)
            entry = state.apps.setdefault(app, {'category': protocols.get(app) or protocols.get(master),
                                                'named': 0, 'guessed': 0, 'protocols': [], 'last': 0})
            entry['guessed'] += 1
            entry['last'] = now
            _unknown(state, 'guess', name, proto, server, server_name, ja4, iface, now)
        else:
            counts['unknown'] += 1
            _unknown(state, 'unknown', None, proto, server, server_name, ja4, iface, now)
    added, refreshed = put(state, pf, puts)
    for key in counts:
        state.totals[key] += counts[key]
    _keep_latest(state.unknown)
    to_cut = len(state.to_cut) - waiting
    state.totals['to_cut'] += to_cut
    trim_cut(state, now)
    counts.update({'added': added, 'refreshed': refreshed, 'tables': len(puts), 'to_cut': to_cut})
    return counts


def _keep_latest(rows):
    """The Unknown list kept to the latest UNKNOWN_KEEP rows of each kind, so that many of one kind -
    guesses, say - never push the others out."""
    kinds = {}
    for row in rows.values():
        kinds.setdefault(row['kind'], []).append(row)
    for found in kinds.values():
        if len(found) > UNKNOWN_KEEP:
            for row in sorted(found, key=lambda r: r['last'])[:len(found) - UNKNOWN_KEEP]:
                rows.pop(row['id'], None)


def _unknown(state, kind, name, proto, server, server_name, ja4, iface, now):
    key = '|'.join(str(x) for x in (kind, name or '', proto, server[0], server[1], server_name, ja4))
    row = state.unknown.get(key)
    if row is None:
        row = state.unknown[key] = {'id': key, 'kind': kind, 'name': name or '', 'proto': proto,
                                    'server': server[0], 'port': server[1], 'server_name': server_name,
                                    'ja4': ja4, 'connections': 0, 'first': now, 'last': now, 'interfaces': []}
    row['connections'] += 1
    row['last'] = now
    if iface and iface not in row['interfaces']:
        row['interfaces'].append(iface)


class Capture:
    """tcpdump -p on one interface, its pipe read without waiting, its packets handed to capture.Flows.
    Stopped - its device gone, say - it is started again after RETRY seconds, the wait doubled each time
    it stops again, up to RETRY_MOST; said when it stops and when it reads again, not each time."""

    def __init__(self, key, dev, now, tcpdump=TCPDUMP):
        self.key, self.dev = key, dev
        self.tcpdump = tcpdump
        self.proc = None
        self.stream = capture.Stream()
        self.flows = capture.Flows(key, WINDOW, now)
        self.read_in_window = 0
        self.window = None
        self.error = None
        self.retry_at = 0.0
        self.delay = RETRY
        self.failing = False

    def start(self, now):
        self.stream = capture.Stream()
        self.flows.since = now
        try:
            # -U: each packet written as it comes, so a quiet interface's packets are not held back in
            # tcpdump's buffer past their window's grace
            self.proc = subprocess.Popen([self.tcpdump, '-p', '-n', '-U', '-i', self.dev, '-s', '0', '-w', '-',
                                          'ip or ip6'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         stdin=subprocess.DEVNULL)
        except OSError as error:
            self.proc = None
            self.error = 'tcpdump could not be started on %s: %s' % (self.dev, error)
            return False
        fd = self.proc.stdout.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.error = None
        return True

    def fileno(self):
        return self.proc.stdout.fileno()

    def trouble(self, state, now):
        """It stopped, or would not start: started again after its wait, which doubles; said only when it
        was reading until now."""
        self.stop()
        self.retry_at = now + self.delay
        self.delay = min(self.delay * 2, RETRY_MOST)
        if not self.failing:
            self.failing = True
            state.fail(self.error, now)

    def read(self, now):
        """What the pipe holds; False when tcpdump has stopped, why in error."""
        try:
            data = os.read(self.fileno(), 1 << 20)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return True
            data = b''
        if not data:
            self.error = 'tcpdump stopped on %s%s' % (self.dev, '' if _device(self.dev) else ': there is no such device')
            return False
        try:
            packets = self.stream.feed(data)
        except capture.StreamError as error:
            self.error = 'what tcpdump wrote on %s could not be read: %s' % (self.dev, error)
            return False
        if self.failing:
            # reading again: said, and its wait starts over
            log('Application Control: capturing again on %s (%s)' % (self.key, self.dev))
            self.failing, self.delay = False, RETRY
        linktype = self.stream.linktype
        for ts, record, wire in packets:
            try:
                self.flows.packet(linktype, ts, record, wire)
            except (IndexError, ValueError, struct.error):
                # a packet the reader cannot make sense of is one packet, not the end of the service
                self.flows.unread += 1
        self.read_in_window += len(packets)
        return True

    def stop(self):
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        except OSError:
            pass
        try:
            self.proc.stdout.close()
        except OSError:
            pass
        self.proc = None


def _device(dev):
    """Whether the system has the device: a VLAN, a tunnel or a PPP link can go, and come back."""
    try:
        socket.if_nametoindex(dev)
        return True
    except OSError:
        return False


def follow(state, captures, watched, now, tcpdump=TCPDUMP):
    """The captures made to match the interfaces watched: one for an interface no longer watched, or on
    another device now, stopped; one for an interface newly watched, started. Said when they change."""
    have = {(c.key, c.dev): c for c in captures}
    out = []
    for key, dev in watched:
        c = have.pop((key, dev), None)
        if c is None:
            c = Capture(key, dev, now, tcpdump)
            if not c.start(now):
                c.trouble(state, now)
        out.append(c)
    for c in have.values():
        c.stop()
    if [(c.key, c.dev) for c in out] != [(c.key, c.dev) for c in captures]:
        if out:
            log('Application Control: classifying on %s' % ', '.join('%s (%s)' % (c.key, c.dev) for c in out))
        else:
            state.fail('no interface to watch: none is internal, and none is chosen in Settings', now)
    return out


class Job:
    """One window's ndpiReader runs, started and not waited for, so the captures are read meanwhile: one
    interface's file at a time, its two runs together - never more than two ndpiReader at once - and the
    file and its CSVs removed once read, so the work directory holds one interface's at a time.

    An interface whose file could not be written, or one of whose runs could not start, ended with an
    error, wrote no CSV or was stopped at TIMEOUT, is not judged: its connections are counted as not
    judged - none called unknown, none put in a table - and the reason is a problem of the window's."""

    def __init__(self, index, parts, reader, work):
        self.index = index
        self.reader = reader
        self.started = time.monotonic()      # the clock of the window's time may step; this one does not
        self.parts = []
        for key, header, win in parts:
            base = os.path.join(work, '%d-%s' % (index, key))
            self.parts.append({'key': key, 'win': win, 'header': header, 'pcap': base + '.pcap',
                               'csv': (base + '.any.csv', base + '.dpi.csv'), 'procs': None, 'rows': None,
                               'problem': None, 'notes': []})
        self.at = 0
        self.unread = 0                      # connections of windows with no file to give ndpiReader
        self.poll()

    def _begin(self, part):
        part['procs'] = [None, None]
        try:
            capture.pcap_file(part['pcap'], part['header'], part['win'].records)
        except OSError as error:
            part['problem'] = 'the window\'s file for %s could not be written: %s' % (part['key'], error)
            return
        for i, guess in ((0, True), (1, False)):
            try:
                part['procs'][i] = subprocess.Popen(ndpi.command(part['pcap'], part['csv'][i], guess, self.reader),
                                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                                    stderr=subprocess.DEVNULL)
            except OSError as error:
                part['problem'] = part['problem'] or 'ndpiReader could not be run on %s: %s' % (part['key'], error)

    def _finish(self, part):
        """Its runs over: its two CSVs read when both ran well, then its files removed."""
        for proc in part['procs'] or ():
            if part['problem'] is None and proc is not None and proc.returncode != 0:
                part['problem'] = 'ndpiReader ended with status %d on %s' % (proc.returncode, part['key'])
        if part['problem'] is None:
            rows = []
            for csv in part['csv']:
                if not ndpi.wrote_csv(csv):
                    part['problem'] = 'ndpiReader wrote no CSV on %s' % part['key']
                    break
                found, bad = ndpi.read_csv(csv)
                if bad:
                    part['notes'].append('%d line(s) of ndpiReader\'s CSV not read on %s' % (bad, part['key']))
                rows.append(found)
            else:
                part['rows'] = rows
        self._remove(part)

    def poll(self):
        """The runs moved on - each interface's begun once the one before has finished; True once all are over."""
        while self.at < len(self.parts):
            part = self.parts[self.at]
            if part['procs'] is None:
                self._begin(part)
            if any(p is not None and p.poll() is None for p in part['procs']):
                return False
            self._finish(part)
            self.at += 1
        return True

    def kill(self):
        """At TIMEOUT: the runs going stopped, those not begun never begun - their interfaces not judged."""
        for part in self.parts[self.at:]:
            for proc in part['procs'] or ():
                if proc is not None and proc.poll() is None:
                    proc.kill()
                    proc.wait()
                    part['problem'] = part['problem'] or 'ndpiReader stopped after %d s on %s' % (ndpi.TIMEOUT, part['key'])
            if part['procs'] is None:
                part['problem'] = 'ndpiReader not run on %s: the window ran out of its %d s' % (part['key'], ndpi.TIMEOUT)
            self._finish(part)
        self.at = len(self.parts)

    def results(self):
        """({key: flow} begun in the window on the interfaces judged, rows named with guessing on, rows
        named by DPI, problems, connections not judged as their interface's runs did not go well)."""
        flows, rows_any, rows_dpi, problems, skipped = {}, {}, {}, [], self.unread
        for part in self.parts:
            problems.extend(part['notes'])
            if part['rows'] is None:
                problems.append(part['problem'] or 'ndpiReader did not run on %s' % part['key'])
                skipped += len(part['win'].flows)
                continue
            for flow in part['win'].flows:
                flows.setdefault(flow.key, flow)
            for found, rows in zip(part['rows'], (rows_any, rows_dpi)):
                for key, row in found.items():
                    rows.setdefault(key, row)
        return flows, rows_any, rows_dpi, problems, skipped

    @staticmethod
    def _remove(part):
        for path in (part['pcap'],) + part['csv']:
            try:
                os.remove(path)
            except OSError:
                pass

    def remove(self):
        for part in self.parts:
            self._remove(part)


class Cutter:
    """cut.py, run on the connections state.to_cut holds - at most CUT_MOST a run - beside the capture and
    not waited for, one run at a time; its answer, read when it ends, counted in the state. The list goes
    to it as a file in the work directory, in memory, removed once the run is over; a run past CUT_TIMEOUT
    is stopped, and its connections are not cut."""

    def __init__(self, work, script=CUT):
        self.work, self.script = work, script
        self.proc = None
        self.batch = []
        self.started = 0.0
        self.runs = 0
        self.paths = ()

    def start(self, state, now):
        if self.proc is not None or not state.to_cut:
            return
        batch, state.to_cut = state.to_cut[:CUT_MOST], state.to_cut[CUT_MOST:]
        self.runs += 1
        base = os.path.join(self.work, 'cut-%d' % self.runs)
        self.paths = (base + '.json', base + '.out')
        try:
            write_json(self.paths[0], batch)
            with open(self.paths[1], 'w') as out:
                self.proc = subprocess.Popen([self.script, 'cut', self.paths[0]], stdin=subprocess.DEVNULL,
                                             stdout=out, stderr=subprocess.DEVNULL)
        except OSError as error:
            self.proc = None
            self._remove()
            state.fail('%d connection(s) of a blocked application not cut: cut.py could not be run: %s'
                       % (len(batch), error), now)
            return
        self.batch, self.started = batch, time.monotonic()

    def poll(self, state, now):
        """The run over: its answer counted. True while one runs."""
        if self.proc is None:
            return False
        if self.proc.poll() is None:
            if time.monotonic() - self.started <= CUT_TIMEOUT:
                return True
            self.proc.kill()
            self.proc.wait()
            state.fail('cut.py took longer than %d s: %d connection(s) of a blocked application may not be cut'
                       % (CUT_TIMEOUT, len(self.batch)), now)
            answer = None
        else:
            try:
                with open(self.paths[1], encoding='utf-8') as handle:
                    answer = json.load(handle)
            except (OSError, ValueError):
                answer = None
            if not isinstance(answer, dict):
                state.fail('cut.py said nothing that could be read: %d connection(s) of a blocked application may '
                           'not be cut' % len(self.batch), now)
        if isinstance(answer, dict):
            count_cut(state, answer, len(self.batch), now)
        self.proc, self.batch = None, []
        self._remove()
        return False

    def finish(self, state, now, wait=5.0):
        """At the service's end: a run going is given `wait` seconds and its answer counted, or it is
        stopped. What waits for a run is left: the service is ending."""
        if self.proc is None:
            return
        try:
            self.proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            state.fail('the service ended while cut.py ran: %d connection(s) of a blocked application may not be cut'
                       % len(self.batch), now)
            self.proc, self.batch = None, []
            self._remove()
            return
        self.poll(state, now)

    def _remove(self):
        for path in self.paths:
            try:
                os.remove(path)
            except OSError:
                pass


def count_cut(state, answer, asked, now):
    """cut.py's answer in the state: the connections cut, the pf states killed, those dropped in hardware
    first, each application's, and what it could not do."""
    def number(value):
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    state.totals['cut'] += number(answer.get('cut'))
    state.totals['cut_states'] += number(answer.get('states'))
    dropped = answer.get('dropped')
    state.totals['cut_dropped'] += number(dropped)
    for app, n in (answer.get('apps') or {}).items():
        entry = state.apps.setdefault(str(app), {'category': None, 'named': 0, 'guessed': 0, 'protocols': [], 'last': 0})
        entry['cut'] = entry.get('cut', 0) + number(n)
    state.last_cut = {'at': now, 'asked': asked, 'cut': number(answer.get('cut')),
                      'states': number(answer.get('states')),
                      'dropped': dropped if dropped is None or dropped == 'unknown' else number(dropped)}
    for problem in answer.get('errors') or []:
        state.fail('the cut: %s' % problem, now)


def reread(state, config, catalogue_path):
    """The settings read again (SIGHUP): the applications blocked among them - looked at here at once, with
    the aliases as config.xml has them now - and the installed nDPI's catalogue as aliases.php last wrote
    it. The interfaces follow at the next window's close. {table: addresses} to put in pf."""
    conf = tables.settings(config)
    if not conf['read']:
        state.fail('%s could not be read: the settings stay as they were' % config)
        return {}
    catalogue = tables.load_catalogue(catalogue_path)
    if catalogue.get('categories'):
        problem = ndpi.protocols_problem(catalogue.get('protocols') or {})
        if problem:
            state.fail('the protocols of the installed nDPI cannot be believed (%s): no server goes into a category '
                       'table' % problem)
            catalogue = dict(catalogue, protocols={})
        state.catalogue = catalogue
    state.conf = conf
    puts = {}
    waiting = len(state.to_cut)
    block(state, tables.present(config), puts)
    state.totals['to_cut'] += len(state.to_cut) - waiting
    trim_cut(state, time.time())
    log('Application Control: settings read again: %d application(s) blocked' % len(state.blocking))
    return puts


def start_state(now, reader, config, catalogue_path, refresh, mount, work):
    """The service's state as it starts: the settings, the catalogue of the installed nDPI read again first -
    so a package updated since is followed - the interfaces, and the work directory emptied. Its error is
    set when there is nothing it can do."""
    conf = tables.settings(config)
    if refresh and ndpi.installed(reader):
        apps.refresh(reader, catalogue_path)
    catalogue = tables.load_catalogue(catalogue_path)
    state = State(now(), catalogue, conf, interfaces(conf, config))
    os.makedirs(work, exist_ok=True)
    for name in os.listdir(work):
        try:
            os.remove(os.path.join(work, name))
        except OSError:
            pass
    if not conf['classify']:
        state.fail('classification is off in Settings')
    elif not ndpi.installed(reader):
        state.fail('nDPI is not installed: %s is missing (pkg install ndpi)' % reader)
    elif not catalogue.get('categories'):
        state.fail('the categories of the installed nDPI are not read yet (apps.py refresh)')
    elif not in_memory(work, mount):
        state.fail('%s is not in memory - the rc script mounts a tmpfs there: no window is written to the disk, so '
                   'nothing is classified' % work)
    return state


def save_state(state, captures, status, unknown):
    """status.json and unknown.json written."""
    try:
        write_json(status, state.status(captures))
        write_json(unknown, state.unknown_rows())
    except OSError as error:
        log('Application Control: %s could not be written: %s' % (status, error))


def serve(stop_after=None, now=time.time, reader=ndpi.NDPIREADER, tcpdump=TCPDUMP, pf=None, config=CONFIG,
          catalogue_path=tables.CATALOGUE, status=STATUS, unknown=UNKNOWN, work=WORK, refresh=True,
          ifconfig=IFCONFIG, mount=MOUNT, cut=CUT):
    """The service's loop until SIGTERM (or, for a test, until stop_after windows are judged)."""
    global reload_asked
    while True:
        state = start_state(now, reader, config, catalogue_path, refresh, mount, work)
        if state.error is None:
            break
        # nothing to do until Settings or the package change; the service stays, and says why - and looks
        # again at a SIGHUP, the page's Apply
        save_state(state, [], status, unknown)
        while running and stop_after is None and not reload_asked:
            time.sleep(1)
        if not running or stop_after is not None:
            return state
        reload_asked = False
    conf, catalogue, watched, start = state.conf, state.catalogue, state.watched, state.since
    pf = pf or tables.Pf()
    cutter = Cutter(work, cut)

    def save(captures):
        save_state(state, captures, status, unknown)

    unread = [False]

    def look(t):
        """The firewall's addresses and its internal networks, read again."""
        state.network = network(lan_devices(watched, config), state.network, ifconfig)
        if state.network.read:
            unread[0] = False
        elif not unread[0]:
            unread[0] = True
            state.fail('the firewall\'s own addresses could not be read (%s -a): no server goes into a table '
                       'until they are' % ifconfig, t)

    problem = ndpi.protocols_problem(catalogue.get('protocols') or {})
    if problem:
        # a category taken from a table read wrong would put servers in the wrong tables: none is taken,
        # and the applications chosen in Settings fill theirs still
        state.fail('the protocols of the installed nDPI cannot be believed (%s): no server goes into a category '
                   'table' % problem, start)
        state.catalogue = dict(catalogue, protocols={})
    captures = follow(state, [], watched, start, tcpdump)
    if not watched:
        # the interfaces are read again at each window's close: one assigned since is followed
        state.fail('no interface to watch: none is internal, and none is chosen in Settings', start)
    look(start)
    save(captures)
    next_close = int(start // WINDOW)
    job = None
    judged = 0
    while running:
        if reload_asked:
            # the settings read again, and an application blocked since cut at once from what is remembered
            reload_asked = False
            put(state, pf, reread(state, config, catalogue_path))
            conf = state.conf
            for problem in pf.errors:
                state.fail(problem)
            pf.errors = []
            cutter.start(state, now())
            save(captures)
        live = [c for c in captures if c.proc is not None and c.read_in_window < PACKETS_PER_WINDOW]
        try:
            ready = select.select(live, [], [], 0.5)[0] if live else []
        except InterruptedError:
            ready = []
        if not live:
            time.sleep(0.5)
        t = now()
        for c in ready:
            if not c.read(t):
                c.trouble(state, t)
        current = int(t // WINDOW)
        for c in captures:
            if c.window != current:
                if c.read_in_window >= PACKETS_PER_WINDOW:
                    state.capped += 1
                c.window, c.read_in_window = current, 0
            if c.proc is None and t >= c.retry_at:
                if not c.start(t):
                    c.trouble(state, t)
        due = int((t - GRACE) // WINDOW) - 1
        if current < next_close or (job is None and due - next_close > BEHIND):
            # The clock stepped back - the windows still open would wait for it, and every connection
            # begun meanwhile be late - or forward, or the service was held up, past windows it would
            # close one by one: those windows are dropped, and windows begin again with this one.
            opened = {i for c in captures for i in c.flows.windows}
            lost = max(0, current - next_close) + sum(1 for i in opened if not next_close <= i < current)
            for c in captures:
                c.flows.restart(t)
            state.dropped += lost
            if current < next_close:
                log('Application Control: the clock went back: %d window(s) still open dropped, classifying goes on '
                    'from now' % lost)
            else:
                log('Application Control: %d window(s) behind - the clock went forward, or the service was held up: '
                    'dropped, classifying goes on from now' % lost)
            next_close = current
        if job is None and next_close <= due:
            parts, unread_flows = [], 0
            for c in captures:
                win = c.flows.close(next_close)
                if win.capped:
                    state.capped += 1
                if win.records and c.stream.header:
                    parts.append((c.key, c.stream.header, win))
                else:
                    unread_flows += len(win.flows)
                c.flows.forget(t)
            # the interfaces again: one assigned, switched on or off, or removed since is followed
            watched = state.watched = interfaces(conf, config)
            captures = follow(state, captures, watched, t, tcpdump)
            look(t)
            job = Job(next_close, parts, reader, work)
            job.unread = unread_flows
            next_close += 1
        over = job is not None and job.poll()
        if job is not None and not over and time.monotonic() - job.started > ndpi.TIMEOUT:
            job.kill()
            state.fail('ndpiReader took longer than %d s on window %d' % (ndpi.TIMEOUT, job.index))
            over = True
        if over:
            flows, rows_any, rows_dpi, problems, skipped = job.results()
            records, not_judged = judge(flows, rows_any, rows_dpi)
            not_judged += skipped
            aliases = tables.present(config)
            counts = apply(state, records, pf, aliases, now())
            state.totals['not_judged'] += not_judged
            counts['not_judged'] = not_judged
            counts['window'] = job.index
            counts['at'] = now()
            counts['seconds'] = round(time.monotonic() - job.started, 3)
            state.last = counts
            state.windows += 1
            for problem in problems + pf.errors:
                state.fail(problem)
            pf.errors = []
            job.remove()
            job = None
            judged += 1
            # the servers are in their tables first, so the block rule holds what comes after; then the cut
            cutter.start(state, now())
            save(captures)
            if stop_after is not None and judged >= stop_after:
                break
        if not cutter.poll(state, t):
            cutter.start(state, t)
    for c in captures:
        c.stop()
    if job is not None:
        job.kill()
        job.remove()
    cutter.finish(state, now())
    state.stopped = now()
    save(captures)
    return state


def stop(signum, frame):
    global running
    running = False


def read_again(signum, frame):
    """SIGHUP: the settings are read again at the loop's next turn."""
    global reload_asked
    reload_asked = True


def main(argv):
    if argv[1:2] != ['run']:
        print('usage: classify.py run', file=sys.stderr)
        return 2
    syslog.openlog('appcontrol', syslog.LOG_PID, syslog.LOG_DAEMON)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, read_again)
    try:
        os.makedirs(STATE, mode=0o750, exist_ok=True)
        serve()
    except Exception as error:                                           # noqa: BLE001
        # said, and the service ends; daemon(8) starts it again
        log('Application Control: the classifier stopped: %r' % error)
        try:
            write_json(STATUS, {'error': {'at': time.time(), 'message': 'the classifier stopped: %r' % error}})
        except OSError:
            pass
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
