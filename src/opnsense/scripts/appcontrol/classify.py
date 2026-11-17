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

What it found goes to /var/db/os-appcontrol: status.json (the page's cards and Applications) and
unknown.json (the page's Unknown), written after every window. Nothing is held on the firewall: no
connection waits for its classification. Errors are written there and to the system log, and the
service goes on: it never fails its caller.
"""

import errno
import fcntl
import ipaddress
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import syslog
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apps                                                              # noqa: E402
import capture                                                           # noqa: E402
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

STATE = '/var/db/os-appcontrol'
WORK = STATE + '/work'
STATUS = STATE + '/status.json'
UNKNOWN = STATE + '/unknown.json'
CONFIG = '/conf/config.xml'
TCPDUMP = '/usr/sbin/tcpdump'
IFCONFIG = '/sbin/ifconfig'

WINDOW = 60.0               # seconds a window gathers new connections
GRACE = 10.0                # seconds a window stays open after it ends, for its connections' later packets
PACKETS_PER_WINDOW = 2000000  # packets one interface is read for in a window; past it, the rest waits
UNKNOWN_KEEP = 500          # rows the Unknown list keeps of each kind, the latest
RETRY = 30.0                # seconds before a capture that stopped is started again
BEHIND = 2                  # windows past their close with none being judged that mean the clock stepped
                            # forward: a window judged past TIMEOUT leaves at most two behind

DYNAMIC_V4 = ('dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp')
DYNAMIC_V6 = ('dhcp6', 'slaac', '6rd', '6to4', 'pppoe')
NOT_WATCHED = ('lo', 'enc', 'pflog', 'pfsync')

running = True


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
    every internal one - switched on, not the WAN, no gateway, an address of its own that is not
    obtained from upstream."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    found = root.find('interfaces')
    out = []
    for node in (list(found) if found is not None else []):
        key, dev = node.tag, (node.findtext('if') or '').strip()
        if not dev or node.find('enable') is None or dev.startswith(NOT_WATCHED):
            continue
        if conf['interfaces']:
            if key in conf['interfaces']:
                out.append((key, dev))
            continue
        if key == 'wan' or node.find('internal_dynamic') is not None:
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
                       'not_tabled': 0, 'added': 0, 'refreshed': 0}
        self.not_tabled = dict.fromkeys(Network.REASONS, 0)
        self.network = Network()
        self.apps = {}
        self.unknown = {}
        self.last = None
        self.error = None
        self.capped = 0
        self.dropped = 0                # windows dropped as the clock stepped
        self.stopped = None

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


def apply(state, records, pf, aliases, now):
    """The records of a window into the state and the tables: the servers of connections nDPI named,
    begun here, into their category's table and their chosen application's - unless state.network
    says why not, which is counted; guesses and unknown connections into the Unknown list, never into
    a table, and those named by a protocol alone when they were begun here."""
    protocols = state.catalogue.get('protocols') or {}
    chosen = set(state.conf.get('apps') or [])
    puts = {}
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
    added = refreshed = 0
    for table in sorted(puts):
        a, r = pf.update(table, puts[table])
        added += a
        refreshed += r
    for key in counts:
        state.totals[key] += counts[key]
    state.totals['added'] += added
    state.totals['refreshed'] += refreshed
    _keep_latest(state.unknown)
    counts.update({'added': added, 'refreshed': refreshed, 'tables': len(puts)})
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
    """tcpdump -p on one interface, its pipe read without waiting, its packets handed to capture.Flows."""

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
            self.retry_at = now + RETRY
            return False
        fd = self.proc.stdout.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.error = None
        return True

    def fileno(self):
        return self.proc.stdout.fileno()

    def read(self, now):
        """What the pipe holds; False when tcpdump has stopped."""
        try:
            data = os.read(self.fileno(), 1 << 20)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return True
            data = b''
        if not data:
            self.stop()
            self.error = 'tcpdump stopped on %s' % self.dev
            self.retry_at = now + RETRY
            return False
        try:
            packets = self.stream.feed(data)
        except capture.StreamError as error:
            self.stop()
            self.error = 'what tcpdump wrote on %s could not be read: %s' % (self.dev, error)
            self.retry_at = now + RETRY
            return False
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


def serve(stop_after=None, now=time.time, reader=ndpi.NDPIREADER, tcpdump=TCPDUMP, pf=None, config=CONFIG,
          catalogue_path=tables.CATALOGUE, status=STATUS, unknown=UNKNOWN, work=WORK, refresh=True,
          ifconfig=IFCONFIG):
    """The service's loop until SIGTERM (or, for a test, until stop_after windows are judged). The
    catalogue of the installed nDPI is read again first, so a package updated since is followed."""
    conf = tables.settings(config)
    if refresh and ndpi.installed(reader):
        apps.refresh(reader, catalogue_path)
    catalogue = tables.load_catalogue(catalogue_path)
    watched = interfaces(conf, config)
    start = now()
    state = State(start, catalogue, conf, watched)
    pf = pf or tables.Pf()
    os.makedirs(work, exist_ok=True)
    for name in os.listdir(work):
        try:
            os.remove(os.path.join(work, name))
        except OSError:
            pass

    def save(captures):
        try:
            write_json(status, state.status(captures))
            write_json(unknown, state.unknown_rows())
        except OSError as error:
            log('Application Control: %s could not be written: %s' % (status, error))

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

    if not conf['classify']:
        state.fail('classification is off in Settings')
    elif not ndpi.installed(reader):
        state.fail('nDPI is not installed: %s is missing (pkg install ndpi)' % reader)
    elif not catalogue.get('categories'):
        state.fail('the categories of the installed nDPI are not read yet (apps.py refresh)')
    elif not watched:
        state.fail('no interface to watch: none is internal, and none is chosen in Settings')
    if state.error is not None:
        # nothing to do until Settings or the package change; the service stays, and says why
        save([])
        while running and stop_after is None:
            time.sleep(5)
        return state

    captures = [Capture(key, dev, start, tcpdump) for key, dev in watched]
    for c in captures:
        if not c.start(start):
            state.fail(c.error)
    log('Application Control: classifying on %s' % ', '.join('%s (%s)' % (c.key, c.dev) for c in captures))
    look(start)
    save(captures)
    next_close = int(start // WINDOW)
    job = None
    judged = 0
    while running:
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
                state.fail(c.error, t)
        current = int(t // WINDOW)
        for c in captures:
            if c.window != current:
                if c.read_in_window >= PACKETS_PER_WINDOW:
                    state.capped += 1
                c.window, c.read_in_window = current, 0
            if c.proc is None and t >= c.retry_at:
                if not c.start(t):
                    state.fail(c.error, t)
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
            save(captures)
            if stop_after is not None and judged >= stop_after:
                break
    for c in captures:
        c.stop()
    if job is not None:
        job.kill()
        job.remove()
    state.stopped = now()
    save(captures)
    return state


def stop(signum, frame):
    global running
    running = False


def main(argv):
    if argv[1:2] != ['run']:
        print('usage: classify.py run', file=sys.stderr)
        return 2
    syslog.openlog('appcontrol', syslog.LOG_PID, syslog.LOG_DAEMON)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
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
