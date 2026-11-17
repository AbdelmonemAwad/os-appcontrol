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
               server name and JA4 its TLS client gave, if any. A TLS, QUIC or HTTP connection that nDPI
               named by that protocol alone - no application on top - is listed there too.

A connection whose beginning was not seen - already open when the capture began - is not judged
unknown, and does not go into a table; one named by nDPI is counted.

What it found goes to /var/db/os-appcontrol: status.json (the page's cards and Applications) and
unknown.json (the page's Unknown), written after every window. Nothing is held on the firewall: no
connection waits for its classification. Errors are written there and to the system log, and the
service goes on: it never fails its caller.
"""

import errno
import fcntl
import json
import os
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

WINDOW = 60.0               # seconds a window gathers new connections
GRACE = 10.0                # seconds a window stays open after it ends, for its connections' later packets
PACKETS_PER_WINDOW = 2000000  # packets one interface is read for in a window; past it, the rest waits
UNKNOWN_KEEP = 500          # rows the Unknown list keeps, the latest
RETRY = 30.0                # seconds before a capture that stopped is started again

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


class State:
    """What has been found since the service started, written for the page after every window."""

    def __init__(self, now, catalogue, conf, watched):
        self.since = now
        self.catalogue = catalogue
        self.conf = conf
        self.watched = watched
        self.windows = 0
        self.totals = {'flows': 0, 'named': 0, 'guessed': 0, 'unknown': 0, 'no_app': 0, 'not_judged': 0,
                       'added': 0, 'refreshed': 0}
        self.apps = {}
        self.unknown = {}
        self.last = None
        self.error = None
        self.capped = 0
        self.stopped = None

    def fail(self, message, now=None):
        self.error = {'at': now or time.time(), 'message': message}
        log(message)

    def status(self, captures=()):
        return {
            'since': self.since, 'windows': self.windows, 'window': WINDOW, 'totals': self.totals,
            'apps': self.apps, 'last': self.last, 'error': self.error, 'capped_windows': self.capped,
            'stopped': self.stopped,
            'interfaces': [{'key': c.key, 'device': c.dev, 'capturing': c.proc is not None,
                            'packets': c.flows.packets, 'late': c.flows.late, 'unread': c.flows.unread,
                            'error': c.error} for c in captures],
            'engine': {'version': self.catalogue.get('version'), 'reader': self.catalogue.get('reader'),
                       'categories': len(self.catalogue.get('categories') or {}),
                       'protocols': len(self.catalogue.get('protocols') or {})},
        }

    def unknown_rows(self):
        rows = sorted(self.unknown.values(), key=lambda r: r['last'], reverse=True)
        return rows[:UNKNOWN_KEEP]


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
    begun here, into their category's table and their chosen application's; guesses and unknown
    connections into the Unknown list, never into a table."""
    protocols = state.catalogue.get('protocols') or {}
    chosen = set(state.conf.get('apps') or [])
    puts = {}
    counts = {'flows': 0, 'named': 0, 'guessed': 0, 'unknown': 0, 'no_app': 0}
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
            if flow is not None and flow.started:
                targets = []
                if category:
                    targets.append(tables.table_for_category(category, aliases))
                for each in {master, app} & chosen:
                    targets.append(tables.table_for_app(each, aliases))
                for table in targets:
                    if table:
                        puts.setdefault(table, set()).add(server[0])
            if ndpi.carried_only(name):
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
    if len(state.unknown) > UNKNOWN_KEEP:
        for row in sorted(state.unknown.values(), key=lambda r: r['last'])[:len(state.unknown) - UNKNOWN_KEEP]:
            state.unknown.pop(row['id'], None)
    counts.update({'added': added, 'refreshed': refreshed, 'tables': len(puts)})
    return counts


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
    """One window's ndpiReader runs, started and not waited for, so the captures are read meanwhile."""

    def __init__(self, index, parts, reader, work):
        self.index = index
        self.parts = []
        self.started = time.time()
        for key, header, win in parts:
            base = os.path.join(work, '%d-%s' % (index, key))
            pcap = base + '.pcap'
            capture.pcap_file(pcap, header, win.records)
            procs = []
            for guess, csv in ((True, base + '.any.csv'), (False, base + '.dpi.csv')):
                try:
                    procs.append(subprocess.Popen(ndpi.command(pcap, csv, guess, reader), stdin=subprocess.DEVNULL,
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                except OSError:
                    procs.append(None)
            self.parts.append({'key': key, 'win': win, 'pcap': pcap, 'csv': (base + '.any.csv', base + '.dpi.csv'),
                               'procs': procs})

    def done(self):
        return all(p is None or p.poll() is not None for part in self.parts for p in part['procs'])

    def kill(self):
        for part in self.parts:
            for p in part['procs']:
                if p is not None and p.poll() is None:
                    p.kill()
                    p.wait()

    def results(self):
        """({key: flow} begun in the window, rows named with guessing on, rows named by DPI, problems)."""
        flows, rows_any, rows_dpi, problems = {}, {}, {}, []
        for part in self.parts:
            for flow in part['win'].flows:
                flows.setdefault(flow.key, flow)
            for i, rows in ((0, rows_any), (1, rows_dpi)):
                proc = part['procs'][i]
                if proc is None:
                    problems.append('ndpiReader could not be run')
                    continue
                if proc.returncode not in (0, None):
                    problems.append('ndpiReader ended with status %d on %s' % (proc.returncode, part['key']))
                found, bad = ndpi.read_csv(part['csv'][i])
                if bad:
                    problems.append('%d line(s) of ndpiReader\'s CSV not read on %s' % (bad, part['key']))
                for key, row in found.items():
                    rows.setdefault(key, row)
        return flows, rows_any, rows_dpi, problems

    def remove(self):
        for part in self.parts:
            for path in (part['pcap'],) + part['csv']:
                try:
                    os.remove(path)
                except OSError:
                    pass


def serve(stop_after=None, now=time.time, reader=ndpi.NDPIREADER, tcpdump=TCPDUMP, pf=None, config=CONFIG,
          catalogue_path=tables.CATALOGUE, status=STATUS, unknown=UNKNOWN, work=WORK, refresh=True):
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
        if job is None and next_close <= due:
            parts = []
            for c in captures:
                win = c.flows.close(next_close)
                if win.capped:
                    state.capped += 1
                if win.records and c.stream.header:
                    parts.append((c.key, c.stream.header, win))
                c.flows.forget(t)
            job = Job(next_close, parts, reader, work)
            next_close += 1
        if job is not None and (job.done() or now() - job.started > ndpi.TIMEOUT):
            if not job.done():
                job.kill()
                state.fail('ndpiReader took longer than %d s on window %d' % (ndpi.TIMEOUT, job.index))
            flows, rows_any, rows_dpi, problems = job.results()
            records, not_judged = judge(flows, rows_any, rows_dpi)
            aliases = tables.present(config)
            counts = apply(state, records, pf, aliases, now())
            state.totals['not_judged'] += not_judged
            counts['not_judged'] = not_judged
            counts['window'] = job.index
            counts['at'] = now()
            counts['seconds'] = round(now() - job.started, 3)
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
