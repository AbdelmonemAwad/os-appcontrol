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
connection nDPI names as it - by its packets, begun here, its server one that goes into a table and an
address of the internet - is handed to cut.py once its window is judged, with its two ends and the name
it carried: its pf states killed by those ends, the coprocessor dropping it first where os-xgs-npu is
installed. cut.py runs beside the capture, one run at a time, so the capture is never held up. A guess,
a connection whose beginning was not seen, one whose server goes into no table - the firewall, a host of
its internal networks, ICMP - and one to an address not on the internet - private, shared, unique-local
(internet()) - are never cut.

What a device sends names its connection - the server name of TLS and QUIC, HTTP's Host - and a device
can write any name to any address. So a blocked application's table, whose rule holds every device's new
connections to it, takes a server only when cut.py finds that the firewall's own resolver gives that
address for that name, and only when nothing named that address, within the address expiry, as an
application that is not blocked (shared()); else that connection alone is cut - the plan's "the block
restricted to cutting the connection where it is needed". Nothing here puts a server in a blocked
application's table, and a table that becomes blocked is emptied first: what went into it before, from
names alone, leaves it. A server in a blocked table that a connection names as an application not
blocked is taken out of it (untable()).

The connections named here that could be cut are remembered - the latest REMEMBER, for REMEMBER_FOR
seconds at most; one seen to end (FIN or RST), or a UDP exchange of two packets, not at all - and when
an application becomes blocked, those remembered as it are cut at once, and their servers put in its
table the same way, so its block rule holds them before a new connection to them has to be named. What
waits for a cut of an application no longer blocked is dropped. SIGHUP has the settings read again
(rc.d appcontrol reload, the page's Apply): the blocked applications among them, the interfaces at the
next window's close, the installed nDPI's catalogue as aliases.php last read it - without a restart,
which would forget what is remembered.

RULES (phase 3). A block rule of the Rules tab blocks its application for the devices of its source
alone - an interface's network, an alias, an address or a network, or every device but those of one of
them: its pf block rule is from that source, and a connection is cut only when its device - the client's
address - is one of it (cut_as()). Each source is read as pf holds it (Where): an interface's networks
from ifconfig -a, an alias's table from pfctl, again at each window's close; one that cannot be read
holds no device, and nothing is cut for it. Blocked for every device by Blocked applications, an
application is cut whoever sends. A server two applications share goes into the table of one only when
the other's block reaches every device the first one's does (tables.covers()); else that connection
alone is cut. Each cut is counted for the rule that made it.

The Suricata rules of the Rules tab follow the same sources: while a rule is switched on, suricata_rules.py
runs beside the capture, not waited for - `start` as the service starts, at boot among them, writing them as
the settings say, as the service reads its own; then `refresh` every SURICATA_EVERY seconds, the rules last
applied resolved again - an alias whose table changed, a new delegated prefix, the installed nDPI's names -
the file written and the Intrusion Detection told only when that changed it. What it could not do is the
page's last error.

What it found goes to /var/db/os-appcontrol: status.json (the page's cards and Applications) and
unknown.json (the page's Unknown), written after every window. Nothing is held on the firewall: no
connection waits for its classification, and an allowed one goes into hardware on os-xgs-npu's own
schedule. Errors are written there and to the system log, and the service goes on: it never fails its
caller.
"""

import signal

reload_asked = False


def read_again(signum, frame):
    """SIGHUP: the settings are read again at the loop's next turn. Set before anything else is imported:
    SIGHUP's own action ends a process, and a reload in the service's first moments - rc.d/appcontrol
    reload, the page's Apply - is not to end it."""
    global reload_asked
    reload_asked = True


signal.signal(signal.SIGHUP, read_again)

import errno                                                             # noqa: E402
import fcntl                                                             # noqa: E402
import ipaddress                                                         # noqa: E402
import json                                                              # noqa: E402
import os                                                                # noqa: E402
import select                                                            # noqa: E402
import socket                                                            # noqa: E402
import struct                                                            # noqa: E402
import subprocess                                                        # noqa: E402
import sys                                                               # noqa: E402
import syslog                                                            # noqa: E402
import time                                                              # noqa: E402

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
POLICY = 'policy.json'      # in the work directory: what is blocked, for whom, as the service holds it, for cut.py
CUT_TIMEOUT = 120           # seconds a cut may take - cut.py ends its kills at its own BUDGET, 90 s, before it
CUT_MOST = 5000             # connections one cut takes; the rest wait for the next
CUT_WAITING = 20000         # connections waiting for a cut at most; past it the oldest are left uncut, and said
CUT_TRIES = 2               # runs a connection is given: one stopped at its time, or past cut.py's own, goes again
SURICATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'suricata_rules.py')
SURICATA_EVERY = 300        # seconds between two looks at the Suricata rules' sources and names: each change
                            # installs every rule of the Intrusion Detection again
SURICATA_TIMEOUT = 900      # seconds a look may take - its reload of the Intrusion Detection's rules among them
REMEMBER = 50000            # connections named here remembered, for a cut when their application is blocked
REMEMBER_FOR = 86400        # seconds: pf keeps an established TCP connection a day without a packet
NAMES_MOST = 20000          # servers whose names are kept, to tell one an application not blocked shares
NAMES_EACH = 4              # names kept of each server, the latest
# What stands for the internet besides the addresses Python's ipaddress takes for global: nothing on a
# firewall. The tests, whose addresses are all documentation ones, put the documentation networks here.
ALSO_GLOBAL = ()

DYNAMIC_V4 = tables.DYNAMIC_V4
DYNAMIC_V6 = tables.DYNAMIC_V6
NOT_WATCHED = tables.NOT_WATCHED

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
    every internal one (tables.interfaces()). Read again at each window's close."""
    return tables.interfaces(conf['interfaces'], path)


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
    HEAD = tables.IFCONFIG_HEAD
    LIMITED = ipaddress.ip_address('255.255.255.255')

    def __init__(self, text='', lan=()):
        self.own, self.networks, self.broadcast = set(), set(), {self.LIMITED}
        # every device's networks, for the sources of the block rules (Where)
        self.by_dev = tables.device_networks(text)
        dev = None
        for line in text.splitlines():
            head = self.HEAD.match(line)
            if head:
                dev = head.group(1)
                continue
            words = line.split()
            if dev is None or len(words) < 2 or words[0] not in ('inet', 'inet6'):
                continue
            found = tables.ifconfig_address(words)
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


def internet(server):
    """Whether a server's address is one of the internet's - global, as Python's ipaddress has it, or in
    ALSO_GLOBAL. Not a private (RFC 1918), shared (RFC 6598), unique-local or other reserved one: a
    host at a VPN's other end, behind a static route or on a DMZ - the firewall's internal networks it is
    not attached to - is never put in a blocked table nor cut, whatever its connections are named."""
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        return False
    return address.is_global or any(address in net for net in ALSO_GLOBAL if net.version == address.version)


# Where the sources of the block rules are: tables.py's, which cut.py judges a connection's device by too
Where = tables.Where


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
                       'cut_dropped': 0, 'cut_tabled': 0, 'cut_alone': 0, 'cut_unblocked': 0, 'cut_skipped': 0,
                       'not_internet': 0, 'untabled': 0}
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
        self.policy = {}                # {application: whom it is blocked for}, as last read (tables.policy())
        self.where = Where()            # the sources of the block rules, resolved
        self.where_held = None          # what they held at the last look at what is blocked (Where.digest())
        self.devices = {}               # {interface: device}, as config.xml last said
        self.unread_said = set()        # the elements of a source said not to be read
        self.remembered = {}            # packed() of its two ends -> (name, began, name it carried), oldest first
        self.to_cut = []                # connections waiting for cut.py
        self.names_at = {}              # server -> {name nDPI gave it: when, on the monotonic clock}
        self.last_cut = None
        self.rule_cut = {}              # the connections cut for each rule - '' for Blocked applications

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
            'waiting_cut': len(self.to_cut), 'last_cut': self.last_cut, 'rule_cut': dict(self.rule_cut),
            'unread_sources': dict(sorted(self.where.unread.items())),
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


_PORT = struct.Struct('!H')


def packed(proto, client, server):
    """A connection's protocol and two ends as bytes - the client's address and port, then the server's: 13
    bytes for IPv4, 37 for IPv6. Remembered so, 50,000 take some 9 MB, where tuples of text took 29."""
    return (bytes((proto,)) + ipaddress.ip_address(client[0]).packed + _PORT.pack(client[1])
            + ipaddress.ip_address(server[0]).packed + _PORT.pack(server[1]))


def unpacked(key):
    """(proto, client, server) of packed(), the ends as (address as text, port)."""
    size = (len(key) - 5) // 2
    return (key[0], (ipaddress.ip_address(key[1:1 + size]).compressed, _PORT.unpack_from(key, 1 + size)[0]),
            (ipaddress.ip_address(key[3 + size:3 + 2 * size]).compressed, _PORT.unpack_from(key, 3 + 2 * size)[0]))


def remember(state, flow, name, host=''):
    """A connection named here that could be cut, remembered with the name it carried: the latest REMEMBER,
    for REMEMBER_FOR seconds."""
    key = packed(flow.proto, flow.client, flow.server)
    state.remembered.pop(key, None)
    state.remembered[key] = (sys.intern(name), flow.began, sys.intern(host) if host else '')
    while len(state.remembered) > REMEMBER:
        del state.remembered[next(iter(state.remembered))]


def forget_remembered(state, mono):
    """The connections remembered for longer than REMEMBER_FOR, forgotten - the oldest first. On the monotonic
    clock, as they were remembered."""
    horizon = mono - REMEMBER_FOR
    while state.remembered:
        key = next(iter(state.remembered))
        if state.remembered[key][1] >= horizon:
            break
        del state.remembered[key]


def cut_as(state, name, client):
    """(application, rule) that a connection nDPI named so, from the device at `client`, is cut as - nDPI's
    application, else the protocol carrying it - when it is blocked for every device (rule '') or by a block
    rule whose source holds the device (the rule's uuid); or None."""
    master, app = ndpi.split_name(name)
    for candidate in (app, master) if app != master else (app,):
        found = state.policy.get(candidate)
        if found is None:
            continue
        if found['everyone']:
            return candidate, ''
        for rule in found['rules']:
            if state.where.holds(rule, client):
                return candidate, rule['uuid']
    return None


def name_scope(state, name):
    """Whom a block of what nDPI named so reaches: its application's and the carrying protocol's, together
    (tables.scope()); nobody when neither is blocked."""
    master, app = ndpi.split_name(name)
    scopes = [tables.scope(state.policy[c]) for c in {app, master} if c in state.policy]
    if any(s == tables.EVERYONE for s in scopes):
        return tables.EVERYONE
    return frozenset().union(*scopes)


def note(state, server, name, mono):
    """A name nDPI gave a server, kept with when: the latest NAMES_EACH of a server, the latest NAMES_MOST
    servers."""
    seen = state.names_at.pop(server, None) or {}
    seen.pop(name, None)
    seen[sys.intern(name)] = mono
    while len(seen) > NAMES_EACH:
        del seen[next(iter(seen))]
    state.names_at[server] = seen
    while len(state.names_at) > NAMES_MOST:
        del state.names_at[next(iter(state.names_at))]


def shared(state, server, mono, app):
    """Whether nDPI named the server, within the address expiry, as an application whose block does not reach
    every device `app`'s block does (tables.covers()) - one not blocked at all, or blocked for other devices:
    its address serves that one too, and putting it in `app`'s table would stop that one for devices it is
    let through for. A protocol named alone - TLS, QUIC, HTTP with no application on top - is no other
    application."""
    horizon = mono - state.conf.get('ttl', tables.TTL)
    mine = tables.scope(state.policy.get(app))
    for name, when in (state.names_at.get(server) or {}).items():
        if when >= horizon and not ndpi.carried_only(name) and not tables.covers(name_scope(state, name), mine):
            return True
    return False


def queue_cut(state, key, name, client, server, proto, began, app, host='', alone=False, rule=''):
    """A connection of a blocked application, for cut.py: forgotten here, as it is being cut. host is the
    name it carried; alone, its server is kept out of its application's table whatever the resolver says
    (shared()); rule, the block rule it is cut for - '' for Blocked applications."""
    state.remembered.pop(key, None)
    state.to_cut.append({'proto': proto, 'client': list(client), 'server': list(server), 'name': name, 'app': app,
                         'began': began, 'host': host, 'alone': alone, 'rule': rule})


def trim_cut(state, now):
    """The connections waiting for cut.py kept to CUT_WAITING, the oldest left uncut - counted, and said."""
    over = len(state.to_cut) - CUT_WAITING
    if over > 0:
        del state.to_cut[:over]
        state.totals['cut_skipped'] += over
        state.fail('%d connection(s) of a blocked application left uncut: more were waiting for cut.py than %d'
                   % (over, CUT_WAITING), now)


def requeue(state, conns, now, why):
    """Connections a cut did not reach queued again, first; a connection is given CUT_TRIES runs, and one past
    them is left uncut - counted, and said."""
    again, spent = [], 0
    for conn in conns:
        if not isinstance(conn, dict):
            continue
        tries = conn.get('tries')
        tries = (tries if isinstance(tries, int) and not isinstance(tries, bool) else 1) + 1
        if tries > CUT_TRIES:
            spent += 1
        else:
            again.append(dict(conn, tries=tries))
    state.to_cut[:0] = again
    if spent:
        state.totals['cut_skipped'] += spent
        state.fail('%d connection(s) of a blocked application left uncut: %s, %d times' % (spent, why, CUT_TRIES), now)
    return len(again)


def block(state, aliases, mono=None, pf=None):
    """The applications blocked now (tables.policy()) - for every device, or for the sources of block rules,
    each element of a new source resolved (Where). What waits for a cut is looked at again: a connection no
    longer blocked for its device is dropped from the queue, counted; one blocked another way now - by another
    rule, or as another application - is cut that way, whether its server is shared worked out again for it.
    When what is blocked has changed - the policy, or what its sources hold: an alias that gained a device -
    every connection remembered is looked at, and one blocked now for its device is queued to be cut - its
    server put in its table by cut.py, as any other's. The tables of the applications blocked since the last
    look are given back to be emptied first: what went into them while they were not blocked went in on a name
    alone. ({application: table}, [tables to empty])."""
    mono = time.monotonic() if mono is None else mono
    found = tables.policy(state.conf, aliases)
    blocked = {app: entry['table'] for app, entry in found.items()}
    newly = {app: table for app, table in blocked.items() if state.blocking.get(app) != table}
    changed = found != state.policy
    state.policy, state.blocking = found, blocked
    state.where.ensure(found, pf or tables.Pf())
    held_now = state.where.digest()
    changed = changed or held_now != state.where_held
    state.where_held = held_now
    kept = []
    for conn in state.to_cut:
        hit = cut_as(state, str(conn.get('name') or conn.get('app') or ''), str((conn.get('client') or [''])[0]))
        if hit is not None:
            again = dict(conn, app=hit[0], rule=hit[1])
            if changed or hit[0] != conn.get('app'):
                # shared with another application or not is a question of whom each block reaches: asked again
                again['alone'] = shared(state, str((conn.get('server') or [''])[0]), mono, hit[0])
            kept.append(again)
    if len(kept) != len(state.to_cut):
        state.totals['cut_unblocked'] += len(state.to_cut) - len(kept)
    state.to_cut = kept
    if changed:
        waiting = len(state.to_cut)
        for key, (name, began, host) in list(state.remembered.items()):
            proto, client, server = unpacked(key)
            hit = cut_as(state, name, client[0])
            if hit is None:
                continue
            if not internet(server[0]):
                state.remembered.pop(key, None)
                state.totals['not_internet'] += 1
                continue
            queue_cut(state, key, name, client, server, proto, began, hit[0], host, shared(state, server[0], mono, hit[0]),
                      hit[1])
        state.totals['to_cut'] += len(state.to_cut) - waiting
    return blocked, sorted(set(newly.values()))


def untable(state, pf, seen):
    """The servers named in this window - seen, {server: {name}} - as an application whose block does not reach
    every device a blocked table's block does, taken out of that table: they serve that application too, for
    devices it is let through for. How many."""
    out = 0
    for app in sorted(state.policy):
        found = state.policy[app]
        mine = tables.scope(found)
        wrong = {server for server, names in seen.items()
                 if any(not ndpi.carried_only(n) and not tables.covers(name_scope(state, n), mine) for n in names)}
        if not wrong:
            continue
        gone = sorted(set(pf.show(found['table']) or ()) & wrong)
        if gone:
            pf.delete(found['table'], gone)
            out += len(gone)
    state.totals['untabled'] += out
    return out


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


def apply(state, records, pf, aliases, now, mono=None):
    """The records of a window into the state and the tables: the servers of connections nDPI named,
    begun here, into their category's table and their chosen application's - unless state.network
    says why not, which is counted; guesses and unknown connections into the Unknown list, never into
    a table, and those named by a protocol alone when they were begun here. A connection of an
    application blocked for its device - or of the protocol carrying it (cut_as()) - whose server would go
    into a table is queued to be cut (state.to_cut) when its server is an address of the internet, with the
    name it carried and the rule it is cut for; its server goes into the blocked table by cut.py alone, once
    the resolver vouches for it. One that is not blocked for its device, and was not seen to end, is
    remembered for when it is. now is the wall clock's, for the page; mono the monotonic clock's, for what is
    kept."""
    mono = time.monotonic() if mono is None else mono
    protocols = state.catalogue.get('protocols') or {}
    chosen = tables.tabled(state.conf)
    puts = {}
    forget_remembered(state, mono)
    blocked, emptied = block(state, aliases, mono, pf)
    for table in emptied:
        pf.flush(table)
    waiting = len(state.to_cut)
    blocked_tables = set(blocked.values())
    # every name the window gives a server first, so that whether a server is shared does not hang on the order
    seen = {}
    for kind, name, flow, row in records:
        if kind == 'named' and flow is not None and flow.started and not state.network.why_not(flow.proto,
                                                                                              flow.server[0]):
            note(state, flow.server[0], name, mono)
            seen.setdefault(flow.server[0], set()).add(name)
    untabled = untable(state, pf, seen)
    counts = {'flows': 0, 'named': 0, 'guessed': 0, 'unknown': 0, 'no_app': 0, 'not_tabled': 0, 'not_internet': 0}
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
                    # a blocked application's table takes a server by cut.py alone, once the resolver vouches
                    if table and table not in blocked_tables:
                        puts.setdefault(table, set()).add(server[0])
                hit = cut_as(state, name, flow.client[0])
                if hit is not None:
                    if internet(server[0]):
                        queue_cut(state, packed(flow.proto, flow.client, flow.server), name, flow.client, flow.server,
                                  flow.proto, flow.began, hit[0], server_name, shared(state, server[0], mono, hit[0]),
                                  hit[1])
                    else:
                        counts['not_internet'] += 1
                elif not flow.ended and not (flow.proto == capture.UDP and flow.packets <= 2):
                    # a UDP question and its answer - DNS, NTP - is over by the time it is judged, and
                    # would fill what is remembered on a busy network
                    remember(state, flow, name, server_name)
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
    counts.update({'added': added, 'refreshed': refreshed, 'tables': len(puts), 'to_cut': to_cut, 'untabled': untabled})
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
        # the packets' times are the wall clock's, read as they came: less this, the monotonic clock's
        self.flows.offset = time.time() - time.monotonic()
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
    to it as a file in the work directory, in memory, removed once the run is over. A run past CUT_TIMEOUT
    is stopped and its connections queued again, as are those cut.py says it did not reach before its own
    budget ran out: each connection is given CUT_TRIES runs (requeue()).

    What is blocked, for whom, goes to it as the service holds it - tables.policy() as the last Apply put it in
    force, read at the start and at each SIGHUP - in a file of the run's (POLICY), written again at a SIGHUP while
    the run goes (keep_policy()): cut.py judges each connection by it, not by config.xml as saved, where a rule
    changed and not applied would stop the cut and not the pf block; and a run under way sees a SIGHUP's change
    before its kills."""

    def __init__(self, work, script=CUT):
        self.work, self.script = work, script
        self.proc = None
        self.batch = []
        self.started = 0.0
        self.runs = 0
        self.paths = ()
        self.policy_path = os.path.join(work, POLICY)

    def keep_policy(self, state, now=None):
        """The policy the service acts on now, written for the run going, if one goes."""
        if self.proc is not None:
            self._policy(state, now)

    def _policy(self, state, now):
        try:
            write_json(self.policy_path, {'policy': state.policy})
        except OSError as error:
            state.fail('what is blocked could not be written for cut.py: %s' % error, now)

    def start(self, state, now):
        if self.proc is not None or not state.to_cut:
            return
        batch, state.to_cut = state.to_cut[:CUT_MOST], state.to_cut[CUT_MOST:]
        self.runs += 1
        base = os.path.join(self.work, 'cut-%d' % self.runs)
        self.paths = (base + '.json', base + '.out', self.policy_path)
        self._policy(state, now)
        try:
            write_json(self.paths[0], batch)
            with open(self.paths[1], 'w') as out:
                self.proc = subprocess.Popen([self.script, 'cut', self.paths[0], self.policy_path],
                                             stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL)
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
            state.fail('cut.py took longer than %d s: %d connection(s) of a blocked application queued again'
                       % (CUT_TIMEOUT, len(self.batch)), now)
            requeue(state, self.batch, now, 'cut.py stopped at %d s' % CUT_TIMEOUT)
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
            if isinstance(answer.get('left'), list) and answer['left']:
                requeue(state, answer['left'], now, 'cut.py ran out of its time before them')
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


class SuricataRules:
    """suricata_rules.py beside the capture, not waited for, one run at a time, while a rule of the Rules tab is
    switched on: `start` once as the service starts - the rules written as the settings say, which the service
    reads itself then - and `refresh` every SURICATA_EVERY seconds after: what was applied resolved again, and the
    Intrusion Detection told only when the file changed (the script runs configctl ids reload itself). Its answer is
    a file in the work directory, read when it ends; what it could not do is the page's last error. A run past
    SURICATA_TIMEOUT is stopped. No script (None): nothing run."""

    def __init__(self, work, script=SURICATA):
        self.work, self.script = work, script
        self.proc = None
        self.started = 0.0
        self.next_at = None
        self.runs = 0
        self.path = None

    def due(self, state):
        return (self.script is not None and self.proc is None and bool(tables.ruled(state.conf))
                and (self.next_at is None or time.monotonic() >= self.next_at))

    def begin(self, state, now):
        """The next run: start the first time, refresh after."""
        verb = 'refresh' if self.runs else 'start'
        self.runs += 1
        self.next_at = time.monotonic() + SURICATA_EVERY
        self.path = os.path.join(self.work, 'suricata-%d.out' % self.runs)
        try:
            with open(self.path, 'w') as out:
                self.proc = subprocess.Popen([self.script, verb], stdin=subprocess.DEVNULL, stdout=out,
                                             stderr=subprocess.DEVNULL)
        except OSError as error:
            self.proc = None
            self._remove()
            state.fail('the Suricata rules of the Rules tab could not be looked at: %s could not be run: %s'
                       % (self.script, error), now)
            return
        self.started = time.monotonic()

    def poll(self, state, now):
        """The run over: what it could not do said. True while one runs."""
        if self.proc is None:
            return False
        if self.proc.poll() is None:
            if time.monotonic() - self.started <= SURICATA_TIMEOUT:
                return True
            self.proc.kill()
            self.proc.wait()
            state.fail('the Suricata rules of the Rules tab: suricata_rules.py took longer than %d s, stopped'
                       % SURICATA_TIMEOUT, now)
        else:
            try:
                with open(self.path, encoding='utf-8') as handle:
                    answer = json.load(handle)
            except (OSError, ValueError):
                answer = None
            if not isinstance(answer, dict):
                state.fail('the Suricata rules of the Rules tab: suricata_rules.py said nothing that could be read', now)
            else:
                for problem in answer.get('errors') or []:
                    state.fail('the Suricata rules of the Rules tab: %s' % problem, now)
        self.proc = None
        self._remove()
        return False

    def finish(self, state, now, wait=5.0):
        """At the service's end: a run going is given `wait` seconds, or stopped."""
        if self.proc is None:
            return
        try:
            self.proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.poll(state, now)

    def _remove(self):
        if self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass


def count_cut(state, answer, asked, now):
    """cut.py's answer in the state: the connections cut, the pf states killed, those dropped in hardware
    first, the servers it put in their tables and the connections it cut alone, those it left as their
    application is no longer blocked, each application's, and what it could not do."""
    def number(value):
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    state.totals['cut'] += number(answer.get('cut'))
    state.totals['cut_states'] += number(answer.get('states'))
    state.totals['cut_tabled'] += number(answer.get('tabled'))
    state.totals['cut_alone'] += number(answer.get('alone'))
    state.totals['cut_unblocked'] += number(answer.get('unblocked'))
    dropped = answer.get('dropped')
    state.totals['cut_dropped'] += number(dropped)
    for app, n in (answer.get('apps') or {}).items():
        entry = state.apps.setdefault(str(app), {'category': None, 'named': 0, 'guessed': 0, 'protocols': [], 'last': 0})
        entry['cut'] = entry.get('cut', 0) + number(n)
    for rule, n in (answer.get('rules') or {}).items():
        state.rule_cut[str(rule)] = state.rule_cut.get(str(rule), 0) + number(n)
    state.last_cut = {'at': now, 'asked': asked, 'cut': number(answer.get('cut')),
                      'states': number(answer.get('states')), 'tabled': number(answer.get('tabled')),
                      'alone': number(answer.get('alone')),
                      'dropped': dropped if dropped is None or dropped == 'unknown' else number(dropped),
                      'hardware': answer.get('hardware') if isinstance(answer.get('hardware'), str) else None}
    for problem in answer.get('errors') or []:
        state.fail('the cut: %s' % problem, now)


def reread(state, config, catalogue_path, pf=None):
    """The settings read again (SIGHUP): the applications blocked among them - looked at here at once, with
    the aliases as config.xml has them now, and the sources of the block rules read again - and the installed
    nDPI's catalogue as aliases.php last wrote it. The interfaces follow at the next window's close. [tables
    to empty]: those of the applications blocked since (block())."""
    conf = tables.settings(config)
    if not conf['read']:
        state.fail('%s could not be read: the settings stay as they were' % config)
        return []
    catalogue = tables.load_catalogue(catalogue_path)
    if catalogue.get('categories'):
        problem = ndpi.protocols_problem(catalogue.get('protocols') or {})
        if problem:
            state.fail('the protocols of the installed nDPI cannot be believed (%s): no server goes into a category '
                       'table' % problem)
            catalogue = dict(catalogue, protocols={})
        state.catalogue = catalogue
    state.conf = conf
    pf = pf or tables.Pf()
    aliases = tables.present(config)
    read_devices(state, config)
    state.where.refresh(tables.policy(conf, aliases), state.devices, state.network.by_dev, pf)
    _blocked, emptied = block(state, aliases, pf=pf)
    say_unread(state)
    trim_cut(state, time.time())
    log('Application Control: settings read again: %d application(s) blocked, %d by block rules of the Rules tab'
        % (len(state.blocking), sum(1 for found in state.policy.values() if found['rules'])))
    return emptied


def read_devices(state, config):
    """The interfaces of config.xml and their devices, read again into the state - the last read kept when config.xml
    cannot be read now, as the firewall's addresses are (network()): an interface's name is never taken for an
    alias's for a window."""
    found = tables.interface_devices(config)
    if found is not None:
        state.devices = found
    return state.devices


def say_unread(state, now=None):
    """An element of a rule's source that cannot be read - an alias pf holds no table for - said once, as the
    page's last error, while it stays so."""
    for element in sorted(set(state.where.unread) - state.unread_said):
        state.fail('part of a block rule\'s source cannot be read, and its devices are not cut: %s'
                   % state.where.unread[element], now)
    state.unread_said = set(state.where.unread)


def was_blocking(status, conf, aliases):
    """{application: table} blocked when the service last wrote status.json and blocked still: a restart
    does not take them for blocked since, which would empty their tables."""
    try:
        with open(status, encoding='utf-8') as handle:
            before = json.load(handle).get('blocking')
    except (OSError, ValueError, AttributeError):
        return {}
    now = tables.blocked(conf, aliases)
    return {app: now[app] for app in (before if isinstance(before, list) else []) if app in now}


def start_state(now, reader, config, catalogue_path, refresh, mount, work, status=STATUS):
    """The service's state as it starts: the settings, the catalogue of the installed nDPI read again first -
    so a package updated since is followed - the interfaces, the applications blocked when it last ran,
    and the work directory emptied. Its error is set when there is nothing it can do."""
    conf = tables.settings(config)
    if refresh and ndpi.installed(reader):
        apps.refresh(reader, catalogue_path)
    catalogue = tables.load_catalogue(catalogue_path)
    state = State(now(), catalogue, conf, interfaces(conf, config))
    state.blocking = was_blocking(status, conf, tables.present(config))
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
          ifconfig=IFCONFIG, mount=MOUNT, cut=CUT, suricata=SURICATA):
    """The service's loop until SIGTERM (or, for a test, until stop_after windows are judged). suricata: the script
    that keeps the Suricata rules of the Rules tab current (SuricataRules), None for none."""
    global reload_asked
    while True:
        state = start_state(now, reader, config, catalogue_path, refresh, mount, work, status)
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
    rules_job = SuricataRules(work, suricata)

    def save(captures):
        save_state(state, captures, status, unknown)

    unread = [False]

    def look(t):
        """The firewall's addresses and its internal networks, read again; and the sources of the block rules."""
        state.network = network(lan_devices(watched, config), state.network, ifconfig)
        if state.network.read:
            unread[0] = False
        elif not unread[0]:
            unread[0] = True
            state.fail('the firewall\'s own addresses could not be read (%s -a): no server goes into a table '
                       'until they are' % ifconfig, t)
        read_devices(state, config)
        state.where.refresh(state.policy, state.devices, state.network.by_dev, pf)
        say_unread(state, t)

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
            for table in reread(state, config, catalogue_path, pf):
                pf.flush(table)
            conf = state.conf
            for problem in pf.errors:
                state.fail(problem)
            pf.errors = []
            # a cut under way judges its connections by what is in force now, before its kills
            cutter.keep_policy(state, now())
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
        # the Suricata rules: written as the service starts, then their sources and names looked at again
        if not rules_job.poll(state, t) and rules_job.due(state):
            rules_job.begin(state, t)
    for c in captures:
        c.stop()
    if job is not None:
        job.kill()
        job.remove()
    cutter.finish(state, now())
    rules_job.finish(state, now())
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
