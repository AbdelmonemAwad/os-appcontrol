#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Application Control's cut: the open connections of a blocked application ended, their servers put in
its table when the firewall's own resolver vouches for them, and what was dropped in hardware for one no
longer blocked handed back.

    cut.py cut <file> [<policy>]
                        cut the connections the JSON file lists, print a JSON summary (classify.py, which gives
                        what is blocked for whom as it holds it, in the policy file)
    cut.py release      hand back from hardware what was dropped for an application no longer blocked,
                        print a JSON summary (the page's Apply, and the plugin's removal)

A blocked application's block rule (plugins.inc.d/appcontrol.inc) stops new connections to the servers
in its table, and pf's states keep the connections opened before. classify.py names each connection
from its first packets; one nDPI names as a blocked application is handed here with its two ends and
the name it carried - the server name of TLS or QUIC, HTTP's Host - and:

- its server goes into the application's table, whose rule holds every device's new connections to it,
  only when the firewall's own resolver - the system's, getaddrinfo() - gives that address for that
  name, and when classify.py did not find the address shared with an application that is not blocked
  (alone). A device writes the name it sends, and can write any name to any address; the resolver's
  answer is what the network itself says of the name. A name not answered within RESOLVE_DEADLINE, an
  address written as a name, and no name at all vouch for nothing. A server nothing vouches for stays
  out of the table, and that connection alone is cut: the plan's "the block restricted to cutting the
  connection where it is needed" (settled point 5);
- every pf state of it is killed by its id - the state on the internal interface and the one out of
  the WAN, whose original ends pf writes in parentheses after NAT - as os-xgs-npu's ja4_cut.py and
  os-blocklists' ja4_cut.py cut a connection: both ends in one state, its protocol, not over, and made
  within SLACK seconds of the connection's first packet, both on the monotonic clock pf counts a state's
  age on - a later connection on the same two ends is not this one, nor is an earlier one a device sent
  a packet on to look like it, and a clock that steps changes neither. Not by address: another
  application on the same server is not cut (settled point 5, option a).

A connection no longer blocked for its device when the run begins is left, and counted: what is blocked, for
whom, is the classifier's - tables.policy() as the last Apply put it in force, which classify.py writes for
this run (the policy file; config.xml as saved only without one, where a rule changed and not applied would
stop the cut and not the pf block) - and each rule's source is resolved again here, as pf holds it now
(tables.Where): one cut for every device (Blocked applications) is left when that application is blocked so
no more; one cut for a block rule of the Rules tab when no rule of its application blocks it any more for its
device - the rule gone, switched off, no longer a block of it, or its source no longer holding the device's
address - and cut for another rule when that one holds it now. The policy file is read again before the
states are listed: a change the service read meanwhile (Apply) is judged by. Each cut is counted for its rule.
The kills stop once the run has had BUDGET seconds,
before classify.py's own limit: the connections not reached are given back in the summary (left), and
classify.py queues them again. The states are looked up by their ends (to_cut()), so a run of 5,000
connections against 100,000 states is one pass over each.

Cut in hardware too (the plan's settled point 6): where os-xgs-npu is installed, its hwdrop.drop_ends()
is called before the first state is killed, once a run with the ends of every state being cut, each
state's apart and with its protocol. With XGS: Settings "Cut in hardware" on the coprocessor drops those
connections at once, both ways; off, it does nothing, and each driver takes a connection out of hardware
once pf has let go of its state. hwdrop.py is loaded from os-xgs-npu's own place, never copied, and its
step has HW_DEADLINE seconds in a thread of its own - then the pf cut goes on whatever it is doing, as
os-blocklists' cut.py and ja4_cut.py do (within(), below). Without os-xgs-npu, pf alone. An os-xgs-npu
whose hwdrop.py has no release_addresses() - older than 2026-11-17, the drop_ends() of its last release
taking no protocol - is asked nothing (hardware(): too old): what it dropped could not be handed back.

A connection the coprocessor dropped stays dropped there while its sender goes on sending (os-xgs-npu's
hwdrop.py, release_addresses()). The servers whose connections were dropped are written down (DROPPED),
each with its application and nothing of the device, and `release` hands back by address those of an
application no longer blocked - unchosen, its table gone, classifying off, the plugin removed - unless an
application still blocked holds the same server. The host then decides its frames again: its pf state
is gone, so they meet the rules as a new connection's. With os-xgs-npu gone since, nothing is in hardware
to hand back, and those are let go; with its hwdrop.py there and not to be used - too old, or failing to
load - they are kept for the next release.

DROPPED is read and written under LOCK, one at a time: a cut adds its own at once, a release holds it
while it hands back. Never fails its caller: what it could not do is in the summary and in the system
log, under appcontrol.
"""

import collections
import fcntl
import importlib.util
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import syslog
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tables                                                            # noqa: E402

STATE = '/var/db/os-appcontrol'
DROPPED = STATE + '/dropped.json'
LOCK = STATE + '/cut.lock'
PFCTL = tables.PFCTL
CONFIG = tables.CONFIG
IFCONFIG = '/sbin/ifconfig'
HWDROP = '/usr/local/opnsense/scripts/xgs/hwdrop.py'    # os-xgs-npu's, where it is installed
WAIT = 40               # seconds one waits for DROPPED while another holds it: past a release's hardware step
SLACK = 5               # seconds between a connection's first packet and its state's making, either way
KEEP = 10000            # servers dropped in hardware written down, the latest
BUDGET = 90             # seconds a cut kills states for; classify.py stops a run at 120
PROTOCOLS = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'ipv6-icmp'}

RESOLVE_DEADLINE = 5    # seconds the names of a run are looked up for, all together
RESOLVERS = 16          # names looked up at once
NAMES_MOST = 2000       # names looked up in one run; the connections of any other are cut alone

HW_DEADLINE = 5         # seconds a cut's hardware step may take; then the pf cut goes on without it
RELEASE_DEADLINE = 30   # seconds a release's may take: it reads the whole flow table, and only Apply waits for it
UNKNOWN = 'unknown'     # how many a hardware step dropped or handed back, when it was left at its deadline
_left = []              # the hardware steps left at their deadline, while they still run
_hwdrop = {}


def log(message):
    syslog.syslog(syslog.LOG_NOTICE, message)


def hwdrop(path=None):
    """os-xgs-npu's hwdrop module, loaded from its installed place and not copied, once a process; None
    when it is not there or does not load. Loaded only when a run has something for it, after everything
    this imports: hwdrop puts its own folder first on the module search path to import its flows.py,
    where a later import would find os-xgs-npu's scripts - the path is put back as it was once it has
    loaded. Its functions need root, as the classifier and configd run this."""
    path = path or HWDROP
    if path in _hwdrop:
        return _hwdrop[path]
    module = None
    if os.path.isfile(path):
        saved = list(sys.path)
        try:
            spec = importlib.util.spec_from_file_location('xgs_hwdrop', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as error:                                       # noqa: BLE001
            log('Application Control: os-xgs-npu\'s hwdrop.py could not be loaded, nothing dropped in hardware: %s'
                % error)
            module = None
        finally:
            sys.path[:] = saved
    _hwdrop[path] = module
    return module


def hardware(path=None):
    """os-xgs-npu's hwdrop as a cut can use it: ('absent', None) without os-xgs-npu; ('broken', None) when its
    hwdrop.py does not load; ('old', None) for one with no release_addresses() - os-xgs-npu before
    2026-11-17, whose drop_ends() takes no protocol and matches nothing given one, and which could not hand
    back what it dropped; else ('ready', the module)."""
    path = path or HWDROP
    if not os.path.isfile(path):
        return 'absent', None
    module = hwdrop(path)
    if module is None:
        return 'broken', None
    if not hasattr(module, 'release_addresses') or not hasattr(module, 'drop_ends'):
        return 'old', None
    return 'ready', module


class HardwareLate(Exception):
    """The hardware step's time is up: raised to within()'s caller at the deadline, and in the step itself
    at its next `in` test (Until), which ends it there."""


class HardwareBusy(HardwareLate):
    """A hardware step left at its deadline still runs: no second one is started beside it."""


class Until:
    """A collection whose `in` test is `inner`'s until `stop` is set, and raises HardwareLate after.
    hwdrop asks it once for each connection of the flow table, between two calls of the driver, and lets
    HardwareLate through: a step left at its deadline writes nothing after it and ends at its next
    connection - hwdrop's paging closed on the way out, which puts the page place it shares with the other
    readers back to 0 and lets the flow-table lock go."""

    def __init__(self, inner, stop):
        self.inner, self.stop = inner, stop

    def __contains__(self, item):
        if self.stop.is_set():
            raise HardwareLate()
        return item in self.inner

    def __iter__(self):
        return iter(self.inner)

    def __len__(self):
        return len(self.inner)


def within(seconds, what, *args):
    """what(stop, *args) in a thread of its own, waited for `seconds` and no longer: its result, or a
    RuntimeError with the text of what it raised; HardwareLate at the deadline, `stop` set for it. The
    thread is a daemon: left at its deadline it ends at its next Until test, at the end of the driver call
    it is in, or with the process, which it never holds up - and while it runs no other is started
    (HardwareBusy). This is os-blocklists' within(), for the same reasons (its cut.py, 2026-11-17)."""
    _left[:] = [t for t in _left if t.is_alive()]
    if _left:
        raise HardwareBusy()
    stop = threading.Event()
    done = {}

    def step():
        try:
            done['value'] = what(stop, *args)
        except HardwareLate:
            pass                # stopped at its deadline: the caller has gone on
        except Exception as error:                                       # noqa: BLE001
            done['error'] = '%s: %s' % (type(error).__name__, error)

    worker = threading.Thread(target=step, name='appcontrol-hwdrop', daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        stop.set()
        _left.append(worker)
        raise HardwareLate()
    if 'error' in done:
        raise RuntimeError(done['error'])
    return done.get('value')


def drop_in_hardware(groups):
    """Connections both of whose ends are in one group - (protocol, ends) of one state being cut - dropped
    on the coprocessor by os-xgs-npu's hwdrop: how many; UNKNOWN when the step was left at its deadline or
    failed, as some may have been dropped by then; None without os-xgs-npu, or with one hardware() does not
    find ready. One call, which reads the whole flow table."""
    hw = hardware()[1]
    if hw is None:
        return None
    try:
        n = int(within(HW_DEADLINE, lambda stop: hw.drop_ends([(proto, Until(ends, stop))
                                                              for proto, ends in groups])) or 0)
    except HardwareBusy:
        log('Application Control: dropping in hardware: a step left at its deadline still runs, none started '
            'beside it; how many were dropped is not known, the pf cut goes on')
        return UNKNOWN
    except HardwareLate:
        log('Application Control: dropping in hardware took more than %g s: left there, how many were dropped '
            'is not known, the pf cut goes on' % HW_DEADLINE)
        return UNKNOWN
    except Exception as error:                                           # noqa: BLE001
        log('Application Control: dropping in hardware failed, how many were dropped is not known: %s' % error)
        return UNKNOWN
    return n


def release_in_hardware(addresses):
    """Connections with either end in `addresses` handed back to the host by os-xgs-npu's hwdrop: how many;
    UNKNOWN when the step was left at its deadline, RELEASE_DEADLINE, or failed - tried again at the next
    release; None when hardware() does not find it ready."""
    hw = hardware()[1]
    if hw is None:
        return None
    try:
        n = int(within(RELEASE_DEADLINE, lambda stop: hw.release_addresses(Until(set(addresses), stop))) or 0)
    except HardwareLate:
        log('Application Control: handing back from hardware took more than %g s or another step still runs: '
            'tried again at the next release' % RELEASE_DEADLINE)
        return UNKNOWN
    except Exception as error:                                           # noqa: BLE001
        log('Application Control: handing back from hardware failed, tried again at the next release: %s' % error)
        return UNKNOWN
    return n


ENDPOINT_V6 = re.compile(r'^([0-9A-Fa-f:.]+)\[(\d+)\]$')
AGE = re.compile(r'\bage (\d+):(\d{2}):(\d{2})\b')
# both halves of a TCP state in one of these: the connection is over, and pf only waits out its end
OVER = {'FIN_WAIT_2', 'TIME_WAIT', 'CLOSED'}


def endpoint(token):
    """(address, port) from a `pfctl -ss` token: IPv4 address:port, IPv6 address[port]; None for anything
    else."""
    token = token.strip('()')
    found = ENDPOINT_V6.match(token)
    if found:
        addr, port = found.group(1), found.group(2)
    elif token.count(':') == 1 and '.' in token:
        addr, port = token.split(':', 1)
    else:
        return None
    try:
        return ipaddress.ip_address(addr).compressed, int(port)
    except ValueError:
        return None


def states(text):
    """[(id, protocol, {(address, port)}, age in seconds or None, over)] from `pfctl -ss -vv`: both ends,
    and the one a translated state was translated from; over when the connection has ended."""
    out, cur = [], None
    for line in text.splitlines():
        if line and not line[0].isspace():
            words = line.split()
            ends = {e for e in (endpoint(t) for t in words[2:]) if e}
            halves = words[-1].split(':') if words else []
            cur = {'proto': words[1] if len(words) > 1 else '', 'ends': ends, 'age': None,
                   'over': bool(halves) and all(h in OVER for h in halves)}
            continue
        if cur is None:
            continue
        found = AGE.search(line)
        if found:
            cur['age'] = int(found.group(1)) * 3600 + int(found.group(2)) * 60 + int(found.group(3))
        found = re.match(r'\s+id: ([0-9a-f]+)', line)
        if found:
            out.append((found.group(1), cur['proto'], cur['ends'], cur['age'], cur['over']))
            cur = None
    return out


Conn = collections.namedtuple('Conn', 'proto client server began app host alone rule', defaults=('',))


def connection(item):
    """A connection of the file - its protocol's name, its client end, its server end, its first packet on
    the monotonic clock (or None), its application, the name it carried, alone: its server kept out of the
    table whatever the resolver says, and the block rule it is cut for ('' for Blocked applications) - or
    None for one that cannot be read."""
    try:
        proto = PROTOCOLS.get(int(item['proto']), str(int(item['proto'])))
        client = (ipaddress.ip_address(item['client'][0]).compressed, int(item['client'][1]))
        server = (ipaddress.ip_address(item['server'][0]).compressed, int(item['server'][1]))
        began = item.get('began')
        return Conn(proto, client, server, None if began is None else float(began), str(item.get('app') or ''),
                    str(item.get('host') or ''), item.get('alone') is True, str(item.get('rule') or ''))
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        return None


def still_for(conn, found, where):
    """What a connection is still to be cut for, by policy() as it is now (found) and the sources as they hold now
    (where, a tables.Where): '' while its application is blocked for every device; a rule's uuid while a block rule
    of its application holds its device - the rule it was queued for first; None when nothing blocks it for its
    device any more."""
    entry = found.get(conn.app)
    if entry is None:
        return None
    if entry['everyone']:
        return ''
    rules = sorted(entry['rules'], key=lambda rule: rule['uuid'] != conn.rule)
    for rule in rules:
        if where is not None and where.holds(rule, conn.client[0]):
            return rule['uuid']
    return None


def blocked_still(conn, found, where=None):
    """Whether a connection is still to be cut, by policy() as it is now (still_for())."""
    return still_for(conn, found, where) is not None


def load_policy(path):
    """What is blocked for whom as the classifier holds it - {application: {'table', 'everyone', 'rules': [{'uuid',
    'number', 'source', 'not'}]}}, tables.policy()'s - from the file it wrote; None when there is none to read."""
    data = load(path, None) if path else None
    policy = data.get('policy') if isinstance(data, dict) else None
    if not isinstance(policy, dict):
        return None
    for entry in policy.values():
        if not isinstance(entry, dict) or not isinstance(entry.get('table'), str) or \
                not isinstance(entry.get('everyone'), bool) or not isinstance(entry.get('rules'), list):
            return None
        for rule in entry['rules']:
            if not isinstance(rule, dict) or not isinstance(rule.get('uuid'), str) or not isinstance(rule.get('not'), bool) \
                    or not isinstance(rule.get('source'), list) or not all(isinstance(e, str) for e in rule['source']):
                return None
    return policy


def sources(found, config, pf):
    """The sources of the block rules of `found` resolved now (tables.Where) - none to resolve, None."""
    if not any(entry['rules'] for entry in found.values()):
        return None
    where = tables.Where()
    where.refresh(found, tables.interface_devices(config) or {}, tables.device_networks(tables.ifconfig(IFCONFIG)), pf)
    return where


def to_cut(conns, all_states, now):
    """{state id: index of its connection}: every state with both ends of a connection and its protocol, not
    over, made within SLACK seconds of the connection's first packet - now, the connection's began and pf's
    age all on the monotonic clock. The states are looked up by their ends, indexed once."""
    by_end = {}
    for n, (_sid, _proto, ends, _age, over) in enumerate(all_states):
        if not over:
            for end in ends:
                by_end.setdefault(end, []).append(n)
    out = {}
    for i, conn in enumerate(conns):
        want, client, server, began = conn[0], conn[1], conn[2], conn[3]
        for n in by_end.get(client, ()):
            sid, proto, ends, age, _over = all_states[n]
            if sid in out or server not in ends or (want and proto and proto != want):
                continue
            if age is not None and began is not None and abs(now - age - began) > SLACK:
                continue    # made well before or after this connection began: another one on its two ends
            out[sid] = i
    return out


NAME = re.compile(r'^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')


def name_of(host):
    """The name a connection carried as the resolver is asked for it - lower case, no last dot, an HTTP
    Host's port left off - or None: no name, a name of one label, or an address written as a name, which
    vouches for nothing."""
    text = (host or '').strip().lower().rstrip('.')
    if text.count(':') == 1 and text.rsplit(':', 1)[1].isdigit():
        text = text.rsplit(':', 1)[0]
    try:
        ipaddress.ip_address(text.strip('[]'))
        return None
    except ValueError:
        pass
    return text if len(text) <= 253 and NAME.match(text) else None


def lookup(name):
    """The addresses the firewall's own resolver gives for a name, as the system asks it."""
    return [info[4][0] for info in socket.getaddrinfo(name, None, 0, socket.SOCK_STREAM)]


def resolve(names, deadline=None, ask=None):
    """{name: {address}} of the names - NAMES_MOST at most - looked up RESOLVERS at a time, in threads of
    their own, and waited for `deadline` seconds in all (RESOLVE_DEADLINE); a name not answered by then, or
    failing, gives none. The threads are daemons: one still asking at the deadline ends with the process,
    which it never holds up."""
    ask = ask or lookup
    deadline = RESOLVE_DEADLINE if deadline is None else deadline
    todo = sorted(names)[:NAMES_MOST]
    found, guard = {}, threading.Lock()

    def worker():
        while True:
            with guard:
                if not todo:
                    return
                name = todo.pop()
            addresses = set()
            try:
                for text in ask(name):
                    try:
                        addresses.add(ipaddress.ip_address(str(text).split('%')[0]).compressed)
                    except ValueError:
                        pass
            except Exception:                                            # noqa: BLE001
                addresses = set()
            with guard:
                found[name] = addresses

    workers = [threading.Thread(target=worker, name='appcontrol-resolve', daemon=True)
               for _ in range(min(RESOLVERS, len(todo)))]
    for worker_thread in workers:
        worker_thread.start()
    until = time.monotonic() + deadline
    for worker_thread in workers:
        worker_thread.join(max(0.0, until - time.monotonic()))
    with guard:
        return dict(found)


def load(path, default):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def save(path, data):
    tmp = path + '.new'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(data, handle)
    os.replace(tmp, path)


def entries(path=None):
    """The servers dropped in hardware written down: [{'app', 'rule', 'server'}], the oldest first - rule the block it
    was dropped for, '' for every device (Blocked applications, and a row written before rules were)."""
    found = load(path or DROPPED, {})
    rows = found.get('dropped') if isinstance(found, dict) else None
    if not isinstance(rows, list):
        return []
    return [{'app': str(r['app']), 'rule': str(r.get('rule') or ''), 'server': str(r['server'])} for r in rows
            if isinstance(r, dict) and r.get('server') and r.get('app')]


def keep(rows, path=None):
    """The list written - its latest KEEP - or removed when empty."""
    path = path or DROPPED
    if rows:
        save(path, {'dropped': rows[-KEEP:]})
    elif os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def write_down(triples, path=None):
    """(application, rule, server) dropped in hardware added to what is written down - each once, the latest last -
    under the lock. A problem, or None."""
    path = path or DROPPED
    handle = locked(wait=WAIT)
    if handle is None:
        return '%s could not be written: another held it for %d s' % (path, WAIT)
    with handle:
        new = sorted(triples)
        again = set(new)
        rows = [r for r in entries(path) if (r['app'], r['rule'], r['server']) not in again]
        rows.extend({'app': app, 'rule': rule, 'server': server} for app, rule, server in new)
        try:
            keep(rows, path)
        except OSError as error:
            return '%s could not be written: %s' % (path, error)
    return None


def kill(sid, summary):
    """One pf state killed by its id; True when pfctl says it did, what it did not said in the summary."""
    try:
        done = subprocess.run([PFCTL, '-k', 'id', '-k', sid], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        summary['errors'].append('pfctl -k id -k %s: %s' % (sid, error))
        return False
    if done.returncode != 0:
        summary['errors'].append('pfctl -k id -k %s ended with status %d' % (sid, done.returncode))
        return False
    return True


def judge(read, found, config, pf):
    """The connections of `read` still to be cut by `found`, each with the rule it is cut for now (still_for())."""
    where = sources(found, config, pf)
    out = []
    for item, conn in read:
        rule = still_for(conn, found, where)
        if rule is not None:
            out.append((item, conn._replace(rule=rule)))
    return out


def cut(conns, now=None, ask=None, config=None, policy=None):
    """The connections cut, the coprocessor dropping them first where os-xgs-npu is installed, and the
    servers the resolver vouches for put in their applications' tables first of all. The summary:
    connections asked for, cut (a state of theirs killed), states killed, dropped in hardware (a count,
    UNKNOWN or None) and the hardware (hardware()), servers put in their tables (tabled), connections whose
    server was not (alone), connections left as nothing blocks them for their device any more (unblocked),
    those the budget did not reach (left, as they were given), per application and per rule, errors. now is
    the monotonic clock's as pf's states are listed, and ask looks a name up (lookup()) - the tests give their
    own; policy is the classifier's file of what is blocked for whom (load_policy())."""
    started = time.monotonic()
    config = config or CONFIG
    summary = {'connections': len(conns), 'cut': 0, 'states': 0, 'dropped': None, 'hardware': None, 'tabled': 0,
               'alone': 0, 'unblocked': 0, 'left': [], 'apps': {}, 'rules': {}, 'errors': []}
    read = [(item, conn) for item, conn in ((item, connection(item)) for item in conns) if conn is not None]
    if len(read) != len(conns):
        summary['errors'].append('%d connection(s) to cut could not be read' % (len(conns) - len(read)))
    if not read:
        return summary
    found = load_policy(policy)
    if found is None:
        if policy:
            summary['errors'].append('%s could not be read: what is blocked taken from %s' % (policy, config))
        conf = tables.settings(config)
        if not conf['read']:
            summary['errors'].append('%s could not be read: nothing cut' % config)
            return summary
        found = tables.policy(conf, tables.present(config))
    pf = tables.Pf(pfctl=PFCTL)
    kept = judge(read, found, config, pf)
    summary['unblocked'] = len(read) - len(kept)
    read = kept
    if not read:
        return summary
    still = {app: entry['table'] for app, entry in found.items()}

    # the servers the resolver vouches for go into their tables before any state is killed, so that the
    # rule holds what the devices send after the cut
    names = {name_of(conn.host) for _, conn in read if not conn.alone} - {None}
    answers = resolve(names, ask=ask) if names else {}
    puts = {}
    for _, conn in read:
        if not conn.alone and conn.server[0] in answers.get(name_of(conn.host), ()):
            puts.setdefault(still[conn.app], set()).add(conn.server[0])
    for table in sorted(puts):
        pf.update(table, puts[table])
    summary['errors'].extend(pf.errors)
    summary['tabled'] = sum(len(servers) for servers in puts.values())
    summary['alone'] = sum(1 for _, conn in read if conn.server[0] not in puts.get(still[conn.app], ()))

    # what is blocked read again: a change the service read meanwhile - Apply - is judged by before the kills
    again = load_policy(policy)
    if again is not None and again != found:
        kept = judge(read, again, config, pf)
        summary['unblocked'] += len(read) - len(kept)
        read = kept
        if not read:
            return summary

    try:
        done = subprocess.run([PFCTL, '-ss', '-vv'], capture_output=True, text=True, errors='replace', timeout=120)
        if done.returncode != 0:
            raise OSError('pfctl -ss exited %d' % done.returncode)
        text = done.stdout
    except (OSError, subprocess.SubprocessError) as error:
        summary['errors'].append('pf\'s states could not be read, nothing cut: %s' % error)
        return summary
    listed = time.monotonic() if now is None else now
    all_states = states(text)
    conns_read = [conn for _, conn in read]
    cuts = to_cut(conns_read, all_states, listed)
    # on the coprocessor first: each state's ends apart, with its protocol, as os-xgs-npu's ja4_cut.py
    # gives them to hwdrop.drop_ends()
    groups = [(proto, ends) for sid, proto, ends, _age, _over in all_states if sid in cuts]
    summary['hardware'] = hardware()[0]
    dropped = drop_in_hardware(groups) if groups else None
    summary['dropped'] = dropped
    if dropped == UNKNOWN or (isinstance(dropped, int) and dropped > 0):
        # which of them the coprocessor dropped is not said, only how many: each server is written down - at
        # once, so a release meanwhile counts it as held by an application still blocked
        problem = write_down({(conns_read[i].app, conns_read[i].rule, conns_read[i].server[0]) for i in set(cuts.values())})
        if problem:
            summary['errors'].append(problem)
    by_conn = {}
    for sid, i in cuts.items():
        by_conn.setdefault(i, []).append(sid)
    order = sorted(by_conn)
    killed = set()
    for at, i in enumerate(order):
        if time.monotonic() - started > BUDGET:
            summary['left'] = [read[j][0] for j in order[at:]]
            summary['errors'].append('%d connection(s) not reached within %g s: given back to be cut again'
                                     % (len(order) - at, BUDGET))
            break
        for sid in sorted(by_conn[i]):
            if kill(sid, summary):
                summary['states'] += 1
                killed.add(i)
    for i in sorted(killed):
        app, rule = conns_read[i].app, conns_read[i].rule
        summary['apps'][app] = summary['apps'].get(app, 0) + 1
        summary['rules'][rule] = summary['rules'].get(rule, 0) + 1
    summary['cut'] = len(killed)
    log('Application Control: %d connection(s) of a blocked application cut, %d pf state(s) killed, %d server(s) '
        'put in their tables, %d connection(s) cut alone%s'
        % (summary['cut'], summary['states'], summary['tabled'], summary['alone'], '' if dropped is None else
           ', how many dropped in hardware first not known' if dropped == UNKNOWN else
           ', %d dropped in hardware first' % dropped))
    return summary


def still_drops(row, found):
    """Whether what was dropped for a row's block is to stay dropped, by policy() as Apply leaves it: its application
    blocked for every device when the row's rule is '' (Blocked applications), else that rule there still, a block of
    its application. Whom a rule's source holds now is not known here - a row names no device - so a source narrowed
    hands nothing back; the rule removed, switched off or no longer a block does."""
    entry = found.get(row['app'])
    if entry is None:
        return False
    if not row['rule']:
        return entry['everyone']
    return any(rule['uuid'] == row['rule'] for rule in entry['rules'])


def release(config=None):
    """Hand back from hardware the connections dropped for a block that no longer stands - an application no
    longer blocked, or the rule they were dropped for removed while another still blocks it (still_drops()) - by
    their servers, less a server a block still standing holds - holding the lock on what is written down
    meanwhile. The summary: handed back (a count, UNKNOWN or None), servers still written down, errors."""
    config = config or CONFIG
    summary = {'released': None, 'kept': 0, 'errors': []}
    handle = locked(wait=WAIT)
    if handle is None:
        summary['errors'].append('another release is running: nothing handed back')
        return summary
    with handle:
        rows = entries()
        summary['kept'] = len(rows)
        if not rows:
            return summary
        conf = tables.settings(config)
        if not conf['read']:
            summary['errors'].append('%s could not be read: nothing handed back' % config)
            return summary
        blocking = tables.policy(conf, tables.present(config))
        standing = [still_drops(r, blocking) for r in rows]
        gone = [r for r, stands in zip(rows, standing) if not stands]
        if not gone:
            return summary
        found, _hw = hardware()
        if found in ('old', 'broken'):
            summary['errors'].append('os-xgs-npu\'s hwdrop.py %s: nothing handed back, kept for the next release'
                                     % ('has no release_addresses() - too old' if found == 'old'
                                        else 'could not be loaded'))
            return summary
        held = {r['server'] for r, stands in zip(rows, standing) if stands}
        addresses = {r['server'] for r in gone} - held
        released = None if found == 'absent' else release_in_hardware(addresses) if addresses else 0
        summary['released'] = released
        if released == UNKNOWN:
            summary['errors'].append('handing back from hardware did not end within %g s: tried again at the next '
                                     'release' % RELEASE_DEADLINE)
            return summary
        # handed back - or os-xgs-npu gone since, with nothing in hardware to hand back: let go
        rows = [r for r, stands in zip(rows, standing) if stands]
        try:
            keep(rows)
        except OSError as error:
            summary['errors'].append('%s could not be written: %s' % (DROPPED, error))
        summary['kept'] = len(rows)
    if released:
        log('Application Control: %d connection(s) handed back from hardware: no application blocked holds '
            'their server now' % released)
    return summary


def locked(path=None, wait=WAIT):
    """The lock, as an open file that lets it go when closed; None after `wait` seconds."""
    try:
        os.makedirs(os.path.dirname(path or LOCK), exist_ok=True)
        handle = open(path or LOCK, 'w')
    except OSError:
        return None
    until = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except OSError:
            if time.monotonic() >= until:
                handle.close()
                return None
            time.sleep(0.2)


def main(argv):
    syslog.openlog('appcontrol', syslog.LOG_PID, syslog.LOG_DAEMON)
    verb = argv[1] if len(argv) > 1 else ''
    if verb not in ('cut', 'release') or (verb == 'cut' and len(argv) < 3):
        print(json.dumps({'errors': ['usage: cut.py cut <file> | cut.py release']}))
        return 0
    try:
        if verb == 'cut':
            # one run at a time is classify.py's: it runs the next once this one has ended
            found = load(argv[2], None)
            if not isinstance(found, list):
                print(json.dumps({'errors': ['%s: no list of connections could be read' % argv[2]]}))
                return 0
            print(json.dumps(cut(found, policy=argv[3] if len(argv) > 3 else None)))
        else:
            print(json.dumps(release()))
    except Exception as error:                                           # noqa: BLE001
        # said, never raised: the classifier and configd read the answer
        log('Application Control: the cut stopped: %r' % error)
        print(json.dumps({'errors': ['the cut stopped: %r' % error]}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
