#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Application Control's cut: the open connections of a blocked application ended, and what was dropped
in hardware for one no longer blocked handed back.

    cut.py cut <file>   cut the connections the JSON file lists, print a JSON summary (classify.py)
    cut.py release      hand back from hardware what was dropped for an application no longer blocked,
                        print a JSON summary (the page's Apply, and the plugin's removal)

A blocked application's block rule (plugins.inc.d/appcontrol.inc) stops new connections to the servers
in its table, and pf's states keep the connections opened before. classify.py names each connection
from its first packets; one nDPI names as a blocked application is handed here with its two ends, and
every pf state of it is killed by its id - the state on the internal interface and the one out of the
WAN, whose original ends pf writes in parentheses after NAT - as os-xgs-npu's ja4_cut.py and
os-blocklists' ja4_cut.py cut a connection: both ends in one state, its protocol, and the state made no
later than the connection's first packet (a later connection on the same two ends is not this one) and
not over. Not by address: another application on the same server is not cut (the plan's settled point
5, option a).

Cut in hardware too (the plan's settled point 6): where os-xgs-npu is installed, its hwdrop.drop_ends()
is called before the first state is killed, once a run with the ends of every state being cut, each
state's apart and with its protocol. With XGS: Settings "Cut in hardware" on the coprocessor drops those
connections at once, both ways; off, it does nothing, and each driver takes a connection out of hardware
once pf has let go of its state. hwdrop.py is loaded from os-xgs-npu's own place, never copied, and its
step has HW_DEADLINE seconds in a thread of its own - then the pf cut goes on whatever it is doing, as
os-blocklists' cut.py and ja4_cut.py do (within(), below). Without os-xgs-npu, pf alone.

A connection the coprocessor dropped stays dropped there while its sender goes on sending (os-xgs-npu's
hwdrop.py, release_addresses()). Each one dropped is written down (DROPPED), with its application and its
server, and `release` hands back by address those of an application no longer blocked - unchosen, its
table gone, classifying off, the plugin removed - unless an application still blocked holds the same
server. The host then decides its frames again: its pf state is gone, so they meet the rules as a new
connection's.

One run at a time (LOCK). Never fails its caller: what it could not do is in the summary and in the
system log, under appcontrol.
"""

import fcntl
import importlib.util
import ipaddress
import json
import os
import re
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
HWDROP = '/usr/local/opnsense/scripts/xgs/hwdrop.py'    # os-xgs-npu's, where it is installed
WAIT = 10               # seconds a run waits for another to end
SLACK = 5               # seconds a state may be younger than its connection's first packet
KEEP = 10000            # connections dropped in hardware written down, the latest
PROTOCOLS = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'ipv6-icmp'}

HW_DEADLINE = 5         # seconds the hardware step may take; then the pf cut goes on without it
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
    failed, as some may have been dropped by then; None without os-xgs-npu. One call, which reads the
    whole flow table."""
    hw = hwdrop()
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
        log('Application Control: dropping in hardware took more than %d s: left there, how many were dropped '
            'is not known, the pf cut goes on' % HW_DEADLINE)
        return UNKNOWN
    except Exception as error:                                           # noqa: BLE001
        log('Application Control: dropping in hardware failed, how many were dropped is not known: %s' % error)
        return UNKNOWN
    return n


def release_in_hardware(addresses):
    """Connections with either end in `addresses` handed back to the host by os-xgs-npu's hwdrop: how many;
    UNKNOWN when the step was left at its deadline or failed - tried again at the next release; None
    without os-xgs-npu, or with one older than its release_addresses, which hands nothing back."""
    hw = hwdrop()
    if hw is None or not hasattr(hw, 'release_addresses'):
        return None
    try:
        n = int(within(HW_DEADLINE, lambda stop: hw.release_addresses(Until(set(addresses), stop))) or 0)
    except HardwareLate:
        log('Application Control: handing back from hardware took more than %d s or another step still runs: '
            'tried again at the next release' % HW_DEADLINE)
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


def connection(item):
    """A connection of the file as (protocol name, client end, server end, first packet's time, application),
    or None for one that cannot be read."""
    try:
        proto = PROTOCOLS.get(int(item['proto']), str(int(item['proto'])))
        client = (ipaddress.ip_address(item['client'][0]).compressed, int(item['client'][1]))
        server = (ipaddress.ip_address(item['server'][0]).compressed, int(item['server'][1]))
        first = float(item.get('first') or 0) or None
        return proto, client, server, first, str(item.get('app') or '')
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def to_cut(conns, all_states, now):
    """{state id: index of its connection}: every state with both ends of a connection, its protocol, made no
    later than the connection's first packet and SLACK seconds, and not over."""
    out = {}
    for sid, proto, ends, age, over in all_states:
        if over:
            continue
        for i, (want, client, server, first, _app) in enumerate(conns):
            if want and proto and proto != want:
                continue
            if client not in ends or server not in ends:
                continue
            if age is not None and first is not None and now - age > first + SLACK:
                continue    # made after the connection began: a later one on the same two ends
            out[sid] = i
            break
    return out


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
    """The connections dropped in hardware written down: [{'app', 'server', 'proto', 'client', 'at'}]."""
    found = load(path or DROPPED, {})
    rows = found.get('dropped') if isinstance(found, dict) else None
    return [r for r in rows if isinstance(r, dict) and r.get('server') and r.get('app')] if isinstance(rows, list) else []


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


def cut(conns, now=None):
    """The connections' pf states killed by id, the coprocessor dropping them first where os-xgs-npu is
    installed; what was dropped written down for a release. The summary: connections asked for, cut
    (a state of theirs killed), states killed, dropped in hardware (a count, UNKNOWN or None), per
    application, errors."""
    summary = {'connections': len(conns), 'cut': 0, 'states': 0, 'dropped': None, 'apps': {}, 'errors': []}
    read = [c for c in (connection(item) for item in conns) if c is not None]
    if len(read) != len(conns):
        summary['errors'].append('%d connection(s) to cut could not be read' % (len(conns) - len(read)))
    if not read:
        return summary
    listed_at = now if now is not None else time.time()
    try:
        done = subprocess.run([PFCTL, '-ss', '-vv'], capture_output=True, text=True, errors='replace', timeout=120)
        if done.returncode != 0:
            raise OSError('pfctl -ss exited %d' % done.returncode)
        text = done.stdout
    except (OSError, subprocess.SubprocessError) as error:
        summary['errors'].append('pf\'s states could not be read, nothing cut: %s' % error)
        return summary
    all_states = states(text)
    cuts = to_cut(read, all_states, listed_at)
    # on the coprocessor first: each state's ends apart, with its protocol, as os-xgs-npu's ja4_cut.py
    # gives them to hwdrop.drop_ends()
    groups = [(proto, ends) for sid, proto, ends, _age, _over in all_states if sid in cuts]
    dropped = drop_in_hardware(groups) if groups else None
    summary['dropped'] = dropped
    killed = set()
    for sid, i in sorted(cuts.items()):
        try:
            done = subprocess.run([PFCTL, '-k', 'id', '-k', sid], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            summary['errors'].append('pfctl -k id -k %s: %s' % (sid, error))
            continue
        if done.returncode != 0:
            summary['errors'].append('pfctl -k id -k %s ended with status %d' % (sid, done.returncode))
            continue
        summary['states'] += 1
        killed.add(i)
    for i in sorted(killed):
        app = read[i][4]
        summary['apps'][app] = summary['apps'].get(app, 0) + 1
    summary['cut'] = len(killed)
    if dropped == UNKNOWN or (isinstance(dropped, int) and dropped > 0):
        # which of them the coprocessor dropped is not said, only how many: each is written down
        rows = entries()
        for i in sorted(set(cuts.values())):
            proto, client, server, _first, app = read[i]
            rows.append({'app': app, 'server': server[0], 'proto': proto, 'client': list(client),
                         'at': int(listed_at)})
        try:
            keep(rows)
        except OSError as error:
            summary['errors'].append('%s could not be written: %s' % (DROPPED, error))
    log('Application Control: %d connection(s) of a blocked application cut, %d pf state(s) killed%s'
        % (summary['cut'], summary['states'], '' if dropped is None else
           ', how many dropped in hardware first not known' if dropped == UNKNOWN else
           ', %d dropped in hardware first' % dropped))
    return summary


def release(config=None):
    """Hand back from hardware the connections dropped for an application no longer blocked
    (tables.blocked()), by their servers, less a server an application still blocked holds. The summary:
    handed back (a count, UNKNOWN or None), connections still written down, errors."""
    config = config or CONFIG
    rows = entries()
    summary = {'released': None, 'kept': len(rows), 'errors': []}
    if not rows:
        return summary
    conf = tables.settings(config)
    if not conf['read']:
        summary['errors'].append('%s could not be read: nothing handed back' % config)
        return summary
    still = set(tables.blocked(conf, tables.present(config)))
    gone = [r for r in rows if r['app'] not in still]
    if not gone:
        return summary
    held = {r['server'] for r in rows if r['app'] in still}
    addresses = {r['server'] for r in gone} - held
    released = release_in_hardware(addresses) if addresses else 0
    summary['released'] = released
    if released == UNKNOWN:
        summary['errors'].append('handing back from hardware did not end: tried again at the next release')
        return summary
    rows = [r for r in rows if r['app'] in still]
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
        lock = locked()
        if lock is None:
            print(json.dumps({'errors': ['another cut or release is running: nothing done']}))
            return 0
        with lock:
            if verb == 'cut':
                found = load(argv[2], None)
                if not isinstance(found, list):
                    print(json.dumps({'errors': ['%s: no list of connections could be read' % argv[2]]}))
                    return 0
                print(json.dumps(cut(found)))
            else:
                print(json.dumps(release()))
    except Exception as error:                                           # noqa: BLE001
        # said, never raised: the classifier and configd read the answer
        log('Application Control: the cut stopped: %r' % error)
        print(json.dumps({'errors': ['the cut stopped: %r' % error]}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
