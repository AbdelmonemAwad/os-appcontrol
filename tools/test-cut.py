#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""cut.py - the open connections of a blocked application ended, their servers put in its table when the
firewall's own resolver vouches for them, and what was dropped in hardware for one no longer blocked handed
back - with stand-ins for what only a firewall has: pfctl, a program that writes how it was called and prints
pf's states as `pfctl -ss -vv` writes them; the resolver, a function of the test's own; and os-xgs-npu's
hwdrop.py, a module of the test's own in a folder of its own, loaded from there as cut.py loads the real one.
No OPNsense, no root:

    python3 tools/test-cut.py

What is checked: pf's states read - IPv4, IPv6, a state after NAT with its original ends in parentheses, one
written with <-, its protocol, its age, a connection over; a connection's states are those holding both its
ends, of its protocol, not over, made within 5 seconds of its first packet - another client of the same server,
a UDP state on the same ends, a later connection on them and an earlier one a device sent a packet on to look
like it are not cut; the states looked up by their ends, 5,000 connections against 37,000 states at once; each
killed by its id, the coprocessor asked first, once, with each state's ends apart and its protocol; its count
in the summary, with the connections cut per application; a server put in its application's table before any
state is killed only when the resolver gives that address for the name its connection carried - not a forged
name, an address written as a name, no name, a name the resolver does not answer in time, nor a server shared
with an application not blocked; a connection of an application no longer blocked left; the kills stopped at
the run's budget and the connections not reached given back; without hwdrop.py pf alone; one too old - no
release_addresses() - or not loading asked nothing; a hardware step that fails or passes its deadline says
"unknown" and the pf cut goes on at once; the module search path left as it was; what was dropped written down
- the application and the server, nothing of the device, each once - and nothing when nothing was; the
hand-back of what an application no longer blocked had dropped - by its servers, less a server an application
still blocked holds - with classifying off, its alias gone, os-xgs-npu gone, too old or not loading (kept for
the next), the step failing or past its own deadline (kept for the next), and nothing written down; the lock:
a cut never waits for a release, a release for another; the command line's answers.
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src', 'opnsense', 'scripts', 'appcontrol'))
import cut                                                               # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


NOW = 1794926400.0      # the monotonic clock as pf's states are listed, in these runs

# pfctl -ss -vv as FreeBSD writes it: a state's first line, then its counters, age and id
STATES = '''all tcp 192.0.2.10:50001 -> 198.51.100.10:443       ESTABLISHED:ESTABLISHED
   [1234567890 + 65535] wscale 7  [987654321 + 65535] wscale 7
   age 00:00:40, expires in 24:00:00, 12:10 pkts, 3000:9000 bytes, rule 12
   id: 00000000000000a1 creatorid: 12345678 gateway: 0.0.0.0
   origif: igb1
all tcp 203.0.113.2:61001 (192.0.2.10:50001) -> 198.51.100.10:443       ESTABLISHED:ESTABLISHED
   age 00:00:40, expires in 24:00:00, 12:10 pkts, 3000:9000 bytes, rule 3
   id: 00000000000000a2 creatorid: 12345678
all udp 192.0.2.10:50001 -> 198.51.100.10:443       MULTIPLE:MULTIPLE
   age 00:00:40, expires in 00:00:60, 3:3 pkts, 300:300 bytes, rule 12
   id: 00000000000000a3 creatorid: 12345678
all tcp 192.0.2.11:50002 -> 198.51.100.10:443       ESTABLISHED:ESTABLISHED
   age 00:00:40, expires in 24:00:00, 12:10 pkts, 3000:9000 bytes, rule 12
   id: 00000000000000a4 creatorid: 12345678
all tcp 192.0.2.10:50003 -> 198.51.100.20:443       FIN_WAIT_2:FIN_WAIT_2
   age 00:00:40, expires in 00:00:30, 12:10 pkts, 3000:9000 bytes, rule 12
   id: 00000000000000a5 creatorid: 12345678
all tcp 192.0.2.10:50004 -> 198.51.100.30:443       ESTABLISHED:ESTABLISHED
   age 00:00:05, expires in 24:00:00, 2:2 pkts, 200:200 bytes, rule 12
   id: 00000000000000a6 creatorid: 12345678
all tcp 2001:db8::10[50007] -> 2001:db8::443[443]       ESTABLISHED:ESTABLISHED
   age 00:01:00, expires in 24:00:00, 12:10 pkts, 3000:9000 bytes, rule 13
   id: 00000000000000a7 creatorid: 12345678
all tcp 198.51.100.40:443 <- 192.0.2.10:50008       ESTABLISHED:ESTABLISHED
   age 00:00:50, expires in 24:00:00, 12:10 pkts, 3000:9000 bytes, rule 12
   id: 00000000000000a8 creatorid: 12345678
all tcp 192.0.2.12:50009 -> 198.51.100.50:443       ESTABLISHED:ESTABLISHED
   age 02:00:00, expires in 24:00:00, 900:800 pkts, 90000:800000 bytes, rule 12
   id: 00000000000000a9 creatorid: 12345678
'''

# the connections classify.py hands over: its two ends as the capture saw them, the application, when it began
# on the monotonic clock, the name it carried
CONNS = [
    {'proto': 6, 'client': ['192.0.2.10', 50001], 'server': ['198.51.100.10', 443], 'name': 'TLS.YouTube',
     'app': 'YouTube', 'began': NOW - 40, 'host': 'video.example', 'alone': False},
    {'proto': 6, 'client': ['192.0.2.10', 50003], 'server': ['198.51.100.20', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'began': NOW - 40, 'host': 'clips.example', 'alone': False},
    {'proto': 6, 'client': ['192.0.2.10', 50004], 'server': ['198.51.100.30', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'began': NOW - 60, 'host': 'clips.example', 'alone': False},
    {'proto': 6, 'client': ['2001:db8::10', 50007], 'server': ['2001:db8::443', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'began': NOW - 60, 'host': 'clips.example', 'alone': False},
    {'proto': 6, 'client': ['192.0.2.10', 50008], 'server': ['198.51.100.40', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'began': NOW - 50, 'host': '', 'alone': False},
    # a device's own packet on another device's two ends, a SYN and a forged ClientHello, 40 s ago: the state on
    # those ends is that device's, two hours old
    {'proto': 6, 'client': ['192.0.2.12', 50009], 'server': ['198.51.100.50', 443], 'name': 'TLS.YouTube',
     'app': 'YouTube', 'began': NOW - 40, 'host': 'video.example', 'alone': False},
]

# the firewall's own resolver, standing in: the names and what it gives for them
ANSWERS = {'video.example': ['198.51.100.10', '2001:db8::10:1'], 'clips.example': ['2001:db8::443', '198.51.100.99']}


def ask(name):
    return ANSWERS.get(name, [])


# os-xgs-npu's hwdrop.py, standing in: it imports its flows.py from its own folder, as the real one does, writes
# each call to the calls file - the same pfctl writes to, so their order shows - and answers as hwdrop_events says
FAKE_HWDROP = '''
import json
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flows  # noqa: E402,F401
import hwdrop_events  # noqa: E402


def say(text):
    with open(hwdrop_events.calls, 'a') as handle:
        handle.write(text + '\\n')


def answer():
    if hwdrop_events.result == 'raise':
        raise RuntimeError('no flow table')
    if hwdrop_events.result == 'slow':
        # a driver call of 1.5 s for each connection, and an `in` test between two, as the real one asks
        for _ in range(10):
            time.sleep(1.5)
            '' in hwdrop_events.watch
        return 9
    return hwdrop_events.result


def drop_ends(groups, path='/conf/config.xml'):
    hwdrop_events.watch = groups[0][1]
    say('hwdrop drop_ends ' + json.dumps(sorted([proto, sorted(map(list, ends))] for proto, ends in groups)))
    return answer()
'''
FAKE_RELEASE = '''

def release_addresses(contains):
    hwdrop_events.watch = contains
    say('hwdrop release_addresses ' + json.dumps(sorted(contains)))
    return answer()
'''

EVENTS = types.ModuleType('hwdrop_events')
EVENTS.result, EVENTS.watch, EVENTS.calls = 0, set(), None
sys.modules['hwdrop_events'] = EVENTS

CONFIG = ('<opnsense><OPNsense><Firewall><Alias><aliases>%s</aliases></Alias></Firewall><AppControl><general>'
          '<classify>%s</classify><blocked>%s</blocked></general></AppControl></OPNsense></opnsense>')


def aliases(*apps):
    return ''.join('<alias><enabled>1</enabled><name>appcontrol_%s</name><type>external</type>'
                   '<description>Application Control: %s</description></alias>' % (a, a) for a in apps)


def config(tmp, classify='1', blocked='YouTube,TikTok', apps=('YouTube', 'TikTok')):
    path = os.path.join(tmp, 'config.xml')
    with open(path, 'w') as handle:
        handle.write(CONFIG % (aliases(*apps), classify, blocked))
    cut.CONFIG = path
    return path


def program(path, text):
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def calls(path):
    try:
        return open(path).read().splitlines()
    except OSError:
        return []


def setup(tmp, hwdrop='ready', states=STATES, kill_fails=(), kill_wait=0):
    """A run's surroundings in tmp: pfctl's stand-in, hwdrop.py's - 'ready', 'old' (no release_addresses()),
    'broken' (it does not load), or None - config.xml with YouTube and TikTok blocked, cut.py's files there."""
    log = os.path.join(tmp, 'calls')
    if os.path.exists(log):
        os.remove(log)
    with open(os.path.join(tmp, 'states.txt'), 'w') as handle:
        handle.write(states)
    program(os.path.join(tmp, 'pfctl'), '#!/bin/sh\necho "pfctl $*" >> %s\n'
            'case "$*" in "-ss -vv") cat %s ;; *"-k id -k %s"*) exit 1 ;; *"-k id"*) sleep %s ;; esac\nexit 0\n'
            % (log, os.path.join(tmp, 'states.txt'), kill_fails[0] if kill_fails else 'none', kill_wait))
    folder = os.path.join(tmp, 'xgs')
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, 'hwdrop.py'), 'w') as handle:
        handle.write({'ready': FAKE_HWDROP + FAKE_RELEASE, 'old': FAKE_HWDROP,
                      'broken': 'raise ImportError("a module of its own missing")\n'}.get(hwdrop, ''))
    with open(os.path.join(folder, 'flows.py'), 'w') as handle:
        handle.write('# os-xgs-npu\'s flows.py, standing in\n')
    cut.PFCTL = os.path.join(tmp, 'pfctl')
    cut.HWDROP = os.path.join(folder, 'hwdrop.py') if hwdrop else os.path.join(tmp, 'absent', 'hwdrop.py')
    cut.DROPPED = os.path.join(tmp, 'dropped.json')
    cut.LOCK = os.path.join(tmp, 'cut.lock')
    cut._hwdrop.clear()
    config(tmp)
    EVENTS.calls = log
    return log


def settle(wait=8):
    """Every hardware step left at its deadline, ended."""
    until = time.monotonic() + wait
    for t in list(cut._left):
        t.join(max(0, until - time.monotonic()))
    cut._left[:] = [t for t in cut._left if t.is_alive()]
    return not cut._left


def kills(lines):
    return [line for line in lines if line.startswith('pfctl -k')]


# ------------------------------------------------------------------------------------ pf's states read
found = cut.states(STATES)
check('pfctl -ss -vv read: nine states, each with its id', [s[0][-2:] for s in found],
      ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9'])
check('a state\'s protocol, its ends, its age', found[0][1:4], ('tcp', {('192.0.2.10', 50001), ('198.51.100.10', 443)}, 40))
check('a state after NAT: its ends and the original one in parentheses', found[1][2],
      {('203.0.113.2', 61001), ('192.0.2.10', 50001), ('198.51.100.10', 443)})
check('IPv6, address[port]', found[6][2], {('2001:db8::10', 50007), ('2001:db8::443', 443)})
check('a state written with <-: both ends', found[7][2], {('198.51.100.40', 443), ('192.0.2.10', 50008)})
check('a connection over (both halves FIN_WAIT_2): said; one going: not', (found[4][4], found[0][4]), (True, False))
check('an endpoint that is not one: none', (cut.endpoint('->'), cut.endpoint('ESTABLISHED:ESTABLISHED'),
                                            cut.endpoint('192.0.2.1:http')), (None, None, None))

read = [cut.connection(c) for c in CONNS]
check('a connection read: tcp, its ends, when it began on the monotonic clock, its application, the name it carried',
      tuple(read[0]), ('tcp', ('192.0.2.10', 50001), ('198.51.100.10', 443), NOW - 40, 'YouTube', 'video.example', False))
check('a connection that cannot be read: none', [cut.connection(c) for c in (
    {'proto': 6}, {'proto': 'x', 'client': ['192.0.2.10', 1], 'server': ['198.51.100.1', 2]},
    {'proto': 6, 'client': ['not an address', 1], 'server': ['198.51.100.1', 2]}, 'not a connection')],
      [None, None, None, None])
check('which states are cut: both ends of a connection, its protocol, not over, made within 5 s of its first packet - '
      'not another client of the same server, a UDP state on the same ends, one over, a later connection on the same '
      'ends, nor another device\'s state, two hours old, on the ends a forged packet named',
      sorted(cut.to_cut(read, found, NOW).items()),
      [('00000000000000a1', 0), ('00000000000000a2', 0), ('00000000000000a7', 3), ('00000000000000a8', 4)])
check('a state made 3 s after its connection\'s first packet was seen - within 5 s - is its own',
      sorted(cut.to_cut([read[0]._replace(began=NOW - 40 - 3)], found, NOW)), ['00000000000000a1', '00000000000000a2'])

# 37,000 states - phase 0's L4 load - against 5,000 connections, looked up by their ends: one pass over each
many_states = [('%016x' % n, 'tcp', {('192.0.2.%d' % (n % 250 + 1), 10000 + n), ('198.51.100.%d' % (n % 200 + 1), 443)},
                30, False) for n in range(37000)]
many_conns = [cut.Conn('tcp', ('192.0.2.%d' % (n % 250 + 1), 10000 + n), ('198.51.100.%d' % (n % 200 + 1), 443), NOW - 30,
                       'YouTube', '', False) for n in range(0, 37000, 37000 // 5000)][:5000]
began = time.monotonic()
matched = cut.to_cut(many_conns, many_states, NOW)
took = time.monotonic() - began
check('5,000 connections against 37,000 states: each matched, in well under a second where every pair took 18 s',
      (len(matched), took < 3), (5000, True))

# ------------------------------------------------------------------------------- the names a server is put in for
check('a name as the resolver is asked for it: lower case, no last dot, an HTTP Host\'s port left off',
      [cut.name_of(h) for h in ('Video.Example.', 'video.example:8080', ' clips.example ')],
      ['video.example', 'video.example', 'clips.example'])
check('no name: an address written as a name, a name of one label, nothing, what is no name',
      [cut.name_of(h) for h in ('198.51.100.10', '[2001:db8::1]:443', '2001:db8::1', 'intranet', '', None, 'a b.example',
                                'x' * 250 + '.example')], [None] * 8)
check('the resolver asked: each name once, what it gives, an address written its one way', cut.resolve(
    {'video.example', 'clips.example', 'none.example'}, ask=ask),
    {'video.example': {'198.51.100.10', '2001:db8::10:1'}, 'clips.example': {'2001:db8::443', '198.51.100.99'},
     'none.example': set()})


def slow_or_failing(name):
    if name == 'slow.example':
        time.sleep(3)
        return ['198.51.100.10']
    raise OSError('no answer')


began = time.monotonic()
answered = cut.resolve({'slow.example', 'broken.example'}, deadline=0.5, ask=slow_or_failing)
check('a name not answered by the deadline, or failing: none for it, and the run not held up',
      (answered, time.monotonic() - began < 2), ({'broken.example': set()}, True))

# --------------------------------------------------------------------------------- a cut, with and without hardware
with tempfile.TemporaryDirectory() as tmp:
    log = setup(tmp, hwdrop=None)
    path_before = list(sys.path)
    summary = cut.cut(CONNS, NOW, ask=ask)
    asked = calls(log)
    check('the servers the resolver vouches for put in their application\'s table first, then pf\'s states read, then '
          'each state killed by its id - without os-xgs-npu, pf alone', asked,
          ['pfctl -t appcontrol_TikTok -T show', 'pfctl -t appcontrol_TikTok -T add 2001:db8::443',
           'pfctl -t appcontrol_YouTube -T show', 'pfctl -t appcontrol_YouTube -T add 198.51.100.10', 'pfctl -ss -vv',
           'pfctl -k id -k 00000000000000a1', 'pfctl -k id -k 00000000000000a2', 'pfctl -k id -k 00000000000000a7',
           'pfctl -k id -k 00000000000000a8'])
    check('put in no table: a server the name it carried does not resolve to - a name written to another address - '
          'one with no name, and one whose name resolves elsewhere',
          (summary['tabled'], summary['alone']), (2, 4))
    check('the summary: 6 asked, 3 cut, 4 states, nothing dropped in hardware, no os-xgs-npu, per application',
          {k: summary[k] for k in ('connections', 'cut', 'states', 'dropped', 'hardware', 'apps', 'unblocked', 'left',
                                   'errors')},
          {'connections': 6, 'cut': 3, 'states': 4, 'dropped': None, 'hardware': 'absent',
           'apps': {'YouTube': 1, 'TikTok': 2}, 'unblocked': 0, 'left': [], 'errors': []})
    check('without os-xgs-npu: nothing written down for a hand-back', os.path.exists(cut.DROPPED), False)

    log = setup(tmp, hwdrop=None)
    summary = cut.cut([dict(c, alone=True) for c in CONNS], NOW, ask=ask)
    check('a server classify.py found shared with an application not blocked: in no table, whatever the resolver says; '
          'its connection cut alone', ([a for a in calls(log) if a.startswith('pfctl -t')], summary['tabled'],
                                       summary['alone'], summary['cut']), ([], 0, 6, 3))
    log = setup(tmp, hwdrop=None)
    summary = cut.cut([dict(CONNS[0], alone=True), CONNS[5]], NOW, ask=ask)
    check('the same name looked up for another connection, which the resolver does not vouch for: the shared server '
          'still in no table', ([a for a in calls(log) if a.startswith('pfctl -t')], summary['tabled'], summary['alone']),
          ([], 0, 2))

    log = setup(tmp, hwdrop=None)
    config(tmp, blocked='YouTube', apps=('YouTube', 'TikTok'))
    summary = cut.cut(CONNS, NOW, ask=ask)
    check('TikTok no longer blocked when the run begins: its connections left, counted, none of its servers tabled',
          (summary['unblocked'], summary['apps'], kills(calls(log)), summary['tabled']),
          (4, {'YouTube': 1}, ['pfctl -k id -k 00000000000000a1', 'pfctl -k id -k 00000000000000a2'], 1))

    log = setup(tmp)
    EVENTS.result = 3
    summary = cut.cut(CONNS, NOW, ask=ask)
    asked = calls(log)
    check('with os-xgs-npu: the coprocessor asked once, after the tables and before the first state is killed',
          [a.split()[0] + ' ' + a.split()[1] for a in asked if not a.startswith('pfctl -t')],
          ['pfctl -ss', 'hwdrop drop_ends', 'pfctl -k', 'pfctl -k', 'pfctl -k', 'pfctl -k'])
    groups = json.loads([a for a in asked if a.startswith('hwdrop')][0].split(' ', 2)[2])
    check('hwdrop.drop_ends: each state\'s ends apart, with its protocol - the original ends after NAT among them',
          groups, sorted([['tcp', sorted([['192.0.2.10', 50001], ['198.51.100.10', 443]])],
                          ['tcp', sorted([['203.0.113.2', 61001], ['192.0.2.10', 50001], ['198.51.100.10', 443]])],
                          ['tcp', sorted([['2001:db8::10', 50007], ['2001:db8::443', 443]])],
                          ['tcp', sorted([['198.51.100.40', 443], ['192.0.2.10', 50008]])]]))
    check('with os-xgs-npu: how many it dropped, in the summary', (summary['dropped'], summary['cut'], summary['hardware']),
          (3, 3, 'ready'))
    check('the module search path as it was', sys.path, path_before)
    check('what was dropped written down: each application\'s server, nothing of the device - no address, port or time',
          json.load(open(cut.DROPPED)), {'dropped': [{'app': 'TikTok', 'server': '198.51.100.40'},
                                                     {'app': 'TikTok', 'server': '2001:db8::443'},
                                                     {'app': 'YouTube', 'server': '198.51.100.10'}]})
    cut.cut(CONNS[3:4], NOW, ask=ask)
    check('a server dropped again: written down once, the latest last', json.load(open(cut.DROPPED))['dropped'],
          [{'app': 'TikTok', 'server': '198.51.100.40'}, {'app': 'YouTube', 'server': '198.51.100.10'},
           {'app': 'TikTok', 'server': '2001:db8::443'}])

    os.remove(cut.DROPPED)
    log = setup(tmp)
    EVENTS.result = 0
    summary = cut.cut(CONNS, NOW, ask=ask)
    check('Cut in hardware off (hwdrop drops none): 0, the pf cut as before, nothing written down',
          (summary['dropped'], summary['states'], os.path.exists(cut.DROPPED)), (0, 4, False))

    for kind in ('old', 'broken'):
        log = setup(tmp, hwdrop=kind)
        EVENTS.result = 3
        summary = cut.cut(CONNS, NOW, ask=ask)
        check('os-xgs-npu\'s hwdrop.py %s: asked nothing, the pf cut alone, nothing written down' % (
            'with no release_addresses() - the release of 2026-11-08, whose drop_ends() takes no protocol - too old'
            if kind == 'old' else 'not loading'),
              (summary['hardware'], summary['dropped'], [a for a in calls(log) if a.startswith('hwdrop')], summary['states'],
               os.path.exists(cut.DROPPED)), (kind, None, [], 4, False))

    log = setup(tmp)
    EVENTS.result = 'raise'
    summary = cut.cut(CONNS, NOW, ask=ask)
    check('a hardware step that fails: "unknown", every state killed all the same, the servers written down',
          (summary['dropped'], summary['states'], len(cut.entries())), ('unknown', 4, 3))

    os.remove(cut.DROPPED)
    log = setup(tmp)
    EVENTS.result = 'slow'
    cut.HW_DEADLINE = 0.5
    began = time.monotonic()
    summary = cut.cut(CONNS, NOW, ask=ask)
    took = time.monotonic() - began
    check('a hardware step past its deadline: left there, "unknown", the pf cut done at once',
          (summary['dropped'], summary['states'], took < 3, len(kills(calls(log)))), ('unknown', 4, True, 4))
    check('the step left at its deadline ends at its next connection, and none is started beside it meanwhile',
          (cut.drop_in_hardware([('tcp', {('192.0.2.1', 1)})]) if cut._left else 'ended', settle()), ('unknown', True))
    cut.HW_DEADLINE = 5

    log = setup(tmp, hwdrop=None, kill_fails=['00000000000000a7'])
    summary = cut.cut(CONNS, NOW, ask=ask)
    check('a state pfctl will not kill: said, the others killed, that connection not counted as cut',
          (summary['states'], summary['cut'], summary['apps'], len(summary['errors'])), (3, 2, {'YouTube': 1, 'TikTok': 1}, 1))

    log = setup(tmp, hwdrop=None, kill_wait=0.6)
    kept_budget = cut.BUDGET
    cut.BUDGET = 1
    try:
        summary = cut.cut(CONNS, NOW, ask=ask)
    finally:
        cut.BUDGET = kept_budget
    check('the run\'s budget spent: the kills stop, the connections not reached given back as they were, said',
          (summary['cut'], [c['client'] for c in summary['left']], summary['errors']),
          (1, [['2001:db8::10', 50007], ['192.0.2.10', 50008]],
           ['2 connection(s) not reached within 1 s: given back to be cut again']))

    log = setup(tmp, hwdrop=None)
    program(os.path.join(tmp, 'pfctl'), '#!/bin/sh\ncase "$*" in *"-T show"*) exit 0 ;; *"-T add"*) exit 0 ;; esac\nexit 1\n')
    summary = cut.cut(CONNS, NOW, ask=ask)
    check('pf\'s states not to be read: nothing cut, said', (summary['cut'], len(summary['errors'])), (0, 1))
    log = setup(tmp, hwdrop=None)
    summary = cut.cut([{'proto': 6}], NOW, ask=ask)
    check('nothing that can be read: pf not asked, said', (calls(log), summary['errors']),
          ([], ['1 connection(s) to cut could not be read']))
    log = setup(tmp, hwdrop=None)
    summary = cut.cut(CONNS, NOW, ask=ask, config=os.path.join(tmp, 'none.xml'))
    check('config.xml not to be read: nothing cut, said - whether an application is blocked still is not known',
          (calls(log), summary['cut'], summary['errors']),
          ([], 0, ['%s could not be read: nothing cut' % os.path.join(tmp, 'none.xml')]))

# ---------------------------------------------------------------------------- the hand-back from hardware
DROPPED_ROWS = [{'app': 'YouTube', 'server': '198.51.100.10'}, {'app': 'TikTok', 'server': '2001:db8::443'},
                {'app': 'TikTok', 'server': '198.51.100.40'}, {'app': 'TikTok', 'server': '198.51.100.10'}]

with tempfile.TemporaryDirectory() as tmp:
    log = setup(tmp)

    def given(rows=DROPPED_ROWS):
        cut.keep([dict(r) for r in rows])

    EVENTS.result = 0
    check('nothing written down: nothing handed back, hwdrop not asked', (cut.release(config(tmp)), calls(log)),
          ({'released': None, 'kept': 0, 'errors': []}, []))
    given()
    check('both applications still blocked: nothing handed back, hwdrop not asked',
          (cut.release(config(tmp))['released'], calls(log), len(cut.entries())), (None, [], 4))
    EVENTS.result = 2
    summary = cut.release(config(tmp, blocked='YouTube'))
    check('TikTok no longer chosen: its servers handed back - less the one YouTube, still blocked, holds',
          (calls(log), summary['released'], sorted(r['app'] for r in cut.entries())),
          (['hwdrop release_addresses ["198.51.100.40", "2001:db8::443"]'], 2, ['YouTube']))
    given()
    log = setup(tmp)
    cut.release(config(tmp, blocked='YouTube,TikTok', apps=('YouTube',)))
    check('TikTok chosen, its alias gone - switched off, or not made: not blocked, handed back the same',
          calls(log), ['hwdrop release_addresses ["198.51.100.40", "2001:db8::443"]'])
    given()
    log = setup(tmp)
    summary = cut.release(config(tmp, classify='0'))
    check('classifying off - the plugin\'s removal looks the same, its aliases gone: everything handed back, nothing kept',
          (calls(log), summary['kept'], os.path.exists(cut.DROPPED)),
          (['hwdrop release_addresses ["198.51.100.10", "198.51.100.40", "2001:db8::443"]'], 0, False))
    given()
    log = setup(tmp)
    EVENTS.result = 'raise'
    summary = cut.release(config(tmp, classify='0'))
    check('the hand-back failing: "unknown", every server kept for the next one, said',
          (summary['released'], len(cut.entries()), len(summary['errors'])), ('unknown', 4, 1))
    log = setup(tmp)
    EVENTS.result = 'slow'
    kept_deadline = cut.RELEASE_DEADLINE
    cut.RELEASE_DEADLINE = 0.5
    began = time.monotonic()
    summary = cut.release(config(tmp, classify='0'))
    cut.RELEASE_DEADLINE = kept_deadline
    check('the hand-back past its own deadline: "unknown", kept for the next one, said - and not a cut\'s 5 s',
          (summary['released'], len(cut.entries()), summary['errors'], time.monotonic() - began < 3, settle()),
          ('unknown', 4, ['handing back from hardware did not end within 0.5 s: tried again at the next release'], True,
           True))
    check('a release\'s deadline is its own: 30 s, the whole flow table read', (cut.RELEASE_DEADLINE, cut.HW_DEADLINE), (30, 5))
    for kind in ('old', 'broken'):
        log = setup(tmp, hwdrop=kind)
        summary = cut.release(config(tmp, blocked='YouTube'))
        check('os-xgs-npu\'s hwdrop.py %s: nothing handed back, every server kept for the next release, said' % kind,
              (summary['released'], len(cut.entries()), [a for a in calls(log) if a.startswith('hwdrop')],
               len(summary['errors'])), (None, 4, [], 1))
    log = setup(tmp, hwdrop=None)
    summary = cut.release(config(tmp, blocked='YouTube'))
    check('os-xgs-npu gone since: nothing in hardware to hand back, the servers of TikTok let go',
          (summary['released'], sorted(r['app'] for r in cut.entries())), (None, ['YouTube']))
    given()
    check('config.xml not to be read: nothing handed back, said', cut.release(os.path.join(tmp, 'none.xml'))['errors'],
          ['%s could not be read: nothing handed back' % os.path.join(tmp, 'none.xml')])
    cut.keep([{'app': 'YouTube', 'server': '198.51.100.%d' % (i % 250)} for i in range(cut.KEEP + 5)])
    check('what is written down: the latest %d' % cut.KEEP, (len(cut.entries()), cut.entries()[0]['server']),
          (cut.KEEP, '198.51.100.5'))
    with open(cut.DROPPED, 'w') as handle:
        handle.write('{"dropped": [{"app": "YouTube"}, "x", {"server": "198.51.100.1", "app": "Zoom", "client": ['
                     '"192.0.2.10", 1]}]}')
    check('a written-down list with rows that are not rows: those left out; a device\'s address an older one kept, '
          'not read', cut.entries(), [{'app': 'Zoom', 'server': '198.51.100.1'}])

# ------------------------------------------------------------------------------------------- the command line


def main(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = cut.main(['cut.py'] + list(argv))
    return status, json.loads(out.getvalue())


with tempfile.TemporaryDirectory() as tmp:
    log = setup(tmp, hwdrop=None)
    request = os.path.join(tmp, 'cut-1.json')
    with open(request, 'w') as handle:
        # begun 40 s ago by the clock cut.py reads, as its states' age says; a name the resolver does not know
        json.dump([dict(CONNS[0], began=time.monotonic() - 40, host='')], handle)
    status, answer = main('cut', request)
    check('cut.py cut <file>: exit 0, its summary as JSON', (status, answer['cut'], answer['states']), (0, 1, 2))
    with open(request, 'w') as handle:
        handle.write('{"not": "a list"}')
    check('cut.py cut, a file that holds no list: exit 0, said', main('cut', request),
          (0, {'errors': ['%s: no list of connections could be read' % request]}))
    check('cut.py with no verb, or cut with no file: exit 0, its usage', (main(), main('cut')),
          ((0, {'errors': ['usage: cut.py cut <file> | cut.py release']}),) * 2)
    status, answer = main('release')
    check('cut.py release: exit 0, its summary as JSON', (status, answer), (0, {'released': None, 'kept': 0, 'errors': []}))
    holder = cut.locked(cut.LOCK)
    kept_wait = cut.WAIT
    cut.WAIT = 0.5
    status, answer = main('release')
    check('one release at a time: another holding the lock, nothing done after the wait, said',
          answer, {'released': None, 'kept': 0, 'errors': ['another release is running: nothing handed back']})
    with open(request, 'w') as handle:
        json.dump([dict(CONNS[0], began=time.monotonic() - 40, host='')], handle)
    status, answer = main('cut', request)
    check('a cut is never held up by a release: its states killed while the lock is held', (answer['cut'], answer['states']),
          (1, 2))
    holder.close()
    cut.WAIT = kept_wait
    status, answer = main('release')
    check('the lock let go: runs again', 'errors' in answer and answer['errors'] == [], True)
    raised = threading.Event()

    def broken(conns, now=None, ask=None, config=None):
        raised.set()
        raise ValueError('a fault of its own')

    real_cut, cut.cut = cut.cut, broken
    try:
        with open(request, 'w') as handle:
            json.dump(CONNS[:1], handle)
        status, answer = main('cut', request)
    finally:
        cut.cut = real_cut
    check('a fault of its own: exit 0, said, never raised', (status, raised.is_set(), answer['errors'][0].startswith(
        'the cut stopped: ValueError')), (0, True, True))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
