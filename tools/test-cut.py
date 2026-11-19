#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""cut.py - the open connections of a blocked application ended, and what was dropped in hardware for one no
longer blocked handed back - with stand-ins for what only a firewall has: pfctl, a program that writes how it
was called and prints pf's states as `pfctl -ss -vv` writes them; and os-xgs-npu's hwdrop.py, a module of the
test's own in a folder of its own, loaded from there as cut.py loads the real one. No OPNsense, no root:

    python3 tools/test-cut.py

What is checked: pf's states read - IPv4, IPv6, a state after NAT with its original ends in parentheses, one
written with <-, its protocol, its age, a connection over; a connection's states are those holding both its
ends, of its protocol, made no later than its first packet, not over - another client of the same server, a
UDP state on the same ends and a later connection on them are not cut; each killed by its id, the
coprocessor asked first, once, with each state's ends apart and its protocol; its count in the summary, with
the connections cut per application; without hwdrop.py pf alone; a hardware step that fails or passes its
deadline says "unknown" and the pf cut goes on at once; the module search path left as it was; what was
dropped written down, and nothing when nothing was; the hand-back of what an application no longer blocked
had dropped - by its servers, less a server an application still blocked holds - with classifying off, its
alias gone, os-xgs-npu gone, the step failing (kept for the next), and nothing written down; the command
line's answers, one run at a time.
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


NOW = 1794926400.0      # 2026-11-17

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
'''

# the connections classify.py hands over: its two ends as the capture saw them, the application, when it began
CONNS = [
    {'proto': 6, 'client': ['192.0.2.10', 50001], 'server': ['198.51.100.10', 443], 'name': 'TLS.YouTube',
     'app': 'YouTube', 'first': NOW - 40},
    {'proto': 6, 'client': ['192.0.2.10', 50003], 'server': ['198.51.100.20', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'first': NOW - 40},
    {'proto': 6, 'client': ['192.0.2.10', 50004], 'server': ['198.51.100.30', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'first': NOW - 60},
    {'proto': 6, 'client': ['2001:db8::10', 50007], 'server': ['2001:db8::443', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'first': NOW - 60},
    {'proto': 6, 'client': ['192.0.2.10', 50008], 'server': ['198.51.100.40', 443], 'name': 'TLS.TikTok',
     'app': 'TikTok', 'first': NOW - 50},
]

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


def release_addresses(contains):
    hwdrop_events.watch = contains
    say('hwdrop release_addresses ' + json.dumps(sorted(contains)))
    return answer()
'''

EVENTS = types.ModuleType('hwdrop_events')
EVENTS.result, EVENTS.watch, EVENTS.calls = 0, set(), None
sys.modules['hwdrop_events'] = EVENTS


def program(path, text):
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def calls(path):
    try:
        return open(path).read().splitlines()
    except OSError:
        return []


def setup(tmp, hwdrop=True, states=STATES, kill_fails=()):
    """A run's surroundings in tmp: pfctl's stand-in, hwdrop.py's (or none), cut.py's files there."""
    log = os.path.join(tmp, 'calls')
    if os.path.exists(log):
        os.remove(log)
    with open(os.path.join(tmp, 'states.txt'), 'w') as handle:
        handle.write(states)
    program(os.path.join(tmp, 'pfctl'), '#!/bin/sh\necho "pfctl $*" >> %s\n'
            'case "$*" in "-ss -vv") cat %s ;; *"-k id -k %s"*) exit 1 ;; esac\nexit 0\n'
            % (log, os.path.join(tmp, 'states.txt'), kill_fails[0] if kill_fails else 'none'))
    folder = os.path.join(tmp, 'xgs')
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, 'hwdrop.py'), 'w') as handle:
        handle.write(FAKE_HWDROP)
    with open(os.path.join(folder, 'flows.py'), 'w') as handle:
        handle.write('# os-xgs-npu\'s flows.py, standing in\n')
    cut.PFCTL = os.path.join(tmp, 'pfctl')
    cut.HWDROP = os.path.join(folder, 'hwdrop.py') if hwdrop else os.path.join(tmp, 'absent', 'hwdrop.py')
    cut.DROPPED = os.path.join(tmp, 'dropped.json')
    cut.LOCK = os.path.join(tmp, 'cut.lock')
    cut._hwdrop.clear()
    EVENTS.calls = log
    return log


def settle(wait=8):
    """Every hardware step left at its deadline, ended."""
    until = time.monotonic() + wait
    for t in list(cut._left):
        t.join(max(0, until - time.monotonic()))
    cut._left[:] = [t for t in cut._left if t.is_alive()]
    return not cut._left


# ------------------------------------------------------------------------------------ pf's states read
found = cut.states(STATES)
check('pfctl -ss -vv read: eight states, each with its id', [s[0][-2:] for s in found],
      ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8'])
check('a state\'s protocol, its ends, its age', found[0][1:4], ('tcp', {('192.0.2.10', 50001), ('198.51.100.10', 443)}, 40))
check('a state after NAT: its ends and the original one in parentheses', found[1][2],
      {('203.0.113.2', 61001), ('192.0.2.10', 50001), ('198.51.100.10', 443)})
check('IPv6, address[port]', found[6][2], {('2001:db8::10', 50007), ('2001:db8::443', 443)})
check('a state written with <-: both ends', found[7][2], {('198.51.100.40', 443), ('192.0.2.10', 50008)})
check('a connection over (both halves FIN_WAIT_2): said; one going: not', (found[4][4], found[0][4]), (True, False))
check('an endpoint that is not one: none', (cut.endpoint('->'), cut.endpoint('ESTABLISHED:ESTABLISHED'),
                                            cut.endpoint('192.0.2.1:http')), (None, None, None))

read = [cut.connection(c) for c in CONNS]
check('a connection read: tcp, its ends, when it began, its application', read[0],
      ('tcp', ('192.0.2.10', 50001), ('198.51.100.10', 443), NOW - 40, 'YouTube'))
check('a connection that cannot be read: none', [cut.connection(c) for c in (
    {'proto': 6}, {'proto': 'x', 'client': ['192.0.2.10', 1], 'server': ['198.51.100.1', 2]},
    {'proto': 6, 'client': ['not an address', 1], 'server': ['198.51.100.1', 2]})], [None, None, None])
check('which states are cut: both ends of a connection, its protocol, made no later than its first packet, not over - '
      'not another client of the same server, a UDP state on the same ends, one over, a later connection on the same ends',
      sorted(cut.to_cut(read, found, NOW).items()),
      [('00000000000000a1', 0), ('00000000000000a2', 0), ('00000000000000a7', 3), ('00000000000000a8', 4)])

# --------------------------------------------------------------------------------- a cut, with and without hardware
with tempfile.TemporaryDirectory() as tmp:
    log = setup(tmp, hwdrop=False)
    path_before = list(sys.path)
    summary = cut.cut(CONNS, NOW)
    asked = calls(log)
    check('without os-xgs-npu: pf alone - its states read, each state killed by its id', asked,
          ['pfctl -ss -vv', 'pfctl -k id -k 00000000000000a1', 'pfctl -k id -k 00000000000000a2',
           'pfctl -k id -k 00000000000000a7', 'pfctl -k id -k 00000000000000a8'])
    check('the summary: 5 asked, 3 cut, 4 states, nothing dropped in hardware, per application',
          {k: summary[k] for k in ('connections', 'cut', 'states', 'dropped', 'apps', 'errors')},
          {'connections': 5, 'cut': 3, 'states': 4, 'dropped': None, 'apps': {'YouTube': 1, 'TikTok': 2}, 'errors': []})
    check('without os-xgs-npu: nothing written down for a hand-back', os.path.exists(cut.DROPPED), False)

    log = setup(tmp)
    EVENTS.result = 3
    summary = cut.cut(CONNS, NOW)
    asked = calls(log)
    check('with os-xgs-npu: the coprocessor asked once, before the first state is killed', [a.split()[0] + ' ' + a.split()[1]
                                                                                           for a in asked],
          ['pfctl -ss', 'hwdrop drop_ends', 'pfctl -k', 'pfctl -k', 'pfctl -k', 'pfctl -k'])
    groups = json.loads(asked[1].split(' ', 2)[2])
    check('hwdrop.drop_ends: each state\'s ends apart, with its protocol - the original ends after NAT among them',
          groups, sorted([['tcp', sorted([['192.0.2.10', 50001], ['198.51.100.10', 443]])],
                          ['tcp', sorted([['203.0.113.2', 61001], ['192.0.2.10', 50001], ['198.51.100.10', 443]])],
                          ['tcp', sorted([['2001:db8::10', 50007], ['2001:db8::443', 443]])],
                          ['tcp', sorted([['198.51.100.40', 443], ['192.0.2.10', 50008]])]]))
    check('with os-xgs-npu: how many it dropped, in the summary', (summary['dropped'], summary['cut']), (3, 3))
    check('the module search path as it was', sys.path, path_before)
    written = cut.entries()
    check('what was dropped written down: each connection cut, its application and its server',
          sorted((r['app'], r['server'], r['proto'], tuple(r['client'])) for r in written),
          [('TikTok', '198.51.100.40', 'tcp', ('192.0.2.10', 50008)), ('TikTok', '2001:db8::443', 'tcp', ('2001:db8::10', 50007)),
           ('YouTube', '198.51.100.10', 'tcp', ('192.0.2.10', 50001))])

    os.remove(cut.DROPPED)
    log = setup(tmp)
    EVENTS.result = 0
    summary = cut.cut(CONNS, NOW)
    check('Cut in hardware off (hwdrop drops none): 0, the pf cut as before, nothing written down',
          (summary['dropped'], summary['states'], os.path.exists(cut.DROPPED)), (0, 4, False))

    log = setup(tmp)
    EVENTS.result = 'raise'
    summary = cut.cut(CONNS, NOW)
    check('a hardware step that fails: "unknown", every state killed all the same, the connections written down',
          (summary['dropped'], summary['states'], len(cut.entries())), ('unknown', 4, 3))

    os.remove(cut.DROPPED)
    log = setup(tmp)
    EVENTS.result = 'slow'
    cut.HW_DEADLINE = 0.5
    began = time.monotonic()
    summary = cut.cut(CONNS, NOW)
    took = time.monotonic() - began
    check('a hardware step past its deadline: left there, "unknown", the pf cut done at once',
          (summary['dropped'], summary['states'], took < 3, len(calls(log)) >= 6), ('unknown', 4, True, True))
    check('the step left at its deadline ends at its next connection, and none is started beside it meanwhile',
          (cut.drop_in_hardware([('tcp', {('192.0.2.1', 1)})]) if cut._left else 'ended', settle()), ('unknown', True))
    cut.HW_DEADLINE = 5

    log = setup(tmp, hwdrop=False, kill_fails=['00000000000000a7'])
    summary = cut.cut(CONNS, NOW)
    check('a state pfctl will not kill: said, the others killed, that connection not counted as cut',
          (summary['states'], summary['cut'], summary['apps'], len(summary['errors'])), (3, 2, {'YouTube': 1, 'TikTok': 1}, 1))

    log = setup(tmp, hwdrop=False)
    program(os.path.join(tmp, 'pfctl'), '#!/bin/sh\nexit 1\n')
    summary = cut.cut(CONNS, NOW)
    check('pf\'s states not to be read: nothing cut, said', (summary['cut'], len(summary['errors'])), (0, 1))
    log = setup(tmp, hwdrop=False)
    summary = cut.cut([{'proto': 6}], NOW)
    check('nothing that can be read: pf not asked, said', (calls(log), summary['errors']),
          ([], ['1 connection(s) to cut could not be read']))

# ---------------------------------------------------------------------------- the hand-back from hardware
CONFIG = ('<opnsense><OPNsense><Firewall><Alias><aliases>%s</aliases></Alias></Firewall><AppControl><general>'
          '<classify>%s</classify><blocked>%s</blocked></general></AppControl></OPNsense></opnsense>')


def aliases(*apps):
    return ''.join('<alias><enabled>1</enabled><name>appcontrol_%s</name><type>external</type>'
                   '<description>Application Control: %s</description></alias>' % (a, a) for a in apps)


def config(tmp, classify='1', blocked='YouTube,TikTok', apps=('YouTube', 'TikTok')):
    path = os.path.join(tmp, 'config.xml')
    with open(path, 'w') as handle:
        handle.write(CONFIG % (aliases(*apps), classify, blocked))
    return path


DROPPED_ROWS = [{'app': 'YouTube', 'server': '198.51.100.10', 'proto': 'tcp', 'client': ['192.0.2.10', 50001], 'at': 1},
                {'app': 'TikTok', 'server': '2001:db8::443', 'proto': 'tcp', 'client': ['2001:db8::10', 50007], 'at': 2},
                {'app': 'TikTok', 'server': '198.51.100.40', 'proto': 'tcp', 'client': ['192.0.2.10', 50008], 'at': 3},
                {'app': 'TikTok', 'server': '198.51.100.10', 'proto': 'tcp', 'client': ['192.0.2.12', 50009], 'at': 4}]

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
    check('the hand-back failing: "unknown", every connection kept for the next one, said',
          (summary['released'], len(cut.entries()), len(summary['errors'])), ('unknown', 4, 1))
    log = setup(tmp, hwdrop=False)
    summary = cut.release(config(tmp, blocked='YouTube'))
    check('os-xgs-npu gone since: nothing to hand back with, the connections of TikTok forgotten',
          (summary['released'], sorted(r['app'] for r in cut.entries())), (None, ['YouTube']))
    check('config.xml not to be read: nothing handed back, said', cut.release(os.path.join(tmp, 'none.xml'))['errors'],
          ['%s could not be read: nothing handed back' % os.path.join(tmp, 'none.xml')])
    cut.keep([dict(DROPPED_ROWS[0], at=i) for i in range(cut.KEEP + 5)])
    check('what is written down: the latest %d' % cut.KEEP, (len(cut.entries()), cut.entries()[0]['at']), (cut.KEEP, 5))
    with open(cut.DROPPED, 'w') as handle:
        handle.write('{"dropped": [{"app": "YouTube"}, "x", {"server": "198.51.100.1", "app": "Zoom"}]}')
    check('a written-down list with rows that are not rows: those left out', cut.entries(),
          [{'server': '198.51.100.1', 'app': 'Zoom'}])

# ------------------------------------------------------------------------------------------- the command line


def main(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = cut.main(['cut.py'] + list(argv))
    return status, json.loads(out.getvalue())


with tempfile.TemporaryDirectory() as tmp:
    log = setup(tmp, hwdrop=False)
    request = os.path.join(tmp, 'cut-1.json')
    with open(request, 'w') as handle:
        # begun 40 s ago by the clock cut.py reads, as its states' age says
        json.dump([dict(CONNS[0], first=time.time() - 40)], handle)
    status, answer = main('cut', request)
    check('cut.py cut <file>: exit 0, its summary as JSON', (status, answer['cut'], answer['states']), (0, 1, 2))
    with open(request, 'w') as handle:
        handle.write('{"not": "a list"}')
    check('cut.py cut, a file that holds no list: exit 0, said', main('cut', request),
          (0, {'errors': ['%s: no list of connections could be read' % request]}))
    check('cut.py with no verb, or cut with no file: exit 0, its usage', (main(), main('cut')),
          ((0, {'errors': ['usage: cut.py cut <file> | cut.py release']}),) * 2)
    cut.CONFIG = config(tmp)
    status, answer = main('release')
    check('cut.py release: exit 0, its summary as JSON', (status, answer), (0, {'released': None, 'kept': 0, 'errors': []}))
    holder = cut.locked(cut.LOCK)
    cut.WAIT = 0.5
    status, answer = main('release')
    check('one run at a time: another holding the lock, nothing done after the wait, said',
          answer, {'errors': ['another cut or release is running: nothing done']})
    holder.close()
    status, answer = main('release')
    check('the lock let go: runs again', 'errors' in answer and answer['errors'] == [], True)
    raised = threading.Event()

    def broken(conns, now=None):
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
