#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""suricata_rules.py - the rules of the Rules tab as local rules of OPNsense's Intrusion Detection - with
stand-ins for what only a firewall has: ifconfig, a program printing ifconfig -a as FreeBSD writes it; pfctl's
tables, held here; config.xml and the catalogue, files of the test's own. The template rendered is the plugin's
own, with Jinja2 as on a firewall. No OPNsense, no Suricata:

    python3 tools/test-suricata.py

What is checked: a name nDPI knows an application by, written for each of the four places a device writes one -
the server name of TLS and QUIC, HTTP's Host, the name of a DNS question - its content Suricata's fast pattern, its
pcre the boundary nDPI asks for, nocase but on http.host, which Suricata refuses it on; what the lines match, run
against host names, the same as nDPI's own rule (ac_domain_match_handler(), written again here) for a name, a name
with a last dot, a last hyphen, a first hyphen, both; a name of other characters refused; a source as Suricata
writes addresses - any, an interface's networks, an address, an alias's table with an entry written with ! taken
out, inverted - and why one cannot be written: not read, holding no address, too long; the firewall's own addresses
taken out of every source - any, inverted, a network holding one as an exception, one written alone no device's -
and every line's destination the internet alone, none of the firewall's addresses, its networks or the blocks that
are not the internet's, as Suricata reads an address group; its addresses not to be read, the file left as it was;
the message, what Suricata takes in one; each rule's lines - its protocol when Suricata reads it, its names, drop
for Block and alert for Alert, each line's sid from a hash of its rule's uuid and its match, kept as the rules
change around it, two meeting taking the next free - or why none: switched off, nothing Suricata can tell, more
lines than a rule takes; the
template rendered - one comment line for each rule, then its lines, each well formed, under Suricata's limit, its
sid its own; the file written in one step, not again when nothing changed, removed when classifying is off or no
rule gives a line; config.xml or the template not to be read leaving the file as it was; a line past the limit
taking its rule out, said; the command line's answers, never a fault raised.
"""
import hashlib
import json
import os
import re
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'appcontrol')
TEMPLATE = os.path.join(ROOT, 'src', 'opnsense', 'service', 'templates', 'OPNsense', 'AppControl', 'appcontrol.rules')
FIX = os.path.join(HERE, 'fixtures')
sys.path.insert(0, SCRIPTS)

import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402
import suricata_rules as sr                                              # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def program(path, text):
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ------------------------------------------------------------------------------------- one name, one place
check('a name: its content, nocase, at the end of the buffer, and the dot before it or nothing - the boundary nDPI asks for',
      sr.name_match('youtu.be', 'tls.sni', True),
      r'tls.sni; content:"youtu.be"; nocase; endswith; pcre:"/(?:^|\.)youtu\.be$/i";')
check('on http.host: no nocase, no /i - Suricata refuses nocase there, the buffer being lower case already',
      sr.name_match('youtu.be', 'http.host', False), r'http.host; content:"youtu.be"; endswith; pcre:"/(?:^|\.)youtu\.be$/";')
check('a name with a last dot: one label after it, nothing more', sr.name_match('youtube.', 'quic.sni', True),
      r'quic.sni; content:"youtube."; nocase; pcre:"/(?:^|\.)youtube\.[^.]*$/i";')
check('a name with a last hyphen: the beginning of a label', sr.name_match('nflxso-', 'dns.query', True),
      r'dns.query; content:"nflxso-"; nocase; pcre:"/(?:^|\.)nflxso-/i";')
check('a name with a first hyphen: the end of a name, after a hyphen - the content says it all',
      sr.name_match('-nflxext.example', 'tls.sni', True), 'tls.sni; content:"-nflxext.example"; nocase; endswith;')
check('a first hyphen and a last dot', sr.name_match('-nflxtest.', 'tls.sni', True),
      r'tls.sni; content:"-nflxtest."; nocase; pcre:"/-nflxtest\.[^.]*$/i";')
check('a name in capitals: lower case', sr.name_match('YouTu.BE', 'tls.sni', True),
      sr.name_match('youtu.be', 'tls.sni', True))
check('a name of other characters, of dots and hyphens alone, or none: refused',
      [sr.name_match(n, 'tls.sni', True) for n in ('bad"name.example', 'a b.example', 'semi;colon', '..', '-', '', 'x' * 254)],
      [None] * 7)


def ndpi_matches(pattern, host):
    """nDPI's own rule for a host name pattern (de5c784: string_to_automa()'s at_end, ac_automata_exact_match()'s rule for
    a last dot, ac_domain_match_handler()), written again here to hold the Suricata lines against: True when any place
    the pattern is found in the host takes it."""
    host = host.lower()
    at_end = pattern[-1] not in '.-'
    start = host.find(pattern)
    while start != -1:
        end = start + len(pattern)
        ok = True
        if at_end and end != len(host):
            ok = False
        if ok and pattern.endswith('.') and '.' in host[end:]:
            ok = False                  # google. takes google.com, not google.hello.com
        if ok:
            if start == 0 and end == len(host):
                return True
            if start >= 1 and pattern[0] not in '.-':
                if host[start - 1] == '.':
                    return True
            elif start >= 1 and pattern[0] == '-':
                return True
            elif start == 0 and pattern[-1] in '.-':
                return True
        start = host.find(pattern, start + 1)
    return False


def suricata_matches(options, host):
    """What Suricata does with one line's options on a buffer holding the host: the content found - at the end with
    endswith, in any case with nocase - and then the pcre, which Python's re reads alike for these."""
    content = re.search(r'content:"([^"]*)";', options).group(1)
    nocase = ' nocase;' in options
    buffer = host.lower() if 'http.host' in options else host
    hay, needle = (buffer.lower(), content.lower()) if nocase else (buffer, content)
    if ' endswith;' in options:
        if not hay.endswith(needle):
            return False
    elif needle not in hay:
        return False
    found = re.search(r'pcre:"/(.*)/(i?)";', options)
    if found:
        return re.search(found.group(1), buffer, re.I if found.group(2) else 0) is not None
    return True


HOSTS = ['youtu.be', 'www.youtu.be', 'myyoutu.be', 'youtu.be.example', 'youtube.com', 'www.youtube.com', 'youtube.co.uk',
         'myyoutube.com', 'youtube', 'nflxso-1.example', 'a.nflxso-2.example', 'xnflxso-3.example', 'a-nflxext.example',
         'nflxext.example', 'a.b-nflxext.example', 'a-nflxtest.com', 'a-nflxtest.co.uk', 'nflxtest.com', 'WWW.YouTu.Be']
PATTERNS = ['youtu.be', 'youtube.', 'nflxso-', '-nflxext.example', '-nflxtest.']
for place, keyword, nocase in sr.PLACES:
    differ = [(p, h) for p in PATTERNS for h in HOSTS
              if suricata_matches(sr.name_match(p, keyword, nocase), h) != ndpi_matches(p, h)]
    check('%s: what the lines take is what nDPI takes, for %d names on %d hosts' % (keyword, len(PATTERNS), len(HOSTS)),
          differ, [])
check('nDPI\'s rule as written here: youtu.be takes www.youtu.be, not myyoutu.be; youtube. takes youtube.com, not '
      'youtube.co.uk; -nflxext.example takes a-nflxext.example, not nflxext.example',
      [ndpi_matches(p, h) for p, h in (('youtu.be', 'www.youtu.be'), ('youtu.be', 'myyoutu.be'), ('youtube.', 'youtube.com'),
                                       ('youtube.', 'youtube.co.uk'), ('-nflxext.example', 'a-nflxext.example'),
                                       ('-nflxext.example', 'nflxext.example'))], [True, False, True, False, True, False])

# ----------------------------------------------------------------------------------------- the sources
IFCONFIG_TEXT = '''em1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255
\tinet6 fe80::11%em1 prefixlen 64 scopeid 0x2
\tinet6 2001:db8:1::1 prefixlen 64
em2: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 198.51.100.129/25 broadcast 198.51.100.255
em3: flags=8802<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500
'''
DEVICES = {'lan': 'em1', 'opt2': 'em2', 'opt3': 'em3'}
BY_DEV = tables.device_networks(IFCONFIG_TEXT)


class Tables:
    """pfctl -t T -T show on tables held here."""

    def __init__(self, held):
        self.held = held

    def __call__(self, args):
        if args[:1] == ['-t'] and args[2:4] == ['-T', 'show'] and args[1] in self.held:
            return 0, ''.join('   %s\n' % a for a in self.held[args[1]])
        return 1, 'pfctl: Table does not exist.'


PF = tables.Pf(run=Tables({'Teachers': ['192.0.2.40', '192.0.2.41'], 'Wing': ['192.0.2.0/25', '!192.0.2.64/26',
                                                                                '192.0.2.70'],
                           'Empty': [], 'Big': ['198.51.100.%d' % i for i in range(256)] +
                           ['2001:db8:%x::1' % i for i in range(600)],
                           'All': ['0.0.0.0/0', '::/0'], 'All4': ['0.0.0.0/0']}))


def rule(**more):
    out = {'number': 1, 'uuid': 'cccccccc-0000-4000-8000-000000000001', 'enabled': True, 'action': 'block', 'app': 'YouTube',
           'source': ['any'], 'not': False, 'description': ''}
    out.update(more)
    return out


check('an address as Suricata writes it: a host without its length, a network with it',
      [sr.address(tables.ipaddress.ip_network(n)) for n in ('192.0.2.5/32', '198.51.100.0/24', '2001:db8::1/128', '2001:db8::/32')],
      ['192.0.2.5', '198.51.100.0/24', '2001:db8::1', '2001:db8::/32'])
cases = [(['any'], False), (['opt2'], False), (['lan'], False), (['198.51.100.7', 'opt2'], False), (['Wing'], False),
         (['Teachers'], True), (['Gone'], False), (['opt3'], False), (['opt3'], True), (['Empty'], False), (['any'], True),
         (['(self)'], False)]
check('a source for Suricata: any; an interface\'s networks, link-local left out; several at once; an alias\'s table, the '
      'entry written with ! taken out; inverted with !; an alias pf holds no table for - unread; an interface with no '
      'address, an empty alias, any inverted - empty, but inverted nothing is every device; the firewall itself - unread',
      [sr.source(rule(source=s, **{'not': n}), DEVICES, BY_DEV, PF) for s, n in cases],
      [('any', None, ''), ('[198.51.100.128/25]', None, ''), ('[192.0.2.0/24,2001:db8:1::/64]', None, ''),
       ('[198.51.100.7,198.51.100.128/25]', None, ''), ('[192.0.2.0/26,192.0.2.70]', None, ''),
       ('![192.0.2.40/31]', None, ''), (None, 'unread', 'Gone'), (None, 'empty', ''), ('any', None, ''),
       (None, 'empty', ''), (None, 'empty', ''), (None, 'unread', '(self)')])
OWN = tables.addresses(IFCONFIG_TEXT)
check('the firewall\'s own addresses in ifconfig -a: every inet and inet6 line\'s, link-local among them',
      sorted(str(a) for a in OWN), ['192.0.2.1', '198.51.100.129', '2001:db8:1::1', 'fe80::11'])


def group(text):
    """What a source or a destination as these lines write it holds, as Suricata reads an address group: any; [a,b,!c] -
    in a or b, not in c; ![a,b] - every address but those of a and b. A function of an address."""
    if text == 'any':
        return lambda a: True
    negated = text.startswith('![')
    items = text[2:-1].split(',') if negated else text[1:-1].split(',')
    plus = [tables.ipaddress.ip_network(i) for i in items if not i.startswith('!')]
    minus = [tables.ipaddress.ip_network(i[1:]) for i in items if i.startswith('!')]

    def holds(address):
        a = tables.ipaddress.ip_address(address)
        inside = any(a.version == n.version and a in n for n in plus)
        return not inside if negated else inside and not any(a.version == n.version and a in n for n in minus)
    return holds


own_cases = [(['any'], False), (['lan'], False), (['opt2'], False), (['Teachers'], True), (['opt3'], True),
             (['192.0.2.1'], False), (['198.51.100.128/31'], False), (['Wing'], False)]
check('a source for Suricata, the firewall\'s own addresses taken out: any - every address but them; an interface\'s network '
      '- each of them inside it an exception of its group; inverted - left out with the excepted ones; an interface with no '
      'address inverted - every address but them; one of them written alone - no device\'s; a network of two, one of them '
      'the firewall\'s - that one its exception; an alias holding one of them - the same',
      [sr.source(rule(source=s, **{'not': n}), DEVICES, BY_DEV, PF, OWN)[:2] for s, n in own_cases],
      [('![192.0.2.1,198.51.100.129,2001:db8:1::1,fe80::11]', None),
       ('[192.0.2.0/24,2001:db8:1::/64,!192.0.2.1,!2001:db8:1::1]', None), ('[198.51.100.128/25,!198.51.100.129]', None),
       ('![192.0.2.1,192.0.2.40/31,198.51.100.129,2001:db8:1::1,fe80::11]', None),
       ('![192.0.2.1,198.51.100.129,2001:db8:1::1,fe80::11]', None), (None, 'empty'),
       ('[198.51.100.128/31,!198.51.100.129]', None), ('[192.0.2.0/26,192.0.2.70,!192.0.2.1]', None)])
check('no source holds an address of the firewall\'s own, as Suricata reads it; each still holds the devices it names',
      ([s for s, n in own_cases for a in OWN if (lambda w: w is not None and group(w)(a))(
          sr.source(rule(source=s, **{'not': n}), DEVICES, BY_DEV, PF, OWN)[0])],
       [group(sr.source(rule(source=s, **{'not': n}), DEVICES, BY_DEV, PF, OWN)[0])(a) for s, n, a in (
           (['any'], False, '203.0.113.9'), (['lan'], False, '192.0.2.10'), (['lan'], False, '2001:db8:1::10'),
           (['opt2'], False, '198.51.100.130'), (['Teachers'], True, '192.0.2.10'), (['Teachers'], True, '192.0.2.40'))]),
      ([], [True, True, True, True, True, False]))
VPN_TEXT = IFCONFIG_TEXT + ('ovpns1: flags=1008051<UP,POINTOPOINT,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 1500\n'
                            '\tinet 10.0.0.1 netmask 0xffffff00\n\tgroups: tun openvpn\n')
check('a source of OpenVPN\'s group - its device the group itself: the networks of its members, the firewall\'s address '
      'there an exception', sr.source(rule(source=['openvpn']), dict(DEVICES, openvpn='openvpn'),
                                      tables.device_networks(VPN_TEXT), PF, tables.addresses(VPN_TEXT))[:2],
      ('[10.0.0.0/24,!10.0.0.1]', None))
check('inverted, an alias holding every address - no device left, and Suricata refuses a group that negates the whole '
      'space: no line; holding every IPv4 address - every IPv6 one but the firewall\'s, written without a negated whole',
      [sr.source(rule(source=['All'], **{'not': True}), DEVICES, BY_DEV, PF, OWN)[:2],
       sr.source(rule(source=['All4'], **{'not': True}), DEVICES, BY_DEV, PF, OWN)[:2]],
      [(None, 'empty'), ('[::/0,!2001:db8:1::1,!fe80::11]', None)])
DEST = sr.destination(OWN, [n for nets in BY_DEV.values() for n in nets])
check('the destination: the internet alone - every address but the firewall\'s own, its networks, the private, shared, '
      'loopback, link-local, documentation and unique-local ones, multicast and the reserved block',
      [group(DEST)(a) for a in ('192.0.2.1', '2001:db8:1::1', '198.51.100.129', '192.0.2.10', '198.51.100.130', '10.0.0.5',
                                '172.16.0.5', '192.168.1.7', '100.64.0.5', '127.0.0.1', '169.254.0.5', '224.0.0.251',
                                '255.255.255.255', '0.0.0.0', '203.0.113.9', '::1', 'fe80::1', 'fc00::5', 'fd00::5', 'ff02::1',
                                '2001:db8:9::1')], [False] * 21)
real_not_internet = tables.NOT_INTERNET
tables.NOT_INTERNET = ()
try:
    bare = sr.destination(OWN, [n for nets in BY_DEV.values() for n in nets])
finally:
    tables.NOT_INTERNET = real_not_internet
check('the destination without the registry\'s blocks: exactly the firewall\'s own addresses and its connected networks, '
      'every interface\'s', bare, '![192.0.2.0/24,198.51.100.128/25,2001:db8:1::/64,fe80::11]')
check('the message: what the rule does, its application, its description - quotes, backslashes and semicolons left out, '
      'a line break a space, letters beyond ASCII kept, at most 200 characters',
      [sr.message(rule(description=d)) for d in ('', 'guests "evening"; a\\b\nnext\tday', 'Zürich office', 'x' * 300)],
      ['Application Control: block YouTube', 'Application Control: block YouTube - guests evening ab next day',
       'Application Control: block YouTube - Zürich office', ('Application Control: block YouTube - ' + 'x' * 300)[:200]])

# ------------------------------------------------------------------------------------------- the rules
IDS = ndpi.parse_protocol_ids(open(os.path.join(FIX, 'ndpiReader-H.txt'), encoding='utf-8').read())
HOSTS_TABLE = ndpi.parse_hosts(open(os.path.join(FIX, 'ndpiReader-protos-dump-1.txt'), encoding='utf-8').read(), IDS)
CATALOGUE = {'categories': {'5': 'Web'}, 'protocols': {'YouTube': 'Media', 'SSH': 'RemoteAccess', 'Mozilla': 'Web',
                                                       'Example_Env': 'Environmental_Services', 'TLS': 'Web'},
             'hosts': HOSTS_TABLE}
U = ['cccccccc-0000-4000-8000-00000000000%d' % n for n in range(10)]
RULES = [rule(number=1, uuid=U[1], app='YouTube', source=['opt2'], description='guests'),
         rule(number=2, uuid=U[2], app='SSH', action='alert'),
         rule(number=3, uuid=U[3], app='Mozilla', enabled=False),
         rule(number=4, uuid=U[4], app='Example_Env'),
         rule(number=5, uuid=U[5], app='YouTube', source=['Gone']),
         rule(number=6, uuid=U[6], app='TLS', source=['Teachers'], **{'not': True})]
built, report = sr.build({'rules': RULES}, CATALOGUE, DEVICES, BY_DEV, PF, OWN)
check('each rule: YouTube from the guests - its 9 names, 4 places each; SSH - its protocol; one switched off; one whose '
      'application Suricata cannot tell; one whose source is not read; TLS from all but Teachers - its protocol',
      {k[-1]: (v['lines'], v['names'], v['protocol'], v['reason']) for k, v in report.items()},
      {'1': (36, 9, None, None), '2': (1, 0, 'ssh', None), '3': (0, 0, None, 'disabled'), '4': (0, 0, None, 'no_match'),
       '5': (0, 9, None, 'unread'), '6': (1, 0, 'tls', None)})
kept_most = sr.MOST_LINES
sr.MOST_LINES = 35
try:
    _many, many_said = sr.build({'rules': [rule(number=1001, uuid=U[7], app='YouTube'), rule(number=1002, uuid=U[8], app='SSH')]},
                                CATALOGUE, DEVICES, BY_DEV, PF, OWN)
finally:
    sr.MOST_LINES = kept_most
check('a rule giving more lines than MOST_LINES: none, said; any number of rules - the 1,001st and the 1,002nd give theirs',
      [(many_said[u]['lines'], many_said[u]['reason']) for u in (U[7], U[8])], [(0, 'too_many'), (1, None)])
check('a source not read: which element', report[U[5]].get('element'), 'Gone')
_built, said_more = sr.build({'rules': [rule(number=1, uuid=U[1], app='Example_Env', source=['Gone']),
                                        rule(number=2, uuid=U[2], app='YouTube', source=['opt3']),
                                        rule(number=3, uuid=U[3], app='YouTube', source=['opt2', 'Gone'])]},
                             CATALOGUE, DEVICES, BY_DEV, PF, OWN)
check('for the page, for every rule switched on - one Suricata cannot tell too: the elements of its source not read, and '
      'whether it holds no device\'s address now; part of a source not read - the rest written, as pf and the cut act on it',
      ([(report[k].get('unread'), report[k].get('empty')) for k in (U[1], U[5])],
       [(said_more[k]['reason'], said_more[k]['unread'], said_more[k]['empty'], said_more[k]['lines']) for k in (U[1], U[2], U[3])],
       [r['source'] for r in _built]),
      ([([], False), (['Gone'], False)], [('no_match', ['Gone'], False, 0), ('empty', [], True, 0), (None, ['Gone'], False, 36)],
       ['[198.51.100.128/25,!198.51.100.129]']))
check('inverted, one element of the source not read: no line - every device but those is not known',
      sr.source(rule(source=['Gone'], **{'not': True}), DEVICES, BY_DEV, PF, OWN), (None, 'unread', 'Gone'))
youtube = built[0]
check('Block: drop, from the guests\' network but the firewall\'s address there; Alert: alert, from every address but '
      'the firewall\'s; the source said in each rule\'s comment',
      [(r['verb'], r['source'], r['source_text']) for r in built],
      [('drop', '[198.51.100.128/25,!198.51.100.129]', 'opt2'), ('alert', '![192.0.2.1,198.51.100.129,2001:db8:1::1,fe80::11]',
                                                                  'any'),
       ('drop', '![192.0.2.1,192.0.2.40/31,198.51.100.129,2001:db8:1::1,fe80::11]', 'not Teachers')])


def hashed_sid(rule_key, match):
    """A line's sid as the test writes it again: SID_BASE plus sha256 of the rule's uuid and its match, within SID_RANGE."""
    return sr.SID_BASE + int(hashlib.sha256(('%s\0%s' % (rule_key, match)).encode('utf-8')).hexdigest()[:15], 16) % sr.SID_RANGE


all_sids = [line['sid'] for r in built for line in r['lines']]
check('the sids: each line\'s from a hash of its rule\'s uuid and what it matches, each its own, between SID_BASE and '
      'SID_BASE + SID_RANGE - under OPNsense\'s own user rules, which count down from 4294967294',
      ([line['sid'] for line in youtube['lines']][:2] == [hashed_sid(U[1], line['match']) for line in youtube['lines']][:2],
       len(set(all_sids)) == len(all_sids), all(sr.SID_BASE <= s < sr.SID_BASE + sr.SID_RANGE for s in all_sids),
       sr.SID_BASE + sr.SID_RANGE < 4294967294 - 1000000), (True, True, True, True))
check('a protocol: the app-layer-protocol of Suricata\'s parser, on any IP protocol', built[1]['lines'],
      [{'proto': 'ip', 'match': 'app-layer-protocol:ssh;', 'sid': hashed_sid(U[2], 'app-layer-protocol:ssh;')}])
moved, _said = sr.build({'rules': [dict(r, number=r['number'] - 1) for r in RULES[1:]]},
                        dict(CATALOGUE, hosts=dict(HOSTS_TABLE, TLS=['tlsnew.example'])), DEVICES, BY_DEV, PF, OWN)
check('a line keeps its sid as the rules change around it - the rule before it deleted, every rule a place back, the '
      'installed nDPI giving another application a name: an Intrusion Detection change by sid stays with its line',
      ([line['sid'] for line in moved[0]['lines']] == [line['sid'] for line in built[1]['lines']],
       moved[1]['lines'][0]['sid'] == built[2]['lines'][0]['sid']), (True, True))
kept_range = sr.SID_RANGE
sr.SID_RANGE = 7
try:
    crowded, _said = sr.build({'rules': RULES[:2]}, dict(CATALOGUE, hosts={'YouTube': ['a.example']}), DEVICES, BY_DEV, PF, OWN)
finally:
    sr.SID_RANGE = kept_range
crowded_sids = [line['sid'] for r in crowded for line in r['lines']]
check('two lines meeting on one sid: the later takes the next one free - each its own still', (len(crowded_sids),
                                                                                              len(set(crowded_sids))), (5, 5))
check('the four places of each name: tls, quic, http and dns', [l['proto'] for l in youtube['lines'][:4]],
      ['tls', 'quic', 'http', 'dns'])
check('the http.host line a rule gets: no nocase, no /i - a rule with nocase on http.host Suricata refuses; the others '
      'with them', ([l['match'] for l in youtube['lines'] if l['proto'] == 'http'][0],
                    all(' nocase;' in l['match'] and '/i";' in l['match'] for l in youtube['lines'] if l['proto'] != 'http'),
                    any(' nocase;' in l['match'] for l in youtube['lines'] if l['proto'] == 'http')),
      (r'http.host; content:"googlevideo.com"; endswith; pcre:"/(?:^|\.)googlevideo\.com$/";', True, False))

text = sr.render(built, TEMPLATE)
lines = [line for line in text.splitlines() if line and not line.startswith('#')]
comments = [line for line in text.splitlines() if line.startswith('# rule ')]
check('rendered: a comment line for each rule, then its lines - 38 - and nothing between them',
      (comments, len(lines), '' in text.rstrip('\n').splitlines()),
      (['# rule 1: block YouTube from opt2', '# rule 2: alert SSH from any', '# rule 6: block TLS from not Teachers'], 38, False))
BROKEN_APP = 'SSH\ndrop ip any any -> any any (sid:1;)'
BROKEN_SOURCE = 'opt2\nalert ip any any -> any any (sid:2;)'
broken, _said = sr.build({'rules': [rule(number=1, uuid=U[1], app=BROKEN_APP, source=[BROKEN_SOURCE])]},
                         dict(CATALOGUE, hosts={BROKEN_APP: ['ssh.example']}), dict(DEVICES, **{BROKEN_SOURCE: 'em2'}),
                         BY_DEV, PF, OWN)
broken_text = sr.render(broken, TEMPLATE)
check('a rule\'s comment line with an application or a source written in config.xml by hand across lines: on one line, no '
      'rule of its own begun', (len(broken), [line for line in broken_text.splitlines()
                                              if ('sid:1;' in line or 'sid:2;' in line) and not line.startswith('#')],
                                broken_text.count('# rule 1: block SSH drop ip')),
      (1, [], 1))
check('a line as Suricata reads one', lines[0],
      r'drop tls [198.51.100.128/25,!198.51.100.129] any -> ' + DEST + r' any (msg:"Application Control: block YouTube - '
      r'guests"; flow:to_server; tls.sni; content:"googlevideo.com"; nocase; endswith; pcre:"/(?:^|\.)googlevideo\.com$/i"; '
      r'threshold:type limit,track by_src,count 1,seconds 60; sid:%d; rev:1;)' % youtube['lines'][0]['sid'])
RULE_LINE = re.compile(r'^(drop|alert) (tls|quic|http|dns|ip) (any|!?\[[0-9a-f.:/,!]+\]) any -> (!\[[0-9a-f.:/,]+\]) any '
                       r'\((.*)\)$')
check('every line: its destination the internet alone - none of the firewall\'s addresses, its networks, a private, '
      'multicast or link-local one - and its source no address of the firewall\'s',
      [line for line in lines for a in sorted(str(o) for o in OWN) + ['192.0.2.10', '198.51.100.130', '2001:db8:1::10',
                                                                      '192.168.1.7', '10.0.0.5', '224.0.0.251', 'fe80::1']
       if group(RULE_LINE.match(line).group(4))(a) or (a in {str(o) for o in OWN} and group(RULE_LINE.match(line).group(3))(a))],
      [])
well = []
for line in lines:
    found = RULE_LINE.match(line)
    options = found.group(5) if found else ''
    parts = [p.strip() for p in options.split('; ') if p.strip()]
    well.append(bool(found) and options.endswith('rev:1;') and options.count('"') % 2 == 0 and
                parts[0].startswith('msg:"') and 'flow:to_server' in parts and any(p.startswith('sid:') for p in parts))
sids = [int(re.search(r'sid:(\d+);', line).group(1)) for line in lines]
check('every line well formed - action, protocol, source, destination, its options closed, msg first, flow, sid, rev - its '
      'sid its own, '
      'under Suricata\'s 8,192 characters', (all(well), len(set(sids)) == len(sids), max(len(line) for line in lines) < 8192),
      (True, True, True))

# ---------------------------------------------------------------------------------------------- written
CONFIG = ('<opnsense><interfaces><lan><if>em1</if></lan><opt2><if>em2</if></opt2><opt3><if>em3</if></opt3></interfaces>'
          '<OPNsense><AppControl><general><classify>%s</classify></general><rules>%s</rules></AppControl></OPNsense></opnsense>')


def rule_xml(uuid, app, source, action='block', enabled='1', inverted='0', description=''):
    return ('<rule uuid="%s"><enabled>%s</enabled><action>%s</action><source>%s</source><source_not>%s</source_not>'
            '<app>%s</app><description>%s</description></rule>' % (uuid, enabled, action, source, inverted, app, description))


with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, 'config.xml')
    catalogue = os.path.join(tmp, 'ndpi.json')
    rules_file = os.path.join(tmp, 'suricata', 'rules', 'appcontrol.rules')
    sr.LOCK = os.path.join(tmp, 'suricata.lock')
    state = os.path.join(tmp, 'suricata.json')
    ifconfig = os.path.join(tmp, 'ifconfig')
    with open(os.path.join(tmp, 'ifconfig.txt'), 'w') as handle:
        handle.write(IFCONFIG_TEXT)
    program(ifconfig, '#!/bin/sh\n[ "$1" = -a ] && cat %s\n' % os.path.join(tmp, 'ifconfig.txt'))
    with open(catalogue, 'w') as handle:
        json.dump(CATALOGUE, handle)

    def write(classify='1', rules_xml=None, template=TEMPLATE, path=None):
        if rules_xml is not None:
            with open(config, 'w') as handle:
                handle.write(CONFIG % (classify, rules_xml))
        return sr.write(config, catalogue, path or rules_file, template, state, ifconfig, PF)

    two = rule_xml(U[1], 'YouTube', 'opt2', description='guests') + rule_xml(U[2], 'SSH', 'any', action='alert')
    summary = write(rules_xml=two)
    check('written: the file, in a directory made for it, as the template renders the rules; changed; its lines; what each '
          'rule gave, kept for the page', (summary['status'], summary['changed'], summary['lines'], os.path.isfile(rules_file),
                                           json.load(open(state))['lines'], sorted(json.load(open(state))['rules'])),
          ('ok', True, 37, True, 37, [U[1], U[2]]))
    check('written: what the template renders - its first line of the rules', [line for line in open(rules_file).read().splitlines()
                                                                               if line.startswith('alert')][0],
          'alert ip ![192.0.2.1,198.51.100.129,2001:db8:1::1,fe80::11] any -> ' + DEST + ' any (msg:"Application Control: '
          'alert SSH"; flow:to_server; app-layer-protocol:ssh; threshold:type limit,track by_src,count 1,seconds 60; '
          'sid:%d; rev:1;)' % hashed_sid(U[2], 'app-layer-protocol:ssh;'))
    before = os.stat(rules_file).st_mtime_ns
    summary = write()
    check('nothing changed: not written again, not changed - no reload asked for', (summary['changed'],
                                                                                    os.stat(rules_file).st_mtime_ns == before),
          (False, True))
    summary = write(rules_xml=rule_xml(U[1], 'YouTube', 'opt2', description='guests, evenings') +
                    rule_xml(U[2], 'SSH', 'any', action='alert'))
    check('a rule\'s description changed: written again, changed', (summary['changed'], 'guests, evenings' in open(rules_file).read()),
          (True, True))
    with open(config, 'w') as handle:
        handle.write('<opnsense')
    summary = write()
    check('config.xml not to be read: failed, said, the file left as it was', (summary['status'], summary['changed'],
                                                                             os.path.isfile(rules_file), summary['errors']),
          ('failed', False, True, ['%s could not be read: the Suricata rules left as they were' % config]))
    summary = write(rules_xml=two, template=os.path.join(tmp, 'no-template.rules'))
    check('the template not to be read: failed, said, the file left as it was',
          (summary['status'], summary['changed'], os.path.isfile(rules_file), summary['errors'][0].startswith(
              'the template could not be rendered, the Suricata rules left as they were')), ('failed', False, True, True))
    program(os.path.join(tmp, 'no-ifconfig'), '#!/bin/sh\nexit 1\n')
    with open(config, 'w') as handle:
        handle.write(CONFIG % ('1', two.replace('guests', 'guests, later')))
    summary = sr.write(config, catalogue, rules_file, TEMPLATE, state, os.path.join(tmp, 'no-ifconfig'), PF)
    check('the firewall\'s own addresses not to be read: failed, said, the file left as it was - no line could leave the '
          'firewall out', (summary['status'], summary['changed'], 'guests, later' in open(rules_file).read(), summary['errors']),
          ('failed', False, False, ['the firewall\'s own addresses could not be read (%s -a): the Suricata rules left as they '
                                    'were' % os.path.join(tmp, 'no-ifconfig')]))
    summary = write(classify='0', rules_xml=two)
    check('classifying off: the file removed - changed - each rule switched off', (summary['changed'], os.path.exists(rules_file),
                                                                                  summary['lines'], summary['rules'][U[1]]['reason']),
          (True, False, 0, 'disabled'))
    summary = write()
    check('removed already: nothing changed', summary['changed'], False)
    summary = write(rules_xml=rule_xml(U[1], 'YouTube', 'opt2', enabled='0') + rule_xml(U[4], 'Example_Env', 'any'))
    check('no rule giving a line - one switched off, one Suricata cannot tell: no file', (summary['changed'], os.path.exists(
        rules_file), {k[-1]: v['reason'] for k, v in summary['rules'].items()}), (False, False, {'1': 'disabled', '4': 'no_match'}))
    summary = write(rules_xml=rule_xml(U[1], 'YouTube', 'Big') + rule_xml(U[2], 'SSH', 'any', action='alert'))
    check('a source too long for a Suricata rule: that rule none, said; the others written',
          (summary['rules'][U[1]]['reason'], summary['rules'][U[2]]['lines'], summary['lines']), ('too_long', 1, 1))
    kept = sr.LONGEST
    # past every line of YouTube's, under SSH's
    sr.LONGEST = len([line for line in open(rules_file).read().splitlines() if 'app-layer-protocol:ssh' in line][0])
    try:
        summary = write(rules_xml=two)
    finally:
        sr.LONGEST = kept
    check('a line past the limit once rendered: its rule taken out, said, the rest written', (
        summary['rules'][U[1]]['reason'], summary['rules'][U[1]]['lines'], summary['rules'][U[2]]['lines'], summary['lines'],
        'googlevideo' in open(rules_file).read()), ('too_long', 0, 1, 1, False))

    # kept current: the rules last applied resolved again, as pf and the cut follow their sources
    def refresh():
        return sr.refresh(config, catalogue, rules_file, TEMPLATE, state, ifconfig, PF)

    PF.run.held['Kids'] = ['192.0.2.50']
    kids = rule_xml(U[1], 'YouTube', 'Kids') + rule_xml(U[3], 'SSH', 'lan', action='alert')
    summary = write(rules_xml=kids)
    applied = json.load(open(state))['applied']
    check('written: what was applied kept - classifying, the rules, a digest of what each puts in force', (
        applied['classify'], [(r['uuid'], r['source']) for r in applied['rules']], sorted(applied['digests'])),
        (True, [(U[1], ['Kids']), (U[3], ['lan'])], [U[1], U[3]]))
    summary = refresh()
    check('refreshed, nothing changed since: the file left, not changed', (summary['status'], summary['changed']), ('ok', False))
    PF.run.held['Kids'] = ['192.0.2.51']
    summary = refresh()
    text = open(rules_file).read()
    check('an alias whose table changed - a hostname resolved again, a MAC seen at another address: the next refresh '
          'writes its new address, changed', (summary['changed'], '[192.0.2.51]' in text, '192.0.2.50' in text), (True, True, False))
    with open(os.path.join(tmp, 'ifconfig.txt'), 'w') as handle:
        handle.write(IFCONFIG_TEXT.replace('2001:db8:1::', '2001:db8:5::'))
    summary = refresh()
    text = open(rules_file).read()
    check('the LAN\'s IPv6 prefix changed (a new delegated prefix): the next refresh writes the new one, the old gone',
          (summary['changed'], '2001:db8:5::/64' in text, '2001:db8:1::' in text), (True, True, False))
    with open(os.path.join(tmp, 'ifconfig.txt'), 'w') as handle:
        handle.write(IFCONFIG_TEXT)
    with open(catalogue, 'w') as handle:
        json.dump(dict(CATALOGUE, hosts=dict(HOSTS_TABLE, YouTube=HOSTS_TABLE['YouTube'] + ['ytnew.example'])), handle)
    summary = refresh()
    check('the installed nDPI read again with a name more for the application: the next refresh writes its four lines',
          (summary['changed'], open(rules_file).read().count('"ytnew.example"'), summary['rules'][U[1]]['names']),
          (True, 4, 10))
    with open(catalogue, 'w') as handle:
        json.dump(CATALOGUE, handle)
    refresh()
    with open(config, 'w') as handle:
        handle.write(CONFIG % ('1', rule_xml(U[1], 'YouTube', 'opt2') + rule_xml(U[3], 'SSH', 'lan', action='alert',
                                                                                 enabled='0')))
    summary = refresh()
    text = open(rules_file).read()
    check('a rule changed in config.xml and not applied - its source, another switched off: a refresh leaves them as '
          'applied, the digests kept', (summary['changed'], '# rule 1: block YouTube from Kids' in text,
                                        'app-layer-protocol:ssh' in text, json.load(open(state))['applied'] == applied),
          (False, True, True, True))
    os.remove(state)
    summary = refresh()
    check('nothing applied kept - /var lost at a boot: a refresh writes as config.xml says', (
        summary['changed'], '# rule 1: block YouTube from opt2' in open(rules_file).read(), 'app-layer-protocol:ssh' in
        open(rules_file).read(), sorted(json.load(open(state))['applied']['digests'])), (True, True, False, [U[1], U[3]]))
    with open(state, 'w') as handle:
        json.dump({'applied': {'classify': True, 'rules': [{'uuid': U[1], 'source': 'not a list'}]}}, handle)
    summary = refresh()
    check('what is kept not rules: as config.xml says', (summary['status'], sorted(summary['applied']['digests'])),
          ('ok', [U[1], U[3]]))
    check('every file written in one step - none left beside it, no fixed name shared by two writers',
          sorted(os.listdir(os.path.dirname(rules_file))), ['appcontrol.rules'])
    holder = sr.locked(sr.LOCK)
    kept_wait = sr.LOCK_WAIT
    sr.LOCK_WAIT = 0.5
    try:
        with open(config, 'w') as handle:
            handle.write(CONFIG % ('1', two))
        before = open(rules_file).read()
        summary = write()
        again = refresh()
    finally:
        sr.LOCK_WAIT = kept_wait
        holder.close()
    check('one writer at a time: another holding the lock past the wait - Apply\'s write, a refresh - nothing written, said',
          (summary['status'], again['status'], open(rules_file).read() == before, summary['errors']),
          ('failed', 'failed', True, ['another write of the Suricata rules held them past 0.5 s: left as they were']))

    # Suricata's own test of a file before it is installed (suricata -T -S), a stand-in refusing what holds a word
    engine_calls = os.path.join(tmp, 'engine-calls')
    refuse = os.path.join(tmp, 'refuse')
    program(os.path.join(tmp, 'suricata-bin'), '#!/usr/bin/env python3\nimport os, sys\na = sys.argv[1:]\n'
            'open(%r, "a").write(" ".join(a) + "\\n")\nrules = a[a.index("-S") + 1]\n'
            'word = open(%r).read().strip() if os.path.exists(%r) else ""\nbad = 0\n'
            'for n, line in enumerate(open(rules).read().splitlines(), 1):\n'
            '    if word == "everything":\n        continue\n'
            '    if word and word in line:\n'
            '        bad += 1\n        sys.stderr.write("E: detect-parse: the reason a stand-in gives\\n")\n'
            '        sys.stderr.write("E: detect: error parsing signature \\"%%s\\" from file %%s at line %%d\\n"'
            ' %% (line, rules, n))\n'
            'if word == "everything":\n    sys.stderr.write("E: conf: the configuration could not be read\\n")\n    sys.exit(1)\n'
            'if bad:\n    sys.exit(1)\nprint("Notice: suricata: Configuration provided was successfully loaded. Exiting.")\n'
            % (engine_calls, refuse, refuse))
    with open(os.path.join(tmp, 'suricata.yaml'), 'w') as handle:
        handle.write('%YAML 1.1\n---\n')
    sr.SURICATA, sr.SURICATA_YAML = os.path.join(tmp, 'suricata-bin'), os.path.join(tmp, 'suricata.yaml')
    with open(refuse, 'w') as handle:
        handle.write('app-layer-protocol:modbus')
    with_modbus = two + rule_xml(U[5], 'Modbus', 'any', action='alert')
    summary = write(rules_xml=with_modbus)
    text = open(rules_file).read()
    asked = open(engine_calls).read().splitlines()
    check('Suricata\'s own test of a new file: suricata -T with OPNsense\'s suricata.yaml, the file alone (-S), its log '
          'apart; the line it refuses taken out - a parser off in suricata.yaml, say - said for its rule, the rest written',
          (asked[0].split()[:3], asked[0].split()[3], asked[0].split()[4].endswith('/appcontrol.rules'), len(asked),
           summary['engine'], summary['rules'][U[5]]['reason'], summary['rules'][U[5]]['refused'],
           'app-layer-protocol:modbus' in text, 'app-layer-protocol:ssh' in text, summary['lines']),
          (['-T', '-c', sr.SURICATA_YAML], '-S', True, 2, {'state': 'refused', 'refused': 1, 'message': None}, 'refused', 1,
           False, True, 37))
    said_of = summary['rules'][U[5]]['refused_by']
    check('what Suricata said of the line it refused, kept for the page: why, on the line before, then which line - the '
          'signature itself and the test\'s folder left out', (said_of.startswith(
              'E: detect-parse: the reason a stand-in gives - E: detect: error parsing signature from file appcontrol.rules '
              'at line '), 'suricata-test.' in said_of, 'alert ip' in said_of), (True, False, False))
    check('the test\'s own folder gone once it has run', [n for n in os.listdir(tmp) if n.startswith('suricata-test.')], [])
    os.remove(engine_calls)
    summary = refresh()
    check('a refresh with a line refused before: tested again - a parser switched on since takes it - and nothing changed, '
          'said', (summary['changed'], summary['engine']['state'], len(open(engine_calls).read().splitlines())),
          (False, 'refused', 1))
    os.remove(refuse)
    os.remove(engine_calls)
    summary = refresh()
    check('the parser on since: the line taken, the file changed', (summary['changed'], summary['engine'],
                                                                    'app-layer-protocol:modbus' in open(rules_file).read()),
          (True, {'state': 'ok', 'refused': 0, 'message': None}, True))
    os.remove(engine_calls)
    summary = refresh()
    check('nothing new to test: Suricata not asked, its verdict kept', (summary['changed'], summary['engine']['state'],
                                                                        os.path.exists(engine_calls)), (False, 'ok', False))
    with open(refuse, 'w') as handle:
        handle.write('everything')
    summary = write(rules_xml=two)
    check('the test failing without naming a line: the file written as it is, Suricata\'s last words said',
          (summary['changed'], summary['engine']), (True, {'state': 'failed', 'refused': 0,
                                                           'message': 'E: conf: the configuration could not be read'}))
    os.remove(refuse)
    os.remove(sr.SURICATA_YAML)
    summary = write(rules_xml=with_modbus)
    check('no suricata.yaml - the Intrusion Detection never set up: not tested, said so', (summary['changed'],
                                                                                          summary['engine']['state']),
          (True, 'unchecked'))
    sr.SURICATA = os.path.join(tmp, 'no-suricata')

    # the command line, with its own places
    sr.RULES, sr.STATE, sr.TEMPLATE, sr.IFCONFIG = rules_file, state, TEMPLATE, ifconfig
    tables.CONFIG, tables.CATALOGUE = config, catalogue
    real_pf = tables.Pf
    tables.Pf = lambda *a, **k: PF
    out = os.path.join(tmp, 'out.txt')

    def main(*argv):
        real = sys.stdout
        with open(out, 'w') as handle:
            sys.stdout = handle
            try:
                status = sr.main(['suricata_rules.py'] + list(argv))
            finally:
                sys.stdout = real
        return status, json.load(open(out))

    try:
        write(rules_xml=two)
        status, answer = main('write')
        check('suricata_rules.py write: JSON, exit 0 - nothing changed', (status, answer['status'], answer['changed']),
              (0, 'ok', False))
        status, answer = main('remove')
        check('suricata_rules.py remove: the file removed, changed, said', (status, answer['changed'], os.path.exists(rules_file)),
              (0, True, False))
        status, answer = main('remove')
        check('removed again: nothing changed', answer['changed'], False)
        reloads = os.path.join(tmp, 'reloads')
        program(os.path.join(tmp, 'configctl'), '#!/bin/sh\necho "$*" >> %s\n' % reloads)
        sr.CONFIGCTL = os.path.join(tmp, 'configctl')
        status, answer = main('start')
        check('suricata_rules.py start - the classifier\'s start: written as config.xml says, then the Intrusion Detection\'s '
              'rules installed again and Suricata told, as it changed', (status, answer['changed'], answer['reload'],
                                                                         open(reloads).read()), (0, True, 'ok', 'ids reload\n'))
        status, answer = main('refresh')
        check('suricata_rules.py refresh, nothing changed: no reload', (status, answer['changed'], 'reload' in answer,
                                                                        open(reloads).read()), (0, False, False, 'ids reload\n'))
        PF.run.held['Teachers'] = ['192.0.2.42']
        with open(state) as handle:
            kept_state = json.load(handle)
        with open(state, 'w') as handle:
            json.dump(dict(kept_state, applied=sr.applied_from({'classify': True, 'rules': [
                dict(rule(number=1, uuid=U[6], app='TLS', source=['Teachers']))]})), handle)
        program(os.path.join(tmp, 'configctl'), '#!/bin/sh\necho "$*" >> %s\nexit 1\n' % reloads)
        status, answer = main('refresh')
        check('suricata_rules.py refresh, the file changed and the reload failing: said, exit 0',
              (status, answer['changed'], answer['reload'], answer['errors']),
              (0, True, 'configctl ids reload ended with status 1', ['configctl ids reload ended with status 1']))
        status, answer = main('nothing')
        check('a verb it does not know: said, exit 0', (status, answer['errors']),
              (0, ['usage: suricata_rules.py write|start|refresh|remove']))
        real_write = sr.write

        def broken(*args, **kwargs):
            raise ValueError('a fault of its own')

        sr.write = broken
        try:
            status, answer = main('write')
        finally:
            sr.write = real_write
        check('a fault of its own: said, never raised, exit 0', (status, answer['status'], answer['errors'][0].startswith(
            'the Suricata rules: ValueError')), (0, 'failed', True))
    finally:
        tables.Pf = real_pf

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
