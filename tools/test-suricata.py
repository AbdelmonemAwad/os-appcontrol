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
out, inverted - and why one cannot be written: not read, holding no address, too long; the message, what Suricata
takes in one; each rule's lines - its protocol when Suricata reads it, its names, drop for Block and alert for
Alert, the sids its number gives - or why none: switched off, nothing Suricata can tell, past 999 rules; the
template rendered - one comment line for each rule, then its lines, each well formed, under Suricata's limit, its
sid its own; the file written in one step, not again when nothing changed, removed when classifying is off or no
rule gives a line; config.xml or the template not to be read leaving the file as it was; a line past the limit
taking its rule out, said; the command line's answers, never a fault raised.
"""
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
                           ['2001:db8:%x::1' % i for i in range(600)]}))


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
         rule(number=6, uuid=U[6], app='TLS', source=['Teachers'], **{'not': True}),
         rule(number=1000, uuid=U[7], app='YouTube')]
built, report = sr.build({'rules': RULES}, CATALOGUE, DEVICES, BY_DEV, PF)
check('each rule: YouTube from the guests - its 9 names, 4 places each; SSH - its protocol; one switched off; one whose '
      'application Suricata cannot tell; one whose source is not read; TLS from all but Teachers - its protocol; one past '
      'the 999th', {k[-1]: (v['lines'], v['names'], v['protocol'], v['reason']) for k, v in report.items()},
      {'1': (36, 9, None, None), '2': (1, 0, 'ssh', None), '3': (0, 0, None, 'disabled'), '4': (0, 0, None, 'no_match'),
       '5': (0, 9, None, 'unread'), '6': (1, 0, 'tls', None), '7': (0, 0, None, 'too_many')})
check('a source not read: which element', report[U[5]].get('element'), 'Gone')
youtube = built[0]
check('Block: drop, from the guests\' network; Alert: alert; the source said in each rule\'s comment',
      [(r['verb'], r['source'], r['source_text']) for r in built],
      [('drop', '[198.51.100.128/25]', 'opt2'), ('alert', 'any', 'any'), ('drop', '![192.0.2.40/31]', 'not Teachers')])
check('the sids: SID_BASE, the rule\'s number times SID_SPAN, then one a line - under OPNsense\'s own user rules, which '
      'count down from 4294967294', ([l['sid'] for l in youtube['lines']][:3], report[U[1]]['sids'],
                                     report[U[6]]['sids'], sr.SID_BASE + sr.MOST_RULES * sr.SID_SPAN + sr.SID_SPAN < 4294967294 - 10000),
      ([3990010001, 3990010002, 3990010003], [3990010001, 3990010036], [3990060001, 3990060001], True))
check('a protocol: the app-layer-protocol of Suricata\'s parser, on any IP protocol', built[1]['lines'],
      [{'proto': 'ip', 'match': 'app-layer-protocol:ssh;', 'sid': 3990020001}])
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
check('a line as Suricata reads one', lines[0],
      r'drop tls [198.51.100.128/25] any -> any any (msg:"Application Control: block YouTube - guests"; flow:to_server; '
      r'tls.sni; content:"googlevideo.com"; nocase; endswith; pcre:"/(?:^|\.)googlevideo\.com$/i"; '
      r'threshold:type limit,track by_src,count 1,seconds 60; sid:3990010001; rev:1;)')
RULE_LINE = re.compile(r'^(drop|alert) (tls|quic|http|dns|ip) (any|!?\[[0-9a-f.:/,]+\]) any -> any any \((.*)\)$')
well = []
for line in lines:
    found = RULE_LINE.match(line)
    options = found.group(4) if found else ''
    parts = [p.strip() for p in options.split('; ') if p.strip()]
    well.append(bool(found) and options.endswith('rev:1;') and options.count('"') % 2 == 0 and
                parts[0].startswith('msg:"') and 'flow:to_server' in parts and any(p.startswith('sid:') for p in parts))
sids = [int(re.search(r'sid:(\d+);', line).group(1)) for line in lines]
check('every line well formed - action, protocol, source, its options closed, msg first, flow, sid, rev - its sid its own, '
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
          'alert ip any any -> any any (msg:"Application Control: alert SSH"; flow:to_server; app-layer-protocol:ssh; '
          'threshold:type limit,track by_src,count 1,seconds 60; sid:3990020001; rev:1;)')
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
    sr.LONGEST = 200            # past every line of YouTube's, under SSH's
    try:
        summary = write(rules_xml=two)
    finally:
        sr.LONGEST = kept
    check('a line past the limit once rendered: its rule taken out, said, the rest written', (
        summary['rules'][U[1]]['reason'], summary['rules'][U[1]]['lines'], summary['rules'][U[2]]['lines'], summary['lines'],
        'googlevideo' in open(rules_file).read()), ('too_long', 0, 1, 1, False))

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
        status, answer = main('nothing')
        check('a verb it does not know: said, exit 0', (status, answer['errors']), (0, ['usage: suricata_rules.py write|remove']))
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
