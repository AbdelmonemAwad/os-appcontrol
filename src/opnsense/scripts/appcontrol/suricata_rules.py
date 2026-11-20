#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Application Control's Suricata rules (the plan's top-01): each rule of the Rules tab as local rules of
OPNsense's own Intrusion Detection, in /usr/local/etc/suricata/rules/appcontrol.rules - the directory whose
*.rules files OPNsense's installRules.py installs, as it installs its own user rules (phase 0's Q4; its L8 on
the second XGS 3300: a file there and configctl ids reload - installed, alerting, gone once removed).

    suricata_rules.py write     the file written as the settings say - the page's Apply, the installation
    suricata_rules.py start     the same, then configctl ids reload when it changed - the classifier's start, at
                                boot among them, as it reads its own settings then
    suricata_rules.py refresh   the rules last written (start or write) resolved again - their sources' addresses,
                                the installed nDPI's names - then configctl ids reload when the file changed: the
                                classifier, every few minutes, so the lines follow an alias, a prefix, an interface
                                as pf and the cut do; a rule saved since and not applied does not come in by it
    suricata_rules.py remove    the file removed

Each prints JSON - changed: whether the file changed, so the caller of write runs configctl ids reload
(installRules.py, then Suricata's own reload) - and exits 0. One at a time (LOCK): a write waits for a refresh.

The lines are the plugin's template, templates/OPNsense/AppControl/appcontrol.rules, rendered here with
Jinja2, not by configd: what they match is no setting's. Each rule of the Rules tab switched on, while
classifying is on, gives:

- one line for each name the installed nDPI knows its application by - its host table, which apps.py reads
  into the catalogue (ndpiReader --protos-dump 1) - in each of the four places a device writes such a name:
  the server name of TLS (tls.sni) and of QUIC (quic.sni), HTTP's Host (http.host), the name a DNS question
  asks for (dns.query). A name matches as nDPI's own ac_domain_match_handler() has it (nDPI de5c784,
  ndpi_main.c): the name itself, or one ending in it after a dot - youtu.be takes www.youtu.be, not
  myyoutu.be; one written with a last dot takes a single label after it - youtube. takes youtube.com, not
  youtube.co.uk; one with a last hyphen begins a label - fbcdn- takes fbcdn-video.example; one with a first
  hyphen ends a name after a hyphen. The content is Suricata's fast pattern, pcre the boundary nDPI asks for;
- one line for its protocol, when the application is a protocol Suricata reads by itself (PROTOCOLS,
  app-layer-protocol) with its parser on in OPNsense's suricata.yaml;
- drop for Block, which Suricata does in IPS mode and alerts in IDS mode, and alert for Alert;
- its source as Suricata writes addresses: the networks the source holds now - an interface's from ifconfig -a,
  an alias's as pf holds its table, an address or a network as written (tables.resolve()) - inverted with ! as
  the rule says, and never the firewall itself: its own addresses are taken out of every source - any is every
  address but the firewall's, an inverted source leaves them out with its own, and one inside a source's network
  is an exception in its group ([network, !address], Suricata's own way of writing it). Suricata sees a device's
  own address before NAT only: on an internal interface it reads;
- its destination the internet alone, as the cut has it (classify.py's internet() and Network): every address but
  the firewall's own, those of the networks it is connected to - ifconfig -a's, every interface's - and those that
  are not the internet's (tables.NOT_INTERNET). In IPS mode, where Suricata sits before the host and before pf, a
  line so never drops a device's connection to the firewall - its web GUI, ssh, its resolver, DHCP - nor to a host
  of its own networks, a private one, a site over a VPN; nor, on the WAN, the firewall's own connections.

A rule gives no line when Suricata cannot tell its application - nDPI knows no name for it and it is no protocol
Suricata reads - when its source cannot be read or holds no address now, when a line would pass Suricata's own
limit of 8,192 characters a rule (DETECT_MAX_RULE_SIZE), or past MOST_RULES; the summary says which, for the
page. sid: SID_BASE + the rule's place among the rules * SID_SPAN + the line's, far below OPNsense's own user
rules, which count down from 4294967294. One alert a device a minute for each line (threshold), however many
connections: a drop still drops each packet.

The file is written only when what it says changes, in one step (a file of its own beside it, renamed into place),
and removed when no rule gives a line. What was written is kept in /var/db/os-appcontrol/suricata.json for the
page, with the rules it was written from - those the last write or start applied, which refresh resolves again,
and by which the page tells a rule changed since. Never fails its caller.
"""

import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

RULES = '/usr/local/etc/suricata/rules/appcontrol.rules'
TEMPLATE = '/usr/local/opnsense/service/templates/OPNsense/AppControl/appcontrol.rules'
STATE = '/var/db/os-appcontrol/suricata.json'
LOCK = '/var/db/os-appcontrol/suricata.lock'
LOCK_WAIT = 300         # seconds a write waits for another - a refresh's ids reload among it
IFCONFIG = '/sbin/ifconfig'
CONFIGCTL = '/usr/local/sbin/configctl'
RELOAD_TIMEOUT = 300    # seconds configctl ids reload is given: installRules.py installs every rule again
SURICATA = '/usr/local/bin/suricata'
SURICATA_YAML = '/usr/local/etc/suricata/suricata.yaml'
TEST_TIMEOUT = 180      # seconds Suricata's own test of a file is given (suricata -T)
TEST_ROUNDS = 2         # tests of one file at most: the lines refused taken out, the rest tested again
SID_BASE = 3990000000
SID_SPAN = 10000
MOST_RULES = 999
LONGEST = 8000          # characters a line at most: Suricata takes 8,192 a rule
SOURCE_LONGEST = 7400   # characters of a source and a destination at most, the rest of a line's options left room
THRESHOLD = 'threshold:type limit,track by_src,count 1,seconds 60;'
# where a device writes a name: Suricata's protocol, its keyword for the name, and whether nocase is taken
# there - http.host is lower case already, and Suricata refuses a rule with nocase on it
PLACES = (('tls', 'tls.sni', True), ('quic', 'quic.sni', True), ('http', 'http.host', False),
          ('dns', 'dns.query', True))
# nDPI's name of a protocol -> Suricata's name of its parser, for those OPNsense's suricata.yaml (26.7) turns on
PROTOCOLS = {'TLS': 'tls', 'HTTP': 'http', 'DNS': 'dns', 'QUIC': 'quic', 'SSH': 'ssh', 'SMTP': 'smtp', 'IMAP': 'imap',
             'FTP_CONTROL': 'ftp', 'Telnet': 'telnet', 'DHCP': 'dhcp', 'SNMP': 'snmp', 'NTP': 'ntp', 'TFTP': 'tftp',
             'NFS': 'nfs', 'Kerberos': 'krb5', 'SMBv1': 'smb', 'SMBv23': 'smb', 'VNC': 'rfb', 'RDP': 'rdp', 'SIP': 'sip',
             'MQTT': 'mqtt', 'Modbus': 'modbus'}
# why a rule gives no line, as the page says it
REASONS = ('disabled', 'no_match', 'unread', 'empty', 'too_long', 'too_many', 'refused')


def engine_check(text, suricata=None, yaml=None, where=None):
    """Suricata's own verdict on a file before it is installed, as suricata-update tests one: suricata -T -S <file>,
    with OPNsense's own suricata.yaml - its parsers on or off as there - and the file's lines alone. (state,
    {sid: what Suricata said}, message): 'ok'; 'refused' - those lines refused, as Suricata names them by their line
    in the file; 'failed' - the test failed naming no line, message its last words; 'unchecked' - no Suricata or no
    suricata.yaml here (the Intrusion Detection never set up), or the test could not run, message why. The file and
    Suricata's log of the test go to a folder of their own in `where` (the state's), removed after."""
    suricata, yaml, where = suricata or SURICATA, yaml or SURICATA_YAML, where or os.path.dirname(STATE)
    if not os.access(suricata, os.X_OK) or not os.path.isfile(yaml):
        return 'unchecked', {}, 'Suricata or its suricata.yaml is not there'
    try:
        os.makedirs(where, exist_ok=True)
        folder = tempfile.mkdtemp(prefix='suricata-test.', dir=where)
    except OSError as error:
        return 'unchecked', {}, 'no folder for the test: %s' % error
    try:
        path = os.path.join(folder, 'appcontrol.rules')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
        try:
            done = subprocess.run([suricata, '-T', '-c', yaml, '-S', path, '-l', folder], capture_output=True, text=True,
                                  errors='replace', timeout=TEST_TIMEOUT, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as error:
            return 'unchecked', {}, 'suricata -T could not be run: %s' % error
        said = '\n'.join([done.stdout or '', done.stderr or '', current(os.path.join(folder, 'suricata.log')) or ''])
        lines = text.splitlines()
        refused = {}
        output = said.splitlines()
        at_line = re.compile(r'\bfrom file %s at line (\d+)' % re.escape(path))
        for i, line in enumerate(output):
            found = at_line.search(line)
            number = int(found.group(1)) if found else 0
            sid = re.search(r'\bsid:(\d+);', lines[number - 1]) if 1 <= number <= len(lines) else None
            if not sid:
                continue
            # Suricata says why on the line before - an unknown keyword, a protocol whose parser is off - then which
            # signature, the whole of it: that one is written short, without the signature and the test's folder
            why = output[i - 1].strip() if i and 'error parsing signature' not in output[i - 1] else ''
            which = re.sub(r'signature ".*" from file', 'signature from file', line).replace(path, 'appcontrol.rules')
            refused[int(sid.group(1))] = MSG_SPACE.sub(' ', (why + ' - ' if why else '') + which.strip())[:300]
        if refused:
            return 'refused', refused, None
        if done.returncode == 0:
            return 'ok', {}, None
        last = [line.strip() for line in said.splitlines() if line.strip()][-2:]
        return 'failed', {}, ' / '.join(last)[:400] or 'suricata -T ended with status %d' % done.returncode
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def name_match(name, keyword, nocase):
    """The options matching one name nDPI knows an application by, in one place a device writes it, or None for
    a name of other characters than nDPI's table writes."""
    name = name.lower()
    if not ndpi.HOST_NAME.match(name) or name.strip('.-') == '':
        return None
    lead, last = name.startswith('-'), name[-1]
    boundary = '' if lead else r'(?:^|\.)'
    end = r'[^.]*$' if last == '.' else '' if last == '-' else '$'
    out = '%s; content:"%s";%s' % (keyword, name, ' nocase;' if nocase else '')
    if end == '$':
        out += ' endswith;'
    if boundary or last == '.':
        out += ' pcre:"/%s%s%s/%s";' % (boundary, name.replace('.', r'\.'), end, 'i' if nocase else '')
    return out


def address(network):
    """A network as Suricata writes an address: a host without its length."""
    return str(network.network_address) if network.prefixlen == network.max_prefixlen else network.with_prefixlen


def own_networks(own):
    """The firewall's own addresses as networks of one address, IPv4 first."""
    return tables.flatten([(ipaddress.ip_network(a), False) for a in own])


def destination(own, connected):
    """Suricata's addresses for every line's destination: the internet alone - every address but the firewall's own,
    those of the networks it is connected to and those that are not the internet's (tables.NOT_INTERNET)."""
    nets = [(n, False) for n in list(tables.NOT_INTERNET) + list(connected)] + [(n, False) for n in own_networks(own)]
    return '![%s]' % ','.join(address(n) for n in tables.flatten(nets))


def negated(excepted):
    """Suricata's addresses for every address but `excepted` (networks, collapsed): ![...]; or, when they hold the whole
    of one family - which Suricata refuses negated ("Complete IP space negated") - the other family's whole space
    less its own exceptions; or None when they hold both families whole: no address is left, as pf's !<table> of
    such an alias blocks nobody either."""
    whole = {n.version for n in excepted if n.prefixlen == 0}
    if whole == {4, 6}:
        return None
    if whole:
        left = 6 if 4 in whole else 4
        rest = ''.join(',!' + address(n) for n in excepted if n.version == left)
        return '[%s%s]' % ('::/0' if left == 6 else '0.0.0.0/0', rest)
    return '![%s]' % ','.join(address(n) for n in excepted)


def resolved(rule, devices, by_dev, pf):
    """{element: tables.resolve()'s answer} of a rule's source, each element once."""
    return {element: tables.resolve(element, devices, by_dev, pf) for element in dict.fromkeys(rule['source'])}


def source(rule, devices, by_dev, pf, own=()):
    """(Suricata's addresses for a rule's source, None, '') - its networks less the firewall's own addresses, every
    address but those when inverted - or (None, why, the element): 'unread' for an element that cannot be read,
    'empty' for a source that holds no address of a device. `own`: the firewall's own addresses."""
    return source_of(rule, resolved(rule, devices, by_dev, pf), own)


def source_of(rule, found, own=()):
    """source(), from the elements resolved already (resolved())."""
    entries, anything = [], False
    for element in rule['source']:
        kind, value = found[element]
        if kind == 'unread':
            return None, 'unread', element
        if kind == 'any':
            anything = True
        else:
            entries.extend(value)
    nets, mine = tables.flatten(entries), own_networks(own)
    if rule['not']:
        # every device but those, and never the firewall itself: its addresses left out with them
        if anything:
            return None, 'empty', ''
        excepted = tables.flatten([(n, False) for n in nets + mine])
        where = negated(excepted) if excepted else 'any'
        return (where, None, '') if where else (None, 'empty', '')
    if anything:
        return ('![%s]' % ','.join(address(n) for n in mine) if mine else 'any'), None, ''
    # a network the firewall's own addresses fill is no device's; one holding one of them takes it as an exception
    kept = [n for n in nets if not any(n.version == o.version and n.subnet_of(o) for o in mine)]
    if not kept:
        return None, 'empty', ''
    inside = [o for o in mine if any(o.version == n.version and o.subnet_of(n) for n in kept)]
    return '[%s]' % ','.join([address(n) for n in kept] + ['!' + address(o) for o in inside]), None, ''


MSG_DROPPED = re.compile(r'["\\;]')
MSG_SPACE = re.compile(r'[\x00-\x1f\x7f\s]+')


def message(rule):
    """msg: the plugin's, what the rule does, its application, its description - what Suricata takes in a
    message: quotes, backslashes and semicolons left out, a line break or another control character a space."""
    text = 'Application Control: %s %s' % (rule['action'], rule['app'])
    if rule['description']:
        text += ' - ' + rule['description']
    return MSG_SPACE.sub(' ', MSG_DROPPED.sub('', text)).strip()[:200]


def build(conf, catalogue, devices, by_dev, pf, own=()):
    """(the template's rules, {uuid: what each rule gave}): for each rule its number, verb, source, destination,
    message and lines - each line Suricata's protocol, its matching options and its sid - or why it gives none.
    `own`: the firewall's own addresses, out of every source and every destination with the networks of by_dev."""
    hosts = catalogue.get('hosts') or {}
    out, report = [], {}
    dest = destination(own, [n for nets in by_dev.values() for n in nets])
    for rule in conf['rules']:
        said = {'number': rule['number'], 'lines': 0, 'names': 0, 'protocol': None, 'reason': None, 'sids': None}
        report[rule['uuid'] or str(rule['number'])] = said
        if not rule['enabled']:
            said['reason'] = 'disabled'
            continue
        if rule['number'] > MOST_RULES:
            said['reason'] = 'too_many'
            continue
        # what its source holds now, whether Suricata can tell its application or not: the page says a rule acts on
        # no device when its source cannot be read or holds no device's address (status.py rules)
        found = resolved(rule, devices, by_dev, pf)
        where, why, element = source_of(rule, found, own)
        said['unread'] = [e for e, (kind, _value) in found.items() if kind == 'unread']
        said['empty'] = why == 'empty'
        lines = []
        protocol = PROTOCOLS.get(rule['app'])
        if protocol:
            lines.append(('ip', 'app-layer-protocol:%s;' % protocol))
            said['protocol'] = protocol
        names = [n for n in hosts.get(rule['app']) or [] if name_match(n, 'tls.sni', True)]
        said['names'] = len(names)
        for name in names:
            for proto, keyword, nocase in PLACES:
                lines.append((proto, name_match(name, keyword, nocase)))
        if not lines:
            said['reason'] = 'no_match'
            continue
        if len(lines) >= SID_SPAN:
            said['reason'] = 'too_many'
            continue
        if where is None:
            said['reason'], said['element'] = why, element
            continue
        if len(where) + len(dest) > SOURCE_LONGEST:
            said['reason'] = 'too_long'
            continue
        first = SID_BASE + rule['number'] * SID_SPAN + 1
        said['lines'], said['sids'] = len(lines), [first, first + len(lines) - 1]
        out.append({'number': rule['number'], 'uuid': rule['uuid'], 'action': rule['action'], 'app': rule['app'],
                    'verb': 'drop' if rule['action'] == 'block' else 'alert', 'source': where, 'destination': dest,
                    'source_text': ('not ' if rule['not'] else '') + ','.join(rule['source']), 'msg': message(rule),
                    'lines': [{'proto': proto, 'match': match, 'sid': first + i} for i, (proto, match) in enumerate(lines)]})
    return out, report


def render(rules, template=TEMPLATE):
    """The template, rendered with the rules given (Jinja2, as configd renders OPNsense's own)."""
    import jinja2
    folder, name = os.path.split(template)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(folder), trim_blocks=True, lstrip_blocks=True,
                             keep_trailing_newline=True, autoescape=False, undefined=jinja2.StrictUndefined)
    return env.get_template(name).render(rules=rules, threshold=THRESHOLD)


def too_long(text):
    """The sids of the lines past LONGEST in a rendered file."""
    out = set()
    for line in text.splitlines():
        if len(line) > LONGEST and not line.startswith('#'):
            found = re.search(r'\bsid:(\d+);', line)
            if found:
                out.add(int(found.group(1)))
    return out


def current(path):
    try:
        with open(path, encoding='utf-8') as handle:
            return handle.read()
    except OSError:
        return None


def remove(path=None):
    """The rules file removed: (changed, problem or None)."""
    path = path or RULES
    try:
        os.remove(path)
        return True, None
    except FileNotFoundError:
        return False, None
    except OSError as error:
        return False, '%s could not be removed: %s' % (path, error)


def put(path, text, mode=0o644):
    """text written to path in one step: a file of its own beside it - no other writer's name - renamed into
    place. Its name begins with a dot and does not end in .rules: installRules.py's glob never takes it."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.%s.' % os.path.basename(path), suffix='.new', dir=folder)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def keep(summary, path=None):
    try:
        put(path or STATE, json.dumps(summary), 0o640)
    except OSError:
        pass


def load(path=None):
    try:
        with open(path or STATE, encoding='utf-8') as handle:
            found = json.load(handle)
        return found if isinstance(found, dict) else {}
    except (OSError, ValueError):
        return {}


def locked(path=None, wait=None):
    """The lock a write, a start, a refresh and a removal of the file hold, one at a time, as an open file; None
    when it could not be had within `wait` seconds (LOCK_WAIT)."""
    path = path or LOCK
    wait = LOCK_WAIT if wait is None else wait
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handle = open(path, 'w')
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


def key(rule):
    return rule['uuid'] or str(rule['number'])


def applied_from(conf):
    """What a write applies: whether classifying is on, the rules as config.xml has them, and their digests."""
    return {'classify': bool(conf['classify']), 'rules': conf['rules'],
            'digests': {key(rule): tables.digest(rule) for rule in conf['rules']}}


RULE_KEYS = {'number': int, 'uuid': str, 'enabled': bool, 'action': str, 'app': str, 'source': list, 'not': bool,
             'description': str}


def applied_rules(applied):
    """The rules a former write applied, as kept in suricata.json, or None when what is kept is not that."""
    if not isinstance(applied, dict) or not isinstance(applied.get('rules'), list) or \
            not isinstance(applied.get('classify'), bool):
        return None
    for rule in applied['rules']:
        if not isinstance(rule, dict) or any(not isinstance(rule.get(k), t) for k, t in RULE_KEYS.items()) or \
                not all(isinstance(e, str) for e in rule['source']):
            return None
    return applied['rules']


def failed(summary, why):
    summary.update({'status': 'failed', 'errors': [why]})
    return summary


def write(config=None, catalogue_path=None, path=None, template=None, state=None, ifconfig=None, pf=None):
    """The rules file made to say what the settings say: the rules of config.xml applied. The summary: status,
    changed, lines, the rules - what each gave - what was applied, and errors."""
    config = config or tables.CONFIG
    summary = {'status': 'ok', 'changed': False, 'lines': 0, 'rules': {}, 'path': path or RULES, 'at': int(time.time()),
               'errors': []}
    conf = tables.settings(config)
    if not conf['read']:
        return failed(summary, '%s could not be read: the Suricata rules left as they were' % config)
    handle = locked()
    if handle is None:
        return failed(summary, 'another write of the Suricata rules held them past %g s: left as they were' % LOCK_WAIT)
    with handle:
        return produce(summary, conf, applied_from(conf), config, catalogue_path, path, template, state, ifconfig, pf)


def refresh(config=None, catalogue_path=None, path=None, template=None, state=None, ifconfig=None, pf=None):
    """The rules the last write applied, kept in suricata.json, resolved again - their sources' addresses and the
    installed nDPI's names as they are now - and the file written when that changed it. A rule saved since and not
    applied does not come in. With nothing applied kept - none written yet, or /var lost at a boot - as write()."""
    config = config or tables.CONFIG
    summary = {'status': 'ok', 'changed': False, 'lines': 0, 'rules': {}, 'path': path or RULES, 'at': int(time.time()),
               'errors': []}
    handle = locked()
    if handle is None:
        return failed(summary, 'another write of the Suricata rules held them past %g s: left as they were' % LOCK_WAIT)
    with handle:
        applied = load(state).get('applied')
        rules = applied_rules(applied)
        if rules is None:
            conf = tables.settings(config)
            if not conf['read']:
                return failed(summary, '%s could not be read: the Suricata rules left as they were' % config)
            applied = applied_from(conf)
        else:
            conf = {'classify': applied['classify'], 'rules': rules}
        return produce(summary, conf, applied, config, catalogue_path, path, template, state, ifconfig, pf)


def produce(summary, conf, applied, config, catalogue_path=None, path=None, template=None, state=None, ifconfig=None,
            pf=None):
    """The file made to say what the rules of conf give now, under the lock; what was applied kept with the summary."""
    path, template = path or RULES, template or TEMPLATE
    summary['applied'] = applied
    rules = []
    if conf['classify'] and any(rule['enabled'] for rule in conf['rules']):
        catalogue = tables.load_catalogue(catalogue_path or tables.CATALOGUE)
        devices = tables.interface_devices(config)
        listed = tables.ifconfig(ifconfig or IFCONFIG)
        own = tables.addresses(listed)
        if not own:
            # with no address of its own known, no line could leave the firewall out of its source and destination
            return failed(summary, 'the firewall\'s own addresses could not be read (%s -a): the Suricata rules left as '
                                   'they were' % (ifconfig or IFCONFIG))
        rules, summary['rules'] = build(conf, catalogue, devices, tables.device_networks(listed), pf or tables.Pf(),
                                        own)
    else:
        summary['rules'] = {key(rule): {'number': rule['number'], 'lines': 0, 'reason': 'disabled'}
                            for rule in conf['rules']}
    text, rounds, before = None, 0, current(path)
    # Suricata's verdict on the file as it is, kept from the write that tested it while nothing new is to be tested
    kept = load(state).get('engine')
    summary['engine'] = kept if isinstance(kept, dict) and before is not None else {'state': 'unchecked', 'refused': 0,
                                                                                     'message': None}
    while rules:
        try:
            text = render(rules, template)
        except Exception as error:                                       # noqa: BLE001
            return failed(summary, 'the template could not be rendered, the Suricata rules left as they were: %s' % error)
        long_ones = too_long(text)
        if long_ones:
            for rule in rules:
                if any(line['sid'] in long_ones for line in rule['lines']):
                    summary['rules'][key(rule)].update({'reason': 'too_long', 'lines': 0, 'sids': None})
            rules = [rule for rule in rules if not any(line['sid'] in long_ones for line in rule['lines'])]
            text = None
            continue
        if text == before or rounds >= TEST_ROUNDS:
            break
        # Suricata's own test of what is new to it: a line it refuses is taken out, said, and the rest tested again
        rounds += 1
        state_now, refused, why = engine_check(text, where=os.path.dirname(state or STATE))
        total = (summary['engine']['refused'] if rounds > 1 else 0) + len(refused)
        # the rest taken once those refused are out: 'refused' says some were. While some are, every look tests again
        # what it would write with them - Suricata's parsers can be switched on since
        summary['engine'] = {'state': 'refused' if total and state_now == 'ok' else state_now, 'refused': total,
                             'message': why}
        if not refused:
            break
        for rule in rules:
            gone = [line for line in rule['lines'] if line['sid'] in refused]
            if not gone:
                continue
            said = summary['rules'][key(rule)]
            said['refused'] = said.get('refused', 0) + len(gone)
            said['refused_by'] = refused[gone[0]['sid']]
            rule['lines'] = [line for line in rule['lines'] if line['sid'] not in refused]
            said['lines'] = len(rule['lines'])
            if not rule['lines']:
                said.update({'reason': 'refused', 'sids': None})
        rules = [rule for rule in rules if rule['lines']]
        text = None
    summary['lines'] = sum(len(rule['lines']) for rule in rules)
    if text is None:
        summary['changed'], problem = remove(path)
        if problem:
            summary['errors'].append(problem)
    elif current(path) != text:
        try:
            put(path, text)
            summary['changed'] = True
        except OSError as error:
            return failed(summary, '%s could not be written: %s' % (path, error))
    keep(summary, state)
    return summary


def reload_ids(configctl=None):
    """configctl ids reload - OPNsense's installRules.py, then Suricata told - after a start or a refresh changed the
    file: 'ok', or why not."""
    try:
        done = subprocess.run([configctl or CONFIGCTL, 'ids', 'reload'], capture_output=True, text=True,
                              timeout=RELOAD_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        return 'configctl ids reload could not be run: %s' % error
    return 'ok' if done.returncode == 0 else 'configctl ids reload ended with status %d' % done.returncode


def main(argv):
    verb = argv[1] if len(argv) > 1 else ''
    try:
        if verb == 'write':
            print(json.dumps(write()))
        elif verb in ('start', 'refresh'):
            summary = write() if verb == 'start' else refresh()
            if summary.get('changed'):
                summary['reload'] = reload_ids()
                if summary['reload'] != 'ok':
                    summary['errors'].append(summary['reload'])
            print(json.dumps(summary))
        elif verb == 'remove':
            handle = locked()
            changed, problem = remove() if handle is not None else (False, 'another write of the Suricata rules held '
                                                                    'them past %g s: not removed' % LOCK_WAIT)
            summary = {'status': 'ok' if problem is None else 'failed', 'changed': changed, 'lines': 0, 'rules': {},
                       'errors': [problem] if problem else []}
            if handle is not None:
                keep(summary)
                handle.close()
            print(json.dumps(summary))
        else:
            print(json.dumps({'status': 'failed', 'changed': False,
                              'errors': ['usage: suricata_rules.py write|start|refresh|remove']}))
    except Exception as error:                                           # noqa: BLE001
        # said, never raised: configd and the page read the answer
        print(json.dumps({'status': 'failed', 'changed': False, 'errors': ['the Suricata rules: %r' % error]}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
