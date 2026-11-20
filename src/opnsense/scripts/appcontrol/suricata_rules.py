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
    suricata_rules.py remove    the file removed

Each prints JSON - changed: whether the file changed, so the caller runs configctl ids reload (installRules.py,
then Suricata's own reload) - and exits 0.

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
- its source as Suricata writes addresses: any, or the networks the source holds now - an interface's from
  ifconfig -a, an alias's as pf holds its table, an address or a network as written (tables.resolve()) -
  inverted with ! as the rule says. Suricata sees a device's own address before NAT only: on an internal
  interface it reads.

A rule gives no line when Suricata cannot tell its application - nDPI knows no name for it and it is no protocol
Suricata reads - when its source cannot be read or holds no address now, when a line would pass Suricata's own
limit of 8,192 characters a rule (DETECT_MAX_RULE_SIZE), or past MOST_RULES; the summary says which, for the
page. sid: SID_BASE + the rule's place among the rules * SID_SPAN + the line's, far below OPNsense's own user
rules, which count down from 4294967294. One alert a device a minute for each line (threshold), however many
connections: a drop still drops each packet.

The file is written only when what it says changes, in one step (renamed into place), and removed when no rule
gives a line. What was written is kept in /var/db/os-appcontrol/suricata.json for the page. Never fails its
caller.
"""

import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

RULES = '/usr/local/etc/suricata/rules/appcontrol.rules'
TEMPLATE = '/usr/local/opnsense/service/templates/OPNsense/AppControl/appcontrol.rules'
STATE = '/var/db/os-appcontrol/suricata.json'
IFCONFIG = '/sbin/ifconfig'
SID_BASE = 3990000000
SID_SPAN = 10000
MOST_RULES = 999
LONGEST = 8000          # characters a line at most: Suricata takes 8,192 a rule
SOURCE_LONGEST = 7400   # characters of a source at most, the rest of a line's options left room
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
REASONS = ('disabled', 'no_match', 'unread', 'empty', 'too_long', 'too_many')


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


def source(rule, devices, by_dev, pf):
    """(Suricata's addresses for a rule's source, None) - any, or [networks] with a ! when inverted - or (None,
    why, the element): 'unread' for an element that cannot be read, 'empty' for a source that holds no address."""
    entries, anything = [], False
    for element in rule['source']:
        kind, value = tables.resolve(element, devices, by_dev, pf)
        if kind == 'unread':
            return None, 'unread', element
        if kind == 'any':
            anything = True
        else:
            entries.extend(value)
    nets = tables.flatten(entries)
    if anything:
        return (None, 'empty', '') if rule['not'] else ('any', None, '')
    if not nets:
        return ('any', None, '') if rule['not'] else (None, 'empty', '')
    group = '[%s]' % ','.join(address(n) for n in nets)
    return ('!' + group if rule['not'] else group), None, ''


MSG_DROPPED = re.compile(r'["\\;]')
MSG_SPACE = re.compile(r'[\x00-\x1f\x7f\s]+')


def message(rule):
    """msg: the plugin's, what the rule does, its application, its description - what Suricata takes in a
    message: quotes, backslashes and semicolons left out, a line break or another control character a space."""
    text = 'Application Control: %s %s' % (rule['action'], rule['app'])
    if rule['description']:
        text += ' - ' + rule['description']
    return MSG_SPACE.sub(' ', MSG_DROPPED.sub('', text)).strip()[:200]


def build(conf, catalogue, devices, by_dev, pf):
    """(the template's rules, {uuid: what each rule gave}): for each rule its number, verb, source, message and
    lines - each line Suricata's protocol, its matching options and its sid - or why it gives none."""
    hosts = catalogue.get('hosts') or {}
    out, report = [], {}
    for rule in conf['rules']:
        said = {'number': rule['number'], 'lines': 0, 'names': 0, 'protocol': None, 'reason': None, 'sids': None}
        report[rule['uuid'] or str(rule['number'])] = said
        if not rule['enabled']:
            said['reason'] = 'disabled'
            continue
        if rule['number'] > MOST_RULES:
            said['reason'] = 'too_many'
            continue
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
        where, why, element = source(rule, devices, by_dev, pf)
        if where is None:
            said['reason'], said['element'] = why, element
            continue
        if len(where) > SOURCE_LONGEST:
            said['reason'] = 'too_long'
            continue
        first = SID_BASE + rule['number'] * SID_SPAN + 1
        said['lines'], said['sids'] = len(lines), [first, first + len(lines) - 1]
        out.append({'number': rule['number'], 'uuid': rule['uuid'], 'action': rule['action'], 'app': rule['app'],
                    'verb': 'drop' if rule['action'] == 'block' else 'alert', 'source': where,
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


def keep(summary, path=None):
    path = path or STATE
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.new'
        with open(tmp, 'w', encoding='utf-8') as handle:
            json.dump(summary, handle)
        os.replace(tmp, path)
    except OSError:
        pass


def write(config=None, catalogue_path=None, path=None, template=None, state=None, ifconfig=None, pf=None):
    """The rules file made to say what the settings say. The summary: status, changed, lines, the rules - what
    each gave - and errors."""
    config, path, template = config or tables.CONFIG, path or RULES, template or TEMPLATE
    summary = {'status': 'ok', 'changed': False, 'lines': 0, 'rules': {}, 'path': path, 'at': int(time.time()),
               'errors': []}
    conf = tables.settings(config)
    if not conf['read']:
        summary.update({'status': 'failed', 'errors': ['%s could not be read: the Suricata rules left as they were'
                                                       % config]})
        return summary
    rules = []
    if conf['classify'] and any(rule['enabled'] for rule in conf['rules']):
        catalogue = tables.load_catalogue(catalogue_path or tables.CATALOGUE)
        devices = tables.interface_devices(config)
        by_dev = tables.device_networks(tables.ifconfig(ifconfig or IFCONFIG))
        rules, summary['rules'] = build(conf, catalogue, devices, by_dev, pf or tables.Pf())
    else:
        summary['rules'] = {rule['uuid'] or str(rule['number']): {'number': rule['number'], 'lines': 0, 'reason': 'disabled'}
                            for rule in conf['rules']}
    text = None
    while rules:
        try:
            text = render(rules, template)
        except Exception as error:                                       # noqa: BLE001
            summary.update({'status': 'failed', 'errors': ['the template could not be rendered, the Suricata rules '
                                                           'left as they were: %s' % error]})
            return summary
        long_ones = too_long(text)
        if not long_ones:
            break
        for rule in rules:
            if any(line['sid'] in long_ones for line in rule['lines']):
                summary['rules'][rule['uuid'] or str(rule['number'])].update({'reason': 'too_long', 'lines': 0,
                                                                              'sids': None})
        rules = [rule for rule in rules if not any(line['sid'] in long_ones for line in rule['lines'])]
        text = None
    summary['lines'] = sum(len(rule['lines']) for rule in rules)
    if text is None:
        summary['changed'], problem = remove(path)
        if problem:
            summary['errors'].append(problem)
    elif current(path) != text:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + '.new'
            with open(tmp, 'w', encoding='utf-8') as handle:
                handle.write(text)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
            summary['changed'] = True
        except OSError as error:
            summary.update({'status': 'failed', 'errors': ['%s could not be written: %s' % (path, error)]})
    keep(summary, state)
    return summary


def main(argv):
    verb = argv[1] if len(argv) > 1 else ''
    try:
        if verb == 'write':
            print(json.dumps(write()))
        elif verb == 'remove':
            changed, problem = remove()
            summary = {'status': 'ok' if problem is None else 'failed', 'changed': changed, 'lines': 0, 'rules': {},
                       'errors': [problem] if problem else []}
            keep(summary)
            print(json.dumps(summary))
        else:
            print(json.dumps({'status': 'failed', 'changed': False, 'errors': ['usage: suricata_rules.py write|remove']}))
    except Exception as error:                                           # noqa: BLE001
        # said, never raised: configd and the page read the answer
        print(json.dumps({'status': 'failed', 'changed': False, 'errors': ['the Suricata rules: %r' % error]}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
