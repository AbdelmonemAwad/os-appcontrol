#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The pf tables of Application Control: their names, which ones the settings ask for, and what is
put into them.

Each table is an alias of type External in config.xml, written through OPNsense's own Alias model by
aliases.php - so it is chosen in a rule's source or destination like any alias, and XGS: Settings'
"Cut open connections when listed" can name it - with Expire: OPNsense's own cron then empties an
address of it once it has not been seen for that long (pfctl -T expire; phase 0's lab, L9). An
address seen again is refreshed with pfctl -T zero, which starts its time again (same lab, on
FreeBSD 15.1); an address new to the table is added with pfctl -T add.

    appcontrol_cat_<category>     one for every category of the installed nDPI
    appcontrol_<application>      one for each application chosen in Settings, in Application tables
                                  or in Blocked applications

A name is what OPNsense takes for an alias: letters, digits and _, at most 31 characters. Any other
character becomes _; a name too long is cut, and given _ and four hex digits of its own SHA-1, so
two names cut alike never meet. The alias's description carries the name nDPI gives.

An application is blocked once it is chosen in Blocked applications - for every device - or in a
block rule of the Rules tab - for the devices of the rule's source - and its table is in config.xml:
plugins.inc.d/appcontrol.inc gives that table its block rules, and classify.py and cut.py cut its
connections (policy(), blocked()). Chosen and not applied yet - its alias not made - nothing of it is
blocked. A blocked application's table takes a server only from cut.py, once the firewall's own
resolver gives that address for the name its connection carried: its rules hold the new connections
of their devices to it.

A rule's source is what OPNsense's own rules take (NetworkAliasField): any, an interface's network, an
alias, an address or a network, one of them inverted. resolve() gives each the addresses it holds now -
an interface's networks from ifconfig, an alias's table from pf, as pf holds it - for the classifier
to tell whether a device is one of them (Held), and for suricata_rules.py to write them for Suricata.

    tables.py wanted       the aliases the settings ask for, as JSON - what aliases.php writes
    tables.py flush-gone   the tables of aliases gone, taken out of pf (Apply, and the plugin's removal)
"""

import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PREFIX = 'appcontrol_'
CATEGORY_PREFIX = 'appcontrol_cat_'
LONGEST = 31
DESCRIPTION = 'Application Control: '
PFCTL = '/sbin/pfctl'
CONFIG = '/conf/config.xml'
CATALOGUE = '/var/db/os-appcontrol/ndpi.json'
BATCH = 64
GONE_WAIT = 15         # seconds flush-gone gives pf to let go of a table its rules still used (Apply's reload)
TTL = 3600
ACTIONS = ('block', 'alert')    # what a rule of the Rules tab does with its application
EVERYONE = 'everyone'           # the scope of an application blocked for every device
# The networks that are not the internet's: IANA's special-purpose blocks that Python's ipaddress takes for not
# global (classify.py's internet()) - private, shared, loopback, link-local, documentation, unique-local - with
# multicast and the reserved block. A Suricata line of the Rules tab takes no destination in them
# (suricata_rules.py). RFC 1918's 192.168/16 is made from the example LAN's /24: the private-data check takes an
# address of 192.168 written whole for somebody's own network.
NOT_INTERNET = tuple(ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
    '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3', '::/128', '::1/128',
    '100::/64', '2001:db8::/32', 'fc00::/7', 'fe80::/10', 'ff00::/8')) + (
    ipaddress.ip_network('192.168.1.0/24').supernet(new_prefix=16),)


def alias_name(prefix, name):
    """The alias for nDPI's name: prefix, the name with anything but letters, digits and _ made _, cut
    to 31 characters with a suffix of its own when it does not fit."""
    plain = re.sub(r'[^A-Za-z0-9_]', '_', name)
    whole = prefix + plain
    if len(whole) <= LONGEST:
        return whole
    return cut_name(prefix, name)


def cut_name(prefix, name):
    plain = re.sub(r'[^A-Za-z0-9_]', '_', name)
    suffix = '_' + hashlib.sha1(name.encode('utf-8')).hexdigest()[:4]
    return prefix + plain[:LONGEST - len(prefix) - len(suffix)] + suffix


def settings(path=CONFIG):
    """The plugin's settings out of config.xml: classify (on by default: no element there is on),
    the interfaces chosen, the applications chosen for a table, those chosen to be blocked (none by
    default), whether what is blocked is logged (off by default), the expiry in seconds, and the rules
    of the Rules tab (rules())."""
    out = {'classify': True, 'interfaces': [], 'apps': [], 'blocked': [], 'block_log': False, 'ttl': TTL,
           'rules': [], 'read': False}
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return out
    out['read'] = True
    out['rules'] = rules(root.find('OPNsense/AppControl/rules'))
    general = root.find('OPNsense/AppControl/general')
    if general is None:
        return out
    out['classify'] = (general.findtext('classify') or '1').strip() == '1'
    out['interfaces'] = [i for i in (general.findtext('interfaces') or '').split(',') if i.strip()]
    out['apps'] = [a for a in (general.findtext('apps') or '').split(',') if a.strip()]
    out['blocked'] = [a for a in (general.findtext('blocked') or '').split(',') if a.strip()]
    out['block_log'] = (general.findtext('block_log') or '0').strip() == '1'
    try:
        out['ttl'] = max(60, int((general.findtext('ttl') or TTL)))
    except ValueError:
        pass
    return out


def rules(node):
    """The rules of the Rules tab, in their order in config.xml: [{'number' (from 1, its place there), 'uuid',
    'enabled', 'action' (block or alert), 'app', 'source' ([element] as OPNsense's NetworkAliasField keeps
    them), 'not' (the source inverted), 'description'}]. A rule with no application, no source or an action
    of another kind is kept, switched off: its place and its number stay its own."""
    out = []
    for number, rule in enumerate(node.findall('rule') if node is not None else [], 1):
        action = (rule.findtext('action') or 'block').strip()
        app = (rule.findtext('app') or '').strip()
        source = [s.strip() for s in (rule.findtext('source') or '').split(',') if s.strip()]
        out.append({'number': number, 'uuid': (rule.get('uuid') or '').strip(),
                    'enabled': (rule.findtext('enabled') or '1').strip() == '1' and action in ACTIONS and bool(app)
                    and bool(source),
                    'action': action, 'app': app, 'source': source,
                    'not': (rule.findtext('source_not') or '0').strip() == '1',
                    'description': (rule.findtext('description') or '').strip()})
    return out


def load_catalogue(path=CATALOGUE):
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def wanted(conf, catalogue):
    """{alias name: {'kind', 'name', 'description'}} the settings ask for: nothing while classifying is
    off; else a table for every category of the installed nDPI and one for each application chosen
    that nDPI knows - in Application tables, in Blocked applications or in a rule of the Rules tab
    switched on, a block rule being on its table. Names are given in order, categories first, and a name
    already given makes the later one take its suffix."""
    if not conf.get('classify'):
        return {}
    out = {}

    def give(prefix, name, kind, description):
        alias = alias_name(prefix, name)
        if alias in out:
            alias = cut_name(prefix, name)
            if alias in out:
                return
        out[alias] = {'kind': kind, 'name': name, 'description': description}

    categories = catalogue.get('categories') or {}
    for cid in sorted(categories, key=lambda c: int(c)):
        name = categories[cid]
        give(CATEGORY_PREFIX, name, 'category', DESCRIPTION + 'category ' + name)
    known = catalogue.get('protocols') or {}
    for app in sorted(tabled(conf)):
        if app in known:
            give(PREFIX, app, 'application', DESCRIPTION + app)
    return out


def ruled(conf):
    """The applications of the rules of the Rules tab switched on."""
    return {rule['app'] for rule in conf.get('rules') or [] if rule['enabled']}


def tabled(conf):
    """The applications a server is put in a table of its own for: those of Application tables, of
    Blocked applications and of the rules of the Rules tab switched on."""
    return set(conf.get('apps') or []) | set(conf.get('blocked') or []) | ruled(conf)


def policy(conf, aliases):
    """{application: {'table', 'everyone', 'rules'}} of the applications blocked: classifying on, its alias in
    config.xml, switched on (present()), and chosen in Blocked applications - everyone True, every device - or
    in a block rule of the Rules tab switched on - its rules, [{'uuid', 'number', 'source', 'not'}], the
    devices of each source. plugins.inc.d/appcontrol.inc registers their block rules on that table. One whose
    alias is not there is not blocked yet: the page's Apply makes it."""
    if not conf.get('classify'):
        return {}
    out = {}

    def entry(app):
        if app not in out:
            table = table_for_app(app, aliases)
            if not table:
                return None
            out[app] = {'table': table, 'everyone': False, 'rules': []}
        return out[app]

    for app in sorted(set(conf.get('blocked') or [])):
        found = entry(app)
        if found is not None:
            found['everyone'] = True
    for rule in conf.get('rules') or []:
        if rule['enabled'] and rule['action'] == 'block':
            found = entry(rule['app'])
            if found is not None:
                found['rules'].append({'uuid': rule['uuid'], 'number': rule['number'], 'source': list(rule['source']),
                                       'not': rule['not']})
    return out


def blocked(conf, aliases):
    """{application: its table} of the applications blocked - for every device or from a rule's source
    (policy())."""
    return {app: found['table'] for app, found in policy(conf, aliases).items()}


def scope(found):
    """Whom an application's block reaches, from its entry in policy(): EVERYONE, or the frozenset of
    (element, inverted) of its rules' sources - a rule's source being any of its elements."""
    if found is None:
        return frozenset()
    if found['everyone']:
        return EVERYONE
    out = frozenset((element, rule['not']) for rule in found['rules'] for element in rule['source'])
    return EVERYONE if ('any', False) in out else out


def covers(wider, narrower):
    """Whether a block of scope `wider` reaches every device one of scope `narrower` reaches, by the rules as
    written - the same elements, or every device: a server of both applications put in the narrower one's table
    then stops nothing the wider one lets through. Two sources that name the same devices differently - an
    alias and an interface's network - are not known to be the same, and do not cover each other."""
    if wider == EVERYONE:
        return True
    if narrower == EVERYONE:
        return False
    return narrower <= wider


DYNAMIC_V4 = ('dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp')
DYNAMIC_V6 = ('dhcp6', 'slaac', '6rd', '6to4', 'pppoe')
NOT_WATCHED = ('lo', 'enc', 'pflog', 'pfsync')


def _is_address(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def interfaces(chosen, path=CONFIG):
    """[(key, device)] of the interfaces chosen that are switched on; with none chosen, every internal one -
    switched on, not the WAN, no gateway of its own nor one in System: Gateways, an address of its own that is not
    obtained from upstream. The classifier watches these (classify.py), and Suricata sees a device's own address on
    them, before NAT (status.py rules)."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    found = root.find('interfaces')
    routed = {(g.findtext('interface') or '').strip() for g in root.findall('gateways/gateway_item')}
    out = []
    for node in (list(found) if found is not None else []):
        key, dev = node.tag, (node.findtext('if') or '').strip()
        if not dev or node.find('enable') is None or dev.startswith(NOT_WATCHED):
            continue
        if chosen:
            if key in chosen:
                out.append((key, dev))
            continue
        if key == 'wan' or key in routed or node.find('internal_dynamic') is not None:
            continue
        if (node.findtext('gateway') or '').strip() or (node.findtext('gatewayv6') or '').strip():
            continue
        v4, v6 = (node.findtext('ipaddr') or '').strip(), (node.findtext('ipaddrv6') or '').strip()
        if v4 in DYNAMIC_V4 or v6 in DYNAMIC_V6:
            continue
        if _is_address(v4) or _is_address(v6) or v6 == 'track6':
            out.append((key, dev))
    return out


def interface_names(path=CONFIG):
    """{interface: the name the firewall's pages give it} - its description, or its key in capitals."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {}
    found = root.find('interfaces')
    return {node.tag: (node.findtext('descr') or '').strip() or node.tag.upper()
            for node in (list(found) if found is not None else [])}


def digest(rule):
    """What a rule of the Rules tab puts in force - switched on or off, its action, its application, its source,
    inverted or not - as a short digest: suricata_rules.py keeps those of the rules it applied, and status.py tells by
    them a rule changed since and not applied yet."""
    what = [bool(rule['enabled']), rule['action'], rule['app'], list(rule['source']), bool(rule['not'])]
    return hashlib.sha1(json.dumps(what).encode('utf-8')).hexdigest()[:16]


def interface_devices(path=CONFIG):
    """{interface: its device} of every interface in config.xml - lan: em1, opt2: vlan02 - the names a rule's
    source takes for an interface's network."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {}
    found = root.find('interfaces')
    out = {}
    for node in (list(found) if found is not None else []):
        dev = (node.findtext('if') or '').strip()
        if dev:
            out[node.tag] = dev
    return out


def ifconfig_address(words):
    """The address and its network of one inet or inet6 line of ifconfig, in any of the ways it writes
    them - 'inet 192.0.2.1 netmask 0xffffff00', 'inet 192.0.2.1/24', 'inet6 fe80::1%em0 prefixlen 64';
    None for a line read as none of them."""
    text, prefix = words[1], None
    if '/' in text:
        text, prefix = text.rsplit('/', 1)
    text = text.split('%')[0]
    for i, word in enumerate(words[2:-1], 2):
        if word == 'netmask':
            try:
                mask = words[i + 1]
                prefix = bin(int(mask, 16) if mask.startswith('0x') else int(ipaddress.IPv4Address(mask))).count('1')
            except ValueError:
                return None
        elif word == 'prefixlen':
            prefix = words[i + 1]
    try:
        return ipaddress.ip_interface(text if prefix is None else '%s/%s' % (text, prefix))
    except ValueError:
        return None


IFCONFIG_HEAD = re.compile(r'^(\S+?):\s+flags=')


def device_networks(text):
    """{device: [network]} of `ifconfig -a`: the networks of each device's addresses, in its order, each once;
    a link-local one left out - no device out there is reached by it."""
    out, dev = {}, None
    for line in (text or '').splitlines():
        head = IFCONFIG_HEAD.match(line)
        if head:
            dev = head.group(1)
            out.setdefault(dev, [])
            continue
        words = line.split()
        if dev is None or len(words) < 2 or words[0] not in ('inet', 'inet6'):
            continue
        found = ifconfig_address(words)
        if found is None or found.network.is_link_local or found.network in out[dev]:
            continue
        out[dev].append(found.network)
    return out


def addresses(text):
    """Every address of the firewall's own in `ifconfig -a`: each inet and inet6 line's, link-local and loopback ones
    among them."""
    out, dev = set(), None
    for line in (text or '').splitlines():
        head = IFCONFIG_HEAD.match(line)
        if head:
            dev = head.group(1)
            continue
        words = line.split()
        if dev is None or len(words) < 2 or words[0] not in ('inet', 'inet6'):
            continue
        found = ifconfig_address(words)
        if found is not None:
            out.add(found.ip)
    return out


def ifconfig(program='/sbin/ifconfig'):
    """`ifconfig -a`'s text; '' when it could not be run."""
    try:
        done = subprocess.run([program, '-a'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ''
    return done.stdout if done.returncode == 0 else ''


def resolve(element, devices, by_dev, pf):
    """What one element of a rule's source holds now: ('any', None); ('nets', [(network, inverted)]) - an
    interface's networks (devices, by_dev: device_networks()), an address or a network written there, or an
    alias's table as pf holds it, an entry pf writes with ! inverted; or ('unread', why) - an alias pf does
    not hold, the firewall itself or one of its addresses, which a source of this plugin's never takes."""
    if element == 'any':
        return 'any', None
    if element in devices:
        return 'nets', [(net, False) for net in by_dev.get(devices[element], [])]
    if element == '(self)' or (element.endswith('ip') and element[:-2] in devices):
        return 'unread', '%s is the firewall itself' % element
    try:
        return 'nets', [(ipaddress.ip_network(element, strict=False), False)]
    except ValueError:
        pass
    entries = pf.entries(element)
    if entries is None:
        return 'unread', 'pf holds no table %s' % element
    return 'nets', entries


def flatten(entries):
    """The networks pf's rule for `entries` holds - an address held when the most specific entry holding it is not
    inverted (Held) - written without !: each entry not inverted, less the inverted ones inside it; then
    collapsed, IPv4 first. An inverted entry no other holds takes nothing out of anything, and adds nothing."""
    plain = [net for net, inverted in entries if not inverted]
    # the widest holes first: a narrower one is then inside a piece left, or inside a hole already taken out
    holes = sorted((net for net, inverted in entries if inverted), key=lambda n: (n.version, n.prefixlen))
    out = []
    for net in plain:
        left = [net]
        for hole in holes:
            if hole.version != net.version or hole == net or not hole.subnet_of(net):
                continue
            pieces = []
            for part in left:
                if hole.subnet_of(part):
                    pieces.extend(part.address_exclude(hole) if hole != part else [])
                else:
                    pieces.append(part)
            left = pieces
        out.extend(left)
    four = list(ipaddress.collapse_addresses([n for n in out if n.version == 4]))
    six = list(ipaddress.collapse_addresses([n for n in out if n.version == 6]))
    return four + six


class Held:
    """Addresses as pf holds them in a table: an address is in it when the most specific entry holding it is
    not inverted - pf's own rule for a table with entries written with !."""

    def __init__(self, entries):
        self.by_length = {}
        for network, inverted in entries:
            self.by_length.setdefault((network.version, network.prefixlen), {})[int(network.network_address)] = inverted
        self.lengths = sorted(self.by_length, key=lambda k: -k[1])

    def __contains__(self, address):
        try:
            address = ipaddress.ip_address(address)
        except ValueError:
            return False
        value = int(address)
        for version, length in self.lengths:
            if version != address.version:
                continue
            bits = address.max_prefixlen - length
            found = self.by_length[(version, length)].get(value >> bits << bits)
            if found is not None:
                return not found
        return False


class Where:
    """Where the sources of the block rules are, for telling whether a device is one of them: each element of a
    source resolved (resolve()) - an interface's networks as ifconfig -a lists them, an alias's table as
    pf holds it, an address or a network as written - all again at each window's close (refresh()), and an
    element new to the rules at once (ensure()). An element that cannot be read holds no device: nothing is
    cut for it, and the rule's pf block still stands."""

    def __init__(self):
        self.held = {}          # element -> 'any', a tables.Held, or None when it could not be read
        self.unread = {}        # element -> why
        self.devices = {}
        self.by_dev = {}

    def refresh(self, policy, devices, by_dev, pf):
        self.held, self.unread, self.devices, self.by_dev = {}, {}, devices, by_dev
        self.ensure(policy, pf)

    def ensure(self, policy, pf):
        for found in policy.values():
            for rule in found['rules']:
                for element in rule['source']:
                    if element in self.held:
                        continue
                    kind, value = resolve(element, self.devices, self.by_dev, pf)
                    if kind == 'any':
                        self.held[element] = 'any'
                    elif kind == 'nets':
                        self.held[element] = Held(value)
                    else:
                        self.held[element] = None
                        self.unread[element] = value

    def holds(self, rule, address):
        """Whether a device's address is one of a rule's source: in one of its elements, or - inverted - in
        none, every one of them read."""
        found = [self.held.get(element) for element in rule['source']]
        if rule['not']:
            if not found or any(h is None for h in found):
                return False
            return not any(isinstance(h, str) or address in h for h in found)
        return any(isinstance(h, str) or (h is not None and address in h) for h in found)


def table_for_category(category, aliases):
    """The table of a category, when its alias is there."""
    name = alias_name(CATEGORY_PREFIX, category)
    if aliases.get(name, {}).get('name') == category:
        return name
    cut = cut_name(CATEGORY_PREFIX, category)
    return cut if aliases.get(cut, {}).get('name') == category else None


def table_for_app(app, aliases):
    name = alias_name(PREFIX, app)
    if aliases.get(name, {}).get('kind') == 'application' and aliases[name]['name'] == app:
        return name
    cut = cut_name(PREFIX, app)
    return cut if aliases.get(cut, {}).get('name') == app else None


def present(path=CONFIG):
    """{alias name: {'kind', 'name'}} of this plugin's aliases in config.xml, switched on: its own are
    named appcontrol_ and described 'Application Control: '."""
    out = {}
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return out
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        name = (alias.findtext('name') or '').strip()
        text = (alias.findtext('description') or '').strip()
        if not name.startswith(PREFIX) or not text.startswith(DESCRIPTION):
            continue
        if (alias.findtext('enabled') or '1').strip() != '1' or (alias.findtext('type') or '') != 'external':
            continue
        rest = text[len(DESCRIPTION):]
        if name.startswith(CATEGORY_PREFIX) and rest.startswith('category '):
            out[name] = {'kind': 'category', 'name': rest[len('category '):]}
        else:
            out[name] = {'kind': 'application', 'name': rest}
    return out


class Pf:
    """pfctl, for this plugin's tables: what a table holds, addresses added or refreshed in it or taken out
    of it, and a table emptied. run(args) -> (exit status, output); a stand-in in the tests."""

    def __init__(self, run=None, pfctl=PFCTL):
        self.pfctl = pfctl
        self.run = run or self._run
        self.errors = []

    def _run(self, args):
        try:
            done = subprocess.run([self.pfctl] + args, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as error:
            return 1, str(error)
        return done.returncode, (done.stdout or '') + (done.stderr or '')

    def show(self, table):
        status, out = self.run(['-t', table, '-T', 'show'])
        if status != 0:
            return None
        return {line.strip() for line in out.splitlines() if line.strip() and not line.startswith('pfctl')}

    def entries(self, table):
        """[(network, inverted)] of what pf holds in a table - an entry written with ! inverted - or None when pf
        holds no such table; a line that is no address is left out."""
        held = self.show(table)
        if held is None:
            return None
        out = []
        for text in sorted(held):
            inverted = text.startswith('!')
            try:
                out.append((ipaddress.ip_network(text.lstrip('!').strip(), strict=False), inverted))
            except ValueError:
                continue
        return out

    def update(self, table, addresses):
        """Each address in the table: added when it is not there, its time started again when it is.
        (added, refreshed); a failure is kept in errors, never raised."""
        addresses = sorted(set(addresses))
        if not addresses:
            return 0, 0
        held = self.show(table)
        if held is None:
            held = set()
        new = [a for a in addresses if a not in held]
        again = [a for a in addresses if a in held]
        for verb, group in (('add', new), ('zero', again)):
            self._each(table, verb, group)
        return len(new), len(again)

    def delete(self, table, addresses):
        """The addresses taken out of the table; a failure kept in errors, never raised."""
        self._each(table, 'delete', sorted(set(addresses)))

    def flush(self, table):
        """Every address taken out of the table; a failure kept in errors, never raised."""
        status, out = self.run(['-t', table, '-T', 'flush'])
        if status != 0:
            self.errors.append('pfctl -t %s -T flush: %s' % (table, out.strip()[:200]))

    def _each(self, table, verb, group):
        for i in range(0, len(group), BATCH):
            status, out = self.run(['-t', table, '-T', verb] + group[i:i + BATCH])
            if status != 0:
                self.errors.append('pfctl -t %s -T %s: %s' % (table, verb, out.strip()[:200]))


def flush_gone(pf, path=CONFIG, wait=GONE_WAIT, sleep=time.sleep):
    """[table] taken out: the appcontrol_ tables pf holds whose alias config.xml no longer has, and that no
    rule uses. A table outlives its alias and its rules and goes on holding its addresses (os-blocklists,
    2026-10-29); emptied only, it stays listed in pf until the next boot (99 of them after Apply off and
    after the removal, on the second XGS 3300, 2026-11-17), so it is killed. One a rule still uses, or
    whose alias is there, is left as it is.

    The filter reload that drops the block rules may still be loading them when this looks: on the second
    XGS 3300 (2026-11-20) appcontrol_YouTube was still a rule's then, at Apply with classifying off and at
    the removal, and stayed in pf with its address. So while a table whose alias is gone is still a rule's,
    this reads pf again a second at a time, `wait` seconds at most, before it takes out what no rule uses."""
    try:
        root = ET.parse(path).getroot()
        names = {(a.findtext('name') or '').strip() for a in root.findall('OPNsense/Firewall/Alias/aliases/alias')}
    except (OSError, ET.ParseError):
        return []
    lines = []
    for tick in range(max(0, int(wait)) + 1):
        status, out = pf.run(['-v', '-s', 'Tables'])
        if status != 0:
            return []
        lines = [line.split() for line in out.splitlines()]
        used = [p for p in lines if len(p) >= 2 and p[1].startswith(PREFIX) and p[1] not in names and 'r' in p[0]]
        if not used or tick == wait:
            break
        sleep(1)
    killed = []
    for parts in lines:
        if len(parts) < 2 or not parts[1].startswith(PREFIX) or 'r' in parts[0] or parts[1] in names:
            continue
        status, text = pf.run(['-t', parts[1], '-T', 'kill'])
        if status == 0:
            killed.append(parts[1])
        else:
            pf.errors.append('pfctl -t %s -T kill: %s' % (parts[1], text.strip()[:200]))
    return killed


def main(argv):
    if argv[1:2] == ['flush-gone']:
        pf = Pf()
        print(json.dumps({'killed': flush_gone(pf), 'errors': pf.errors}))
        return 0
    if argv[1:2] == ['wanted']:
        conf = settings()
        print(json.dumps({'ttl': conf['ttl'], 'classify': conf['classify'],
                          'aliases': wanted(conf, load_catalogue())}))
        return 0
    print('usage: tables.py wanted|flush-gone', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
