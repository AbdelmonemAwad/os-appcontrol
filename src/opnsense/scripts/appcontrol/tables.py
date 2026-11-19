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

An application is blocked once it is chosen in Blocked applications and its table is in config.xml:
plugins.inc.d/appcontrol.inc gives that table a block rule, and classify.py and cut.py cut its
connections (blocked()). Chosen and not applied yet - its alias not made - nothing of it is blocked.
A blocked application's table takes a server only from cut.py, once the firewall's own resolver gives
that address for the name its connection carried: the rule holds every device's new connections to it.

    tables.py wanted       the aliases the settings ask for, as JSON - what aliases.php writes
    tables.py flush-gone   the tables of aliases gone, taken out of pf (Apply, and the plugin's removal)
"""

import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

PREFIX = 'appcontrol_'
CATEGORY_PREFIX = 'appcontrol_cat_'
LONGEST = 31
DESCRIPTION = 'Application Control: '
PFCTL = '/sbin/pfctl'
CONFIG = '/conf/config.xml'
CATALOGUE = '/var/db/os-appcontrol/ndpi.json'
BATCH = 64
TTL = 3600


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
    default), whether what is blocked is logged (off by default), the expiry in seconds."""
    out = {'classify': True, 'interfaces': [], 'apps': [], 'blocked': [], 'block_log': False, 'ttl': TTL,
           'read': False}
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return out
    out['read'] = True
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
    that nDPI knows - in Application tables or in Blocked applications, a blocked application's rule
    being on its table. Names are given in order, categories first, and a name already given makes the
    later one take its suffix."""
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
    for app in sorted(set(conf.get('apps') or []) | set(conf.get('blocked') or [])):
        if app in known:
            give(PREFIX, app, 'application', DESCRIPTION + app)
    return out


def tabled(conf):
    """The applications a server is put in a table of its own for: those of Application tables and of
    Blocked applications."""
    return set(conf.get('apps') or []) | set(conf.get('blocked') or [])


def blocked(conf, aliases):
    """{application: its table} of the applications blocked: classifying on, chosen in Blocked
    applications, and its alias in config.xml, switched on (present()) - the rule
    plugins.inc.d/appcontrol.inc registers is on that table. One chosen whose alias is not there is not
    blocked yet: the page's Apply makes it."""
    if not conf.get('classify'):
        return {}
    out = {}
    for app in sorted(set(conf.get('blocked') or [])):
        table = table_for_app(app, aliases)
        if table:
            out[app] = table
    return out


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


def flush_gone(pf, path=CONFIG):
    """[table] taken out: the appcontrol_ tables pf holds whose alias config.xml no longer has, and that no
    rule uses. A table outlives its alias and its rules and goes on holding its addresses (os-blocklists,
    2026-10-29); emptied only, it stays listed in pf until the next boot (99 of them after Apply off and
    after the removal, on the second XGS 3300, 2026-11-17), so it is killed. One a rule still uses, or
    whose alias is there, is left as it is."""
    try:
        root = ET.parse(path).getroot()
        names = {(a.findtext('name') or '').strip() for a in root.findall('OPNsense/Firewall/Alias/aliases/alias')}
    except (OSError, ET.ParseError):
        return []
    status, out = pf.run(['-v', '-s', 'Tables'])
    if status != 0:
        return []
    killed = []
    for line in out.splitlines():
        parts = line.split()
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
