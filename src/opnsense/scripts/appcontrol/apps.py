#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The applications and categories of the installed nDPI, read from its own ndpiReader.

    apps.py refresh     read them again into /var/db/os-appcontrol/ndpi.json, and say what was read
    apps.py list        the applications, for the Applications field of Settings: {name: name}
    apps.py check       categories.json against the installed nDPI: what one has and the other not

The tables follow the installed nDPI, not a list kept here: a category the package gains has its
table after the next Apply. categories.json - nDPI's categories as the package's commit (de5c784)
names them, for their Arabic in opnsense-arabic - stands in only when ndpiReader -a 1 gives
nothing. Every command prints JSON and exits 0.
"""

import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ndpi                                                              # noqa: E402
import tables                                                            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CATEGORIES = os.path.join(HERE, 'categories.json')
PKG = '/usr/sbin/pkg'
VERSION = re.compile(r'Welcome to nDPI ([0-9][^\s]*)')


def committed(path=CATEGORIES):
    """{id: name} of categories.json."""
    try:
        with open(path, encoding='utf-8') as handle:
            found = json.load(handle).get('categories', {})
        return {int(k): v for k, v in found.items() if isinstance(v, str) and v}
    except (OSError, ValueError, AttributeError):
        return {}


def package_version(pkg=PKG):
    try:
        done = subprocess.run([pkg, 'query', '%v', 'ndpi'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout.strip() or None


def refresh(reader=ndpi.NDPIREADER, path=tables.CATALOGUE, fallback=CATEGORIES, pkg=PKG):
    """What the installed nDPI knows, written to path: its categories by -a 1 (categories.json when it
    gives none), its protocols with their categories by -H, the package's version."""
    out = {'read_at': int(time.time()), 'installed': ndpi.installed(reader), 'errors': []}
    categories, source = {}, None
    help_text = ''
    if out['installed']:
        categories = ndpi.parse_categories(ndpi.run_text([reader, '-a', '1']))
        source = 'ndpiReader -a 1'
        help_text = ndpi.run_text([reader, '-H'])
    if not categories:
        categories = committed(fallback)
        source = 'categories.json'
        if out['installed']:
            out['errors'].append('ndpiReader -a 1 gave no category: categories.json used')
    protocols = ndpi.parse_protocols(help_text, categories) if help_text else {}
    if out['installed'] and not protocols:
        out['errors'].append('ndpiReader -H gave no protocol')
    found = VERSION.search(help_text)
    out.update({'categories': {str(k): v for k, v in sorted(categories.items())}, 'categories_from': source,
                'protocols': protocols, 'reader': found.group(1) if found else None,
                'version': package_version(pkg) if out['installed'] else None})
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.new'
        with open(tmp, 'w', encoding='utf-8') as handle:
            json.dump(out, handle)
        os.replace(tmp, path)
    except OSError as error:
        out['errors'].append('%s could not be written: %s' % (path, error))
    return out


def options(catalogue):
    """{name: name} of the protocols nDPI knows, for a field that takes several."""
    return {name: name for name in sorted(catalogue.get('protocols') or {}, key=str.lower)}


def check(reader=ndpi.NDPIREADER, fallback=CATEGORIES):
    here = committed(fallback)
    box = ndpi.parse_categories(ndpi.run_text([reader, '-a', '1'])) if ndpi.installed(reader) else {}
    return {'installed': bool(box), 'committed': len(here), 'installed_categories': len(box),
            'only_committed': {str(k): v for k, v in sorted(here.items()) if box and box.get(k) != v},
            'only_installed': {str(k): v for k, v in sorted(box.items()) if here.get(k) != v}}


def main(argv):
    verb = argv[1] if len(argv) > 1 else ''
    if verb == 'refresh':
        out = refresh()
        print(json.dumps({'installed': out['installed'], 'categories': len(out['categories']),
                          'categories_from': out['categories_from'], 'protocols': len(out['protocols']),
                          'version': out['version'], 'errors': out['errors']}))
    elif verb == 'list':
        catalogue = tables.load_catalogue()
        if not catalogue.get('protocols'):
            catalogue = refresh()
        print(json.dumps(options(catalogue)))
    elif verb == 'check':
        print(json.dumps(check()))
    else:
        print(json.dumps({'error': 'usage: apps.py refresh|list|check'}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
