#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Make the page's map of nDPI's category names from categories.json, and say when it is not current.

The page translates through lang._() like every other part of OPNsense, and lang._() resolves at the
template's compile time against a literal. The categories are nDPI's, a data file's names, so
index.volt carries a map from each name to the same name passed through lang._(); every name has to
be listed, and a category added to categories.json and not to the map would come out in English on
an Arabic page with nothing to say so. So the map is made from the file here, as os-linkhealth makes
its own, and each name is in source.json, its Arabic in opnsense-arabic (tools/check-strings.py).

    tools/gen-data-strings.py           write the map and add the names source.json lacks
    tools/gen-data-strings.py --check   change nothing; exit 1 when the map or source.json is not current
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(HERE, 'src', 'opnsense', 'scripts', 'appcontrol')
VIEW = os.path.join(HERE, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'AppControl', 'index.volt')
SOURCE = os.path.join(SCRIPTS, 'i18n', 'ui', 'source.json')
BEGIN = '        /* AC-CATEGORIES-BEGIN */'
END = '        /* AC-CATEGORIES-END */'


def names():
    with open(os.path.join(SCRIPTS, 'categories.json'), encoding='utf-8') as handle:
        found = json.load(handle)['categories']
    return [found[k] for k in sorted(found, key=int)]


def quoted(value):
    """A JavaScript and Volt single-quoted literal: a backslash and an apostrophe escaped once."""
    return value.replace('\\', '\\\\').replace("'", "\\'")


def block(strings):
    lines = [BEGIN,
             '        /* nDPI\'s categories as the page shows them, the English as nDPI writes it - this map is made',
             '           from categories.json by tools/gen-data-strings.py, which checks it is current. */',
             '        const category_text = {']
    for i, value in enumerate(strings):
        text = quoted(value)
        lines.append("            '%s': \"{{ lang._('%s') }}\"%s" % (text, text, ',' if i < len(strings) - 1 else ''))
    lines.append('        };')
    lines.append(END)
    return '\n'.join(lines)


def main(argv):
    check = '--check' in argv
    strings = names()
    with open(VIEW, encoding='utf-8') as handle:
        text = handle.read()
    if BEGIN not in text or END not in text:
        print('index.volt has no %s ... %s block' % (BEGIN.strip(), END.strip()))
        return 1
    start = text.index(BEGIN)
    finish = text.index(END) + len(END)
    updated = text[:start] + block(strings) + text[finish:]
    with open(SOURCE, encoding='utf-8') as handle:
        source = json.load(handle)
    missing = [s for s in strings if s not in source]
    if check:
        problems = 0
        if updated != text:
            print('the category map in index.volt is not current: run tools/gen-data-strings.py')
            problems += 1
        for value in missing:
            print('not in source.json: %s' % value)
            problems += 1
        if not problems:
            print('categories: %d, all in the map and in source.json' % len(strings))
        return 1 if problems else 0
    if updated != text:
        with open(VIEW, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(updated)
        print('map written: %d categories' % len(strings))
    if missing:
        with open(SOURCE, 'w', encoding='utf-8', newline='\n') as handle:
            json.dump(sorted(set(source) | set(missing)), handle, ensure_ascii=False, indent=1)
            handle.write('\n')
        print('added to source.json: %d' % len(missing))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
