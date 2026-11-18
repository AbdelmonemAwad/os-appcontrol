#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""ndpiReader, from OPNsense's package ndpi: what it is run with, and how its answers are read.

A window's packets are given to ndpiReader twice, as a file (classify.py writes it):

    ndpiReader -q -i <window.pcap> -C <out.csv> --cfg=NULL,packets_limit_per_flow,8
    ndpiReader -q -i <window.pcap> -C <out.csv> --cfg=NULL,packets_limit_per_flow,8 -d

The CSV holds one row a connection nDPI named, "|" between the columns, the first line its header
(#flow_id|protocol|first_seen|...|ndpi_proto|...|server_name_sni|...); a connection nDPI could not
name is left out. That is from nDPI's source (de5c784, the package's commit), not measured: without -v,
printFlowsStats() writes the flows node_print_known_proto_walker() walks, those with a protocol, and a
file is read to its end with no flow purged as idle (live captures alone are). Phase 0's lab had no
connection nDPI could not name. -d is ndpiReader's "Disable protocol guess (by ip and by port) and use
only DPI" (its own help on that package), so a connection named in the first run and not in the second
was named by a guess, by its port or its address - shown as a guess and never put in a table (the
plan's settled point 4).

The catalogue of the installed nDPI is read from two more of its options: -a 1, "List known
categories", and -H, its help with the table of the protocols it knows - name, breed, category and
ports a line. Their format here is the source's (nDPI de5c784, the package's own commit:
ndpi_generate_options() and ndpi_dump_protocols()); it was not read on a box in phase 0, and
categories.json, the same nDPI's categories, stands in when -a 1 gives nothing.
"""

import ipaddress
import os
import re
import subprocess

NDPIREADER = '/usr/local/bin/ndpiReader'
PACKETS_PER_FLOW = 8
TIMEOUT = 120

# the protocols whose application nDPI names on top of them (its subclassification knobs for tls,
# quic and http, on by default in its own help): a connection named by one of these alone was
# given no application
CARRIERS = ('TLS', 'QUIC', 'HTTP')

OPTION = re.compile(r'<Option(\d+) value="(\d+)">([^<]*)</Option\d+>')
PROTOCOL = re.compile(r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$')

# two protocols every nDPI has, and the categories its own table gives them: a table read that says
# otherwise was not read as nDPI writes it, and none of its categories is to be believed
SURE = {'TLS': 'Web', 'DNS': 'Network'}


def command(pcap, csv, guess=True, reader=NDPIREADER):
    """The ndpiReader run over one window's file; with guess False, DPI alone (-d)."""
    out = [reader, '-q', '-i', pcap, '-C', csv, '--cfg=NULL,packets_limit_per_flow,%d' % PACKETS_PER_FLOW]
    if not guess:
        out.append('-d')
    return out


def canonical(text):
    """An address as one spelling, so a row's ends and a capture's meet."""
    try:
        return ipaddress.ip_address(text.strip()).compressed
    except ValueError:
        return text.strip()


def wrote_csv(path):
    """True when ndpiReader wrote its CSV: the file is there and begins with its header, which comes
    before any row - a run that ended early wrote none."""
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            return handle.readline().startswith('#')
    except OSError:
        return False


def read_csv(path):
    """{key: row} of ndpiReader's CSV, the key the connection's two ends (capture.flow_key) and the row
    {'proto', 'src', 'sport', 'dst', 'dport', 'name', 'by_ip', 'server_name', 'packets'}; the rows and
    the header it could not read are counted in the second value. A file with the header only - what
    ndpiReader writes with -v - gives no row."""
    rows, bad = {}, 0
    try:
        handle = open(path, encoding='utf-8', errors='replace')
    except OSError:
        return rows, bad
    with handle:
        first = handle.readline()
        if not first.startswith('#'):
            return rows, 1 if first.strip() else 0
        head = first[1:].rstrip('\r\n').split('|')
        col = {name: i for i, name in enumerate(head)}
        need = ('protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'ndpi_proto')
        if any(n not in col for n in need):
            return rows, 1
        for line in handle:
            line = line.rstrip('\r\n')
            if not line:
                continue
            # the last column, the HTTP user agent, may hold a "|" of its own
            cells = line.split('|', len(head) - 1)
            if len(cells) < len(head) - 1:
                bad += 1
                continue
            try:
                proto = int(cells[col['protocol']])
                sport, dport = int(cells[col['src_port']]), int(cells[col['dst_port']])
            except ValueError:
                bad += 1
                continue
            src, dst = canonical(cells[col['src_ip']]), canonical(cells[col['dst_ip']])
            name = cells[col['ndpi_proto']].strip()
            if not name:
                bad += 1
                continue

            def cell(n):
                return cells[col[n]].strip() if n in col and col[n] < len(cells) else ''

            packets = 0
            for n in ('c_to_s_pkts', 's_to_c_pkts'):
                try:
                    packets += int(cell(n) or 0)
                except ValueError:
                    pass
            key = (proto,) + (((src, sport) + (dst, dport)) if (src, sport) <= (dst, dport)
                              else ((dst, dport) + (src, sport)))
            rows[key] = {'proto': proto, 'src': src, 'sport': sport, 'dst': dst, 'dport': dport,
                         'name': name, 'by_ip': cell('proto_by_ip'), 'server_name': cell('server_name_sni'),
                         'packets': packets}
    return rows, bad


def split_name(name):
    """(master, application) of the name nDPI gives a connection: TLS.YouTube is TLS carrying YouTube;
    DNS is DNS alone, its own application."""
    if '.' in name:
        master, app = name.split('.', 1)
        return master, app
    return name, name


def carried_only(name):
    """A connection named by a protocol that carries applications, and no application on top of it."""
    return '.' not in name and name in CARRIERS


def parse_categories(text):
    """{id: name} of ndpiReader -a 1: one '<OptionN value="N">Name</OptionN>' a category; the empty
    names left out (nDPI lists only the categories it names)."""
    out = {}
    for found in OPTION.finditer(text or ''):
        name = found.group(3).strip()
        if name:
            out[int(found.group(2))] = name
    return out


def parse_protocols(text, categories):
    """{name: category} of ndpiReader -H: the lines of its protocol table, from the source's
    "%3d %8d %-26s %-10s %-8s %-21s %-18s %-31s %-31s %6d" - id, user id, name, layer 4 (may be
    empty), X for a protocol that is no application's (or empty), breed, category, ports. The
    category is the first word after the name that is one of nDPI's categories, so an empty column
    before it does not move it. The table of risks that follows it is not read."""
    names = set(categories.values()) if isinstance(categories, dict) else set(categories)
    out = {}
    for line in (text or '').splitlines():
        if 'supported risks' in line:
            break
        found = PROTOCOL.match(line)
        if not found:
            continue
        for word in found.group(4).split():
            if word in names:
                out[found.group(3)] = word
                break
    return out


def protocols_problem(protocols):
    """Why the table of protocols read from -H is not to be believed - empty, or TLS not in Web or DNS
    not in Network - or None."""
    if not protocols:
        return 'ndpiReader -H gave no protocol'
    wrong = ['%s in %s, not %s' % (name, protocols.get(name) or 'no category', category)
             for name, category in sorted(SURE.items()) if protocols.get(name) != category]
    if wrong:
        return 'ndpiReader -H was not read as nDPI writes it: %s' % '; '.join(wrong)
    return None


def run_text(args, timeout=60):
    """What a program printed, its errors after; '' when it could not be run."""
    try:
        done = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ''
    return (done.stdout or '') + (done.stderr or '')


def installed(reader=NDPIREADER):
    return os.access(reader, os.X_OK)
