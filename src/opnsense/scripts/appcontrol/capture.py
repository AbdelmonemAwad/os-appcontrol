#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What one interface carries, read as tcpdump hands it over: each connection's first packets kept for
nDPI, and what a TLS client says first - the server name it asks for and its JA4 fingerprint.

tcpdump (-p, so no port is made promiscuous) writes the capture in pcap's own format to a pipe; Stream
takes the bytes as they come and hands back one packet at a time. Flows follows each connection by its
two ends and keeps its first KEEP packets in the window it began in, so a connection is never cut in
two by the end of a window: a window is closed only some seconds after it ends (classify.py), and
what a connection sends after its first KEEP packets is counted, not kept. ndpiReader then reads a
window's kept packets from a small file instead of everything the interface carried - it stops
looking at a connection after its first 8 packets anyway (--cfg=NULL,packets_limit_per_flow,8,
enough for every flow in phase 0's lab).

The server of a connection is the end its SYN went to, or for a connection with no SYN seen, the end
its first packet went to. A SYN on two ends already followed begins a new connection when the old one
ended (FIN or RST) or its window is closed: a port used again is judged again. A connection without
SYN - UDP, ICMP - heard from again after it was forgotten as idle is one that was going, not one begun.
A TLS client's first bytes are put together from its first segments and read as a ClientHello: the
server name (SNI), the first ALPN and the JA4 fingerprint, as FoxIO's JA4 specification defines it.
What was put together is let go once the connection has its KEEP packets or its window closes. QUIC's
ClientHello is encrypted and is not read here.

Nothing here runs a program or touches the firewall: classify.py does that.
"""

import hashlib
import ipaddress
import struct

KEEP = 16                       # packets kept of each connection, both ways together
MAX_RECORD = 262144             # the largest packet tcpdump writes with -s 0
HELLO_MAX = 16389               # a ClientHello in one TLS record: 5 bytes of header and 16 KiB

TCP, UDP, ICMP, ICMP6 = 6, 17, 1, 58
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

# pcap link types tcpdump writes for the interfaces a firewall has: Ethernet (VLAN interfaces too,
# their tag already taken off), the BSD loopback and tunnels (a 4-byte address family first), raw IP
ETHERNET, BSD_NULL, BSD_LOOP, RAW, RAW_DLT, RAW_V4, RAW_V6 = 1, 0, 108, 101, 12, 228, 229
FAMILIES = {2: 4, 24: 6, 28: 6, 30: 6}     # AF_INET, and AF_INET6 as the BSDs and macOS number it

_U16 = struct.Struct('!H')
_U32 = struct.Struct('!I')
_PORTS = struct.Struct('!HH')

# GREASE values (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa - left out of every JA4 count and list
GREASE = frozenset((x << 8) | x for x in range(0x0a, 0x100, 0x10))

TLS_VERSIONS = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3', 0x0002: 's2',
                0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3'}


class StreamError(Exception):
    """The bytes are not a pcap capture, or a record cannot be one."""


class Stream:
    """pcap's format, a chunk at a time: the global header, then (time, record, length on the wire) for
    each packet.

    The record is the 16-byte record header and the packet together, as they came, so a window's file
    is the global header followed by the records kept, unchanged.
    """

    MAGIC = {b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
             b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9)}

    def __init__(self):
        self.buffer = bytearray()
        self.header = None          # the 24 bytes of the global header, once read
        self.linktype = None
        self.scale = 1e-6
        self.record = None

    def feed(self, data):
        self.buffer += data
        buf = self.buffer
        at = 0
        out = []
        if self.header is None:
            if len(buf) < 24:
                return out
            magic = bytes(buf[0:4])
            if magic not in self.MAGIC:
                raise StreamError('not a pcap capture (magic %s)' % magic.hex())
            order, self.scale = self.MAGIC[magic]
            self.header = bytes(buf[0:24])
            self.linktype = struct.unpack(order + 'I', self.header[20:24])[0] & 0x0fffffff
            self.record = struct.Struct(order + 'IIII')
            at = 24
        head = self.record
        scale = self.scale
        size = len(buf)
        while size - at >= 16:
            sec, frac, incl, wire = head.unpack_from(buf, at)
            if incl > MAX_RECORD:
                raise StreamError('a record of %d bytes' % incl)
            end = at + 16 + incl
            if end > size:
                break
            out.append((sec + frac * scale, bytes(buf[at:end]), wire))
            at = end
        if at:
            del buf[:at]
        return out


def decode(linktype, record):
    """(proto, src, sport, dst, dport, tcp flags, tcp seq, payload start, payload end) of a packet's
    record, addresses as raw bytes and the payload as offsets into the record; None for what has no
    IP header read here (ARP, a link type not known here)."""
    off = 16
    size = len(record)
    if linktype == ETHERNET:
        if size < off + 14:
            return None
        kind = (record[off + 12] << 8) | record[off + 13]
        off += 14
        while kind in (0x8100, 0x88a8, 0x9100) and size >= off + 4:
            kind = (record[off + 2] << 8) | record[off + 3]
            off += 4
        if kind == 0x0800:
            return _ipv4(record, off)
        if kind == 0x86dd:
            return _ipv6(record, off)
        return None
    if linktype in (BSD_NULL, BSD_LOOP):
        if size < off + 4:
            return None
        # loopback's family is in network order; null's in the order of the machine that captured
        little, big = struct.unpack_from('<I', record, off)[0], struct.unpack_from('>I', record, off)[0]
        version = FAMILIES.get(big) if linktype == BSD_LOOP else FAMILIES.get(little, FAMILIES.get(big))
        off += 4
    elif linktype in (RAW, RAW_DLT, RAW_V4, RAW_V6):
        version = record[off] >> 4 if size > off else None
    else:
        return None
    if version == 4:
        return _ipv4(record, off)
    if version == 6:
        return _ipv6(record, off)
    return None


def _ipv4(data, off):
    if len(data) < off + 20 or data[off] >> 4 != 4:
        return None
    ihl = (data[off] & 15) * 4
    total = (data[off + 2] << 8) | data[off + 3]
    # the IP length, not the frame's: Ethernet pads a short frame, and the padding is no payload
    end = off + total if ihl <= total <= len(data) - off else len(data)
    proto = data[off + 9]
    src = data[off + 12:off + 16]
    dst = data[off + 16:off + 20]
    if ((data[off + 6] & 0x1f) << 8) | data[off + 7]:
        return (proto, src, 0, dst, 0, 0, 0, 0, 0)     # a later fragment: no port to read
    return _l4(data, proto, src, dst, off + ihl, end)


def _ipv6(data, off):
    if len(data) < off + 40 or data[off] >> 4 != 6:
        return None
    end = min(off + 40 + _U16.unpack_from(data, off + 4)[0], len(data))
    nxt = data[off + 6]
    src = data[off + 8:off + 24]
    dst = data[off + 24:off + 40]
    at = off + 40
    for _ in range(8):
        if nxt in (0, 43, 60):                         # hop-by-hop, routing, destination options
            if end < at + 2:
                return None
            nxt, at = data[at], at + (data[at + 1] + 1) * 8
        elif nxt == 44:                                # fragment
            if end < at + 8:
                return None
            if _U16.unpack_from(data, at + 2)[0] & 0xfff8:
                return (data[at], src, 0, dst, 0, 0, 0, 0, 0)
            nxt, at = data[at], at + 8
        elif nxt == 51:                                # authentication header
            if end < at + 2:
                return None
            nxt, at = data[at], at + (data[at + 1] + 2) * 4
        else:
            break
    return _l4(data, nxt, src, dst, at, end)


def _l4(data, proto, src, dst, at, end):
    if proto == TCP:
        if end < at + 20:
            return (proto, src, 0, dst, 0, 0, 0, 0, 0)
        sport, dport = _PORTS.unpack_from(data, at)
        start = at + (data[at + 12] >> 4) * 4
        return (proto, src, sport, dst, dport, data[at + 13], _U32.unpack_from(data, at + 4)[0],
                start, end if start < end else start)
    if proto == UDP:
        if end < at + 8:
            return (proto, src, 0, dst, 0, 0, 0, 0, 0)
        sport, dport = _PORTS.unpack_from(data, at)
        return (proto, src, sport, dst, dport, 0, 0, at + 8, end if at + 8 < end else at + 8)
    return (proto, src, 0, dst, 0, 0, 0, 0, 0)


def address(raw):
    """An address as text, spelt as ndpi.canonical() spells a row's, so the two meet."""
    return ipaddress.ip_address(bytes(raw)).compressed


def flow_key(proto, a, a_port, b, b_port):
    """The two ends of a connection in one order whichever way a packet goes, addresses as text - the
    same key for a connection read here and for a row of ndpiReader's CSV."""
    one, two = (a, int(a_port)), (b, int(b_port))
    return (int(proto),) + (one + two if one <= two else two + one)


class Flow:
    __slots__ = ('key', 'proto', 'client', 'server', 'started', 'first', 'last', 'packets', 'bytes',
                 'window', 'kept', 'keep', 'cut', 'ended', 'iface', 'client_raw', 'syn_seq', 'segments',
                 'hello_done', 'sni', 'alpn', 'ja4')

    def __init__(self, proto, client, server, started, ts, window, iface, client_raw, keep):
        self.proto = proto
        self.client = client                    # (address, port), the address as text
        self.server = server
        self.started = started                  # its beginning was seen here
        self.first = self.last = ts
        self.packets = self.bytes = 0
        self.window = window
        self.kept = 0
        self.keep = keep
        self.cut = False                        # its window's bytes ran out before its KEEP packets were kept
        self.ended = False                      # a FIN or an RST was seen
        self.iface = iface
        self.client_raw = client_raw            # (raw address, port), to tell which way a packet goes
        self.syn_seq = None
        self.segments = None
        self.hello_done = proto != TCP
        self.sni = self.alpn = self.ja4 = None
        self.key = flow_key(proto, client[0], client[1], server[0], server[1])


class Window:
    """What one interface carried in one window: the records kept, and the connections that began."""
    __slots__ = ('index', 'records', 'kept_bytes', 'flows', 'capped')

    def __init__(self, index):
        self.index = index
        self.records = []
        self.kept_bytes = 0
        self.flows = []
        self.capped = False


class Flows:
    """The connections of one interface, by their two ends, and the windows their first packets are kept in.

    seconds      the length of a window; window i holds the connections whose first packet came in
                 [i * seconds, (i + 1) * seconds)
    since        when the capture began: a connection with no SYN whose first packet came in the
                 first SETTLE seconds may be one that was already going, and is not taken as begun
    """

    SETTLE = 2.0
    IDLE = 180.0                # a connection not heard from this long is forgotten
    GONE = 3600.0               # how long the ends of a forgotten connection without SYN are remembered
    MAX_FLOWS = 300000          # connections remembered at once
    MAX_GONE = 100000           # forgotten connections without SYN remembered at once
    MAX_WINDOW_FLOWS = 100000   # connections begun in one window that are followed
    MAX_WINDOW_BYTES = 32 << 20  # what one window keeps, in bytes

    def __init__(self, iface, seconds, since):
        self.iface = iface
        self.seconds = float(seconds)
        self.since = since
        self.table = {}
        self.windows = {}
        self.gone = {}                  # hash of the ends of a connection without SYN forgotten -> when
        self.closed_until = None        # windows up to this index are closed
        self.packets = 0
        self.late = 0                   # packets of a window already closed when they were read
        self.unread = 0                 # packets with no IP header read here
        self.not_followed = 0           # connections begun past a window's limits

    def window_of(self, ts):
        return int(ts // self.seconds)

    def packet(self, linktype, ts, record, size):
        """Take one packet: follow its connection, keep it while the connection has fewer than KEEP and
        its window has bytes left."""
        self.packets += 1
        d = decode(linktype, record)
        if d is None:
            self.unread += 1
            return
        proto, src, sport, dst, dport, flags, seq, start, end = d
        one, two = (src, sport), (dst, dport)
        key = (proto,) + (one + two if one <= two else two + one)
        flow = self.table.get(key)
        if flow is not None and proto == TCP and flags & SYN and not flags & ACK and (
                flow.ended or (self.closed_until is not None and flow.window <= self.closed_until)):
            # the same two ends begin again - the old connection ended, or was judged with its window:
            # a new connection, judged on its own
            flow = None
        if flow is None:
            index = self.window_of(ts)
            if self.closed_until is not None and index <= self.closed_until:
                self.late += 1
                return
            win = self.windows.get(index)
            if win is None:
                win = self.windows[index] = Window(index)
            if len(self.table) >= self.MAX_FLOWS:
                win.capped = True
                self.not_followed += 1
                return
            keep = len(win.flows) < self.MAX_WINDOW_FLOWS and win.kept_bytes < self.MAX_WINDOW_BYTES
            if not keep:
                win.capped = True
                self.not_followed += 1
            if proto == TCP and flags & SYN:
                # a SYN goes from the client; a SYN and ACK, to it
                if flags & ACK:
                    client, server = (dst, dport), (src, sport)
                else:
                    client, server = (src, sport), (dst, dport)
                started = True
            else:
                client, server = (src, sport), (dst, dport)
                # without a SYN, begun here only when it was not going already: not in the capture's
                # first seconds, and not a connection forgotten as idle and now heard from again
                started = (proto != TCP and ts - self.since >= self.SETTLE
                           and self.gone.pop(hash(key), None) is None)
            flow = Flow(proto, (address(client[0]), client[1]), (address(server[0]), server[1]), started,
                        ts, index, self.iface, client, keep)
            self.table[key] = flow
            if keep:
                win.flows.append(flow)
        flow.packets += 1
        flow.bytes += size
        flow.last = ts
        if proto == TCP and flags & (FIN | RST):
            flow.ended = True
        if flow.keep and flow.kept < KEEP:
            win = self.windows.get(flow.window)
            if win is None:
                return
            if win.kept_bytes + len(record) > self.MAX_WINDOW_BYTES:
                # the window's bytes are spent: this connection keeps nothing more, and what it kept
                # is judged only if nDPI names it from that
                win.capped = True
                flow.keep, flow.cut = False, True
                _hello_drop(flow)
                return
            win.records.append(record)
            win.kept_bytes += len(record)
            flow.kept += 1
            if not flow.hello_done and (src, sport) == flow.client_raw:
                if flags & SYN:
                    flow.syn_seq = seq
                elif end > start:
                    _hello_segment(flow, seq, record[start:end])
            if flow.kept >= KEEP:
                _hello_drop(flow)

    def close(self, index):
        """The window, closed: no packet is kept in it after this, and what its connections' ClientHellos
        put together so far is let go. An earlier window still open - a clock set back - is closed with
        it, and what it kept dropped."""
        if self.closed_until is None or index > self.closed_until:
            self.closed_until = index
        found = Window(index)
        for i in sorted(i for i in self.windows if i <= index):
            win = self.windows.pop(i)
            for flow in win.flows:
                _hello_drop(flow)
            if i == index:
                found = win
        return found

    def restart(self, now):
        """The clock stepped - back, or forward past windows never closed: every window still open
        dropped with what it kept, the connections followed keep nothing more and are heard from in the
        clock's new time, and windows begin again with the one now. How many windows were dropped."""
        dropped = len(self.windows)
        self.windows = {}
        self.closed_until = self.window_of(now) - 1
        self.since = min(self.since, now - self.SETTLE)
        for flow in self.table.values():
            flow.keep = False
            flow.last = min(flow.last, now)
            _hello_drop(flow)
        return dropped

    def forget(self, now):
        """Connections not heard from for IDLE seconds; how many. The ends of one without SYN are
        remembered for GONE seconds, MAX_GONE of them at most: heard from again, it is one that was
        going, not one begun."""
        idle = now - self.IDLE
        gone = [k for k, f in self.table.items() if f.last < idle]
        for k in gone:
            if self.table.pop(k).proto != TCP:
                self.gone[hash(k)] = now
        horizon = now - self.GONE
        if self.gone and (len(self.gone) > self.MAX_GONE or next(iter(self.gone.values())) < horizon):
            # in the order they were forgotten: the oldest first
            kept = [(k, t) for k, t in self.gone.items() if t >= horizon]
            self.gone = dict(kept[-self.MAX_GONE:])
        return len(gone)


def _hello_drop(flow):
    """What a ClientHello put together so far, let go: nothing more of it is read."""
    flow.segments = None
    flow.hello_done = True


def _hello_segment(flow, seq, payload):
    """A segment the client sent: put the first bytes together, and read them as a ClientHello once
    the TLS record is whole. The first byte decides: not a TLS handshake, and nothing more is looked at."""
    if flow.segments is None:
        flow.segments = {}
    flow.segments[seq] = bytes(payload[:HELLO_MAX])
    base = (flow.syn_seq + 1) & 0xffffffff if flow.syn_seq is not None else min(flow.segments)
    data = bytearray()
    want = base
    for _ in range(len(flow.segments)):
        piece = flow.segments.get(want)
        if piece is None:
            break
        data += piece
        want = (want + len(piece)) & 0xffffffff
    if not data:
        return
    if data[0] != 0x16:
        flow.hello_done = True
        flow.segments = None
        return
    if len(data) < 5:
        return
    need = 5 + _U16.unpack_from(data, 3)[0]
    if len(data) >= need or len(data) >= HELLO_MAX:
        hello = client_hello(bytes(data[:need]))
        if hello:
            flow.sni, flow.alpn, flow.ja4 = hello['sni'], hello['alpn'], hello['ja4']
        flow.hello_done = True
        flow.segments = None


def client_hello(record, transport='t'):
    """{'sni', 'alpn', 'ja4', 'version'} of a TLS record holding a ClientHello; None when it is not one.

    JA4 (FoxIO): t, the TLS version (supported_versions' highest, else the ClientHello's own), d with a
    server name and i without, the count of cipher suites and of extensions (GREASE left out, two digits,
    at most 99), the first ALPN's first and last character (00 without), then the first 12 hex digits
    of the SHA-256 of the cipher suites sorted, and of the extensions sorted - without server_name and
    ALPN - followed by '_' and the signature algorithms in their own order.
    """
    try:
        if len(record) < 9 or record[0] != 0x16 or record[5] != 0x01:
            return None
        body = record[9:9 + ((record[6] << 16) | (record[7] << 8) | record[8])]
        legacy = _U16.unpack_from(body, 0)[0]
        at = 2 + 32                                         # version, random
        at += 1 + body[at]                                  # session id
        count = _U16.unpack_from(body, at)[0]
        ciphers = [_U16.unpack_from(body, at + 2 + i)[0] for i in range(0, count, 2)]
        at += 2 + count
        at += 1 + body[at]                                  # compression methods
        extensions, sni, alpn, versions, sigalgs = [], None, None, [], []
        if at + 2 <= len(body):
            end = min(at + 2 + _U16.unpack_from(body, at)[0], len(body))
            at += 2
            while at + 4 <= end:
                kind, size = _U16.unpack_from(body, at)[0], _U16.unpack_from(body, at + 2)[0]
                value = body[at + 4:at + 4 + size]
                at += 4 + size
                extensions.append(kind)
                if kind == 0x0000 and len(value) >= 5 and value[2] == 0:
                    sni = value[5:5 + _U16.unpack_from(value, 3)[0]].decode('ascii', 'replace')
                elif kind == 0x0010 and len(value) >= 3:
                    alpn = bytes(value[3:3 + value[2]]) or None
                elif kind == 0x002b and len(value) >= 1:
                    versions = [_U16.unpack_from(value, 1 + i)[0] for i in range(0, value[0] - 1, 2)]
                elif kind == 0x000d and len(value) >= 2:
                    size = _U16.unpack_from(value, 0)[0]
                    sigalgs = [_U16.unpack_from(value, 2 + i)[0] for i in range(0, size - 1, 2)]
    except (IndexError, struct.error):
        return None
    ciphers = [c for c in ciphers if c not in GREASE]
    extensions = [e for e in extensions if e not in GREASE]
    versions = [v for v in versions if v not in GREASE]
    sigalgs = [s for s in sigalgs if s not in GREASE]
    version = TLS_VERSIONS.get(max(versions) if versions else legacy, '00')
    if alpn:
        if _alnum(alpn[0]) and _alnum(alpn[-1]):
            alpn_part = chr(alpn[0]) + chr(alpn[-1])
        else:
            text = alpn.hex()
            alpn_part = text[0] + text[-1]
    else:
        alpn_part = '00'
    head = '%s%s%s%02d%02d%s' % (transport, version, 'd' if sni is not None else 'i', min(len(ciphers), 99),
                                 min(len(extensions), 99), alpn_part)
    rest = sorted('%04x' % e for e in extensions if e not in (0x0000, 0x0010))
    part_c = ','.join(rest)
    if sigalgs:
        part_c += '_' + ','.join('%04x' % s for s in sigalgs)
    hash_b = hashlib.sha256(','.join(sorted('%04x' % c for c in ciphers)).encode()).hexdigest()[:12] \
        if ciphers else '0' * 12
    hash_c = hashlib.sha256(part_c.encode()).hexdigest()[:12] if rest else '0' * 12
    return {'sni': sni, 'alpn': alpn.decode('ascii', 'replace') if alpn else None,
            'ja4': '%s_%s_%s' % (head, hash_b, hash_c), 'version': version}


def _alnum(byte):
    return 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5a or 0x61 <= byte <= 0x7a


def pcap_file(path, header, records):
    """A window's file: the stream's own global header, then the records kept, as they came."""
    with open(path, 'wb') as handle:
        handle.write(header)
        for record in records:
            handle.write(record)
