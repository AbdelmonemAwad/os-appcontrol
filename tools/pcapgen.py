#!/usr/bin/env python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Packets for the tests, built byte by byte: Ethernet (a VLAN tag when asked), IPv4 or IPv6, TCP or UDP,
a TLS ClientHello and a DNS query, and the pcap file tcpdump writes around them. Documentation
addresses only (RFC 5737, RFC 3849) and locally administered MAC addresses.

The ClientHello by default is the one FoxIO's JA4 specification gives as its example - a browser's:
15 cipher suites, 16 extensions, h2 first, TLS 1.3 - whose JA4 the specification states:
t13d1516h2_8daaf6152771_e5627efa2ab1. GREASE values are put among them as a browser does.
"""
import ipaddress
import struct

CLIENT_MAC = bytes.fromhex('020000000002')
SERVER_MAC = bytes.fromhex('020000000001')

CHROME_CIPHERS = [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
                  0x009c, 0x009d, 0x002f, 0x0035]
CHROME_EXTENSIONS = [0x1a1a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
                     0x0033, 0x002d, 0x002b, 0x001b, 0x4469, 0x0015, 0x2a2a]
CHROME_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
CHROME_JA4 = 't13d1516h2_8daaf6152771_e5627efa2ab1'

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def header(linktype=1, snaplen=262144, order='<'):
    return struct.pack(order + 'IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype)


def record(ts, frame, wire=None, order='<'):
    sec = int(ts)
    usec = int(round((ts - sec) * 1e6))
    return struct.pack(order + 'IIII', sec, usec, len(frame), wire or len(frame)) + frame


def ether(payload, kind, vlan=None, to_server=True):
    dst, src = (SERVER_MAC, CLIENT_MAC) if to_server else (CLIENT_MAC, SERVER_MAC)
    tag = struct.pack('!HH', 0x8100, vlan) if vlan is not None else b''
    frame = dst + src + tag + struct.pack('!H', kind) + payload
    return frame + b'\0' * max(0, 60 - len(frame))          # padded to Ethernet's least, as on the wire


def ip4(src, dst, proto, payload, frag=0):
    total = 20 + len(payload)
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, frag, 64, proto, 0,
                       ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed) + payload


def ip6(src, dst, nh, payload, ext=b''):
    return struct.pack('!IHBB16s16s', 6 << 28, len(ext) + len(payload), nh, 64,
                       ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed) + ext + payload


def tcp(sport, dport, seq, ack, flags, payload=b''):
    return struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0) \
        + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def frame(src, dst, proto, l4, vlan=None, to_server=True):
    if ':' in src:
        return ether(ip6(src, dst, proto, l4), 0x86dd, vlan, to_server)
    return ether(ip4(src, dst, proto, l4), 0x0800, vlan, to_server)


def _ext(kind, value):
    return struct.pack('!HH', kind, len(value)) + value


def client_hello(sni='www.example.com', alpn=(b'h2', b'http/1.1'), ciphers=None, extensions=None, sigalgs=None,
                 versions=(0x0a0a, 0x0304, 0x0303), padding=0):
    """A TLS record holding a ClientHello; padding adds that many bytes to the padding extension, to
    make the record span TCP segments."""
    ciphers = CHROME_CIPHERS if ciphers is None else ciphers
    extensions = CHROME_EXTENSIONS if extensions is None else extensions
    sigalgs = CHROME_SIGALGS if sigalgs is None else sigalgs
    body = []
    for kind in extensions:
        if kind == 0x0000:
            if sni is None:
                continue
            name = sni.encode()
            body.append(_ext(kind, struct.pack('!HBH', len(name) + 3, 0, len(name)) + name))
        elif kind == 0x0010:
            if not alpn:
                continue
            items = b''.join(bytes([len(a)]) + a for a in alpn)
            body.append(_ext(kind, struct.pack('!H', len(items)) + items))
        elif kind == 0x000d:
            algs = b''.join(struct.pack('!H', s) for s in sigalgs)
            body.append(_ext(kind, struct.pack('!H', len(algs)) + algs))
        elif kind == 0x002b:
            vs = b''.join(struct.pack('!H', v) for v in versions)
            body.append(_ext(kind, bytes([len(vs)]) + vs))
        elif kind == 0x000a:
            groups = b''.join(struct.pack('!H', g) for g in (0x0a0a, 0x001d, 0x0017, 0x0018))
            body.append(_ext(kind, struct.pack('!H', len(groups)) + groups))
        elif kind == 0x000b:
            body.append(_ext(kind, b'\x01\x00'))
        elif kind == 0x0015:
            body.append(_ext(kind, b'\0' * (32 + padding)))
        elif kind == 0x0033:
            share = struct.pack('!HH', 0x001d, 32) + b'\x11' * 32
            body.append(_ext(kind, struct.pack('!H', len(share)) + share))
        elif kind == 0x002d:
            body.append(_ext(kind, b'\x01\x01'))
        elif kind == 0x0005:
            body.append(_ext(kind, b'\x01\x00\x00\x00\x00'))
        elif kind == 0xff01:
            body.append(_ext(kind, b'\x00'))
        else:
            body.append(_ext(kind, b''))
    extensions_bytes = b''.join(body)
    suites = b''.join(struct.pack('!H', c) for c in ciphers)
    hello = (struct.pack('!H', 0x0303) + b'\x22' * 32 + b'\x20' + b'\x33' * 32 + struct.pack('!H', len(suites)) + suites
             + b'\x01\x00' + struct.pack('!H', len(extensions_bytes)) + extensions_bytes)
    handshake = b'\x01' + struct.pack('!I', len(hello))[1:] + hello
    return b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake


def dns_query(name='www.example.com', ident=0x1234):
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)


def tcp_connection(ts, client, cport, server, sport, hello=None, mss=1448, vlan=None, server_data=b'', syn=True,
                   data=b''):
    """[(time, frame)] of a TCP connection: the handshake (unless syn is False, a connection already
    open), the client's first bytes in segments of mss, and the server's answer."""
    out = []
    c_seq, s_seq = 1000, 50000
    t = ts
    if syn:
        out.append((t, frame(client, server, 6, tcp(cport, sport, c_seq, 0, TCP_SYN), vlan)))
        out.append((t + 0.001, frame(server, client, 6, tcp(sport, cport, s_seq, c_seq + 1, TCP_SYN | TCP_ACK),
                                     vlan, to_server=False)))
        out.append((t + 0.002, frame(client, server, 6, tcp(cport, sport, c_seq + 1, s_seq + 1, TCP_ACK), vlan)))
        t += 0.003
    first = hello if hello is not None else data
    seq = c_seq + 1
    for i in range(0, len(first), mss):
        piece = first[i:i + mss]
        out.append((t, frame(client, server, 6, tcp(cport, sport, seq, s_seq + 1, TCP_ACK | TCP_PSH, piece), vlan)))
        seq += len(piece)
        t += 0.001
    if server_data:
        out.append((t, frame(server, client, 6, tcp(sport, cport, s_seq + 1, seq, TCP_ACK | TCP_PSH, server_data),
                             vlan, to_server=False)))
    return out


def capture(packets, linktype=1):
    """The bytes tcpdump -w - writes for [(time, frame)]."""
    return header(linktype) + b''.join(record(t, f) for t, f in sorted(packets, key=lambda p: p[0]))
