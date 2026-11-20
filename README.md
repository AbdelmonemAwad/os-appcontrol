<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/readme/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/images/readme/banner-light.svg">
  <img src="docs/images/readme/banner-light.svg" alt="os-appcontrol - Which application a connection belongs to, and acting on it" width="100%">
</picture>

<p align="center">
  <img alt="status: written, not released" src="https://img.shields.io/badge/status-written%2C%20not%20released-lightgrey.svg?style=flat-square">
  <a href="https://github.com/AbdelmonemAwad/os-appcontrol/actions/workflows/checks.yml"><img alt="checks on main" src="https://img.shields.io/github/actions/workflow/status/AbdelmonemAwad/os-appcontrol/checks.yml?branch=main&amp;style=flat-square&amp;label=checks"></a>
  <a href="LICENSE"><img alt="licence: BSD-2-Clause" src="https://img.shields.io/badge/licence-BSD--2--Clause-blue.svg?style=flat-square"></a>
  <a href="#what-is-tested"><img alt="OPNsense 26.7" src="https://img.shields.io/badge/OPNsense-26.7-d94f00.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/opnsense-arabic"><img alt="the page in English and in Arabic" src="https://img.shields.io/badge/GUI-English%20%C2%B7%20Arabic-2da44e.svg?style=flat-square"></a>
  <a href="https://github.com/AbdelmonemAwad/os-xgs-npu"><img alt="part of os-xgs-npu" src="https://img.shields.io/badge/part%20of-os--xgs--npu-9a6700.svg?style=flat-square"></a>
</p>

# Application Control for OPNsense

Knowing which application a connection belongs to - with the open nDPI library - and acting on it: pf tables per application for rules and for routing by gateway, Suricata rules, and a cut in the coprocessor once a connection is known.

> ~~**Planned - nothing here runs yet.** This repository was opened on 2026-11-16 to hold
> Application Control as a plugin of its own. No code has been written or moved into it, and there is no
> release.~~
>
> **Written, not released (2026-11-17).** The first part is here: each connection's application named
> by nDPI, on by default, and pf tables of the servers named - one for every nDPI category, one for each
> application chosen. ~~Nothing is blocked yet.~~ It has run on the second XGS 3300, the XGS 136 and a plain
> OPNsense: what was run is under [What is tested](#what-is-tested).
>
> **The second part, written (2026-11-20), not yet run on an appliance.** An application chosen in
> Settings' *Blocked applications* is blocked: a block rule of the plugin's on its table stops a new
> connection to its servers, and each connection nDPI names as it is cut - its pf states killed by its
> two ends and, where os-xgs-npu is installed with *Cut in hardware* on, dropped on the coprocessor
> first; what was dropped there is handed back once the application is no longer blocked. A server goes
> into that table only when the firewall's own resolver gives its address for the name the connection
> carried: a device cannot have an address of its choosing blocked for everyone by writing a name to
> it. Nothing is blocked until an application is chosen. Its checks ran away from an appliance (below).
>
> **The third part, written (2026-11-20), not yet run on an appliance.** The Rules tab: a rule is an
> application, a source - any, an interface's network such as the guest network, an alias, an address
> or a network, or every device but one of them - and Block or Alert. Block puts a block rule of the
> plugin's on the application's table from that source alone, cuts the connections nDPI names as it
> from there - in hardware too where os-xgs-npu is installed - and writes a Suricata rule for
> OPNsense's own Intrusion Detection; Alert writes the Suricata rule alone. A Suricata rule matches the
> names the installed nDPI knows the application by, as nDPI matches them, or its protocol when Suricata
> reads that protocol itself, on a device's way to the internet alone. After its review, each finding was
> fixed the same day. Its checks ran away from an appliance (below).

<p align="center"><b>Contents:</b> <a href="#what-it-does">What it does</a> &middot; <a href="#how-a-connection-is-named">How a connection is named</a> &middot; <a href="#how-an-application-is-blocked">How an application is blocked</a> &middot; <a href="#how-a-rule-of-the-rules-tab-acts">How a rule of the Rules tab acts</a> &middot; <a href="#not-yet-and-why">Not yet, and why</a> &middot; <a href="#what-is-tested">What is tested</a> &middot; <a href="#installation">Installation</a> &middot; <a href="#updates">Updates</a> &middot; <a href="#where-it-fits">Where it fits</a> &middot; <a href="#licence">Licence</a></p>

## What it does

**Firewall: Application Control** (XGS: Application Control, order 59, when os-xgs-npu is installed),
one page:

- **classification, on by default** - a service reads a copy of what the internal interfaces carry
  and names each connection's application with nDPI's `ndpiReader`, from OPNsense's own package
  `ndpi`. It stands in no connection's way: stopped, or failing, it changes no traffic;
- **tables** - every server nDPI names goes into the table of its category, `appcontrol_cat_<category>`,
  one for every category of the installed nDPI, and into `appcontrol_<application>` for each
  application chosen in Settings. Each is an alias of type External in Firewall: Aliases, written
  through OPNsense's own Alias model, so a rule's source or destination can name it, and so can XGS:
  Settings' "Cut open connections when listed". An address leaves its table once it has not been seen
  for the alias's Expire - 3600 s by default - carried out by OPNsense's own cron; seen again, its time
  starts again;
- **never in a table** - the firewall's own addresses and its LAN's - any address on the networks of
  its internal interfaces, and of those watched - read from `ifconfig -a` at each window's close; an
  address that is no server's - multicast, broadcast, link-local, loopback, unspecified; and the other
  end of an ICMP connection. Such a connection is counted as named, and status.json says why it went
  into no table;
- **guesses** - a connection nDPI names only by its port or its address is shown as a guess and put in
  no table;
- **Unknown** - the connections nDPI could not name, the guesses, and those it named by their protocol
  alone - TLS, QUIC or HTTP with no application on top - each listed with its server, and the server
  name and JA4 fingerprint its client sent first, so its source can be found. One not named, or named
  by its protocol alone, is listed only when its beginning was seen. The latest 500 of each kind are
  kept;
- **blocking, off until chosen** - each application chosen in *Blocked applications* gets a table of its
  own, as one of *Application tables* does, and a block rule of the plugin's on it; the connections nDPI
  names as it are cut, in hardware too where os-xgs-npu is installed. Its table takes a server only when
  the firewall's own resolver vouches for it, and the rule holds every port of a server in it, so another
  service on the same address is blocked as well. The Applications tab says, for each, whether it is
  blocked or chosen and not applied yet, the connections cut and the packets its block rules stopped
  since the rules were last loaded; a line under the cards, what is blocked and whether os-xgs-npu's *Cut
  in hardware* is on - or the os-xgs-npu installed too old for it. *Log what is blocked* (off) logs each
  packet the rules drop;
- **rules, by source** - the Rules tab, a grid of rules each with its source, its application and its
  action: Block, for the devices of the source alone - the plugin's block rule from there, their
  connections cut, a Suricata rule - or Alert, a Suricata rule alone. The grid says what each does now,
  against what the last Apply put in force: in force, changed and not applied yet, or acting on no device;
  the connections cut for it; its Suricata rules, those Suricata refused, or why it has none; under it,
  whether the Intrusion Detection is on, in which mode and on which interfaces, and the rules deleted that
  act until Apply (below);
- **the cards** - applications named, connections classified, unknown, and the last error, with what
  reading the installed nDPI's catalogue found wrong; under them, the windows cut short at a limit.

Off, the classifier stops and the plugin's aliases leave Firewall: Aliases - switched off instead where a
rule or a setting still names one - and with them the block rules; what a cut dropped in hardware is
handed back, and the Suricata rules of the Rules tab are taken away.

## How a connection is named

The design is phase 0's, settled on 2026-11-17 by the plan, the new-plugin standard and a lab of nDPI
itself on a lab XGS 3300 and XGS 136 - nDPI's runs, not this plugin's:

- **read, never in the way** - on each internal interface (one with an address of its own and no
  gateway - its own, or one in System: Gateways - unless Settings names others), `tcpdump -p` copies
  what the host sees through BPF to the service's pipe. `-p` leaves the port as it is: on an XGS 136 a
  front port made promiscuous is a request to the switch's agent, and `ndpiReader` reading a port
  itself always makes it promiscuous. The interfaces are read again at each window's close, so one
  assigned or switched on since is followed. A capture that stops - its device gone - is started again
  after 30 seconds, the wait doubled each time it stops again up to 10 minutes, and said when it stops
  and when it reads again;
- **a connection's first packets** - the service keeps the first 16 packets of each connection, both
  ways, in the window of 60 seconds it began in; 10 seconds after a window ends, its packets go to
  `ndpiReader` as a small file, on a tmpfs the rc script mounts at the start and takes down at the
  stop: never on the disk (160 MiB at most, memory only for what is in it; without it the classifier
  writes nothing, and says why). nDPI stops looking at a connection after its first 8 packets here
  (`--cfg=NULL,packets_limit_per_flow,8`), which was enough for every connection of phase 0's lab. A
  connection is never cut in two by a window's end; what it sends after its first 16 packets is
  counted, not kept. A window keeps at most 32 MiB an interface, checked before each packet: past it,
  a connection keeps nothing more, and is judged only if nDPI names it from what it kept. A SYN on two
  ends already followed begins a new connection once the old one ended or its window closed;
- **twice, once without guessing** - `ndpiReader -C` writes a row for each connection it names, and
  leaves out those it cannot: that is from nDPI's source (de5c784), not measured - without `-v` it
  writes only the flows that have a protocol, and reads a file to its end without purging any flow;
  phase 0's lab had no connection nDPI could not name. It is run once as it is and once with `-d`, its
  own "use only DPI": a connection named only in the first run was named by a guess. One interface's
  file at a time, its two runs together - never more than two `ndpiReader` at once - and the file and
  its CSVs removed once read. A run that cannot start, fails, writes no CSV or is still going at 120
  seconds leaves that interface's connections of the window not judged: none called unknown, none put
  in a table;
- **the server** - the end a connection's SYN went to, or, with no SYN, the end its first packet went
  to. A connection whose beginning was not seen - open before the service started, or, without a SYN,
  heard from again after it was forgotten as idle - is not called unknown, and its server goes into no
  table;
- **its category** - the category nDPI's table of protocols (`ndpiReader -H`) gives its application, or
  its protocol when it has no application on top. The categories and the applications are those of
  the installed nDPI (`ndpiReader -a 1` and `-H`), read again each time the service starts. A table in
  which TLS is not in Web, or DNS not in Network, was not read as nDPI writes it: that is said, on the
  page too, and no category is taken from it, while the applications chosen in Settings fill their
  tables still;
- **a clock that steps** - back, or forward past windows not yet closed: the windows still open are
  dropped, counted in status.json, and the windows begin again with the one now;
- **JA4 and the server name** - read by the service from the client's first segments, put together:
  the ClientHello's server name, its first ALPN and its JA4 fingerprint as FoxIO's specification
  defines it. JA4 is read from TLS over TCP only; QUIC's ClientHello is encrypted, and for QUIC the
  server name is nDPI's.

Nothing holds a connection on the host until it is named: on an XGS, os-xgs-npu moves a connection
into hardware on its own schedule, and the service classifies what the host saw before that.

## How an application is blocked

The design is the plan's (svc-2-11) with phase 0's settled points 5 and 6: a table for the application
with an expiry, a block rule the plugin registers, and the connections open to it cut, by their two ends,
in the coprocessor first where os-xgs-npu is installed:

- **blocked** - an application chosen in *Blocked applications* whose table is in Firewall: Aliases, made
  by Apply as one of *Application tables* is, while classifying is on. Chosen and not applied yet, or
  with classifying off, nothing of it is blocked, and the page says so. An application is matched by
  nDPI's name or by the protocol carrying it: blocking TLS blocks TLS.YouTube too;
- **the rule** - `plugins.inc.d/appcontrol.inc` registers, at every filter reload, `block in quick to
  <appcontrol_<application>>` for IPv4 and for IPv6, on no interface, at priority 1 - before the rules of
  Firewall: Rules, as os-blocklists' are - described "Application Control: block" and the application's
  name, logged when *Log what is blocked* is on. Inbound on every interface: a device's packet to a server
  in the table is dropped where it enters, from a LAN, a VLAN or a VPN alike, on every port - so another
  service on the same address, a front end of Google's or a CDN's, is blocked as well; the firewall's own
  connections go out and are not held by it. It stops new connections only: pf lets a packet of a state it
  holds through before any rule;
- **what goes into a blocked table** - what a device sends names its connection, the server name of TLS and
  QUIC or HTTP's Host, and a device can write any name to any address: one TLS connection, or one UDP
  packet, naming the blocked application to the office's resolver would otherwise have the rule hold every
  device's connections to it. So a blocked application's table takes a server only from `cut.py`, and only
  when the firewall's own resolver - the system's, as `getaddrinfo()` asks it - gives that address for that
  name, within 5 seconds for a run's names together; an address written as a name, and no name at all, vouch
  for nothing. Nor does it take a server nDPI named, within the address expiry, as an application that is
  not blocked - Search and Gmail on a YouTube front end - and a server in it that a connection names as one
  is taken out: a QUIC connection to it is named from its first packet, which the rule drops after the
  capture has seen it - the latest four names of the latest 20,000 servers are kept for that, 7.7 MB at the
  most as measured here. A server nothing vouches for stays out of the table, and its connection alone is
  cut - the plan's "the block restricted to cutting the connection where it is needed". A table that becomes
  blocked is emptied first, so what went into it while its application was only in *Application tables*, on
  a name alone, leaves it; a restart that finds it blocked before (status.json) leaves it as it is. It never
  holds the firewall's own addresses, those of its internal networks, nor an address that is not on the
  internet - private (RFC 1918), shared (RFC 6598), unique-local - as Python's `ipaddress` has them: a host
  at a VPN's other end, behind a static route or on a DMZ is neither put in a table nor cut, so the rule
  shuts no one out of the firewall nor off one of its sites;
- **the cut** - once a window is judged, each connection nDPI named as a blocked application, by its
  packets, begun here, to an address of the internet, is handed to `cut.py` with its two ends and the name
  it carried. `cut.py` puts its server in the table when the resolver vouches for it, then kills by its id
  every pf state holding both ends - the one on the internal interface and the one out of the WAN, whose
  original ends pf writes after NAT - of the connection's protocol, not over, and made within 5 seconds of
  the connection's first packet, as os-xgs-npu's and os-blocklists' JA4 cuts match: another application on
  the same server is not cut, nor a later connection on the same ends, nor another device's older one on
  the ends a forged packet named. The first packet's time is kept on the monotonic clock beside tcpdump's,
  as pf counts a state's age, so a clock that steps changes nothing. The states are looked up by their
  ends, read once: 5,000 connections against 37,000 states were matched in 0.04 seconds on the
  workstation the checks ran on, where matching every pair took 15.6. It runs beside the capture, one run
  at a time, at most 5,000 connections a run and 20,000 waiting; it stops its kills at 90 s and gives back
  the connections it did not reach, and one stopped at 120 s has its connections queued again - two runs
  each, then they are left and said. A connection whose application is no longer blocked is dropped from
  the queue, and `cut.py` leaves one whose application is not blocked when its run begins. What it could
  not do is the page's last error. A guess, a connection whose beginning was not seen, and one to the
  firewall, a host of its internal networks or an address not on the internet are never cut;
- **in hardware first** - where os-xgs-npu is installed, `cut.py` loads its `hwdrop.py` from its own
  place, not a copy, and has `drop_ends()` drop those connections on the coprocessor before the first
  state is killed, each state's ends apart with its protocol - with XGS: Settings' *Cut in hardware* on,
  at once and both ways; off, each driver takes a connection out of hardware once pf has let go of its
  state. The step has 5 seconds in a thread of its own; past them, or failing, the pf cut goes on and
  how many were dropped is "unknown", as os-blocklists has it. Without os-xgs-npu, pf alone. An os-xgs-npu
  whose `hwdrop.py` has no `release_addresses()` - its release of 2026-11-08, whose `drop_ends()` takes no
  protocol and matches nothing given one - is asked nothing, and the page says it is too old;
- **blocked later** - the service remembers the connections it named that could be cut - the latest
  50,000, for a day, some 9 MB at the most as measured here; one seen to end, or a UDP question and its
  answer, not at all - and when an application becomes blocked, those it remembers as it are cut at
  once and their servers put in its table the same way, when the resolver vouches for them, so its rule
  holds them before a new connection to them has to be named. Apply has the service read its settings
  again (`rc.d/appcontrol reload`, a SIGHUP, which mounts the window files' tmpfs first should it be
  gone) rather than restart it, which would forget them; the service sets its SIGHUP handler before
  anything else it loads, so a reload in its first moments does not end it;
- **handed back** - a connection the coprocessor dropped stays dropped there while its sender goes on
  sending (os-xgs-npu's `hwdrop.py`). `cut.py` writes down each server whose connections were dropped,
  with its application and the block it was dropped for - every device, or a rule of the Rules tab - and
  nothing of the device - no address, port or time - and `cut.py release` - run by Apply and by the
  removal - hands back, by their servers, those of a block that no longer stands - an application no longer
  blocked, or the rule they were dropped for removed while another still blocks it - unless a block still
  standing holds the same server. pf then decides their packets
  again, their states gone. The list is written under a lock that a cut holds only while it adds to it,
  so Apply's hand-back never waits out a cut; a hand-back has 30 seconds, its whole flow table read, and
  what it could not do is said after Apply and kept for the next. With os-xgs-npu gone since, nothing is
  in hardware to hand back; with its `hwdrop.py` there and too old or not loading, the list is kept;
- **counted** - the connections cut, the pf states killed and how many the coprocessor dropped, in
  status.json and on the page; the servers put in a blocked table and the connections cut alone, in
  status.json; and, for each blocked application, the packets its two rules stopped, read from pf's own
  counters (`pfctl -v -s rules`), which start again at 0 whenever the rules are loaded - any Apply in
  Firewall, an interface or gateway event - unless OPNsense's own keep-counters option is on: the page says
  "since the rules were last loaded".

An allowed connection is not held: it goes into hardware on os-xgs-npu's own schedule, as before. Phase
0's lab found the host had seen enough of every connection it tried before that - 8 packets at most were
needed, at a round trip of 50 ms too - so nothing waits for its classification.

## How a rule of the Rules tab acts

The design is the plan's (top-01) with phase 0's settled points 8 and 9: OPNsense's own rule has no field
for an application, and no plugin can give it one - a field added to its model is gone at the next update -
so the rules are a grid on the plugin's page, and each becomes a pf table, a pf rule, a cut and a Suricata
rule:

- **a rule** - switched on or off, its action (Block or Alert), its source, inverted or not, its
  application as the installed nDPI names it, and a description; kept through the plugin's own model as
  the dialog saves it, put into the firewall by Apply, the same as the Settings tab's. Its source is what
  OPNsense's own rules take for one, through the same selector: any, an interface's network - a group's
  too, OpenVPN's or WireGuard's - an alias, or an address or a network written by hand; several at once,
  but any and an address written by hand only alone, as OPNsense's own selector keeps them; or one of them
  inverted - every device but those. The model refuses what names no device connecting through the
  firewall - the firewall itself, an address of one of its interfaces by its name or written by hand as
  config.xml gives it one (a virtual IP's too), a table of this plugin's, which holds servers - and, as
  OPNsense's own rules do, any with others and an inverted source of more than one item. An exception for
  one device is a rule whose source is every device but that one;
- **its table** - the application of each rule switched on gets its table, as one of *Application tables*
  does; one with a block rule takes a server by `cut.py` alone, once the firewall's own resolver vouches
  for it, as a table of *Blocked applications* does (above);
- **Block, in pf** - `plugins.inc.d/appcontrol.inc` registers `block in quick from <source> to
  <appcontrol_<application>>`, IPv4 and IPv6, at priority 1, after the rules of *Blocked applications*,
  the source written as OPNsense writes its own rules' (`Rule::mapAddressInfo()`): an interface's network
  as `(device:network)` - with `fe80::/10` beside it in IPv6, as OPNsense adds it - an alias as its table,
  `!` before one inverted. Each family takes the elements of its own: an address or a network written by
  hand goes into its own family's rule alone - pfctl refuses a rule that holds an address of the other family
  alone, and with it the firewall's whole ruleset - a family left with nothing gets no rule, and inverted, an
  address of one family leaves every device of the other in the source: that family's rule is from any.
  Described "Application Control: block", the application and "from" the source, the interfaces by their
  descriptions; logged when *Log what is blocked* is on. A device outside the source is let through to the
  same servers;
- **Block, the cut** - a connection nDPI names as the application, or the protocol carrying it, is cut
  when its device's address is one of the source - an interface's networks as `ifconfig -a` lists them, a
  group's as the `groups:` lines of `ifconfig -a` name its members, an alias's table as pf holds it (an entry
  written with `!` taking addresses out, as pf has it), an address or a network as written - each read again
  at each window's close and at Apply. An element that cannot be read - an alias pf holds no table for -
  holds no device: nothing is cut for it, and that is said once as the last error; the rest of the source
  still acts. Blocked for every device by *Blocked applications*, any device's connection is cut, and
  nDPI's application comes before the protocol carrying it, as there. The rest is the second part's: the
  two ends, the hardware first, what is remembered cut when a rule comes in - for the devices of its source
  alone, and again when a source gains a device (an alias's table that changed) - and what waits for a cut
  looked at again when the rules change, whether its server is shared asked again for the application it is
  cut as. `cut.py` judges each connection by what the classifier holds in force - the last Apply's, written for
  each run, not config.xml as saved since - with each rule's source resolved again as its run begins and the
  policy read again before its kills. A server two applications share goes into the table of one only when
  the other's block reaches every device the first one's does - the same elements of a source, or every
  device; else that connection alone is cut, and a server in a table that a connection names so is taken out
  of it. Two names for the same devices - an alias and an interface's network - are not taken for the same.
  Each cut is counted for its rule;
- **Suricata** - at Apply, `suricata_rules.py` renders the plugin's template
  (`templates/OPNsense/AppControl/appcontrol.rules`, with Jinja2, as configd renders OPNsense's own -
  but not by configd, which holds neither the names nor the addresses) into
  `/usr/local/etc/suricata/rules/appcontrol.rules`, the directory whose files the Intrusion Detection's
  `installRules.py` installs beside its own user rules (phase 0's L8: a file there, then `configctl ids
  reload` - installed, alerting on a test name three times, gone once removed). When the file changes,
  Apply runs `ids reload`. The classifier keeps it current while a rule is switched on: as it starts - at
  boot among them - it writes it as the settings say, as it reads its own, the names of the nDPI it has just
  read among them; then every five minutes it resolves the rules last applied again - an alias whose table
  changed, a hostname or a MAC seen at another address, a new delegated prefix, an interface - and the file
  is written, and `ids reload` run, only when that changed it - or when such a reload failed before, configd
  busy; a rule saved and not applied does not come in that way. One writer at a time, each through a file of
  its own beside the target. Each rule switched on gives:
  - a line for each name the installed nDPI knows its application by - its host table, `ndpiReader
    --protos-dump 1`, read with its catalogue - in each of the four places a device writes one: the server
    name of TLS (`tls.sni`) and of QUIC (`quic.sni`), HTTP's Host (`http.host`) and the name a DNS question
    asks for (`dns.query`). A name matches as nDPI's own `ac_domain_match_handler()` matches it (nDPI's
    commit de5c784): the name, or one ending in it after a dot; written with a last dot, one label after it
    and no more; with a last hyphen, the beginning of a label; with a first hyphen, the end of a name after a
    hyphen. The content is Suricata's fast pattern, a pcre the boundary; `nocase` but on `http.host`, which
    Suricata refuses it on, its buffer lower case already;
  - a line for its protocol, `app-layer-protocol`, when the application is one Suricata reads by itself
    with its parser on in OPNsense's `suricata.yaml`: TLS, HTTP, DNS, QUIC, SSH, SMTP, IMAP, FTP, Telnet,
    DHCP, SNMP, NTP, TFTP, NFS, Kerberos, SMB, VNC, RDP, SIP, MQTT and Modbus;
  - `drop` for Block, which Suricata does in the Intrusion Detection's IPS mode and alerts on in its IDS
    mode, `alert` for Alert; its source as the addresses it holds now, `!` before it inverted, and never the
    firewall itself: its own addresses, every one `ifconfig -a` lists, are taken out of every source - any is
    every address but them, an inverted source leaves them out with its own, one inside a source's network
    is an exception in its group (`[network,!address]`, Suricata's own way of writing it). A group that
    would negate the whole of one family, which Suricata refuses, is written as the other family's whole
    space less its exceptions; one that would negate both gives no line, as pf's `!<table>` of such an alias
    blocks nobody. A source that cannot be read in part gives the rest, as pf and the cut act on it; an
    inverted one needs every element;
  - its destination the internet alone, as the cut has it: every address but the firewall's own, those of
    every network it is connected to and the blocks that are not the internet's - private, shared, loopback,
    link-local, documentation, unique-local, multicast and the reserved block. In IPS mode, where Suricata
    sits before the host and before pf, a line so never drops a device's connection to the firewall - its
    web GUI, ssh, its resolver, DHCP - nor to a host of its own networks, a private one or a site over a VPN;
    nor, on the WAN, the firewall's own connections;
  - one alert a device a minute for each line (`threshold`), a drop still dropping each packet; its message
    the plugin's, its action, its application and its description; its sid its own while its rule stands,
    from a hash of the rule's uuid and what the line matches, between 3,000,000,000 and 3,999,999,999 - far
    below OPNsense's own user rules, which count down from 4294967294 - two lines meeting on one taking the
    next free. A change the Intrusion Detection's page makes to one of these lines by its sid - switched off,
    its action - stays with that line when another rule is deleted or nDPI gains a name, and goes with it;
    the plugin's lines are changed on its own page;
  - none, said on the Rules tab, when Suricata can tell its application by neither, when its source cannot
    be read or holds no device's address now, when a line would pass Suricata's own limit of 8,192
    characters, or past 9,999 lines for one rule.

  Each file new to Suricata is tested by Suricata itself before it is installed, as suricata-update tests
  one: `suricata -T -S` with OPNsense's own `suricata.yaml`, so with its parsers on or off as there, in a
  folder of its own under `/var/db/os-appcontrol`. A line it refuses, named by its line in the file, is kept
  out, the rest tested again, and the Rules tab says how many of a rule's lines Suricata refused and what it
  said; a test failing without naming a line leaves the file as it is and the tab says Suricata's last words;
  with no `suricata.yaml` - the Intrusion Detection never set up - nothing is tested and the tab claims
  nothing. While a line is refused, every look tests again what it would write with it, so a parser switched
  on since takes it.

  Suricata sees a device's own address before NAT only, on an internal interface the Intrusion Detection
  reads; the Rules tab says whether it is on, in which mode, on which interfaces - and when none of them is
  internal - and whether Suricata runs. Its alerts are in Services: Intrusion Detection, under the plugin's
  message. The 1,647 names of ndpi-6.0.d20260909,1 that phase 0's lab read on the second XGS 3300 all give
  lines - 6,588, 368 characters at the longest - in a run here on that dump, not kept in the repository;
- **what the tab says** - each rule's state against what the last Apply put in force, by a digest of what
  each rule applied puts in force, kept with the Suricata rules: in force; changed, not applied yet - pf, the
  cut and Suricata still act as before; switched off; its source cannot be read, or holds no device's address
  now - it acts on none; not applied yet when its table is not made. The rules deleted since the last Apply,
  which act until the next, are counted under the grid, and the grid carries OPNsense's own reminder to
  apply, as the Intrusion Detection's page has it;
- **the removal** - the rules file goes with the plugin, and `ids reload` follows, by `uninstall.sh` and by
  the package's removal alike - also when only its installed copy in `opnsense.rules/` is left, a reload
  having failed before; classifying off takes it away at Apply.

## Not yet, and why

- **the page in a browser, an address expiring, beyond 1 Gbit/s** - the plugin has run on the second
  XGS 3300, the XGS 136 and a plain OPNsense (below), driven from the shell through the calls the page
  makes; the page itself has not been opened in a browser. An address leaving its table at its Expire,
  the tables over a day, and the cost above the 941 Mbit/s the lab carried are not measured.
- **`ndpiReader -H` and `-a 1` as other nDPI builds write them** - their format here is the source's
  (nDPI's commit de5c784, the package's): `ndpi_dump_protocols()` and `ndpi_generate_options()`. Those
  of ndpi-6.0.d20260909,1 were read on the three systems below: 99 categories, so `-a 1`'s
  (`categories.json` has 93), and the table of protocols believed - its servers went into Web, Cloud,
  Media and Network. If `-a 1` gives nothing, `categories.json`, nDPI's categories as that commit names
  them, stands in; `apps.py check` says how the two differ.
- **a category given by a host name** - nDPI can give a connection a category of its own from its host
  list; the table here is its application's category from `-H`. How often the two differ is not
  measured. Each connection's own category, which `ndpiReader -K json` gives, is phase 2's.
- **category 32** - categories.json and the page's map leave out nDPI's category 32. The installed
  nDPI's `-a 1` names it all the same, so its table is made at runtime, under nDPI's English name, which
  the page shows untranslated; and when categories.json stands in for `-a 1`, that category's protocols
  drop out of the protocol map - offered in no Settings list, their servers in no category table.
- **bytes per application** - counted from pf's states: the research left it on the lab's L4, and it is
  not built.
- **blocking on an appliance** - the block rules, the cut and the hand-back have run here only, against
  stand-ins (below), not yet on an XGS or a plain OPNsense. What they rest on was measured elsewhere: a
  TLS stream in hardware whose pf states were killed by their ids stopped within the two seconds that
  measurement was read in (os-xgs-npu's `docs/measurements/ja4-cut-2026-10-19.md`), and `hwdrop.py`'s
  drop and hand-back stopped and then let through again a 200 Mbit/s stream on the second XGS 3300
  (os-xgs-npu's `docs/measurements/hand-back-2026-11-17.md`). How many packets the rules stop, and how
  long a cut takes on a busy firewall, are not measured.
- **the first connection to a new server** - a server goes into a blocked application's table when a
  connection to it is named and the resolver vouches for it, so the first one to a server its table does
  not hold yet runs until its window is judged - some 10 to 70 seconds - and is cut then. A server leaves
  the table once unseen for the address expiry, and a blocked try is never named, so each server is
  learned again about once an expiry. Shorter windows while something is blocked are not built: the cost
  of the windows was measured at 60 seconds.
- **a server cut alone** - one nothing vouches for stays out of the table: each new connection to it runs
  until its window is judged and is cut then. That is so for a device whose names come from a resolver
  of its own - DNS over HTTPS, say - when the firewall's resolver gives other addresses for the same name,
  for a name written as an address, and for an application nDPI names with no name at all. A connection
  over UDP - QUIC - takes a new pf state with its next packet once its own is killed, so with pf alone it
  goes on; where os-xgs-npu drops it on the coprocessor (*Cut in hardware* on) it stops. A block of one
  device's connections to one server, in pf, for a connection cut alone, is not built.
- **a name of one's own domain** - the resolver vouches for what a domain's own name servers say: a
  device whose owner has a domain, and gives a name in it that nDPI takes as the application's, can still
  have the firewall's resolver give an address of his choosing for it, and that address goes into the
  table. A single `curl --resolve`, or one forged QUIC packet, no longer does. Corroborating the address
  in the capture itself - the device's own DNS answer seen going to it - or a block that holds only the
  devices seen using the application are not built.
- **what is not cut** - a guess, a connection whose beginning was not seen, one to the firewall, a host
  of its internal networks or an address not on the internet, and one on an interface the service does
  not read; the rule still stops a new connection to a server in the table on every interface. What the
  service remembers since it started - the latest 50,000 for a day - is forgotten by a restart: a boot,
  an update, `install.sh`.
- **a category blocked** - an application alone can be chosen, in *Blocked applications* or in a rule of
  the Rules tab; a category's table can be named in a rule of the owner's own.
- **the Rules tab on an appliance** - its pf rules, its cuts and its Suricata rules have run here only,
  against stand-ins (below). No Suricata has read the rules file yet: each file is tested by Suricata itself
  on the firewall before it is installed, but whether Suricata 8.0.8, as OPNsense 26.7 builds it, takes every
  line - `quic.sni`, the pcre, the threshold, the 22 protocols - and alerts and drops on them, and what a
  reload of many lines costs, are the lab's. The checks here run no Suricata: none could be run where they
  were written, and a check of a Suricata of the runner's, with a `suricata.yaml` guessed at, would judge
  another build and other parsers than the firewall's own test does.
- **a pass rule** - a rule letting a device through what *Blocked applications* blocks for every device is
  not built: that block comes first and is final, and a pass rule ahead of it would also take that device's
  traffic past every rule of the owner's own. An exception is a block rule whose source is every device but
  that one, with the application not in *Blocked applications*.
- **a Suricata rule's source as it changes** - the pf rule and the cut follow an alias whose table changes,
  or an interface's network, at once; Suricata within five minutes, each change installing every rule of the
  Intrusion Detection again (`ids reload`), and not while the classifier is stopped. After an nDPI update,
  Suricata's names follow at the classifier's next start or at Apply, as the categories do.
- **a source narrowed** - what was dropped in hardware for a rule is written down by server, with nothing of
  the device; so a rule whose source is narrowed hands nothing back, and the devices left out keep their
  dropped connections until their senders stop. A rule removed or switched off hands back.
- **an address of one family, inverted** - every device but 192.0.2.5 leaves out that address alone: the same
  device's IPv6 address is blocked, in pf, the cut and Suricata alike. An alias holding both its addresses
  leaves the device out.
- **the Intrusion Detection's own changes** - a line changed by its sid on the Intrusion Detection's page keeps
  the change while its rule stands. Whether an Intrusion Detection policy - "alert to drop" for every ruleset,
  say - reaches a local file such as this one was not read: it would turn the plugin's Alert rules into drops,
  and it is the lab's.
- **who may make Suricata drop** - the page's privilege (`page-firewall-appcontrol`) writes the Intrusion
  Detection's local rules and runs `ids reload`: a user with this page and not the Intrusion Detection's can
  make Suricata drop. It adds nothing to what the page could do already - its Block rules block in pf - and
  OPNsense gives a page one privilege; it is said here rather than split.
- **a name nDPI gives a narrower application** - nDPI takes the most specific of its names that match a
  host - youtube-ui.l.google.com is YouTube's though google.com is Google's - and a Suricata line matches on
  its own, so a rule of Google takes that host too.
- **what Suricata sees** - a device's own address before NAT, on an internal interface the Intrusion
  Detection reads: on the WAN, after NAT, a rule's source matches no device's IPv4 address, and the tab says
  when none of the interfaces it reads is internal. In IDS mode its rules alert and drop nothing; the pf rule
  and the cut block all the same. A Suricata line takes a connection to the internet alone, as the cut does:
  a DNS question to the firewall's own resolver for a blocked name is not dropped - its connection is still
  stopped by the server-name lines and by pf - and a Block rule of SMB from the guests leaves their SMB to an
  office server, as a Block rule of a protocol leaves the firewall's own services.
- **packets, not connections** - what the rules stopped is pf's count of packets, since the rules were
  last loaded: one try of a connection is several. The rule drops; a client is not told, and waits for
  its own timeout.
- **routing by gateway** - phase 4.
- **at line rate** - the service reads at most 2,000,000 packets an interface in a window - the rest
  waits - and follows at most 100,000 connections begun in one window, keeping 32 MiB of their packets;
  the page says how many windows were cut short. Its cost was measured at 941 Mbit/s (below); the rate
  it holds beyond that was not.

## What is tested

On 2026-11-17, from this branch, away from an appliance - the checks, run under Python 3.14 and PHP 8.5:

- **the classifier** - `tools/test-classify.py`, 157 checks:
  - ndpiReader's CSV as phase 0's lab read it on an XGS 3300 with ndpi-6.0.d20260909,1
    (`tools/fixtures/lab-*.csv`, every address made a documentation one): the connections and names
    the lab counted - TLS.Wikipedia, TLS.Cloudflare and TLS.Mozilla 11 each and DNS 8, TLS.YouTube 12
    and TLS.Twitch 12, HTTP.Canonical 20, SMTP 5 - and a file of the header alone giving none;
  - the catalogue: categories and protocols from `-a 1` and `-H` in the source's format, and
    `categories.json` in their stead; a table of protocols in which TLS is not in Web or DNS not in
    Network said by `apps.py refresh`, and taken for no category by the service;
  - the alias names: at most 31 characters, `_` for any other character, a long one cut with a suffix
    of its own, every category's name its own;
  - the capture, on packets built byte by byte: the pcap stream in chunks, a connection's server, the
    ClientHello put together from two segments, in order or not, and the JA4 of FoxIO's own example,
    `t13d1516h2_8daaf6152771_e5627efa2ab1`; IPv6 behind a VLAN tag and an extension header; padding,
    fragments, tunnels; the first 16 packets of a connection kept in its window and the rest counted;
    a window's bytes checked before each packet, and a connection cut short by them not called
    unknown; a ClientHello's pieces let go at the 16th packet and at the window's close; a SYN on ends
    used before beginning a new connection once the old one ended or its window closed, and not while
    it is open; a UDP connection heard from again after it went idle not taken as begun, and one an
    hour later taken as begun;
  - each connection named, guessed or unknown, and what goes into which table: a guess, an unknown
    connection, one open before the start and a row no capture matched never do; an address new to a
    table added, one there refreshed; the Unknown list kept to its latest 500 of each kind, and a
    protocol named alone listed only for a connection begun here;
  - never in a table: `ifconfig -a` as FreeBSD writes it - netmasks in hex, `/25`, `prefixlen`, a CARP
    address, a point-to-point link - read for the firewall's own addresses and its internal networks;
    ICMP and ICMPv6, multicast, broadcast, link-local, loopback and unspecified addresses, the firewall
    and a LAN host kept out and counted with the reason, a server out there or on the WAN's network
    put in, and nothing put in while the addresses are not read;
  - the interfaces read by default: the internal ones - not the WAN, static or not, nor one with a
    gateway, its own or one of System: Gateways, or an address from upstream;
  - a packet the reader cannot make sense of counted, and the capture going on; a capture that stops
    again and again started after 30 s, the wait doubled to 10 minutes, said once, and said again
    when it reads again;
  - ndpiReader: one interface's file at a time, never more than two runs at once, each file gone once
    read; a run that fails, one that writes no CSV and one still going at its time - and the interface
    after it, never run - each leaving its connections not judged;
  - one run of the service with stand-in `tcpdump`, `ndpiReader`, `ifconfig` and `mount` programs and a
    stand-in `pfctl`: `tcpdump -p -U`, ndpiReader twice, the tables, status.json and unknown.json, the
    firewall's addresses read at the start and at each window's close, its files removed and tcpdump
    stopped when it ends; and runs of it with ndpiReader failing, nDPI's protocols not to be believed,
    the clock set 1000 s forward and 1000 s back, an interface switched off and another assigned while
    it runs, no interface until one is switched on, the work directory not in memory, and nDPI
    missing;
  - `status.py`: each application with its table and the addresses pf holds there, the category
    tables, what reading the catalogue found wrong and when, and a pidfile believed only when its
    process is the classifier;
- **the aliases** - `tools/test-aliases.php`, 21 checks, with stand-ins for OPNsense's Alias model whose
  validation is the model's own for the fields written (OPNsense 26.7's `Alias.xml`,
  `AliasNameField.php` and `DescriptionField.php`): every alias the plugin would make for nDPI's 93
  categories and the applications of `-H` taken, and a name, a type, an Expire or a description the
  model refuses refused; an External alias with Expire made for each table, its Expire refreshed,
  nothing written when nothing changed, the owner's alias of the same name left; on removal every alias
  of the plugin's taken out, switched off instead where a rule or XGS: Settings still names it;
  `aliases.php` saving only after a clean validation, and touching nothing when the names cannot be
  read, `tables.py` fails or the model refuses a name;
- **the page's API** - `tools/test-mvc.php`, 18 checks, with stand-ins for OPNsense's MVC base: the
  status passed on and an answer it cannot read said, the grids' rows, and Apply's order - the aliases,
  the filter, cron, the tables of aliases gone, the classifier started again or stopped when off -
  with the tables taken out passed on to the page, nothing done after aliases not written but the
  classifier stopped when off, and nothing for a GET;
- **the installation** - `tools/test-install.py`, 37 checks: `install/install.sh`,
  `install/uninstall.sh`, the package's `post-install.sh`, `pre-deinstall.sh` and `post-deinstall.sh`,
  `place-menu.sh` and the rc script, in a temporary root with stand-ins for `service`, `configctl`,
  `pkg`, `pfctl`, `pkill`, `mount`, `umount`, `daemon` and `rc.subr`: every file laid down with its mode
  and taken away, the menu in XGS (59) or Firewall, nothing copied when a file has a syntax error, the
  package `ndpi` installed when missing and removed only when the installer installed it and nothing
  needs it, the classifier started on by default or stopped when off, the tmpfs of the window files
  mounted at its start - once - and taken down at its stop, running or not, and by every removal, the
  classifier stopped and the aliases taken out before the files go, the tables of aliases gone taken out of pf,
  and nothing done by the old package in an upgrade;
- **the self-update** - `tools/test-self-update.py`, 45 checks, as os-blocklists has it;
- **the strings** - `tools/check-strings.py`: each of the 156 strings the GUI shows is in `source.json`,
  nDPI's 93 category names among them through the page's map (`tools/gen-data-strings.py`); 38 had
  their Arabic in opnsense-arabic already, and the other 118 are in its pull request 80, merged first;
- **the rest of the checks** - every installed file removed by the uninstaller
  (`tools/check-uninstall.sh`), `php -l`, `py_compile` and pyflakes, `sh -n`, XML and JSON, nothing
  private, no Arabic in the code, the copyright line; and, by hand, the page kit and the page's script
  run under node with a stand-in jQuery - the Last error card with the catalogue's errors, and the line
  of windows cut short shown and hidden.

64 behaviours those tests cover were taken out in turn, on a copy, and the tests failed on each:
among them a guess judged as named, a connection open before the start put in a table, the WAN read
by default, `tcpdump` run without `-p`, the DPI run without `-d`, every packet of a connection kept,
the JA4's sorting, GREASE and supported_versions, an address seen again added instead of refreshed,
an alias made without Expire, one a rule names removed, Apply going on after the aliases failed, the
aliases taken out after the files, and `ndpi` removed though another package needs it. A first run
had found 7 of them untested: the tests reach 6 now, and the seventh changed nothing - a row with a
"|" in its last column is read either way. After the review of that day, each of its fixes was undone
in turn the same way - 68 changes, among them the byte cap checked only when a connection begins, the
firewall, a LAN host or ICMP put in a table, a failed ndpiReader's connections called unknown, every
interface's runs begun at once, a clock step not seen, the interfaces read once, the window files
written outside memory, a protocol table not believed used all the same, Apply leaving the classifier
running when off and an alias the model refuses saved - and the tests failed on each.

On the appliances and a plain OPNsense, the same day, from this branch at f782d49, as a user meets it:
`install/install.sh`, the classifier's first windows, the page's Apply with classifying off and then on
(set through the model, then the calls Apply makes, in its order), and `install/uninstall.sh`:

- **the second XGS 3300** (OPNsense 26.7.9_1, os-xgs-npu installed) - `install.sh` ended 0 in 6 s and
  installed `ndpi-6.0.d20260909,1` itself; XGS: Application Control; the window files on a tmpfs. The
  bench machine's traffic through F2 for 75 s (HTTPS, HTTP, DNS): after two windows, of 94 connections
  88 named and 6 guessed, 5 named by their protocol alone; 18 servers in the category tables; the
  firewall's own addresses (4), addresses that are no server's (15) and a LAN host (1) kept out; 99
  category tables, their 99 aliases External with Expire 3600
  ([photograph](docs/images/measurements/phase1-install-2026-11-17.png));
- **its cost** - four TCP streams through F2 for 40 s, the CPU time taken over 30 s: with os-xgs-npu's
  flow maker on (a connection in hardware after its first packets), 940 Mbit/s, `tcpdump` 0.3% and the
  classifier 2.4% of one core, the box 99% idle; with it off (every packet through the host), 941
  Mbit/s, 6.8% and 62.9%, 85% idle; 29 MB resident; no window cut short
  ([photograph](docs/images/measurements/phase1-cost-2026-11-17.png));
- **Apply and the removal** - off: the classifier stopped, its 99 aliases out of Firewall: Aliases, its
  99 tables out of pf; on: all back; `uninstall.sh` ended 0 in 4 s: no file of the plugin under
  /usr/local, `/var/db/os-appcontrol` gone, `ndpi` removed, no tmpfs, no table, no alias, config.xml as
  before but for the saves' stamps and the plugin's own settings
  ([photograph](docs/images/measurements/phase1-cycle-2026-11-17.png));
- **the XGS 136** (OPNsense 26.7.9_1) - `install.sh` 0 in 8 s, `ndpi` installed by it, XGS: Application
  Control; no lab traffic through it: its own interfaces' 29 connections all named and none in a table -
  its own addresses (12) and addresses that are no server's (15); Apply off and on, and `uninstall.sh` 0
  in 4 s, nothing left ([install](docs/images/measurements/phase1-136-install-2026-11-17.png),
  [Apply and removal](docs/images/measurements/phase1-136-cycle-2026-11-17.png));
- **a plain OPNsense** (26.7.7, the nano image in qemu, no os-xgs-npu) - `install.sh` 0 in 10 s, `ndpi`
  installed by it, Firewall: Application Control, the window files on a tmpfs; nothing through it to
  classify; Apply off and on, and `uninstall.sh` 0 in 8 s, nothing left
  ([install](docs/images/measurements/phase1-plain-vm-install-2026-11-17.png),
  [Apply and removal](docs/images/measurements/phase1-plain-vm-cycle-2026-11-17.png)).

Found by the first run on the 3300 and fixed in this branch: the tables of aliases gone were only
emptied, so 99 stayed listed in pf after Apply off and after the removal, until the next boot. They are
taken out now, by Apply, `uninstall.sh` and the package's `post-deinstall.sh`, and the runs above found
none left.

Not tested: the page in a browser, an address expiring, beyond 1 Gbit/s (above).

On 2026-11-20, from the branch of the second part, away from an appliance - its checks, run under Python
3.14 and PHP 8.5, and the first part's run again beside them, all passing:

- **the cut** - `tools/test-cut.py`, 42 checks, with a stand-in `pfctl` and a stand-in of os-xgs-npu's
  `hwdrop.py`, loaded from a folder of its own as the real one is: pf's states as `pfctl -ss -vv` writes
  them - IPv4, IPv6, a state after NAT with its original ends, one written with `<-`, its age, one over;
  a connection's states those holding both its ends, of its protocol, made no later than its first packet
  and not over - not another client of the same server, a UDP state on the same ends, one over, nor a
  later connection on the same ends; each killed by its id; `hwdrop.drop_ends()` asked once, before the
  first kill, with each state's ends and its protocol; without os-xgs-npu, pf alone; a hardware step that
  fails, or is past its deadline - left there, no second one beside it - "unknown", the pf cut done at
  once; the module search path as it was; what the coprocessor dropped written down, the latest 10,000,
  and nothing when it dropped none; the hand-back of an application no longer blocked - unchosen, its
  alias gone, classifying off - by its servers, less a server an application still blocked holds; a
  hand-back that fails kept for the next; os-xgs-npu gone since; the command line's answers, one run at
  a time, and a fault of its own said, never raised;
- **the block rules** - `tools/test-rules.php`, 17 checks, with stand-ins for OPNsense's Firewall Plugin
  and Alias model: two rules, IPv4 and IPv6, for each application blocked - block, inbound, quick, to its
  table, on no interface, priority 1, described with its name, logged as the setting says - and none for
  one not chosen, one not applied yet, an alias switched off, a category's, an owner's alias of the same
  name, or one not External; none with classifying off or nothing chosen; the start at boot as it was;
- **the classifier** - `tools/test-classify.py`, 196 checks, 39 of them new: the settings read; a table
  for each application blocked; what is blocked - chosen, its alias there, classifying on; what is
  remembered kept as its two ends packed, read back as they were; in a window,
  a connection of a blocked application queued for the cut after its server is in its table - not a
  guess, one not begun here, or one to a LAN host - and of the protocol carrying it; nothing cut for one
  chosen and not applied yet; the others remembered, the latest of them for a day - not one seen to end,
  nor a UDP question and its answer;
  an application blocked later cut at once from what is remembered, its servers put in its table; what
  waits for a cut kept to its bound, and said; `cut.py` run beside the capture - its answer counted, per
  application too, at most 5,000 a run, one run at a time, one past its time stopped, one that cannot be
  run or whose answer cannot be read said; a run of the service with an application blocked, its
  connection cut; one in which it becomes blocked by a SIGHUP, its remembered connection cut without a
  restart; a service waiting for what it needs looking again at a SIGHUP; `status.py`: blocked or chosen
  and not applied yet, the connections cut, the packets of its two block rules and of no other rule
  naming its table, and os-xgs-npu's *Cut in hardware*;
- **the page's API** - `tools/test-mvc.php`, 19 checks: Apply reads the classifier's settings again
  instead of restarting it, then hands back from hardware and passes the count on;
- **the installation** - `tools/test-install.py`, 39 checks: the removal - `uninstall.sh` and the
  package's `pre-deinstall.sh` - hands back from hardware once the aliases are out, while `cut.py` is
  there; `rc.d/appcontrol reload` sends the running classifier a SIGHUP, and starts one not running;
- **the strings** - 171 the GUI shows, every one in `source.json`; 14 of the 16 new wait for their Arabic
  in opnsense-arabic;
- **the rest** - `tools/check-uninstall.sh`, `php -l`, `py_compile` and pyflakes, `sh -n`, XML and JSON,
  nothing private, no Arabic in the code, the copyright line; the page kit ("kit"), and the page's script
  run under node with a stand-in jQuery: the line of what is blocked, with *Cut in hardware* on, off and
  without os-xgs-npu, one chosen and not applied yet, and nothing blocked; the Blocked column.

45 behaviours of the second part were taken out in turn, on a copy, and the tests failed on each: among
them a connection cut by its server alone, a UDP state cut for a TCP connection, a later connection on
the same ends cut, the hardware step after the kills or with no deadline, a server still blocked handed
back, a failed hand-back forgotten, a guess cut, a blocked application's servers not put in its table,
what is remembered never forgotten or its ends packed the wrong way round, a cut run never stopped, a
SIGHUP not acted on, an owner's rule on an interface counted as the plugin's, the rules after the
owner's or outbound, Apply restarting the classifier, and the removal not handing back. A first run had
found one of them untested - an owner's alias by the plugin's kind of name whose description would
have read as an application's - and the tests reach it now.

After the review of the second part, the same day, each of its findings was fixed in this branch and
tested the same way - all the checks above run again, all passing:

- **the cut** - `tools/test-cut.py`, 62 checks now: a server put in its application's table before any state
  is killed only when the resolver stand-in gives that address for the name its connection carried, and not
  for a name written to another address, an address written as a name, no name, a name not answered within
  the deadline, nor a server classify.py found shared; a connection of an application no longer blocked
  left; a state made more than 5 seconds before its connection began - another device's, two hours old, on
  the ends a forged packet named - not cut; 5,000 connections against 37,000 states matched in well under a
  second; the kills stopped at the run's budget and the connections not reached given back; an os-xgs-npu
  with no `release_addresses()`, and one not loading, asked nothing - their list kept by a release; the
  servers written down with their application alone, each once; a release's own 30 seconds; a cut never held
  up by a release's lock;
- **the classifier** - `tools/test-classify.py`, 226 checks now: no server put in a blocked table by the
  classifier, a table that becomes blocked emptied once and not at a restart that finds it blocked
  before; one forged QUIC packet's address in no table, its connection queued with the name it carried;
  a server named as an application not blocked, in the same window or within the expiry, cut alone, and
  one in a blocked table so named taken out of it; a connection to an address not on the internet -
  203.0.113.0/24 standing for a site over a VPN - neither cut nor tabled, at once or when remembered;
  what waits for a cut dropped when its application is unblocked, at a window and at a SIGHUP;
  connections a cut did not reach, or one stopped at its time, queued again for a second run, then left
  and said; a connection's first packet on the monotonic clock, a clock stepped 30 s leaving two
  connections 5 s apart there; SIGHUP's handler set before anything else is loaded; os-xgs-npu too old
  for the cut in hardware said by `status.py`;
- **the installation** - `tools/test-install.py`, 40 checks now: `rc.d/appcontrol reload` mounts the
  window files' tmpfs first when it is gone, then sends the SIGHUP;
- **the page** - its script under node with a stand-in jQuery: the line of what is blocked with *Cut in
  hardware* on, off, os-xgs-npu too old and absent, the packets "since the rules were last loaded", and
  Apply's line with what the hand-back could not do; the strings - 173 the GUI shows, every one in
  `source.json`, 16 of them waiting for their Arabic in opnsense-arabic.

36 behaviours of these fixes were taken out in turn, on a copy, and the tests failed on each: among them
a server tabled whatever the resolver says, a shared one tabled all the same, an address written as a
name vouching, a table that becomes blocked not emptied, the age check one way only, no budget for the
kills, a run stopped at its time not queued again, a blocked connection to an address not on the
internet cut, what waits for an unblocked application kept, a cut holding the lock for its whole run, an
os-xgs-npu too old asked all the same, the device written down beside its server, the wall clock's time
handed to the cut, SIGHUP's handler set late and a reload that does not mount the tmpfs. The old
matching, every state against every connection, put back: the timing check alone failed.

Not run: anything of the second part on an appliance or a plain OPNsense, and its page in a browser.

On 2026-11-20, from the branch of the third part, away from an appliance - its checks, run under Python
3.14 and PHP 8.5, and those of the first two parts run again beside them, all passing:

- **the Suricata rules** - `tools/test-suricata.py`, 42 checks, new: a name of each shape nDPI writes - a
  name, a last dot, a last hyphen, a first hyphen, both - in each of the four places, as its options are
  written, and what they take run against 19 host names the same as nDPI's own `ac_domain_match_handler()`,
  written again in the test, takes; `nocase` everywhere but `http.host`; a name of other characters refused;
  a source as Suricata writes addresses - any, an interface's networks without link-local, several at once,
  an alias with an entry written with `!` taken out, inverted - and why one cannot be: not read, holding no
  address, the firewall itself; the message without quotes, backslashes or semicolons; each rule's lines -
  its protocol, its names, drop for Block and alert for Alert, its sids - or why none; the plugin's own
  template rendered, every line well formed, under Suricata's limit, its sid its own, the `http.host` line
  without `nocase`; the file written in one step, not again when nothing changed, removed when classifying
  is off or no rule gives a line, left as it was when config.xml or the template cannot be read; a line past
  the limit taking its rule out; the command line's answers;
- **the classifier and the tables** - `tools/test-classify.py`, 274 checks, 48 of them new: the rules read
  from config.xml, numbered, one of another action or with no source switched off; a table for each rule's
  application; whom each application is blocked for, and when one block reaches every device another does;
  a source's elements resolved - an interface's networks from `ifconfig -a`, an alias's table from pf with
  its `!` entries, the firewall itself refused; a window with a rule of the guests: a guest's connection
  queued for that rule, a LAN device's remembered; every device but an alias's; an alias pf holds no table
  for cutting nothing, said once; nDPI's application before the protocol carrying it; a server shared with
  an application blocked for other devices cut alone, not tabled, or taken out of the table - and left where
  both blocks reach the same devices; the rules changed - what waits dropped once its device is no longer
  of the source, what is remembered cut for the new source's devices alone; cut.py's count per rule; a SIGHUP reading the
  interfaces and the sources again; `status.py rules` - each rule's state, its cuts, its Suricata lines, the
  Intrusion Detection's state; the Applications tab with an application blocked by rules alone; the host
  table read from `--protos-dump 1`;
- **the cut** - `tools/test-cut.py`, 64 checks: a connection cut for its rule while that rule blocks it,
  counted for it; one of every device whose application only a rule blocks, and one whose rule is gone, left;
- **the block rules** - `tools/test-rules.php`, 23 checks: a block rule of the Rules tab from its source
  alone - an interface's network, an alias inverted, several at once - after those of *Blocked
  applications*, described with the source as the pages name it; none for an Alert rule, one switched off,
  one of another action, with no source, or whose application has no table;
- **the page's API and the model** - `tools/test-mvc.php`, 28 checks, and `tools/test-model.php`, 7, new:
  Apply writing the Suricata rules after the filter and running `ids reload` when they changed, taking them
  away when classifying is off even with the aliases not written; the Rules grid's rows and its calls on
  `rules.rule`; the source selector's networks and aliases; a source refused - the firewall itself, an
  address of its own, a table of this plugin's, any with others, an inverted source of several items or of
  any - on its own field, a rule unchanged not looked at;
- **the installation** - `tools/test-install.py`, 44 checks: the Suricata rules written by `install.sh`
  and the package's `post-install.sh`, `ids reload` when they changed; the rules file - a half-written one
  too - taken away by `uninstall.sh`, the package's `pre-deinstall.sh` (not in an upgrade) and
  `post-deinstall.sh`, then `ids reload`; the template laid down and removed;
- **the strings** - 221 the GUI shows, every one in `source.json`; 27 of the 48 new wait for their Arabic in
  opnsense-arabic, with the second part's 16;
- **the rest** - `tools/check-uninstall.sh`, `php -l`, `py_compile` and pyflakes, `sh -n`, XML, JSON and the
  workflow's YAML, nothing private, no Arabic in the code, the copyright line, the page kit ("kit"); and, by
  hand, the page's script run under node with a stand-in jQuery, 23 checks: the Rules grid's formatters - the action,
  the source by an interface's name and inverted, what a rule does now - the Intrusion Detection's line,
  the line under the cards with block rules, Apply's answer with the Suricata rules written, taken away or
  failing.

55 behaviours of the third part were taken out in turn, on a copy, and the tests failed on each: among
them an Alert rule taken for a block, a rule from any not every device, one block taken to reach what
another reaches the wrong way round, a table's `!` entries taking nothing out, an inverted source taken as
it is, the protocol before nDPI's application, a shared server judged without whom its blocks reach, what
waits for a cut not looked at again by its device, the rule not handed to the cut, a connection of a rule
gone cut all the same, a name matched with no boundary before it, a last dot taking any labels after it,
an inverted source written for Suricata without `!`, Alert written as drop, the file written again when
nothing changed, a line past the limit left in, an inverted source given to pf without its `!`, `ids
reload` not asked when the rules changed, the firewall itself taken as a source and `uninstall.sh` leaving
the rules file. A first run had found one of them untested - `nocase` on the `http.host` line a rule gets,
which Suricata refuses - and the tests reach it now.

After the review of the third part, the same day, each of its findings was fixed in this branch and tested
the same way - every check above run again, all passing, and each new one failing on the branch as it was
before the fixes:

- **the block rules** - `tools/test-rules.php`, 26 checks now: an address or a network written by hand in its
  own family's rule alone, inverted the other family's from any, and no registered rule holding an address of
  the other family - pfctl refuses such a rule and with it the firewall's whole ruleset;
- **the Suricata rules** - `tools/test-suricata.py`, 80 checks now: each line's destination and source read as
  Suricata reads an address group - the destination the internet alone, none of the firewall's addresses,
  its networks or the blocks that are not the internet's; no source holding a firewall's address, any every
  address but them, a network holding one as an exception; a whole family negated never written; the rules
  last applied resolved again - an alias whose table changed, a new prefix, a name more in nDPI's table - and a
  rule changed and not applied not coming in; a reload that failed asked for again; one writer at a time,
  through files of their own; Suricata's own
  test, a stand-in refusing a line, failing, or not there; a sid kept as the rules change around it, two
  meeting taking the next free; part of a source not read giving the rest; a comment line kept on one line;
  OpenVPN's group;
- **the classifier and the page's state** - `tools/test-classify.py`, 290 checks now: `suricata_rules.py` run
  as the service starts and every SURICATA_EVERY seconds, its problems the last error; cut.py given the
  policy the service holds, written again at a SIGHUP while a run goes; each rule's state against what was
  applied - changed, not applied yet; acting on none, its source not read or empty - and the rules deleted
  since; the Intrusion Detection's interfaces and whether one is internal; an interface group's networks; a
  connection cut another way asked again whether its server is shared; an alias that gains a device; the
  interfaces kept when config.xml cannot be read; an empty switch read as PHP reads it;
- **the cut** - `tools/test-cut.py`, 71 checks now: judged by the classifier's policy - a rule switched off and
  not applied still cutting, one not applied not - with its rule's source resolved again, another rule of its
  application taking it, a change while the run goes judged before the kills; what is dropped written down
  with its rule, and a rule removed while another blocks its application handing back what no block holds -
  nothing when the application is blocked for every device since;
- **the model and the page's API** - `tools/test-model.php`, 9 checks, and `tools/test-mvc.php`, 29: an
  address config.xml gives the firewall, written by hand, refused as the firewall itself; the selector's
  labels escaped; the lines Suricata refused passed to the grid;
- **the installation** - `tools/test-install.py`, 47 checks now: the removals asking for `ids reload` when only
  the installed copy is left, and taking away a writer's half-written file;
- **the strings** - 231 the GUI shows, every one in `source.json`; 35 of the third part's wait for their Arabic
  in opnsense-arabic, with the second part's 16;
- **the page**, by hand, its script under node with a stand-in jQuery, 33 checks, the 11 of this round failing
  on the page as it was: a rule changed and not applied, one acting on none, the lines Suricata refused, the
  Intrusion Detection's interfaces, its test failing, the rules deleted since, the tab read again with the
  grid, each tab's Apply its own answer, the selector's labels made plain once, single host and any kept
  alone; and 16 probes, one for each fix, failing on the branch before the fixes and passing after.

Not run: anything of the third part on an appliance or a plain OPNsense, no Suricata reading its rules
file, and its page in a browser.

## Installation

It is not in the OPNsense plugin repository, so there is no `pkg install os-appcontrol`, and there is
no release yet.

**From a checkout** of this repository, on the firewall, as root:

```sh
sh install/install.sh
```

It checks the PHP with `php -l` and the Python with `py_compile` before anything is copied, installs
the package `ndpi` when it is not there (it needs the package mirror), copies `src/` onto `/usr/local`,
puts the page in the menu (`place-menu.sh`: XGS with os-xgs-npu, Firewall without), writes the aliases,
reloads the filter and cron, writes the Suricata rules of the Rules tab (`ids reload` when they changed),
starts the classifier, and records the commit for the self-update. Safe to run again: the settings in
config.xml are kept.

`sh install/uninstall.sh` stops the classifier, takes the plugin's aliases out of Firewall: Aliases
(switched off instead where a rule or a setting still names one) - and with them its block rules -
hands back from hardware what a cut dropped there, takes its Suricata rules out of the Intrusion
Detection's (`ids reload`), takes down the tmpfs of its window files, removes its files and its state,
takes the tables of the aliases gone out of pf, and removes the package `ndpi` only when `install.sh`
installed it and no other package needs it. The settings - the rules of the Rules tab among them - stay
in config.xml.

**From a package**, once there is a release: `tools/make-package.sh` builds it on a firewall, and
`release.yml` in a FreeBSD virtual machine for each release, as os-blocklists does. The package
depends on `ndpi`.

## Updates

As os-blocklists: taken by hand, to this repository's **releases** - from **XGS: Updates**, its
*Plugins* tab, where an os-xgs-npu that lists this plugin is installed, or by running
`/usr/local/opnsense/scripts/appcontrol/self-update.py` (`check` to ask). A release is installed only as
its owner signed it (`release.json` and its Ed25519 signature, the public key in `release-keys/`), only
forward, by the `install/install.sh` it carries. No cron entry runs it.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue. It installs the same on a plain OPNsense, where pf alone holds the tables and the page says so.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE).
