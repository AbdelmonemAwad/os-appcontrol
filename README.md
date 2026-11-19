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
> first; what was dropped there is handed back once the application is no longer blocked. Nothing is
> blocked until an application is chosen. Its checks ran away from an appliance (below).

<p align="center"><b>Contents:</b> <a href="#what-it-does">What it does</a> &middot; <a href="#how-a-connection-is-named">How a connection is named</a> &middot; <a href="#how-an-application-is-blocked">How an application is blocked</a> &middot; <a href="#not-yet-and-why">Not yet, and why</a> &middot; <a href="#what-is-tested">What is tested</a> &middot; <a href="#installation">Installation</a> &middot; <a href="#updates">Updates</a> &middot; <a href="#where-it-fits">Where it fits</a> &middot; <a href="#licence">Licence</a></p>

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
  names as it are cut, in hardware too where os-xgs-npu is installed. The Applications tab says, for each,
  whether it is blocked or chosen and not applied yet, the connections cut and the packets its block rules
  stopped; a line under the cards, what is blocked and whether os-xgs-npu's *Cut in hardware* is on.
  *Log what is blocked* (off) logs each packet the rules drop;
- **the cards** - applications named, connections classified, unknown, and the last error, with what
  reading the installed nDPI's catalogue found wrong; under them, the windows cut short at a limit.

Off, the classifier stops and the plugin's aliases leave Firewall: Aliases - switched off instead where a
rule or a setting still names one - and with them the block rules; what a cut dropped in hardware is
handed back.

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
  in the table is dropped where it enters, from a LAN, a VLAN or a VPN alike; the firewall's own
  connections go out and are not held by it. A table never holds the firewall's own addresses nor its
  internal networks', so the rule shuts no one out of the firewall. It stops new connections only: pf
  lets a packet of a state it holds through before any rule;
- **the cut** - once a window is judged, each connection nDPI named as a blocked application, by its
  packets, begun here, whose server went into its table is handed to `cut.py` with its two ends, after
  the server is in the table. `cut.py` kills by its id every pf state holding both ends - the one on the
  internal interface and the one out of the WAN, whose original ends pf writes after NAT - of the
  connection's protocol, made no later than its first packet and not over, as os-xgs-npu's and
  os-blocklists' JA4 cuts do: another application on the same server is not cut. It runs beside the
  capture, one run at a time, at most 5,000 connections a run and 20,000 waiting, and is stopped at
  120 s; what it could not do is the page's last error. A guess, a connection whose beginning was not
  seen, and one to the firewall or a host of its internal networks - those that go into no table - are
  never cut;
- **in hardware first** - where os-xgs-npu is installed, `cut.py` loads its `hwdrop.py` from its own
  place, not a copy, and has `drop_ends()` drop those connections on the coprocessor before the first
  state is killed, each state's ends apart with its protocol - with XGS: Settings' *Cut in hardware* on,
  at once and both ways; off, each driver takes a connection out of hardware once pf has let go of its
  state. The step has 5 seconds in a thread of its own; past them, or failing, the pf cut goes on and
  how many were dropped is "unknown", as os-blocklists has it. Without os-xgs-npu, pf alone;
- **blocked later** - the service remembers the connections it named that could be cut - the latest
  50,000, for a day; one seen to end, or a UDP question and its answer, not at all - and when an
  application becomes blocked, those it remembers as it are cut at once and their servers put in its
  table, so its rule holds them before a new connection to them has to be named. Apply has the service
  read its settings again (`rc.d/appcontrol reload`, a SIGHUP) rather than restart it, which would forget
  them;
- **handed back** - a connection the coprocessor dropped stays dropped there while its sender goes on
  sending (os-xgs-npu's `hwdrop.py`). `cut.py` writes each one down with its application and its server,
  and `cut.py release` - run by Apply and by the removal - hands back, by their servers, those of an
  application no longer blocked, unless an application still blocked holds the same server. pf then
  decides their packets again, their states gone;
- **counted** - the connections cut, the pf states killed and how many the coprocessor dropped, in
  status.json and on the page; and, for each blocked application, the packets its two rules stopped,
  read from pf's own counters (`pfctl -v -s rules`).

An allowed connection is not held: it goes into hardware on os-xgs-npu's own schedule, as before. Phase
0's lab found the host had seen enough of every connection it tried before that - 8 packets at most were
needed, at a round trip of 50 ms too - so nothing waits for its classification.

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
  connection to it is named, so the first one to a server its table does not hold yet runs until its
  window is judged - some 10 to 70 seconds - and is cut then. A server leaves the table once unseen for
  the address expiry, and a blocked try is never named, so each server is learned again about once an
  expiry. Shorter windows while something is blocked are not built: the cost of the windows was measured
  at 60 seconds.
- **what is not cut** - a guess, a connection whose beginning was not seen, one to the firewall or a host
  of its internal networks, and one on an interface the service does not read; the rule still stops a new
  connection to a server in the table on every interface. What the service remembers since it started -
  the latest 50,000 for a day - is forgotten by a restart: a boot, an update, `install.sh`.
- **a category blocked, an exception for one device** - an application alone can be chosen; a category's
  table can be named in a rule of the owner's own. Rules by source - "this application, from that
  network" - are phase 3's grid (the plan's top-01).
- **packets, not connections** - what the rules stopped is pf's count of packets: one try of a connection
  is several. The rule drops; a client is not told, and waits for its own timeout.
- **Suricata rules, routing by gateway** - phases 3 and 4.
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
- **the classifier** - `tools/test-classify.py`, 195 checks, 38 of them new: the settings read; a table
  for each application blocked; what is blocked - chosen, its alias there, classifying on; in a window,
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

44 behaviours of the second part were taken out in turn, on a copy, and the tests failed on each: among
them a connection cut by its server alone, a UDP state cut for a TCP connection, a later connection on
the same ends cut, the hardware step after the kills or with no deadline, a server still blocked handed
back, a failed hand-back forgotten, a guess cut, a blocked application's servers not put in its table,
what is remembered never forgotten, a cut run never stopped, a SIGHUP not acted on, an owner's rule on an
interface counted as the plugin's, the rules after the owner's or outbound, Apply restarting the
classifier, and the removal not handing back. The first run had found one of them untested - an owner's
alias by the plugin's kind of name whose description would have read as an application's - and the
tests reach it now.

Not run: anything of the second part on an appliance or a plain OPNsense, and its page in a browser.

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
reloads the filter and cron, starts the classifier, and records the commit for the self-update. Safe to
run again: the settings in config.xml are kept.

`sh install/uninstall.sh` stops the classifier, takes the plugin's aliases out of Firewall: Aliases
(switched off instead where a rule or a setting still names one) - and with them its block rules -
hands back from hardware what a cut dropped there, takes down the tmpfs of its window files, removes its
files and its state, takes the tables of the aliases gone out of pf, and removes the package `ndpi` only
when `install.sh` installed it and no other package needs it. The settings stay in config.xml.

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
