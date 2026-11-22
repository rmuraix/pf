# Packet Flow

[![License](https://img.shields.io/github/license/rmuraix/pf)](./LICENSE)
[![Build](https://github.com/rmuraix/pf/actions/workflows/build.yml/badge.svg)](https://github.com/rmuraix/pf/actions/workflows/build.yml)  
A lightweight, interactive network monitor for the terminal.

`pf` captures packets on one interface and groups TCP/UDP traffic into
bidirectional **flows**, with live byte/packet counts and transfer rates per
direction. ICMP, ARP and frames it cannot parse are kept in a separate event
log. It favours being simple and immediately readable over deep protocol
analysis.

```
 Flows  Details  Events                                                                    sort: activity
PROTOCOL LOCAL                  REMOTE                    ← RECEIVED → SENT     ← RATE       → RATE       LAST SEEN
UDP      10.0.0.2:40123         1.1.1.1:53                4.2 KiB    920 B      1.4 KiB/s    306 B/s      1s ago
TCP      10.0.0.2:22            10.0.0.15:60318           21.1 KiB   1.8 KiB    5.3 KiB/s    470 B/s      2s ago
TCP      10.0.0.2:51432         142.250.196.110:443       2.3 KiB    12.0 KiB   475 B/s      2.4 KiB/s    3s ago
TCP      10.0.0.2:51876         151.101.1.69:443          2.8 KiB    11.2 KiB   0 B/s        0 B/s        5s ago
UDP      10.0.0.2:5353          224.0.0.251:5353          0 B        1000 B     0 B/s        0 B/s        9s ago
eth0 capturing │ packets 81 │ flows 5 │ packets lost 0
q quit │ Space pause │ Tab switch view │ / filter │ ↑↓/jk move │ Enter open │ s sort
```

## Installation

```shell
cargo install --git https://github.com/rmuraix/pf
```

## Usage

```shell
sudo pf -i <NETWORK INTERFACE>
```

The interface opens immediately; there is no other mode. `pf` needs an
interactive terminal and exits with an error if stdin or stdout is redirected.

```
Options:
  -i, --interface <NETWORK INTERFACE>  Name of the network interface
      --noudp                          Ignore UDP: no UDP flows, and UDP packets are not counted
      --no-color                       Use a monochrome theme (or set NO_COLOR)
  -h, --help                           Print help
  -V, --version                        Print version
```

`--no-color` and a non-empty `NO_COLOR` environment variable select a
monochrome theme. Nothing relies on colour alone: direction is also shown with
arrows (`←` inbound, `→` outbound) and `IN`/`OUT` labels, and the selected row
is drawn in reverse video.

### Views

| View | Shows |
| --- | --- |
| **Flows** (default) | One row per flow: protocol, local and remote endpoint, bytes received/sent (`←`/`→`), packets, current rate per direction, time since the last packet. Columns are dropped on narrow terminals. |
| **Details** | The selected flow: full endpoints, interface, state (open, closed, ended), first/last packet time, duration, packets, bytes and rate per direction, and the most recent packets (time offset, direction, length, TCP flags). |
| **Events** | Recent packets that are not TCP/UDP flows: ICMP, ICMPv6, ARP, and frames that were unsupported, fragmented or malformed (with the reason). Newest first, times in UTC. |

The status bar always shows the interface, capture status, packet and flow
counters, dropped-packet and eviction counters, and the keys that apply.

### Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `k` `j` | Move the selection (scroll the history in Details). `PageUp`/`PageDown` move by 10. |
| `Enter` | Open the selected flow |
| `Esc` | Back to the flow list; clears an active filter |
| `Tab` / `Shift+Tab` | Next / previous view |
| `/` | Filter (see below). `Enter` keeps it, `Esc` clears it |
| `s` | Sort flows by recent activity or by traffic volume |
| `Space` | Pause / resume the display |
| `q`, `Ctrl+C` | Quit |

While typing a filter every key goes into the text, so `q`, `j` or `s` do not
trigger shortcuts. `Ctrl+C` always quits.

### Filter

Space-separated terms, all of which must match (flows and events):

| Term | Matches |
| --- | --- |
| `tcp`, `udp`, `icmp`, `icmpv6`, `arp` | the protocol |
| `443`, `:443`, `port:443` | either endpoint's port |
| `10.0.0.2`, `fe80::1` | either endpoint's IP address |
| `10.0.0.2:443` | either endpoint exactly |
| anything else, e.g. `192.168` | substring of either endpoint's IP address |

Example: `tcp 443 192.168` shows TCP flows on port 443 involving a `192.168.*`
address.

### Pause

Pausing freezes only what is displayed (marked `PAUSED` in the status bar).
Capture and aggregation continue, so nothing is lost: resuming shows the
current, complete counts at once.

## How it works

`Capture → Parser → Aggregator → TUI`, with capture, parsing/aggregation and
the UI on separate threads (no async runtime):

* The capture thread only reads packets and passes them on through a bounded
  channel; terminal speed cannot slow it down. If aggregation falls behind,
  capture waits and the kernel drops packets, which is reported as `packets lost` (from
  libpcap statistics).
* The aggregator owns all counters. The UI copies a snapshot of them about ten
  times a second, so heavy traffic does not make navigation sluggish.

### Flows

A flow is identified by interface, protocol (TCP/UDP) and the two
`(IP, port)` endpoints, regardless of direction. Volume is the on-wire frame
length (link-layer header included). Rates are averaged over the last five
seconds.

* **Local / remote**: the local side is the host address the parser identified;
  otherwise (loopback, forwarded or promiscuous traffic) it is the sender of the
  first packet seen.
* **Expiry and port reuse**: a flow is dropped after 60 s without packets, or 5 s
  after a TCP connection closed (RST, or FIN from both sides). Packets after
  that, or a new SYN on a closed connection, start a new flow rather than being
  merged into the old one. TCP sessions are not reconstructed beyond this.
* **Bounds**: at most 4096 flows (the least recently active eighth is evicted
  when full), 64 packets of history per flow and 1000 events. Evictions are
  counted (`evicted: N flows, M events` in the status bar) and never change the
  totals. They are different from `packets lost`, which counts packets that were never
  seen.

## ## Requirements

`pf` captures with [libpcap](https://www.tcpdump.org/) (via the `pcap` crate)
and needs it at build time and, on Windows, at run time.

| OS | Build | Run |
| --- | --- | --- |
| Linux | `libpcap-dev` (Debian/Ubuntu), `libpcap-devel` (Fedora), `libpcap` (Arch) | `libpcap` shared library |
| macOS | Nothing (libpcap ships with macOS) | Nothing |
| Windows | [Npcap SDK](https://npcap.com/#download): add its `Lib\x64` (or `Lib\ARM64`) folder to the `LIB` environment variable | [Npcap](https://npcap.com/#download) installed (provides `wpcap.dll`) |

### Permissions

Live capture needs raw-capture privileges:

* **Linux**: run as root, or grant the binary capabilities instead:
  `sudo setcap cap_net_raw,cap_net_admin=eip $(which pf)`.
* **macOS**: run as root (`sudo pf ...`) or make `/dev/bpf*` readable for your user.
* **Windows**: run from an Administrator terminal, or allow non-admin capture
  when installing Npcap. On Windows the interface name is the Npcap device
  name, e.g. `\Device\NPF_{GUID}`.

### Supported link-layer types

Ethernet, raw IP (e.g. TUN), BSD/macOS/Npcap loopback, and Linux cooked capture
(v1 and v2, e.g. interface `any`). The type is read from libpcap; an interface
with any other type (e.g. 802.11 monitor mode, PPP) is rejected with an error.

### Notes

* Timestamps and lengths come from libpcap; frames are captured in full
  (snapshot length 65535).
* IP fragments are reported as unknown frames in the event log: the transport
  header is not reliably available.
* Interrupting with `Ctrl+C`, `SIGINT`, `SIGTERM` or `SIGHUP` restores the
  terminal. `SIGKILL` cannot be handled; run `reset` if the terminal is left in
  a bad state.

### Platform support and testing

Linux and macOS are built and tested in CI; Windows is compile-checked only
(the runner has no Npcap driver). Unit tests cover aggregation, filtering,
sorting, pause semantics and rendering (with ratatui's `TestBackend`) on every
platform. Live capture needs privileges, so it is only exercised in CI on Linux
(loopback, inside a pseudo terminal, including shutdown and terminal
restoration). Live capture and the TUI on macOS and Windows have not been
tested automatically.

## Contributing

Your contribution is always welcome. Please read [Contributing Guide](.github/CONTRIBUTING.md).
