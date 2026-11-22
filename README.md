# Packet Flow

[![License](https://img.shields.io/github/license/rmuraix/pf)](./LICENSE)
[![Build](https://github.com/rmuraix/pf/actions/workflows/build.yml/badge.svg)](https://github.com/rmuraix/pf/actions/workflows/build.yml)  
A lightweight, interactive network monitor for the terminal.

![screen shot](./static/pf_screenshot.png)

`pf` groups TCP/UDP traffic on one interface into bidirectional **flows** with
live bytes, packets and rates per direction. Views: **Flows** (the list),
**Details** (one flow and its recent packets) and **Events** (ICMP, ARP and
frames that could not be parsed).

## Installation

```shell
cargo install --git https://github.com/rmuraix/pf
```

## Usage

```shell
sudo pf -i <NETWORK INTERFACE>
```

`pf` needs an interactive terminal and exits with an error if stdin or stdout is
redirected.

```
Options:
  -i, --interface <NETWORK INTERFACE>  Name of the network interface
      --noudp                          Ignore UDP: no UDP flows, and UDP packets are not counted
      --no-color                       Use a monochrome theme (or set NO_COLOR)
```

### Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `k` `j` | Move (scroll history in Details) |
| `Enter` / `Esc` | Open the selected flow / go back (also clears the filter) |
| `Tab` / `Shift+Tab` | Switch view |
| `/` | Filter; `Enter` keeps it, `Esc` clears it |
| `s` | Sort by recent activity or traffic volume |
| `Space` | Pause / resume the display (capture keeps counting) |
| `q`, `Ctrl+C` | Quit |

### Filter

Space-separated terms, all must match: a protocol (`tcp`, `udp`, `icmp`,
`icmpv6`, `arp`), a port (`443`, `:443`), an IP address (`10.0.0.2`), an
endpoint (`10.0.0.2:443`) or part of an address (`192.168`).
Example: `tcp 443 192.168`.

## How it works

`Capture → Parser → Aggregator → TUI` on separate threads, so a slow terminal
never slows capture.

* A flow is identified by interface, protocol and the two `(IP, port)` endpoints,
  in either direction. Volume is the on-wire frame length.
* A flow expires after 60 s without packets, or 5 s after a TCP close; a later
  packet (or a new SYN on a closed connection) starts a new flow.
* Storage is bounded: 4096 flows, 64 packets per flow, 1000 events. Evictions
  (`evicted: …` in the status bar) never change the totals, and are distinct
  from `packets lost`, which counts packets the kernel dropped.
* Local/remote: the host address if known, otherwise (e.g. loopback) the sender
  of the first packet.

## Requirements

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

* Live capture and the TUI are exercised in CI on Linux only; macOS is built and
  unit-tested, Windows is compile-checked (the runner has no Npcap).
* `Ctrl+C`, `SIGINT`, `SIGTERM` and `SIGHUP` restore the terminal. After
  `SIGKILL`, run `reset`.

## Contributing

Your contribution is always welcome. Please read [Contributing Guide](.github/CONTRIBUTING.md).
