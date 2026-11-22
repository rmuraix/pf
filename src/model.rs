use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;

/// Hardware address, displayed as lowercase colon-separated hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpKind {
    EchoReply { seq: u16, id: u16 },
    EchoRequest { seq: u16, id: u16 },
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
        is_dns: bool,
    },
    Tcp {
        src_port: u16,
        dst_port: u16,
        length: usize,
    },
    Icmp(IcmpKind),
    Icmpv6 {
        type_u8: u8,
    },
    Arp {
        operation: u16,
        sender_mac: MacAddress,
        sender_ip: Ipv4Addr,
        target_mac: MacAddress,
        target_ip: Ipv4Addr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub interface: String,
    pub direction: Direction,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: Transport,
}

impl NetEvent {
    pub fn new(
        interface: impl Into<String>,
        direction: Direction,
        source: IpAddr,
        destination: IpAddr,
        transport: Transport,
    ) -> Self {
        Self {
            interface: interface.into(),
            direction,
            source,
            destination,
            transport,
        }
    }
}

/// Link-layer header fields of a frame that could not be turned into a
/// [`NetEvent`]. Addresses are zero when the link layer has none (raw IP,
/// loopback) or not a 6-byte one (Linux cooked capture).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetSummary {
    pub source: MacAddress,
    pub destination: MacAddress,
    pub ethertype: u16,
}

/// Why a frame produced no [`NetEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnparsedReason {
    /// EtherType is not IPv4, IPv6 or ARP.
    UnsupportedEtherType,
    /// IP protocol is not TCP, UDP, ICMP (IPv4) or ICMPv6 (IPv6).
    UnsupportedProtocol,
    /// A header of the named protocol is too short or invalid.
    Malformed(&'static str),
    /// IPv4/IPv6 fragment: the transport header is not reliably available.
    Fragmented,
    /// Dropped by the `--noudp` option. (Reported like any other unparsed
    /// frame to keep the pre-refactor output.)
    Filtered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnparsedFrame {
    pub interface: String,
    /// Number of captured bytes.
    pub length: usize,
    /// `None` when not even a link-layer header could be read.
    pub ethernet: Option<EthernetSummary>,
    pub reason: UnparsedReason,
}

/// Result of parsing one captured frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Event(NetEvent),
    Unparsed(UnparsedFrame),
}
