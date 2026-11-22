//! Turns [`CapturedFrame`]s into [`ParseOutcome`]s. No printing happens here.
//!
//! This module (with `packets`) is the only place that uses `etherparse`
//! types, and `capture` the only one that uses `pcap` types.

mod direction;
mod packets;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use etherparse::err::{Layer, packet::SliceError};
use etherparse::{EtherType, Ethernet2HeaderSlice, NetSlice, SlicedPacket};

use crate::frame::{CapturedFrame, LinkType};
use crate::model::{
    Direction as FlowDir, EthernetSummary, MacAddress, NetEvent, Observation, ParseOutcome,
    Transport, UnparsedFrame, UnparsedReason,
};

/// Length of the BSD loopback (`DLT_NULL`/`DLT_LOOP`) address-family header.
const LOOPBACK_HEADER_LEN: usize = 4;
/// Length of the Linux cooked capture v1 / v2 headers.
const SLL_HEADER_LEN: usize = 16;
const SLL2_HEADER_LEN: usize = 20;

pub struct Parser {
    host_ips: HashSet<IpAddr>,
    noudp: bool,
}

/// Link-layer view of a frame: addresses, EtherType and the network payload.
struct LinkFrame<'a> {
    summary: EthernetSummary,
    payload: &'a [u8],
}

impl<'a> LinkFrame<'a> {
    /// `Err` names the link layer whose header is too short.
    fn from_frame(frame: &'a CapturedFrame) -> Result<Self, &'static str> {
        let data = &frame.data[..];
        match frame.link_type {
            LinkType::Ethernet => {
                let eth = Ethernet2HeaderSlice::from_slice(data).map_err(|_| "Ethernet")?;
                Ok(Self::new(
                    MacAddress(eth.source()),
                    MacAddress(eth.destination()),
                    eth.ether_type().0,
                    &data[eth.slice().len()..],
                ))
            }
            LinkType::RawIp => Self::ip_only(data),
            LinkType::Loopback => Self::ip_only(data.get(LOOPBACK_HEADER_LEN..).ok_or("Loopback")?),
            LinkType::LinuxSll => {
                let h = data.get(..SLL_HEADER_LEN).ok_or("Linux cooked")?;
                // pkttype(2) hatype(2) addrlen(2) addr(8) protocol(2)
                Ok(Self::sll(
                    u16::from_be_bytes([h[4], h[5]]),
                    &h[6..14],
                    u16::from_be_bytes([h[14], h[15]]),
                    &data[SLL_HEADER_LEN..],
                ))
            }
            LinkType::LinuxSll2 => {
                let h = data.get(..SLL2_HEADER_LEN).ok_or("Linux cooked")?;
                // protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1) addrlen(1) addr(8)
                Ok(Self::sll(
                    u16::from(h[11]),
                    &h[12..20],
                    u16::from_be_bytes([h[0], h[1]]),
                    &data[SLL2_HEADER_LEN..],
                ))
            }
        }
    }

    fn new(source: MacAddress, destination: MacAddress, ethertype: u16, payload: &'a [u8]) -> Self {
        Self {
            summary: EthernetSummary {
                source,
                destination,
                ethertype,
            },
            payload,
        }
    }

    /// An IP packet without link-layer addresses. The EtherType follows the
    /// IP version nibble; anything else gets 0 and is reported as an
    /// unsupported EtherType.
    fn ip_only(ip: &'a [u8]) -> Result<Self, &'static str> {
        let ethertype = match ip.first().ok_or("IP")? >> 4 {
            4 => EtherType::IPV4.0,
            6 => EtherType::IPV6.0,
            _ => 0,
        };
        Ok(Self::new(
            MacAddress([0; 6]),
            MacAddress([0; 6]),
            ethertype,
            ip,
        ))
    }

    /// Linux cooked capture: the sender address is only used if it is a MAC.
    fn sll(addr_len: u16, addr: &[u8], protocol: u16, payload: &'a [u8]) -> Self {
        let source = match <[u8; 6]>::try_from(&addr[..addr_len.min(8) as usize]) {
            Ok(mac) => MacAddress(mac),
            Err(_) => MacAddress([0; 6]),
        };
        Self::new(source, MacAddress([0; 6]), protocol, payload)
    }
}

/// Protocol name for the layer a packet failed to parse at.
fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::LinuxSllHeader => "Linux cooked",
        Layer::Ethernet2Header | Layer::EtherPayload => "Ethernet",
        Layer::VlanHeader => "VLAN",
        Layer::MacsecHeader | Layer::MacsecPacket => "MACsec",
        Layer::IpHeader => "IP",
        Layer::Ipv4Header | Layer::Ipv4Packet | Layer::IpAuthHeader => "IPv4",
        Layer::Ipv6Header
        | Layer::Ipv6Packet
        | Layer::Ipv6ExtHeader
        | Layer::Ipv6HopByHopHeader
        | Layer::Ipv6DestOptionsHeader
        | Layer::Ipv6RouteHeader
        | Layer::Ipv6FragHeader => "IPv6",
        Layer::UdpHeader | Layer::UdpPayload => "UDP",
        Layer::TcpHeader => "TCP",
        Layer::Icmpv4 | Layer::Icmpv4Timestamp | Layer::Icmpv4TimestampReply => "ICMP",
        Layer::Icmpv6 => "ICMPv6",
        Layer::Igmp => "IGMP",
        Layer::Arp => "ARP",
    }
}

fn malformed(err: SliceError) -> UnparsedReason {
    UnparsedReason::Malformed(match err {
        SliceError::Len(e) => layer_name(e.layer),
        SliceError::LinuxSll(_) => "Linux cooked",
        SliceError::Macsec(_) => "MACsec",
        SliceError::Ip(_) => "IP",
        SliceError::Ipv4(_) | SliceError::Ipv4Exts(_) => "IPv4",
        SliceError::Ipv6(_) | SliceError::Ipv6Exts(_) => "IPv6",
        SliceError::Tcp(_) => "TCP",
    })
}

impl Parser {
    pub fn new(host_ips: HashSet<IpAddr>, noudp: bool) -> Self {
        Self { host_ips, noudp }
    }

    /// [`Self::parse`] plus the capture time and on-wire length, which is
    /// all the aggregator needs from the frame.
    pub fn observe(&self, frame: &CapturedFrame) -> Observation {
        Observation {
            timestamp: frame.timestamp,
            wire_len: frame.original_len,
            outcome: self.parse(frame),
        }
    }

    pub fn parse(&self, frame: &CapturedFrame) -> ParseOutcome {
        let unparsed = |ethernet, reason| {
            ParseOutcome::Unparsed(UnparsedFrame {
                interface: Arc::clone(&frame.interface),
                length: frame.captured_len(),
                ethernet,
                reason,
            })
        };
        let link = match LinkFrame::from_frame(frame) {
            Ok(link) => link,
            Err(layer) => return unparsed(None, UnparsedReason::Malformed(layer)),
        };
        match self.parse_network(&frame.interface, &link) {
            Ok(event) => ParseOutcome::Event(event),
            Err(reason) => unparsed(Some(link.summary), reason),
        }
    }

    fn parse_network(
        &self,
        interface: &Arc<str>,
        link: &LinkFrame,
    ) -> Result<NetEvent, UnparsedReason> {
        let sliced = SlicedPacket::from_ether_type(EtherType(link.summary.ethertype), link.payload)
            .map_err(malformed)?;
        let (source, destination, transport) = match &sliced.net {
            Some(NetSlice::Arp(arp)) => {
                let arp = packets::arp(arp).ok_or(UnparsedReason::Malformed("ARP"))?;
                let (source, destination) = (IpAddr::V4(arp.sender_ip), IpAddr::V4(arp.target_ip));
                // The MACs are those of the Ethernet header, as before.
                let transport = Transport::Arp {
                    operation: arp.operation,
                    sender_mac: link.summary.source,
                    sender_ip: arp.sender_ip,
                    target_mac: link.summary.destination,
                    target_ip: arp.target_ip,
                };
                (source, destination, transport)
            }
            Some(NetSlice::Ipv4(ip)) => {
                if ip.is_payload_fragmented() {
                    return Err(UnparsedReason::Fragmented);
                }
                let header = ip.header();
                let (src, dst) = (header.source_addr(), header.destination_addr());
                (
                    IpAddr::V4(src),
                    IpAddr::V4(dst),
                    self.ip_transport(&sliced)?,
                )
            }
            Some(NetSlice::Ipv6(ip)) => {
                if ip.is_payload_fragmented() {
                    return Err(UnparsedReason::Fragmented);
                }
                let header = ip.header();
                let (src, dst) = (header.source_addr(), header.destination_addr());
                (
                    IpAddr::V6(src),
                    IpAddr::V6(dst),
                    self.ip_transport(&sliced)?,
                )
            }
            None => return Err(UnparsedReason::UnsupportedEtherType),
        };
        let direction = if direction::is_destination(destination, &self.host_ips) {
            FlowDir::Inbound
        } else {
            FlowDir::Outbound
        };
        Ok(NetEvent::new(
            Arc::clone(interface),
            direction,
            source,
            destination,
            transport,
        ))
    }

    /// Transport of an unfragmented IP packet, honouring `--noudp`.
    fn ip_transport(&self, sliced: &SlicedPacket) -> Result<Transport, UnparsedReason> {
        let slice = sliced
            .transport
            .as_ref()
            .ok_or(UnparsedReason::UnsupportedProtocol)?;
        if self.noudp && matches!(slice, etherparse::TransportSlice::Udp(_)) {
            return Err(UnparsedReason::Filtered);
        }
        packets::transport(slice).ok_or(UnparsedReason::UnsupportedProtocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IcmpKind, TcpFlags};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    // Packet fixtures are assembled from plain bytes so the tests do not
    // depend on the parsing (or any packet-building) library.

    const HOST: [u8; 4] = [10, 0, 0, 2];
    const PEER: [u8; 4] = [1, 1, 1, 1];
    const IPV4: u16 = 0x0800;
    const IPV6: u16 = 0x86dd;
    const ARP: u16 = 0x0806;
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ICMP: u8 = 1;
    const ICMPV6: u8 = 58;
    const GRE: u8 = 47;

    fn parser(noudp: bool) -> Parser {
        Parser::new(HashSet::from([IpAddr::V4(Ipv4Addr::from(HOST))]), noudp)
    }

    fn frame(link_type: LinkType, data: Vec<u8>) -> CapturedFrame {
        CapturedFrame {
            timestamp: SystemTime::UNIX_EPOCH,
            interface: Arc::from("eth0"),
            link_type,
            original_len: data.len(),
            data,
        }
    }

    /// IPv4 header (no options) with the given addresses, protocol, fragment
    /// field (flags + offset) and payload.
    fn ipv4_with(src: [u8; 4], dst: [u8; 4], proto: u8, frag: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x45, 0];
        b.extend((20 + payload.len() as u16).to_be_bytes());
        b.extend([0, 0]);
        b.extend(frag.to_be_bytes());
        b.extend([64, proto, 0, 0]);
        b.extend(src);
        b.extend(dst);
        b.extend(payload);
        b
    }

    /// Unfragmented IPv4 packet from `PEER` to `HOST`.
    fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
        ipv4_with(PEER, HOST, proto, 0, payload)
    }

    fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x60, 0, 0, 0];
        b.extend((payload.len() as u16).to_be_bytes());
        b.extend([next, 64]);
        b.extend(src);
        b.extend(dst);
        b.extend(payload);
        b
    }

    fn v6(last: u8) -> [u8; 16] {
        let mut a = [0; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        a[15] = last;
        a
    }

    fn udp(src: u16, dst: u16, data_len: usize) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(src.to_be_bytes());
        b.extend(dst.to_be_bytes());
        b.extend((8 + data_len as u16).to_be_bytes());
        b.extend([0, 0]);
        b.extend(vec![0; data_len]);
        b
    }

    fn tcp(src: u16, dst: u16, data_len: usize) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(src.to_be_bytes());
        b.extend(dst.to_be_bytes());
        b.extend([0; 8]); // seq, ack
        b.extend([0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]); // 20-byte header, SYN
        b.extend(vec![0; data_len]);
        b
    }

    fn icmp_echo(ty: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut b = vec![ty, 0, 0, 0];
        b.extend(id.to_be_bytes());
        b.extend(seq.to_be_bytes());
        b
    }

    fn arp_request(sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0, 1, 0x08, 0x00, 6, 4, 0, 1];
        b.extend([0xaa; 6]);
        b.extend(sender);
        b.extend([0; 6]);
        b.extend(target);
        b
    }

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1];
        b.extend(ethertype.to_be_bytes());
        b.extend(payload);
        b
    }

    fn event(outcome: ParseOutcome) -> NetEvent {
        match outcome {
            ParseOutcome::Event(e) => e,
            other => panic!("expected event, got {other:?}"),
        }
    }

    fn unparsed(outcome: ParseOutcome) -> UnparsedFrame {
        match outcome {
            ParseOutcome::Unparsed(f) => f,
            other => panic!("expected unparsed, got {other:?}"),
        }
    }

    fn reason(outcome: ParseOutcome) -> UnparsedReason {
        unparsed(outcome).reason
    }

    fn eth_frame(ethertype: u16, payload: &[u8]) -> CapturedFrame {
        frame(LinkType::Ethernet, ethernet(ethertype, payload))
    }

    #[test]
    fn ipv4_udp_is_filtered_by_noudp() {
        let f = eth_frame(IPV4, &ipv4(UDP, &udp(53, 53000, 0)));
        let u = unparsed(parser(true).parse(&f));
        assert_eq!(u.reason, UnparsedReason::Filtered);
        assert_eq!(u.length, f.captured_len());
        assert_eq!(u.ethernet.unwrap().ethertype, IPV4);

        let ev = event(parser(false).parse(&f));
        assert_eq!(
            ev.transport,
            Transport::Udp {
                src_port: 53,
                dst_port: 53000,
                length: 8,
                is_dns: true
            }
        );
        assert_eq!(&*ev.interface, "eth0");
        assert_eq!(ev.direction, FlowDir::Inbound);
        assert_eq!(ev.source, IpAddr::V4(Ipv4Addr::from(PEER)));
        assert_eq!(ev.destination, IpAddr::V4(Ipv4Addr::from(HOST)));
    }

    #[test]
    fn noudp_keeps_tcp() {
        let f = eth_frame(IPV4, &ipv4(TCP, &tcp(1, 2, 0)));
        assert!(matches!(
            event(parser(true).parse(&f)).transport,
            Transport::Tcp { .. }
        ));
    }

    #[test]
    fn ipv4_tcp_length_is_header_plus_payload_without_padding() {
        // Ethernet minimum-size padding after the IP packet must not count.
        let mut data = ethernet(IPV4, &ipv4(TCP, &tcp(55555, 80, 5)));
        data.extend([0; 12]);
        let ev = event(parser(false).parse(&frame(LinkType::Ethernet, data)));
        assert_eq!(ev.direction, FlowDir::Inbound);
        assert_eq!(
            ev.transport,
            Transport::Tcp {
                src_port: 55555,
                dst_port: 80,
                length: 25,
                flags: TcpFlags {
                    syn: true,
                    ..TcpFlags::default()
                }
            }
        );
    }

    #[test]
    fn tcp_flags_are_decoded() {
        // 20-byte header; flags byte: FIN=0x01 SYN=0x02 RST=0x04 ACK=0x10.
        let with_flags = |flags: u8| {
            let mut seg = tcp(1, 2, 0);
            seg[13] = flags;
            let f = eth_frame(IPV4, &ipv4(TCP, &seg));
            match event(parser(false).parse(&f)).transport {
                Transport::Tcp { flags, .. } => flags,
                other => panic!("not TCP: {other:?}"),
            }
        };
        assert_eq!(
            with_flags(0x12),
            TcpFlags {
                syn: true,
                ack: true,
                fin: false,
                rst: false
            }
        );
        assert_eq!(
            with_flags(0x11),
            TcpFlags {
                syn: false,
                ack: true,
                fin: true,
                rst: false
            }
        );
        assert_eq!(
            with_flags(0x04),
            TcpFlags {
                syn: false,
                ack: false,
                fin: false,
                rst: true
            }
        );
    }

    #[test]
    fn observe_carries_timestamp_and_wire_len() {
        let mut f = eth_frame(IPV4, &ipv4(TCP, &tcp(1, 2, 0)));
        f.original_len = 9000;
        f.timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(7);
        let obs = parser(false).observe(&f);
        assert_eq!(obs.wire_len, 9000);
        assert_eq!(obs.timestamp, f.timestamp);
        assert!(matches!(obs.outcome, ParseOutcome::Event(_)));
    }

    #[test]
    fn ipv6_tcp_outbound() {
        let ip = ipv6(v6(1), v6(2), TCP, &tcp(50000, 443, 0));
        let ev = event(parser(false).parse(&eth_frame(IPV6, &ip)));
        assert_eq!(
            ev.transport,
            Transport::Tcp {
                src_port: 50000,
                dst_port: 443,
                length: 20,
                flags: TcpFlags {
                    syn: true,
                    ..TcpFlags::default()
                }
            }
        );
        assert_eq!(ev.direction, FlowDir::Outbound);
        assert_eq!(ev.source, IpAddr::V6(Ipv6Addr::from(v6(1))));
    }

    #[test]
    fn ipv6_udp() {
        let ip = ipv6(v6(1), v6(2), UDP, &udp(5000, 5001, 4));
        let ev = event(parser(false).parse(&eth_frame(IPV6, &ip)));
        assert!(matches!(
            ev.transport,
            Transport::Udp {
                length: 12,
                is_dns: false,
                ..
            }
        ));
    }

    #[test]
    fn ipv6_icmpv6() {
        let ip = ipv6(v6(1), v6(2), ICMPV6, &icmp_echo(128, 7, 1));
        let ev = event(parser(false).parse(&eth_frame(IPV6, &ip)));
        assert_eq!(ev.transport, Transport::Icmpv6 { type_u8: 128 });
    }

    #[test]
    fn ipv4_icmp_echo_and_other() {
        let echo = |ty| ipv4(ICMP, &icmp_echo(ty, 123, 9));
        let kind = |ty| match event(parser(false).parse(&eth_frame(IPV4, &echo(ty)))).transport {
            Transport::Icmp(k) => k,
            other => panic!("not icmp: {other:?}"),
        };
        assert_eq!(kind(8), IcmpKind::EchoRequest { id: 123, seq: 9 });
        assert_eq!(kind(0), IcmpKind::EchoReply { id: 123, seq: 9 });
        assert_eq!(kind(3), IcmpKind::Other(3));
    }

    #[test]
    fn arp_request_inbound() {
        let f = eth_frame(ARP, &arp_request([10, 0, 0, 3], HOST));
        let ev = event(parser(false).parse(&f));
        assert_eq!(ev.direction, FlowDir::Inbound);
        assert_eq!(
            ev.transport,
            Transport::Arp {
                operation: 1,
                sender_mac: MacAddress([0, 0, 0, 0, 0, 1]),
                sender_ip: Ipv4Addr::new(10, 0, 0, 3),
                target_mac: MacAddress([0, 0, 0, 0, 0, 2]),
                target_ip: Ipv4Addr::from(HOST),
            }
        );
        let f = eth_frame(ARP, &arp_request(HOST, [10, 0, 0, 9]));
        assert_eq!(event(parser(false).parse(&f)).direction, FlowDir::Outbound);
    }

    #[test]
    fn vlan_tagged_frames_are_parsed() {
        let mut inner = vec![0, 5]; // VLAN id 5
        inner.extend(IPV4.to_be_bytes());
        inner.extend(ipv4(TCP, &tcp(1, 2, 0)));
        let ev = event(parser(false).parse(&eth_frame(0x8100, &inner)));
        assert!(matches!(ev.transport, Transport::Tcp { dst_port: 2, .. }));
    }

    #[test]
    fn unsupported_ethertype_and_protocol_are_explicit() {
        let f = eth_frame(0x88cc, &[0; 10]);
        assert_eq!(
            reason(parser(false).parse(&f)),
            UnparsedReason::UnsupportedEtherType
        );
        for proto in [GRE, 2 /* IGMP */] {
            let f = eth_frame(IPV4, &ipv4(proto, &[0; 8]));
            assert_eq!(
                reason(parser(false).parse(&f)),
                UnparsedReason::UnsupportedProtocol
            );
        }
    }

    #[test]
    fn malformed_packets_are_explicit() {
        // Too short for an Ethernet header: no summary available.
        let u = unparsed(parser(false).parse(&frame(LinkType::Ethernet, vec![0; 5])));
        assert_eq!(u.reason, UnparsedReason::Malformed("Ethernet"));
        assert!(u.ethernet.is_none());
        assert_eq!(u.length, 5);

        let cases = [
            (eth_frame(IPV4, &[0x45; 4]), "IPv4"),
            (eth_frame(IPV6, &[0x60; 4]), "IPv6"),
            (eth_frame(ARP, &[0; 4]), "ARP"),
            (eth_frame(IPV4, &ipv4(TCP, &[0; 4])), "TCP"),
            (eth_frame(IPV4, &ipv4(UDP, &[0; 4])), "UDP"),
            (eth_frame(IPV4, &ipv4(ICMP, &[8, 0])), "ICMP"),
            (
                eth_frame(IPV6, &ipv6(v6(1), v6(2), ICMPV6, &[128])),
                "ICMPv6",
            ),
        ];
        for (f, name) in cases {
            let u = unparsed(parser(false).parse(&f));
            assert_eq!(u.reason, UnparsedReason::Malformed(name));
            // The Ethernet header was readable.
            assert!(u.ethernet.is_some(), "{name}");
        }
    }

    #[test]
    fn bad_ip_header_fields_are_malformed() {
        // IPv4 version nibble says 6 inside an IPv4 EtherType.
        let mut ip = ipv4(TCP, &tcp(1, 2, 0));
        ip[0] = 0x65;
        assert!(matches!(
            reason(parser(false).parse(&eth_frame(IPV4, &ip))),
            UnparsedReason::Malformed(_)
        ));
        // TCP data offset below the minimum.
        let mut seg = tcp(1, 2, 0);
        seg[12] = 0x10;
        assert_eq!(
            reason(parser(false).parse(&eth_frame(IPV4, &ipv4(TCP, &seg)))),
            UnparsedReason::Malformed("TCP")
        );
    }

    #[test]
    fn fragments_are_reported_not_misparsed() {
        // Later fragment: payload is arbitrary data, not a UDP header.
        let later = ipv4_with(PEER, HOST, UDP, 185, &udp(1, 2, 0));
        // First fragment (MF set, offset 0).
        let first = ipv4_with(PEER, HOST, UDP, 0x2000, &udp(1, 2, 0));
        for ip in [later, first] {
            assert_eq!(
                reason(parser(false).parse(&eth_frame(IPV4, &ip))),
                UnparsedReason::Fragmented
            );
        }
        // IPv6 fragment extension header (next header 44), offset 1.
        let mut ext = vec![UDP, 0, 0, 8, 0, 0, 0, 1];
        ext.extend(udp(1, 2, 0));
        let ip = ipv6(v6(1), v6(2), 44, &ext);
        assert_eq!(
            reason(parser(false).parse(&eth_frame(IPV6, &ip))),
            UnparsedReason::Fragmented
        );
    }

    #[test]
    fn ipv6_extension_headers_are_skipped() {
        // Hop-by-hop options header (8 bytes) before TCP.
        let mut ext = vec![TCP, 0, 1, 4, 0, 0, 0, 0];
        ext.extend(tcp(1, 2, 0));
        let ip = ipv6(v6(1), v6(2), 0, &ext);
        let ev = event(parser(false).parse(&eth_frame(IPV6, &ip)));
        assert!(matches!(ev.transport, Transport::Tcp { dst_port: 2, .. }));
    }

    #[test]
    fn bsd_loopback_header_is_four_bytes_in_either_byte_order() {
        let ip = ipv4(UDP, &udp(1, 2, 0));
        for af in [[2, 0, 0, 0], [0, 0, 0, 2]] {
            let mut data = af.to_vec();
            data.extend(&ip);
            let ev = event(parser(false).parse(&frame(LinkType::Loopback, data)));
            assert!(matches!(ev.transport, Transport::Udp { .. }));
        }
        let mut data = vec![0, 0, 0, 30];
        data.extend(ipv6(v6(1), v6(2), TCP, &tcp(1, 2, 0)));
        let ev = event(parser(false).parse(&frame(LinkType::Loopback, data)));
        assert!(matches!(ev.transport, Transport::Tcp { .. }));
    }

    #[test]
    fn loopback_is_not_parsed_as_ethernet() {
        // A 14-byte Ethernet-style placeholder header must NOT be skipped.
        let mut data = vec![0; 14];
        data.extend(ipv4(UDP, &udp(1, 2, 0)));
        assert!(matches!(
            parser(false).parse(&frame(LinkType::Loopback, data)),
            ParseOutcome::Unparsed(_)
        ));
        // Non-IP payload after the 4-byte header.
        let f = frame(LinkType::Loopback, vec![0, 0, 0, 2, 0x10, 0, 0, 0]);
        assert_eq!(
            reason(parser(false).parse(&f)),
            UnparsedReason::UnsupportedEtherType
        );
    }

    #[test]
    fn raw_ip_uses_zeroed_macs() {
        let ip = ipv4(UDP, &udp(1, 2, 0));
        let ev = event(parser(false).parse(&frame(LinkType::RawIp, ip)));
        assert!(matches!(ev.transport, Transport::Udp { .. }));
        let ev = event(parser(false).parse(&frame(
            LinkType::RawIp,
            ipv6(v6(1), v6(2), TCP, &tcp(1, 2, 0)),
        )));
        assert!(matches!(ev.transport, Transport::Tcp { .. }));

        let u = unparsed(parser(false).parse(&frame(LinkType::RawIp, ipv4(GRE, &[0; 8]))));
        let eth = u.ethernet.unwrap();
        assert_eq!(eth.source, MacAddress([0; 6]));
        assert_eq!(eth.ethertype, IPV4);
        assert_eq!(u.reason, UnparsedReason::UnsupportedProtocol);

        // Empty data and a non-IP first nibble must not panic.
        assert!(
            unparsed(parser(false).parse(&frame(LinkType::RawIp, vec![])))
                .ethernet
                .is_none()
        );
        assert_eq!(
            reason(parser(false).parse(&frame(LinkType::RawIp, vec![0x10; 20]))),
            UnparsedReason::UnsupportedEtherType
        );
    }

    #[test]
    fn linux_cooked_v1_and_v2() {
        let ip = ipv4(TCP, &tcp(1, 2, 0));
        // v1: pkttype, hatype=1, addrlen=6, addr[8], protocol
        let mut v1 = vec![0, 0, 0, 1, 0, 6, 0xde, 0xad, 0xbe, 0xef, 0, 1, 0, 0];
        v1.extend(IPV4.to_be_bytes());
        v1.extend(&ip);
        // v2: protocol, reserved, ifindex, hatype, pkttype, addrlen, addr[8]
        let mut v2 = IPV4.to_be_bytes().to_vec();
        v2.extend([
            0, 0, 0, 0, 0, 2, 0, 1, 0, 6, 0xde, 0xad, 0xbe, 0xef, 0, 1, 0, 0,
        ]);
        v2.extend(&ip);
        for (lt, data) in [(LinkType::LinuxSll, v1), (LinkType::LinuxSll2, v2)] {
            let ev = event(parser(false).parse(&frame(lt, data.clone())));
            assert!(matches!(ev.transport, Transport::Tcp { dst_port: 2, .. }));
            // Truncated inside the cooked header.
            let short = frame(lt, data[..10].to_vec());
            let u = unparsed(parser(false).parse(&short));
            assert_eq!(u.reason, UnparsedReason::Malformed("Linux cooked"));
        }
    }

    #[test]
    fn linux_cooked_unsupported_protocol_keeps_sender_mac() {
        let mut v1 = vec![0, 0, 0, 1, 0, 6, 0xde, 0xad, 0xbe, 0xef, 0, 1, 0, 0];
        v1.extend([0x88, 0xcc, 1, 2, 3]);
        let u = unparsed(parser(false).parse(&frame(LinkType::LinuxSll, v1)));
        assert_eq!(u.reason, UnparsedReason::UnsupportedEtherType);
        let eth = u.ethernet.unwrap();
        assert_eq!(eth.source, MacAddress([0xde, 0xad, 0xbe, 0xef, 0, 1]));
        assert_eq!(eth.ethertype, 0x88cc);
    }

    #[test]
    fn ipv4_total_length_zero_from_tso_is_reported() {
        // NIC segmentation offload leaves total length 0 in outbound captures.
        let mut ip = ipv4(TCP, &tcp(1, 2, 0));
        ip[2] = 0;
        ip[3] = 0;
        let r = reason(parser(false).parse(&eth_frame(IPV4, &ip)));
        assert_eq!(r, UnparsedReason::Malformed("IPv4"));
    }

    #[test]
    fn every_truncation_is_handled_without_panic() {
        let packets = [
            (IPV4, ipv4(TCP, &tcp(1, 2, 8))),
            (IPV4, ipv4(UDP, &udp(53, 2, 8))),
            (IPV4, ipv4(ICMP, &icmp_echo(8, 1, 1))),
            (IPV6, ipv6(v6(1), v6(2), TCP, &tcp(1, 2, 8))),
            (IPV6, ipv6(v6(1), v6(2), ICMPV6, &icmp_echo(128, 1, 1))),
            (ARP, arp_request(PEER, HOST)),
        ];
        for (ethertype, payload) in packets {
            let full = ethernet(ethertype, &payload);
            for len in 0..full.len() {
                let cut = frame(LinkType::Ethernet, full[..len].to_vec());
                assert!(
                    matches!(parser(false).parse(&cut), ParseOutcome::Unparsed(_)),
                    "cut at {len} of {} must not yield an event",
                    full.len()
                );
            }
            assert!(matches!(
                parser(false).parse(&frame(LinkType::Ethernet, full)),
                ParseOutcome::Event(_)
            ));
        }
    }
}
