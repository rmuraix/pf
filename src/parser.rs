//! Turns [`CapturedFrame`]s into [`ParseOutcome`]s. No printing happens here.
//!
//! This module (with `packets`) and `capture` are the only places that use
//! `pnet` types.

mod direction;
mod packets;

use std::collections::HashSet;
use std::net::IpAddr;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::util::MacAddr;

use crate::frame::{CapturedFrame, LinkType};
use crate::model::{
    Direction as FlowDir, EthernetSummary, MacAddress, NetEvent, ParseOutcome, Transport,
    UnparsedFrame, UnparsedReason,
};
use packets::{build_icmp_event, build_icmpv6_event, build_tcp_event, build_udp_event};

/// Length of an Ethernet II header.
const ETHERNET_HEADER_LEN: usize = 14;

pub struct Parser {
    host_ips: HashSet<IpAddr>,
    noudp: bool,
}

/// Link-layer view of a frame: addresses, EtherType and the network payload.
struct LinkFrame<'a> {
    summary: EthernetSummary,
    payload: &'a [u8],
}

fn mac(addr: MacAddr) -> MacAddress {
    MacAddress([addr.0, addr.1, addr.2, addr.3, addr.4, addr.5])
}

impl<'a> LinkFrame<'a> {
    fn ethernet(data: &'a [u8]) -> Option<Self> {
        let eth = EthernetPacket::new(data)?;
        Some(Self {
            summary: EthernetSummary {
                source: mac(eth.get_source()),
                destination: mac(eth.get_destination()),
                ethertype: eth.get_ethertype().0,
            },
            payload: &data[ETHERNET_HEADER_LEN..],
        })
    }

    /// An IP packet without real link-layer addresses (zeroed MACs).
    /// `None` unless the first nibble says IPv4 or IPv6.
    fn ip_only(ip: &'a [u8]) -> Option<Self> {
        let ethertype = match ip.first()? >> 4 {
            4 => EtherTypes::Ipv4,
            6 => EtherTypes::Ipv6,
            _ => return None,
        };
        Some(Self {
            summary: EthernetSummary {
                source: MacAddress([0; 6]),
                destination: MacAddress([0; 6]),
                ethertype: ethertype.0,
            },
            payload: ip,
        })
    }

    fn from_frame(frame: &'a CapturedFrame) -> Option<Self> {
        let data = &frame.data[..];
        let ip_offset = match frame.link_type {
            LinkType::Ethernet => return Self::ethernet(data),
            LinkType::Loopback => ETHERNET_HEADER_LEN,
            LinkType::RawIp => 0,
        };
        // As before the refactor: data that is not IPv4/IPv6 after the
        // placeholder header is parsed as a regular Ethernet frame.
        data.get(ip_offset..)
            .and_then(Self::ip_only)
            .or_else(|| Self::ethernet(data))
    }
}

impl Parser {
    pub fn new(host_ips: HashSet<IpAddr>, noudp: bool) -> Self {
        Self { host_ips, noudp }
    }

    pub fn parse(&self, frame: &CapturedFrame) -> ParseOutcome {
        let interface = &frame.interface;
        let unparsed = |ethernet, reason| {
            ParseOutcome::Unparsed(UnparsedFrame {
                interface: interface.to_string(),
                length: frame.captured_len(),
                ethernet,
                reason,
            })
        };
        let Some(link) = LinkFrame::from_frame(frame) else {
            return unparsed(None, UnparsedReason::Malformed("Ethernet"));
        };
        match self.parse_network(interface, &link, EtherType(link.summary.ethertype)) {
            Ok(event) => ParseOutcome::Event(event),
            Err(reason) => unparsed(Some(link.summary), reason),
        }
    }

    fn parse_network(
        &self,
        interface: &str,
        link: &LinkFrame,
        ethertype: EtherType,
    ) -> Result<NetEvent, UnparsedReason> {
        let ips = &self.host_ips;
        match ethertype {
            EtherTypes::Ipv4 => {
                let ip = Ipv4Packet::new(link.payload).ok_or(UnparsedReason::Malformed("IPv4"))?;
                let (src, dst) = (
                    IpAddr::V4(ip.get_source()),
                    IpAddr::V4(ip.get_destination()),
                );
                let proto = ip.get_next_level_protocol();
                match proto {
                    IpNextHeaderProtocols::Icmp => {
                        build_icmp_event(interface, src, dst, ip.payload(), ips)
                            .ok_or(UnparsedReason::Malformed("ICMP"))
                    }
                    _ => self.parse_common(interface, src, dst, proto, ip.payload()),
                }
            }
            EtherTypes::Ipv6 => {
                let ip = Ipv6Packet::new(link.payload).ok_or(UnparsedReason::Malformed("IPv6"))?;
                let (src, dst) = (
                    IpAddr::V6(ip.get_source()),
                    IpAddr::V6(ip.get_destination()),
                );
                let proto = ip.get_next_header();
                match proto {
                    IpNextHeaderProtocols::Icmpv6 => {
                        build_icmpv6_event(interface, src, dst, ip.payload(), ips)
                            .ok_or(UnparsedReason::Malformed("ICMPv6"))
                    }
                    _ => self.parse_common(interface, src, dst, proto, ip.payload()),
                }
            }
            EtherTypes::Arp => build_arp_event(interface, &link.summary, link.payload, ips)
                .ok_or(UnparsedReason::Malformed("ARP")),
            _ => Err(UnparsedReason::UnsupportedEtherType),
        }
    }

    /// TCP and UDP, shared by IPv4 and IPv6.
    fn parse_common(
        &self,
        interface: &str,
        src: IpAddr,
        dst: IpAddr,
        proto: IpNextHeaderProtocol,
        payload: &[u8],
    ) -> Result<NetEvent, UnparsedReason> {
        match proto {
            IpNextHeaderProtocols::Udp if self.noudp => Err(UnparsedReason::Filtered),
            IpNextHeaderProtocols::Udp => {
                build_udp_event(interface, src, dst, payload, &self.host_ips)
                    .ok_or(UnparsedReason::Malformed("UDP"))
            }
            IpNextHeaderProtocols::Tcp => {
                build_tcp_event(interface, src, dst, payload, &self.host_ips)
                    .ok_or(UnparsedReason::Malformed("TCP"))
            }
            _ => Err(UnparsedReason::UnsupportedProtocol),
        }
    }
}

fn build_arp_event(
    interface: &str,
    eth: &EthernetSummary,
    payload: &[u8],
    ips: &HashSet<IpAddr>,
) -> Option<NetEvent> {
    let header = ArpPacket::new(payload)?;
    let dir = if direction::is_destination(IpAddr::V4(header.get_target_proto_addr()), ips) {
        FlowDir::Inbound
    } else {
        FlowDir::Outbound
    };
    Some(NetEvent::new(
        interface,
        dir,
        IpAddr::V4(header.get_sender_proto_addr()),
        IpAddr::V4(header.get_target_proto_addr()),
        Transport::Arp {
            operation: header.get_operation().0,
            sender_mac: eth.source,
            sender_ip: header.get_sender_proto_addr(),
            target_mac: eth.destination,
            target_ip: header.get_target_proto_addr(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::MutablePacket;
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::udp::MutableUdpPacket;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::SystemTime;

    fn parser(noudp: bool) -> Parser {
        Parser::new(
            HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]),
            noudp,
        )
    }

    fn frame(link_type: LinkType, data: Vec<u8>) -> CapturedFrame {
        CapturedFrame {
            timestamp: SystemTime::UNIX_EPOCH,
            interface: Arc::from("eth0"),
            link_type,
            data,
        }
    }

    /// IPv4 packet with the given protocol and payload bytes.
    fn ipv4(proto: IpNextHeaderProtocol, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + payload.len()];
        let mut ip = MutableIpv4Packet::new(&mut buf[..]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(proto);
        ip.set_source(Ipv4Addr::new(1, 1, 1, 1));
        ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
        ip.set_payload(payload);
        buf
    }

    fn udp_segment() -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        let mut udp = MutableUdpPacket::new(&mut buf[..]).unwrap();
        udp.set_source(53);
        udp.set_destination(53000);
        udp.set_length(8);
        buf
    }

    fn ethernet(ethertype: EtherType, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
        let mut eth = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        eth.set_ethertype(ethertype);
        eth.set_source(MacAddr(0, 0, 0, 0, 0, 1));
        eth.set_destination(MacAddr(0, 0, 0, 0, 0, 2));
        eth.set_payload(payload);
        buf
    }

    fn event(outcome: ParseOutcome) -> NetEvent {
        match outcome {
            ParseOutcome::Event(e) => e,
            other => panic!("expected event, got {other:?}"),
        }
    }

    fn reason(outcome: ParseOutcome) -> UnparsedReason {
        match outcome {
            ParseOutcome::Unparsed(f) => f.reason,
            other => panic!("expected unparsed, got {other:?}"),
        }
    }

    #[test]
    fn ipv4_udp_is_filtered_by_noudp() {
        let f = frame(
            LinkType::Ethernet,
            ethernet(
                EtherTypes::Ipv4,
                &ipv4(IpNextHeaderProtocols::Udp, &udp_segment()),
            ),
        );
        match parser(true).parse(&f) {
            ParseOutcome::Unparsed(u) => {
                assert_eq!(u.reason, UnparsedReason::Filtered);
                assert_eq!(u.length, f.captured_len());
                assert_eq!(u.ethernet.unwrap().ethertype, EtherTypes::Ipv4.0);
            }
            other => panic!("expected unparsed, got {other:?}"),
        }
        let ev = event(parser(false).parse(&f));
        assert!(matches!(ev.transport, Transport::Udp { is_dns: true, .. }));
        assert_eq!(ev.interface, "eth0");
        assert_eq!(ev.direction, FlowDir::Inbound);
    }

    #[test]
    fn ipv6_tcp_outbound() {
        let mut ip6_buf = vec![0u8; 40 + 20];
        {
            let mut ip6 = MutableIpv6Packet::new(&mut ip6_buf[..]).unwrap();
            ip6.set_version(6);
            ip6.set_payload_length(20);
            ip6.set_next_header(IpNextHeaderProtocols::Tcp);
            ip6.set_hop_limit(64);
            ip6.set_source(Ipv6Addr::LOCALHOST);
            ip6.set_destination(Ipv6Addr::LOCALHOST);
            let mut tcp = MutableTcpPacket::new(ip6.payload_mut()).unwrap();
            tcp.set_source(50000);
            tcp.set_destination(443);
        }
        let f = frame(LinkType::Ethernet, ethernet(EtherTypes::Ipv6, &ip6_buf));
        let ev = event(parser(false).parse(&f));
        assert!(matches!(ev.transport, Transport::Tcp { dst_port: 443, .. }));
        assert_eq!(ev.direction, FlowDir::Outbound);
    }

    #[test]
    fn ipv6_icmpv6() {
        let mut ip6_buf = vec![0u8; 40 + 4];
        {
            let mut ip6 = MutableIpv6Packet::new(&mut ip6_buf[..]).unwrap();
            ip6.set_version(6);
            ip6.set_payload_length(4);
            ip6.set_next_header(IpNextHeaderProtocols::Icmpv6);
            ip6.payload_mut()[0] = 128;
        }
        let f = frame(LinkType::Ethernet, ethernet(EtherTypes::Ipv6, &ip6_buf));
        let ev = event(parser(false).parse(&f));
        assert_eq!(ev.transport, Transport::Icmpv6 { type_u8: 128 });
    }

    #[test]
    fn ipv4_icmp_echo_request() {
        let mut icmp = vec![0u8; 8];
        MutableIcmpPacket::new(&mut icmp[..])
            .unwrap()
            .set_icmp_type(IcmpTypes::EchoRequest);
        let f = frame(
            LinkType::Ethernet,
            ethernet(EtherTypes::Ipv4, &ipv4(IpNextHeaderProtocols::Icmp, &icmp)),
        );
        let ev = event(parser(false).parse(&f));
        assert!(matches!(ev.transport, Transport::Icmp(_)));
    }

    #[test]
    fn arp_request_inbound() {
        let mut arp_buf = vec![0u8; 28];
        {
            let mut arp = MutableArpPacket::new(&mut arp_buf[..]).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 3));
            arp.set_target_proto_addr(Ipv4Addr::new(10, 0, 0, 2));
        }
        let f = frame(LinkType::Ethernet, ethernet(EtherTypes::Arp, &arp_buf));
        let ev = event(parser(false).parse(&f));
        assert_eq!(ev.direction, FlowDir::Inbound);
        match ev.transport {
            Transport::Arp {
                operation,
                sender_ip,
                target_ip,
                target_mac,
                ..
            } => {
                assert_eq!(operation, ArpOperations::Request.0);
                assert_eq!(sender_ip, Ipv4Addr::new(10, 0, 0, 3));
                assert_eq!(target_ip, Ipv4Addr::new(10, 0, 0, 2));
                assert_eq!(target_mac, MacAddress([0, 0, 0, 0, 0, 2]));
            }
            other => panic!("not arp: {other:?}"),
        }
    }

    #[test]
    fn unsupported_ethertype_and_protocol_are_explicit() {
        let f = frame(LinkType::Ethernet, ethernet(EtherType(0x88cc), &[0; 10]));
        assert_eq!(
            reason(parser(false).parse(&f)),
            UnparsedReason::UnsupportedEtherType
        );

        let f = frame(
            LinkType::Ethernet,
            ethernet(EtherTypes::Ipv4, &ipv4(IpNextHeaderProtocols::Gre, &[0; 8])),
        );
        assert_eq!(
            reason(parser(false).parse(&f)),
            UnparsedReason::UnsupportedProtocol
        );
    }

    #[test]
    fn malformed_packets_are_explicit() {
        // Too short for an Ethernet header: no EthernetSummary available.
        match parser(false).parse(&frame(LinkType::Ethernet, vec![0; 5])) {
            ParseOutcome::Unparsed(u) => {
                assert_eq!(u.reason, UnparsedReason::Malformed("Ethernet"));
                assert!(u.ethernet.is_none());
                assert_eq!(u.length, 5);
            }
            other => panic!("expected unparsed, got {other:?}"),
        }
        // Truncated IPv4 header, ARP body and TCP segment.
        let cases = [
            (ethernet(EtherTypes::Ipv4, &[0x45; 4]), "IPv4"),
            (ethernet(EtherTypes::Ipv6, &[0x60; 4]), "IPv6"),
            (ethernet(EtherTypes::Arp, &[0; 4]), "ARP"),
            (
                ethernet(EtherTypes::Ipv4, &ipv4(IpNextHeaderProtocols::Tcp, &[0; 4])),
                "TCP",
            ),
            (
                ethernet(EtherTypes::Ipv4, &ipv4(IpNextHeaderProtocols::Udp, &[0; 4])),
                "UDP",
            ),
        ];
        for (data, name) in cases {
            let r = reason(parser(false).parse(&frame(LinkType::Ethernet, data)));
            assert_eq!(r, UnparsedReason::Malformed(name));
        }
    }

    #[test]
    fn loopback_and_raw_ip_use_zeroed_macs() {
        let ip = ipv4(IpNextHeaderProtocols::Udp, &udp_segment());
        let mut loopback = vec![0u8; ETHERNET_HEADER_LEN];
        loopback.extend_from_slice(&ip);
        for f in [
            frame(LinkType::Loopback, loopback),
            frame(LinkType::RawIp, ip.clone()),
        ] {
            let ev = event(parser(false).parse(&f));
            assert!(matches!(ev.transport, Transport::Udp { .. }));
        }
        // Unsupported protocol keeps the zeroed MAC summary.
        let raw = frame(LinkType::RawIp, ipv4(IpNextHeaderProtocols::Gre, &[0; 8]));
        match parser(false).parse(&raw) {
            ParseOutcome::Unparsed(u) => {
                let eth = u.ethernet.unwrap();
                assert_eq!(eth.source, MacAddress([0; 6]));
                assert_eq!(eth.ethertype, EtherTypes::Ipv4.0);
            }
            other => panic!("expected unparsed, got {other:?}"),
        }
    }

    #[test]
    fn loopback_without_ip_falls_back_to_ethernet() {
        // Not IPv4/IPv6 after the placeholder header: parsed as Ethernet.
        let f = frame(LinkType::Loopback, ethernet(EtherType(0x88cc), &[0; 10]));
        assert_eq!(
            reason(parser(false).parse(&f)),
            UnparsedReason::UnsupportedEtherType
        );
        // Too short: must not panic.
        let f = frame(LinkType::RawIp, vec![]);
        assert_eq!(
            reason(parser(false).parse(&f)),
            UnparsedReason::Malformed("Ethernet")
        );
    }
}
