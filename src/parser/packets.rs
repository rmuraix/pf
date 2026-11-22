//! Maps etherparse slices to model types.

use std::net::Ipv4Addr;

use etherparse::{ArpPacketSlice, EtherType, Icmpv4Type, TransportSlice};

use crate::model::{IcmpKind, Transport};

/// TCP, UDP, ICMP or ICMPv6 as a [`Transport`]; `None` for anything else
/// (e.g. IGMP).
pub(crate) fn transport(slice: &TransportSlice) -> Option<Transport> {
    Some(match slice {
        TransportSlice::Udp(udp) => {
            let (src_port, dst_port) = (udp.source_port(), udp.destination_port());
            Transport::Udp {
                src_port,
                dst_port,
                length: udp.length(),
                is_dns: src_port == 53 || dst_port == 53,
            }
        }
        TransportSlice::Tcp(tcp) => Transport::Tcp {
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            // Header plus payload, as before the etherparse migration.
            length: tcp.slice().len(),
        },
        TransportSlice::Icmpv4(icmp) => Transport::Icmp(match icmp.icmp_type() {
            Icmpv4Type::EchoReply(e) => IcmpKind::EchoReply {
                seq: e.seq,
                id: e.id,
            },
            Icmpv4Type::EchoRequest(e) => IcmpKind::EchoRequest {
                seq: e.seq,
                id: e.id,
            },
            _ => IcmpKind::Other(icmp.type_u8()),
        }),
        TransportSlice::Icmpv6(icmp) => Transport::Icmpv6 {
            type_u8: icmp.type_u8(),
        },
        TransportSlice::Igmp(_) => return None,
    })
}

/// Addresses of an Ethernet/IPv4 ARP packet.
pub(crate) struct Arp {
    pub operation: u16,
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

/// `None` unless the packet carries IPv4 protocol addresses.
pub(crate) fn arp(slice: &ArpPacketSlice) -> Option<Arp> {
    let packet = slice.to_packet();
    if packet.proto_addr_type != EtherType::IPV4 {
        return None;
    }
    let ip = |bytes: &[u8]| <[u8; 4]>::try_from(bytes).ok().map(Ipv4Addr::from);
    Some(Arp {
        operation: packet.operation.0,
        sender_ip: ip(packet.sender_protocol_addr())?,
        target_ip: ip(packet.target_protocol_addr())?,
    })
}
