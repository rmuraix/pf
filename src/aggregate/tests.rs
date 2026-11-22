use super::*;
use crate::model::{IcmpKind, MacAddress, NetEvent};
use std::net::Ipv4Addr;

const HOST: &str = "10.0.0.2";
const PEER: &str = "1.1.1.1";

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn tcp_flags(syn: bool, ack: bool, fin: bool, rst: bool) -> TcpFlags {
    TcpFlags { syn, ack, fin, rst }
}

const ACK: TcpFlags = TcpFlags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
};

/// A packet as the parser would report it.
struct Pkt {
    iface: &'static str,
    time: u64,
    direction: Direction,
    src: (&'static str, u16),
    dst: (&'static str, u16),
    wire_len: usize,
    transport: fn(u16, u16) -> Transport,
}

fn tcp_transport(src_port: u16, dst_port: u16) -> Transport {
    Transport::Tcp {
        src_port,
        dst_port,
        length: 0,
        flags: ACK,
    }
}

fn udp_transport(src_port: u16, dst_port: u16) -> Transport {
    Transport::Udp {
        src_port,
        dst_port,
        length: 0,
        is_dns: false,
    }
}

impl Pkt {
    /// Outbound TCP from `HOST:50000` to `PEER:443`.
    fn out() -> Self {
        Self {
            iface: "eth0",
            time: 100,
            direction: Direction::Outbound,
            src: (HOST, 50000),
            dst: (PEER, 443),
            wire_len: 100,
            transport: tcp_transport,
        }
    }

    /// The reply to [`Pkt::out`].
    fn inbound() -> Self {
        Self {
            direction: Direction::Inbound,
            src: (PEER, 443),
            dst: (HOST, 50000),
            ..Self::out()
        }
    }

    fn at(self, time: u64) -> Self {
        Self { time, ..self }
    }

    fn len(self, wire_len: usize) -> Self {
        Self { wire_len, ..self }
    }

    fn iface(self, iface: &'static str) -> Self {
        Self { iface, ..self }
    }

    fn udp(self) -> Self {
        Self {
            transport: udp_transport,
            ..self
        }
    }

    fn observation(&self, flags: Option<TcpFlags>) -> Observation {
        let mut transport = (self.transport)(self.src.1, self.dst.1);
        if let (Transport::Tcp { flags: f, .. }, Some(flags)) = (&mut transport, flags) {
            *f = flags;
        }
        Observation {
            timestamp: at(self.time),
            wire_len: self.wire_len,
            outcome: ParseOutcome::Event(NetEvent::new(
                self.iface,
                self.direction,
                ip(self.src.0),
                ip(self.dst.0),
                transport,
            )),
        }
    }
}

fn feed(agg: &mut Aggregator, pkt: Pkt) {
    agg.ingest(pkt.observation(None));
}

fn feed_flags(agg: &mut Aggregator, pkt: Pkt, flags: TcpFlags) {
    agg.ingest(pkt.observation(Some(flags)));
}

fn aggregator() -> Aggregator {
    Aggregator::new(Limits::default())
}

fn flows(agg: &Aggregator, now: u64) -> Vec<FlowSummary> {
    let mut flows = agg.snapshot(at(now)).flows;
    flows.sort_by_key(|f| f.id);
    flows
}

#[test]
fn opposite_directions_share_one_flow() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out());
    feed(&mut agg, Pkt::inbound());

    let flows = flows(&agg, 100);
    assert_eq!(flows.len(), 1);
    let flow = &flows[0];
    assert_eq!(flow.local, SocketAddr::new(ip(HOST), 50000));
    assert_eq!(flow.remote, SocketAddr::new(ip(PEER), 443));
    assert_eq!(flow.packets.outbound, 1);
    assert_eq!(flow.packets.inbound, 1);
}

#[test]
fn inbound_first_packet_identifies_the_local_side() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::inbound());

    let flow = &flows(&agg, 100)[0];
    assert_eq!(flow.local, SocketAddr::new(ip(HOST), 50000));
    assert_eq!(flow.remote, SocketAddr::new(ip(PEER), 443));
    assert_eq!(flow.packets.inbound, 1);
}

#[test]
fn loopback_counts_both_directions_in_one_flow() {
    // The parser calls every packet on `lo` outbound (loopback addresses are
    // not host addresses), so the flow must derive directions itself.
    let lo = |src: (&'static str, u16), dst: (&'static str, u16)| Pkt {
        iface: "lo",
        direction: Direction::Outbound,
        src,
        dst,
        ..Pkt::out()
    };
    let mut agg = aggregator();
    feed(
        &mut agg,
        lo(("127.0.0.1", 40000), ("127.0.0.1", 8080)).len(60),
    );
    feed(
        &mut agg,
        lo(("127.0.0.1", 8080), ("127.0.0.1", 40000)).len(1500),
    );

    let flows = flows(&agg, 100);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].local.port(), 40000);
    assert_eq!(flows[0].bytes.outbound, 60);
    assert_eq!(flows[0].bytes.inbound, 1500);
}

#[test]
fn protocol_and_interface_separate_flows() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out());
    feed(&mut agg, Pkt::out().udp());
    feed(&mut agg, Pkt::out().iface("eth1"));

    assert_eq!(flows(&agg, 100).len(), 3);
}

#[test]
fn different_ports_on_the_same_hosts_are_different_flows() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out());
    feed(
        &mut agg,
        Pkt {
            src: (HOST, 50001),
            ..Pkt::out()
        },
    );

    assert_eq!(flows(&agg, 100).len(), 2);
}

#[test]
fn volume_uses_wire_length_not_payload_length() {
    let mut agg = aggregator();
    // `Transport::Tcp::length` is 0 in the fixtures; only `wire_len` counts.
    feed(&mut agg, Pkt::out().len(1514));
    feed(&mut agg, Pkt::inbound().len(66));

    let flow = &flows(&agg, 100)[0];
    assert_eq!(flow.bytes.outbound, 1514);
    assert_eq!(flow.bytes.inbound, 66);
    assert_eq!(flow.total_bytes(), 1580);
    assert_eq!(flow.total_packets(), 2);
    assert_eq!(agg.counters().bytes, 1580);
    assert_eq!(agg.counters().packets, 2);
}

#[test]
fn timestamps_track_first_and_last_packet() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(100));
    feed(&mut agg, Pkt::inbound().at(103));

    let flow = &flows(&agg, 110)[0];
    assert_eq!(flow.first_seen, at(100));
    assert_eq!(flow.last_seen, at(103));
    assert_eq!(flow.duration(), Duration::from_secs(3));
}

#[test]
fn late_packets_do_not_move_last_seen_backwards() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(105));
    feed(&mut agg, Pkt::out().at(101));

    assert_eq!(flows(&agg, 110)[0].last_seen, at(105));
}

#[test]
fn rate_is_averaged_over_the_flow_age_then_the_window() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(100).len(1000));
    feed(&mut agg, Pkt::out().at(101).len(3000));
    feed(&mut agg, Pkt::inbound().at(101).len(500));

    // Two seconds old: 4000 bytes / 2 s outbound.
    let flow = &flows(&agg, 101)[0];
    assert_eq!(flow.rate.outbound, 2000.0);
    assert_eq!(flow.rate.inbound, 250.0);

    // Still inside the 5 s window: spread over the 5 s.
    let flow = &flows(&agg, 104)[0];
    assert_eq!(flow.rate.outbound, 800.0);
}

#[test]
fn rate_decays_to_zero_when_traffic_stops() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(100).len(1000));

    assert!(flows(&agg, 100)[0].rate.outbound > 0.0);
    assert_eq!(flows(&agg, 105)[0].rate.outbound, 0.0);
    // Totals are unaffected by the decay.
    assert_eq!(flows(&agg, 105)[0].bytes.outbound, 1000);
}

#[test]
fn rate_only_counts_recent_seconds_of_a_long_flow() {
    let mut agg = aggregator();
    for t in 100..200 {
        feed(&mut agg, Pkt::out().at(t).len(100));
    }
    // 100 B every second: steady 100 B/s, not total / age.
    assert_eq!(flows(&agg, 199)[0].rate.outbound, 100.0);
}

#[test]
fn idle_flows_expire() {
    let mut agg = Aggregator::new(Limits {
        idle_timeout: Duration::from_secs(30),
        ..Limits::default()
    });
    feed(&mut agg, Pkt::out().at(100));

    agg.expire(at(129));
    assert_eq!(agg.flow_count(), 1);
    agg.expire(at(130));
    assert_eq!(agg.flow_count(), 0);
    assert_eq!(agg.counters().flows_expired, 1);
}

#[test]
fn endpoint_reuse_after_idle_starts_a_new_flow() {
    let mut agg = Aggregator::new(Limits {
        idle_timeout: Duration::from_secs(30),
        ..Limits::default()
    });
    feed(&mut agg, Pkt::out().at(100).len(1000));
    // No sweep ran in between: the arrival itself must notice the gap.
    feed(&mut agg, Pkt::out().at(200).len(60));

    let flows = flows(&agg, 200);
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].bytes.outbound, 60,
        "old session must not be merged"
    );
    assert_eq!(flows[0].first_seen, at(200));
    assert_eq!(flows[0].id, 2);
    assert_eq!(agg.counters().flows_expired, 1);
}

#[test]
fn tcp_syn_after_close_starts_a_new_flow() {
    let fin = tcp_flags(false, true, true, false);
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(100).len(1000));
    feed_flags(&mut agg, Pkt::out().at(101), fin);
    feed_flags(&mut agg, Pkt::inbound().at(101), fin);
    assert!(flows(&agg, 101)[0].closed);

    feed_flags(
        &mut agg,
        Pkt::out().at(102),
        tcp_flags(true, false, false, false),
    );

    let flows = flows(&agg, 102);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].id, 2);
    assert_eq!(flows[0].total_packets(), 1);
    assert!(!flows[0].closed);
}

#[test]
fn tcp_rst_closes_and_a_new_syn_replaces_it() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(100));
    feed_flags(
        &mut agg,
        Pkt::inbound().at(101),
        tcp_flags(false, false, false, true),
    );
    assert!(flows(&agg, 101)[0].closed);

    feed_flags(
        &mut agg,
        Pkt::out().at(102),
        tcp_flags(true, false, false, false),
    );
    assert_eq!(flows(&agg, 102)[0].id, 2);
}

#[test]
fn syn_retransmission_on_an_open_flow_is_not_a_new_session() {
    let syn = tcp_flags(true, false, false, false);
    let mut agg = aggregator();
    feed_flags(&mut agg, Pkt::out().at(100), syn);
    feed_flags(&mut agg, Pkt::out().at(101), syn);

    let flows = flows(&agg, 101);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].packets.outbound, 2);
}

#[test]
fn a_single_fin_does_not_close_the_flow() {
    let mut agg = aggregator();
    feed_flags(
        &mut agg,
        Pkt::out().at(100),
        tcp_flags(false, true, true, false),
    );
    feed_flags(
        &mut agg,
        Pkt::out().at(101),
        tcp_flags(true, false, false, false),
    );

    // Half-closed connections keep flowing; a lone FIN is not a session end.
    assert_eq!(flows(&agg, 101).len(), 1);
    assert_eq!(flows(&agg, 101)[0].id, 1);
}

#[test]
fn closed_flows_expire_after_the_linger_time() {
    let mut agg = Aggregator::new(Limits {
        closed_linger: Duration::from_secs(5),
        ..Limits::default()
    });
    feed_flags(
        &mut agg,
        Pkt::out().at(100),
        tcp_flags(false, false, false, true),
    );

    agg.expire(at(104));
    assert_eq!(agg.flow_count(), 1);
    agg.expire(at(105));
    assert_eq!(agg.flow_count(), 0);
}

#[test]
fn flow_table_is_bounded_and_evicts_the_least_recent() {
    let mut agg = Aggregator::new(Limits {
        max_flows: 16,
        ..Limits::default()
    });
    for port in 0..16u16 {
        feed(
            &mut agg,
            Pkt {
                src: (HOST, 1000 + port),
                ..Pkt::out().at(100 + u64::from(port))
            },
        );
    }
    assert_eq!(agg.flow_count(), 16);

    feed(
        &mut agg,
        Pkt {
            src: (HOST, 2000),
            ..Pkt::out().at(200)
        },
    );

    // An eighth (2 flows) is dropped to make room: the two oldest.
    assert_eq!(agg.flow_count(), 15);
    assert_eq!(agg.counters().flows_evicted, 2);
    let ports: Vec<u16> = flows(&agg, 200).iter().map(|f| f.local.port()).collect();
    assert!(!ports.contains(&1000) && !ports.contains(&1001));
    assert!(ports.contains(&1002) && ports.contains(&2000));
}

#[test]
fn memory_stays_bounded_under_a_flood_of_new_flows() {
    let limits = Limits {
        max_flows: 100,
        history_len: 4,
        event_capacity: 10,
        ..Limits::default()
    };
    let mut agg = Aggregator::new(limits);
    for i in 0..10_000u32 {
        let port = (i % 60_000) as u16 + 1024;
        feed(
            &mut agg,
            Pkt {
                src: (HOST, port),
                dst: (PEER, (i / 1000) as u16 + 1),
                ..Pkt::out().at(100 + u64::from(i / 100))
            },
        );
        assert!(agg.flow_count() <= limits.max_flows);
    }
    let counters = agg.counters();
    assert_eq!(counters.packets, 10_000);
    assert_eq!(
        counters.flows_evicted + agg.flow_count() as u64,
        10_000,
        "every flow is either tracked or counted as evicted"
    );
}

#[test]
fn eviction_does_not_change_totals() {
    let mut agg = Aggregator::new(Limits {
        max_flows: 8,
        ..Limits::default()
    });
    for port in 0..100u16 {
        feed(
            &mut agg,
            Pkt {
                src: (HOST, 1000 + port),
                ..Pkt::out().len(100)
            },
        );
    }
    assert_eq!(agg.counters().packets, 100);
    assert_eq!(agg.counters().bytes, 10_000);
}

#[test]
fn history_is_bounded_and_chronological() {
    let mut agg = Aggregator::new(Limits {
        history_len: 3,
        ..Limits::default()
    });
    for t in 100..106 {
        feed(&mut agg, Pkt::out().at(t).len(t as usize));
    }
    feed(&mut agg, Pkt::inbound().at(106).len(7));

    let detail = agg.flow_detail(1, at(106)).unwrap();
    assert_eq!(detail.history_capacity, 3);
    let lens: Vec<usize> = detail.history.iter().map(|s| s.wire_len).collect();
    assert_eq!(lens, [104, 105, 7]);
    assert_eq!(detail.history.last().unwrap().direction, Direction::Inbound);
    // The summary still counts every packet, not just the remembered ones.
    assert_eq!(detail.summary.total_packets(), 7);
}

#[test]
fn flow_detail_is_none_for_an_expired_flow() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().at(100));
    assert!(agg.flow_detail(1, at(100)).is_some());
    agg.expire(at(1000));
    assert!(agg.flow_detail(1, at(1000)).is_none());
}

fn icmp(time: u64) -> Observation {
    Observation {
        timestamp: at(time),
        wire_len: 98,
        outcome: ParseOutcome::Event(NetEvent::new(
            "eth0",
            Direction::Outbound,
            ip(HOST),
            ip(PEER),
            Transport::Icmp(IcmpKind::EchoRequest { seq: 1, id: 2 }),
        )),
    }
}

fn unparsed(reason: UnparsedReason) -> Observation {
    Observation {
        timestamp: at(100),
        wire_len: 60,
        outcome: ParseOutcome::Unparsed(UnparsedFrame {
            interface: Arc::from("eth0"),
            length: 60,
            ethernet: None,
            reason,
        }),
    }
}

#[test]
fn non_flow_packets_go_to_the_event_log() {
    let mut agg = aggregator();
    agg.ingest(icmp(100));
    agg.ingest(Observation {
        timestamp: at(101),
        wire_len: 42,
        outcome: ParseOutcome::Event(NetEvent::new(
            "eth0",
            Direction::Inbound,
            ip(PEER),
            ip(HOST),
            Transport::Arp {
                operation: 1,
                sender_mac: MacAddress([0; 6]),
                sender_ip: Ipv4Addr::new(1, 1, 1, 1),
                target_mac: MacAddress([0; 6]),
                target_ip: Ipv4Addr::new(10, 0, 0, 2),
            },
        )),
    });
    agg.ingest(unparsed(UnparsedReason::Malformed("TCP")));
    agg.ingest(Observation {
        timestamp: at(102),
        wire_len: 70,
        outcome: ParseOutcome::Event(NetEvent::new(
            "eth0",
            Direction::Outbound,
            ip("fe80::1"),
            ip("ff02::1"),
            Transport::Icmpv6 { type_u8: 135 },
        )),
    });

    let snap = agg.snapshot(at(102));
    assert!(snap.flows.is_empty());
    assert_eq!(snap.events.len(), 4);
    let seqs: Vec<u64> = snap.events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, [1, 2, 3, 4]);
    assert_eq!(snap.events[0].wire_len, 98);
    assert!(matches!(
        snap.events[2].outcome,
        ParseOutcome::Unparsed(UnparsedFrame {
            reason: UnparsedReason::Malformed("TCP"),
            ..
        })
    ));
    assert_eq!(snap.counters.packets, 4);
}

#[test]
fn event_log_is_bounded_and_counts_evictions() {
    let mut agg = Aggregator::new(Limits {
        event_capacity: 3,
        ..Limits::default()
    });
    for t in 0..10 {
        agg.ingest(icmp(100 + t));
    }

    let snap = agg.snapshot(at(200));
    assert_eq!(snap.events.len(), 3);
    assert_eq!(snap.events[0].seq, 8, "oldest entries are evicted first");
    assert_eq!(snap.counters.events_evicted, 7);
    assert_eq!(
        snap.counters.packets, 10,
        "totals are not affected by eviction"
    );
}

#[test]
fn noudp_filtered_frames_are_counted_but_neither_logged_nor_tracked() {
    let mut agg = aggregator();
    agg.ingest(unparsed(UnparsedReason::Filtered));
    agg.ingest(unparsed(UnparsedReason::Filtered));

    let snap = agg.snapshot(at(100));
    assert!(snap.events.is_empty());
    assert!(snap.flows.is_empty());
    assert_eq!(snap.counters.filtered, 2);
    assert_eq!(snap.counters.packets, 0);
}

#[test]
fn flow_traffic_is_not_logged_as_events() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out());
    assert!(agg.snapshot(at(100)).events.is_empty());
}

#[test]
fn snapshots_are_independent_of_later_ingestion() {
    let mut agg = aggregator();
    feed(&mut agg, Pkt::out().len(100));
    let before = agg.snapshot(at(100));

    feed(&mut agg, Pkt::out().len(100));
    agg.ingest(icmp(101));

    assert_eq!(before.flows[0].packets.outbound, 1);
    assert!(before.events.is_empty());
    assert_eq!(before.counters.packets, 1);
    assert_eq!(agg.counters().packets, 3);
}
