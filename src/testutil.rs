//! Packet fixtures shared by the aggregator and UI tests.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::model::{Direction, IcmpKind, NetEvent, Observation, ParseOutcome, TcpFlags, Transport};

pub(crate) const HOST: &str = "10.0.0.2";
pub(crate) const PEER: &str = "1.1.1.1";

pub(crate) fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

pub(crate) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(crate) const ACK: TcpFlags = TcpFlags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
};

/// A packet as the parser would report it.
pub(crate) struct Pkt {
    pub(crate) iface: &'static str,
    pub(crate) time: u64,
    pub(crate) direction: Direction,
    pub(crate) src: (&'static str, u16),
    pub(crate) dst: (&'static str, u16),
    pub(crate) wire_len: usize,
    pub(crate) transport: fn(u16, u16) -> Transport,
}

pub(crate) fn tcp_transport(src_port: u16, dst_port: u16) -> Transport {
    Transport::Tcp {
        src_port,
        dst_port,
        length: 0,
        flags: ACK,
    }
}

pub(crate) fn udp_transport(src_port: u16, dst_port: u16) -> Transport {
    Transport::Udp {
        src_port,
        dst_port,
        length: 0,
        is_dns: false,
    }
}

impl Pkt {
    /// Outbound TCP from `HOST:50000` to `PEER:443`.
    pub(crate) fn out() -> Self {
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
    pub(crate) fn inbound() -> Self {
        Self {
            direction: Direction::Inbound,
            src: (PEER, 443),
            dst: (HOST, 50000),
            ..Self::out()
        }
    }

    pub(crate) fn at(self, time: u64) -> Self {
        Self { time, ..self }
    }

    pub(crate) fn len(self, wire_len: usize) -> Self {
        Self { wire_len, ..self }
    }

    pub(crate) fn iface(self, iface: &'static str) -> Self {
        Self { iface, ..self }
    }

    pub(crate) fn udp(self) -> Self {
        Self {
            transport: udp_transport,
            ..self
        }
    }

    pub(crate) fn observation(&self, flags: Option<TcpFlags>) -> Observation {
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

pub(crate) fn icmp(time: u64) -> Observation {
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
