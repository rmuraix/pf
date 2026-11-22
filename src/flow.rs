//! Bidirectional TCP/UDP flows.
//!
//! A [`Flow`] is the traffic between two `(ip, port)` endpoints on one
//! interface, regardless of which side sent a packet. This module knows
//! nothing about rendering, and never reads the clock: every time-dependent
//! method takes the timestamp as an argument, so behaviour is deterministic.
//!
//! Time arithmetic uses `duration_since(..).unwrap_or_default()`, so a wall
//! clock that jumps backwards yields zero elapsed time instead of an error.

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::model::{Direction, TcpFlags};

/// Identifies one flow session. Unlike [`FlowKey`] it is never reused: when
/// an endpoint pair starts a new session, the new flow gets a new id.
pub type FlowId = u64;

/// Length of the rate averaging window, in whole seconds.
const RATE_WINDOW_SECS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

/// Direction-independent flow identity: the endpoints are stored in sorted
/// order, so `a → b` and `b → a` produce equal keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    interface: Arc<str>,
    protocol: Protocol,
    low: SocketAddr,
    high: SocketAddr,
}

impl FlowKey {
    pub fn new(interface: Arc<str>, protocol: Protocol, a: SocketAddr, b: SocketAddr) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        Self {
            interface,
            protocol,
            low,
            high,
        }
    }
}

/// A pair of values, one per [`Direction`], seen from the flow's local side.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByDirection<T> {
    pub inbound: T,
    pub outbound: T,
}

impl<T> ByDirection<T> {
    pub fn get(&self, direction: Direction) -> &T {
        match direction {
            Direction::Inbound => &self.inbound,
            Direction::Outbound => &self.outbound,
        }
    }

    fn get_mut(&mut self, direction: Direction) -> &mut T {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }
}

/// Bytes per whole second for the last [`RATE_WINDOW_SECS`] seconds, in a
/// fixed-size ring so memory does not grow with traffic.
#[derive(Debug, Clone, Default)]
struct RateWindow {
    /// `(second since the epoch, bytes in that second)`, indexed by
    /// `second % RATE_WINDOW_SECS`.
    buckets: [(u64, u64); RATE_WINDOW_SECS],
}

impl RateWindow {
    fn record(&mut self, second: u64, bytes: u64) {
        let slot = &mut self.buckets[(second % RATE_WINDOW_SECS as u64) as usize];
        if second > slot.0 {
            *slot = (second, 0);
        }
        // An older second would clobber a newer bucket sharing this slot.
        if second == slot.0 {
            slot.1 += bytes;
        }
    }

    /// Average bytes per second over the window ending at `now_second`. A
    /// flow younger than the window is averaged over its own age instead, so
    /// it does not look slower than it is.
    fn bytes_per_sec(&self, now_second: u64, first_second: u64) -> f64 {
        let oldest = now_second.saturating_sub(RATE_WINDOW_SECS as u64 - 1);
        let bytes: u64 = self
            .buckets
            .iter()
            .filter(|(second, _)| (oldest..=now_second).contains(second))
            .map(|(_, bytes)| bytes)
            .sum();
        let span = now_second.saturating_sub(oldest.max(first_second)) + 1;
        bytes as f64 / span as f64
    }
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn elapsed(from: SystemTime, to: SystemTime) -> Duration {
    to.duration_since(from).unwrap_or_default()
}

/// One entry of a flow's recent packet history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketSample {
    pub timestamp: SystemTime,
    pub direction: Direction,
    /// Length on the wire.
    pub wire_len: usize,
    /// `Some` for TCP.
    pub flags: Option<TcpFlags>,
}

/// Read-only view of a [`Flow`] at one point in time.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSummary {
    pub id: FlowId,
    pub interface: Arc<str>,
    pub protocol: Protocol,
    /// The host side if the parser identified it, otherwise the sender of
    /// the first packet seen (e.g. on loopback, where both ends are local).
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub packets: ByDirection<u64>,
    pub bytes: ByDirection<u64>,
    /// Current rate in bytes per second.
    pub rate: ByDirection<f64>,
    /// TCP only: a RST, or a FIN from both sides, was seen.
    pub closed: bool,
}

impl FlowSummary {
    pub fn total_packets(&self) -> u64 {
        self.packets.inbound + self.packets.outbound
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes.inbound + self.bytes.outbound
    }

    pub fn duration(&self) -> Duration {
        elapsed(self.first_seen, self.last_seen)
    }
}

/// A [`FlowSummary`] plus the most recent packets, oldest first.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowDetail {
    pub summary: FlowSummary,
    pub history: Vec<PacketSample>,
    /// Maximum number of packets kept in `history`.
    pub history_capacity: usize,
}

/// Aggregated state of one flow.
#[derive(Debug)]
pub struct Flow {
    id: FlowId,
    interface: Arc<str>,
    protocol: Protocol,
    local: SocketAddr,
    remote: SocketAddr,
    first_seen: SystemTime,
    last_seen: SystemTime,
    packets: ByDirection<u64>,
    bytes: ByDirection<u64>,
    rates: ByDirection<RateWindow>,
    history: VecDeque<PacketSample>,
    history_capacity: usize,
    fin_seen: ByDirection<bool>,
    closed: bool,
}

impl Flow {
    pub fn new(
        id: FlowId,
        key: &FlowKey,
        local: SocketAddr,
        first_seen: SystemTime,
        history_capacity: usize,
    ) -> Self {
        let remote = if key.low == local { key.high } else { key.low };
        Self {
            id,
            interface: Arc::clone(&key.interface),
            protocol: key.protocol,
            local,
            remote,
            first_seen,
            last_seen: first_seen,
            packets: ByDirection::default(),
            bytes: ByDirection::default(),
            rates: ByDirection::default(),
            history: VecDeque::new(),
            history_capacity,
            fin_seen: ByDirection::default(),
            closed: false,
        }
    }

    pub fn id(&self) -> FlowId {
        self.id
    }

    pub fn last_seen(&self) -> SystemTime {
        self.last_seen
    }

    /// Accounts one packet sent by `source` (one of the flow's endpoints).
    ///
    /// The direction is derived from `source` and the flow's own local
    /// endpoint, not from the parser's per-packet direction: the parser
    /// calls every packet "outbound" on loopback.
    pub fn record(
        &mut self,
        timestamp: SystemTime,
        source: SocketAddr,
        wire_len: usize,
        flags: Option<TcpFlags>,
    ) {
        let direction = if source == self.local {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        self.last_seen = self.last_seen.max(timestamp);
        *self.packets.get_mut(direction) += 1;
        *self.bytes.get_mut(direction) += wire_len as u64;
        self.rates
            .get_mut(direction)
            .record(unix_secs(timestamp), wire_len as u64);

        if let Some(flags) = flags {
            if flags.fin {
                *self.fin_seen.get_mut(direction) = true;
            }
            self.closed |= flags.rst || (self.fin_seen.inbound && self.fin_seen.outbound);
        }

        if self.history_capacity > 0 {
            if self.history.len() == self.history_capacity {
                self.history.pop_front();
            }
            self.history.push_back(PacketSample {
                timestamp,
                direction,
                wire_len,
                flags,
            });
        }
    }

    /// Whether a packet at `timestamp` belongs to a new session on the same
    /// endpoint pair rather than to this flow.
    ///
    /// That is the case when the flow was idle for `idle_timeout`, or when
    /// a TCP connection was closed and a fresh SYN (without ACK) arrives.
    /// A SYN retransmission on a still-open flow does not count.
    pub fn is_superseded_by(
        &self,
        timestamp: SystemTime,
        flags: Option<TcpFlags>,
        idle_timeout: Duration,
    ) -> bool {
        let new_syn = self.closed && flags.is_some_and(|f| f.syn && !f.ack);
        new_syn || elapsed(self.last_seen, timestamp) >= idle_timeout
    }

    /// Whether the flow has been quiet for `idle_timeout`, or for
    /// `closed_linger` once it is closed.
    pub fn is_expired(
        &self,
        now: SystemTime,
        idle_timeout: Duration,
        closed_linger: Duration,
    ) -> bool {
        let quiet = elapsed(self.last_seen, now);
        quiet >= idle_timeout || (self.closed && quiet >= closed_linger)
    }

    pub fn summary(&self, now: SystemTime) -> FlowSummary {
        let now_second = unix_secs(now);
        let first_second = unix_secs(self.first_seen);
        let rate = |window: &RateWindow| window.bytes_per_sec(now_second, first_second);
        FlowSummary {
            id: self.id,
            interface: Arc::clone(&self.interface),
            protocol: self.protocol,
            local: self.local,
            remote: self.remote,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            packets: self.packets,
            bytes: self.bytes,
            rate: ByDirection {
                inbound: rate(&self.rates.inbound),
                outbound: rate(&self.rates.outbound),
            },
            closed: self.closed,
        }
    }

    pub fn detail(&self, now: SystemTime) -> FlowDetail {
        FlowDetail {
            summary: self.summary(now),
            history: self.history.iter().copied().collect(),
            history_capacity: self.history_capacity,
        }
    }
}
