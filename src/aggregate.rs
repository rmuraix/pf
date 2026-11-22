//! Aggregates [`Observation`]s into flows and an event log.
//!
//! [`Aggregator`] is plain data: it is mutated by exactly one writer and read
//! through [`Aggregator::snapshot`], so it works the same with or without a UI
//! and is easy to test with synthetic observations.
//!
//! Everything is bounded (see [`Limits`]). Totals in [`Counters`] are kept
//! apart from the per-flow and per-event storage, so evicting a flow or a
//! log entry never makes them inaccurate; the eviction itself is counted.

use std::collections::VecDeque;
use std::collections::hash_map::{Entry, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::flow::{Flow, FlowDetail, FlowId, FlowKey, FlowSummary, Protocol};
use crate::model::{
    Direction, Observation, ParseOutcome, TcpFlags, Transport, UnparsedFrame, UnparsedReason,
};

/// Internal tuning knobs; not exposed on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// A flow with no packets for this long is dropped, and a later packet
    /// on the same endpoints starts a new flow.
    pub idle_timeout: Duration,
    /// A closed TCP flow is dropped after this much quiet time.
    pub closed_linger: Duration,
    /// Maximum number of tracked flows.
    pub max_flows: usize,
    /// Packets remembered per flow.
    pub history_len: usize,
    /// Entries kept in the event log.
    pub event_capacity: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            closed_linger: Duration::from_secs(5),
            max_flows: 4096,
            history_len: 64,
            event_capacity: 1000,
        }
    }
}

/// Running totals since start-up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Packets seen, excluding those hidden by `--noudp`.
    pub packets: u64,
    /// Bytes on the wire for those packets.
    pub bytes: u64,
    /// Packets hidden by `--noudp`.
    pub filtered: u64,
    /// Flows dropped for being idle or closed.
    pub flows_expired: u64,
    /// Flows dropped early because the table was full.
    pub flows_evicted: u64,
    /// Event log entries pushed out by newer ones.
    pub events_evicted: u64,
}

/// A packet that is not part of a TCP/UDP flow: ICMP, ICMPv6, ARP, or a
/// frame that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEntry {
    /// Increases by one per entry, so a UI can keep its place in the log.
    pub seq: u64,
    pub timestamp: SystemTime,
    pub wire_len: usize,
    pub outcome: ParseOutcome,
}

/// Consistent copy of the aggregator state, cheap enough to take on every
/// UI refresh: flows come without history, events are shared.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub taken_at: SystemTime,
    pub flows: Vec<FlowSummary>,
    /// Oldest first.
    pub events: Vec<Arc<EventEntry>>,
    pub counters: Counters,
}

pub struct Aggregator {
    limits: Limits,
    flows: HashMap<FlowKey, Flow>,
    events: VecDeque<Arc<EventEntry>>,
    counters: Counters,
    next_flow_id: FlowId,
    next_event_seq: u64,
}

/// The part of a [`Transport`] that makes a packet part of a flow.
struct FlowPacket {
    protocol: Protocol,
    src_port: u16,
    dst_port: u16,
    flags: Option<TcpFlags>,
}

impl FlowPacket {
    fn of(transport: &Transport) -> Option<Self> {
        match *transport {
            Transport::Tcp {
                src_port,
                dst_port,
                flags,
                ..
            } => Some(Self {
                protocol: Protocol::Tcp,
                src_port,
                dst_port,
                flags: Some(flags),
            }),
            Transport::Udp {
                src_port, dst_port, ..
            } => Some(Self {
                protocol: Protocol::Udp,
                src_port,
                dst_port,
                flags: None,
            }),
            _ => None,
        }
    }
}

impl Aggregator {
    pub fn new(mut limits: Limits) -> Self {
        limits.max_flows = limits.max_flows.max(1);
        limits.event_capacity = limits.event_capacity.max(1);
        Self {
            limits,
            flows: HashMap::new(),
            events: VecDeque::new(),
            counters: Counters::default(),
            next_flow_id: 1,
            next_event_seq: 1,
        }
    }

    /// Accounts one observation. Never drops it silently: it ends up in a
    /// flow, in the event log, or (for `--noudp`) in `counters.filtered`.
    pub fn ingest(&mut self, obs: Observation) {
        let Observation {
            timestamp,
            wire_len,
            outcome,
        } = obs;
        if matches!(
            &outcome,
            ParseOutcome::Unparsed(UnparsedFrame {
                reason: UnparsedReason::Filtered,
                ..
            })
        ) {
            self.counters.filtered += 1;
            return;
        }
        self.counters.packets += 1;
        self.counters.bytes += wire_len as u64;

        if let ParseOutcome::Event(event) = &outcome {
            if let Some(packet) = FlowPacket::of(&event.transport) {
                self.record_flow(
                    &event.interface,
                    timestamp,
                    wire_len,
                    event.direction,
                    (event.source, event.destination),
                    &packet,
                );
                return;
            }
        }
        self.push_event(EventEntry {
            seq: 0,
            timestamp,
            wire_len,
            outcome,
        });
    }

    fn record_flow(
        &mut self,
        interface: &Arc<str>,
        timestamp: SystemTime,
        wire_len: usize,
        direction: Direction,
        (source, destination): (IpAddr, IpAddr),
        packet: &FlowPacket,
    ) {
        let src = SocketAddr::new(source, packet.src_port);
        let dst = SocketAddr::new(destination, packet.dst_port);
        let key = FlowKey::new(Arc::clone(interface), packet.protocol, src, dst);
        // Inbound means the destination is a host address. Otherwise the
        // sender is assumed to be local; on loopback this is merely the
        // first packet's sender, which keeps both directions in one flow.
        let local = match direction {
            Direction::Inbound => dst,
            Direction::Outbound => src,
        };

        if self.flows.len() >= self.limits.max_flows && !self.flows.contains_key(&key) {
            self.evict_oldest();
        }
        let id = self.next_flow_id;
        let history_len = self.limits.history_len;

        let flow = match self.flows.entry(key) {
            Entry::Vacant(slot) => {
                self.next_flow_id += 1;
                let flow = Flow::new(id, slot.key(), local, timestamp, history_len);
                slot.insert(flow)
            }
            Entry::Occupied(slot) => {
                let superseded =
                    slot.get()
                        .is_superseded_by(timestamp, packet.flags, self.limits.idle_timeout);
                let flow = slot.into_mut();
                if superseded {
                    // Same endpoints, different session: start over rather
                    // than merging the two.
                    self.counters.flows_expired += 1;
                    self.next_flow_id += 1;
                    let key = FlowKey::new(Arc::clone(interface), packet.protocol, src, dst);
                    *flow = Flow::new(id, &key, local, timestamp, history_len);
                }
                flow
            }
        };
        flow.record(timestamp, src, wire_len, packet.flags);
    }

    /// Drops the least recently active eighth of the table in one pass, so
    /// the cost per insertion stays low even when new flows arrive faster
    /// than they can expire (e.g. a port scan).
    fn evict_oldest(&mut self) {
        let batch = (self.limits.max_flows / 8).max(1);
        let mut by_age: Vec<(SystemTime, FlowKey)> = self
            .flows
            .iter()
            .map(|(key, flow)| (flow.last_seen(), key.clone()))
            .collect();
        if batch < by_age.len() {
            by_age.select_nth_unstable_by_key(batch, |(last_seen, _)| *last_seen);
            by_age.truncate(batch);
        }
        for (_, key) in &by_age {
            self.flows.remove(key);
        }
        self.counters.flows_evicted += by_age.len() as u64;
    }

    fn push_event(&mut self, mut entry: EventEntry) {
        if self.events.len() >= self.limits.event_capacity {
            self.events.pop_front();
            self.counters.events_evicted += 1;
        }
        entry.seq = self.next_event_seq;
        self.next_event_seq += 1;
        self.events.push_back(Arc::new(entry));
    }

    /// Drops flows that are idle or closed as of `now`. Call periodically:
    /// a flow that stops receiving packets is never looked at otherwise.
    pub fn expire(&mut self, now: SystemTime) {
        let before = self.flows.len();
        let Limits {
            idle_timeout,
            closed_linger,
            ..
        } = self.limits;
        self.flows
            .retain(|_, flow| !flow.is_expired(now, idle_timeout, closed_linger));
        self.counters.flows_expired += (before - self.flows.len()) as u64;
    }

    pub fn snapshot(&self, now: SystemTime) -> Snapshot {
        Snapshot {
            taken_at: now,
            flows: self.flows.values().map(|flow| flow.summary(now)).collect(),
            events: self.events.iter().cloned().collect(),
            counters: self.counters,
        }
    }

    /// `None` if the flow has expired or been evicted.
    pub fn flow_detail(&self, id: FlowId, now: SystemTime) -> Option<FlowDetail> {
        self.flows
            .values()
            .find(|flow| flow.id() == id)
            .map(|flow| flow.detail(now))
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests;
