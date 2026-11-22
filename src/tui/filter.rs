//! The `/` filter: whitespace-separated terms, all of which must match.
//!
//! | Term                    | Matches                                     |
//! |-------------------------|---------------------------------------------|
//! | `tcp` `udp` `icmp` ...  | the protocol                                |
//! | `443`, `:443`, `port:443` | either endpoint's port                    |
//! | `1.2.3.4`, `::1`        | either endpoint's IP address                |
//! | `1.2.3.4:443`           | either endpoint, exactly                    |
//! | anything else           | substring of either endpoint's IP address   |

use std::net::{IpAddr, SocketAddr};

use crate::aggregate::EventEntry;
use crate::flow::FlowSummary;
use crate::model::{ParseOutcome, Transport};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Protocol(&'static str),
    Port(u16),
    Ip(IpAddr),
    Endpoint(SocketAddr),
    /// Lowercase substring of the textual address, e.g. `192.168`.
    IpText(String),
}

const PROTOCOLS: [&str; 5] = ["tcp", "udp", "icmp", "icmpv6", "arp"];

impl Term {
    fn parse(raw: &str) -> Self {
        let lower = raw.to_ascii_lowercase();
        if let Some(protocol) = PROTOCOLS.iter().find(|p| **p == lower) {
            return Self::Protocol(protocol);
        }
        let port = lower
            .strip_prefix("port:")
            .or_else(|| lower.strip_prefix(':'))
            .unwrap_or(&lower);
        if let Ok(port) = port.parse() {
            return Self::Port(port);
        }
        if let Ok(ip) = lower.parse() {
            return Self::Ip(ip);
        }
        if let Ok(endpoint) = lower.parse() {
            return Self::Endpoint(endpoint);
        }
        Self::IpText(lower)
    }

    fn matches(&self, protocol: &str, endpoints: &[Endpoint]) -> bool {
        match self {
            Self::Protocol(p) => protocol.eq_ignore_ascii_case(p),
            Self::Port(port) => endpoints.iter().any(|e| e.1 == Some(*port)),
            Self::Ip(ip) => endpoints.iter().any(|e| e.0 == *ip),
            Self::Endpoint(sa) => endpoints
                .iter()
                .any(|e| e.0 == sa.ip() && e.1 == Some(sa.port())),
            Self::IpText(text) => endpoints
                .iter()
                .any(|e| e.0.to_string().contains(text.as_str())),
        }
    }
}

/// An address and, where the packet has one, a port.
type Endpoint = (IpAddr, Option<u16>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    terms: Vec<Term>,
}

impl Filter {
    pub fn parse(input: &str) -> Self {
        Self {
            terms: input.split_whitespace().map(Term::parse).collect(),
        }
    }

    pub fn matches_flow(&self, flow: &FlowSummary) -> bool {
        let protocol = flow.protocol.to_string();
        let endpoint = |sa: SocketAddr| (sa.ip(), Some(sa.port()));
        self.all(&protocol, &[endpoint(flow.local), endpoint(flow.remote)])
    }

    /// Events only have addresses (no ports), so port terms never match.
    pub fn matches_event(&self, event: &EventEntry) -> bool {
        let ParseOutcome::Event(e) = &event.outcome else {
            return self.terms.is_empty();
        };
        let protocol = match e.transport {
            Transport::Icmp(_) => "icmp",
            Transport::Icmpv6 { .. } => "icmpv6",
            Transport::Arp { .. } => "arp",
            Transport::Tcp { .. } => "tcp",
            Transport::Udp { .. } => "udp",
        };
        self.all(protocol, &[(e.source, None), (e.destination, None)])
    }

    fn all(&self, protocol: &str, endpoints: &[Endpoint]) -> bool {
        self.terms.iter().all(|t| t.matches(protocol, endpoints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::{Aggregator, Limits};
    use crate::testutil::*;

    fn flows() -> Vec<FlowSummary> {
        let mut agg = Aggregator::new(Limits::default());
        for pkt in [
            Pkt::out(),       // tcp 10.0.0.2:50000 ↔ 1.1.1.1:443
            Pkt::out().udp(), // udp, same endpoints
            Pkt {
                dst: ("192.168.1.9", 8080),
                ..Pkt::out()
            },
            Pkt {
                dst: ("2001:db8::1", 53),
                src: ("fe80::2", 4000),
                ..Pkt::out()
            },
        ] {
            agg.ingest(pkt.observation(None));
        }
        let mut flows = agg.snapshot(at(100)).flows;
        flows.sort_by_key(|f| f.id);
        flows
    }

    fn matching(filter: &str) -> Vec<u64> {
        let filter = Filter::parse(filter);
        flows()
            .iter()
            .filter(|f| filter.matches_flow(f))
            .map(|f| f.id)
            .collect()
    }

    #[test]
    fn empty_filter_matches_everything() {
        assert_eq!(matching(""), [1, 2, 3, 4]);
        assert_eq!(matching("   "), [1, 2, 3, 4]);
    }

    #[test]
    fn protocol_terms_are_case_insensitive() {
        assert_eq!(matching("tcp"), [1, 3, 4]);
        assert_eq!(matching("UDP"), [2]);
    }

    #[test]
    fn ports_match_either_endpoint() {
        assert_eq!(matching("443"), [1, 2]);
        assert_eq!(matching(":443"), [1, 2]);
        assert_eq!(matching("port:50000"), [1, 2, 3]);
        assert_eq!(matching("8080"), [3]);
    }

    #[test]
    fn ip_terms_match_exactly_or_by_substring() {
        assert_eq!(matching("1.1.1.1"), [1, 2]);
        // `1.1.1.1` is not a substring match of `10.0.0.2` or `192.168.1.9`.
        assert_eq!(matching("192.168"), [3]);
        assert_eq!(matching("10.0.0"), [1, 2, 3]);
        assert_eq!(matching("2001:db8::1"), [4]);
        assert_eq!(matching("fe80"), [4]);
        assert_eq!(matching("1.1.1.1:443"), [1, 2]);
        assert_eq!(matching("1.1.1.1:80"), Vec::<u64>::new());
    }

    #[test]
    fn terms_are_anded() {
        assert_eq!(matching("tcp 443"), [1]);
        assert_eq!(matching("udp 8080"), Vec::<u64>::new());
        assert_eq!(matching("tcp 10.0.0 :8080"), [3]);
    }

    #[test]
    fn unknown_text_matches_nothing() {
        assert_eq!(matching("nonsense"), Vec::<u64>::new());
    }

    fn event_matches(filter: &str, event: &EventEntry) -> bool {
        Filter::parse(filter).matches_event(event)
    }

    #[test]
    fn events_match_on_protocol_and_address_but_not_port() {
        let mut agg = Aggregator::new(Limits::default());
        agg.ingest(icmp(100));
        let event = agg.snapshot(at(100)).events[0].clone();

        assert!(event_matches("icmp", &event));
        assert!(event_matches("1.1.1.1 icmp", &event));
        assert!(!event_matches("arp", &event));
        assert!(!event_matches("tcp", &event));
        assert!(!event_matches("0", &event));
        assert!(!event_matches("443", &event));
    }
}
