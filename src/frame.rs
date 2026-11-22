//! Capture-independent frame representation.
//!
//! A [`CapturedFrame`] is the hand-off between the capture backend and the
//! parser. It owns its bytes and mentions no capture-library types, so it can
//! be sent to another thread or task and the backend can later be replaced
//! without touching the parser.
//!
//! # Limitations (current `pnet` backend)
//!
//! `pnet::datalink` only yields the raw bytes of each frame. Therefore:
//!
//! * `timestamp` is **not** a kernel/hardware capture time. It is read from the
//!   system clock (`SystemTime::now()`) when user space receives the frame.
//!   It includes scheduling/queueing delay, can be later than the real arrival
//!   time, and can be identical for several frames when the OS hands them over
//!   in a batch (e.g. BPF reads on macOS). It follows the wall clock, so it can
//!   jump backwards if the clock is adjusted.
//! * The on-the-wire length is unknown. [`CapturedFrame::captured_len`] is the
//!   number of bytes delivered, which may be smaller than the original frame if
//!   the backend truncated it (pnet's default read buffer is 4096 bytes).
//! * Frame direction (inbound/outbound) is not provided; the parser infers it
//!   from the host's IP addresses.

use std::sync::Arc;
use std::time::SystemTime;

/// How the leading bytes of [`CapturedFrame::data`] must be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet II frame starting at byte 0.
    Ethernet,
    /// macOS loopback as delivered by pnet's BPF backend: a 14-byte all-zero
    /// placeholder Ethernet header followed by an IPv4/IPv6 packet.
    Loopback,
    /// No link-layer header: the data starts with an IPv4/IPv6 header
    /// (macOS point-to-point/TUN interfaces).
    RawIp,
}

/// An owned frame as received from the capture backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Time user space received the frame; see the module docs for accuracy.
    pub timestamp: SystemTime,
    /// Name of the interface the frame was captured on.
    pub interface: Arc<str>,
    pub link_type: LinkType,
    /// Raw bytes exactly as delivered by the backend.
    pub data: Vec<u8>,
}

impl CapturedFrame {
    /// Number of bytes captured (`data.len()`).
    pub fn captured_len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_len_matches_data() {
        let frame = CapturedFrame {
            timestamp: SystemTime::UNIX_EPOCH,
            interface: Arc::from("eth0"),
            link_type: LinkType::Ethernet,
            data: vec![0; 42],
        };
        assert_eq!(frame.captured_len(), 42);
    }
}
