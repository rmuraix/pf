//! Capture-independent frame representation.
//!
//! A [`CapturedFrame`] is the hand-off between the capture backend and the
//! parser. It owns its bytes and mentions no capture-library types, so it can
//! be sent to another thread or task and the backend can later be replaced
//! without touching the parser.
//!
//! # Metadata provided by the libpcap backend
//!
//! * `timestamp` is the capture time libpcap reports (kernel/driver time,
//!   microsecond resolution, wall clock). It is not the time user space read
//!   the frame. Being wall-clock time, it can jump if the system clock is
//!   adjusted.
//! * [`CapturedFrame::original_len`] is the length of the frame on the wire;
//!   [`CapturedFrame::captured_len`] is the number of bytes in `data`. They
//!   differ when the capture was truncated by the snapshot length.
//! * Frame direction (inbound/outbound) is not provided; the parser infers it
//!   from the host's IP addresses.

use std::sync::Arc;
use std::time::SystemTime;

/// How the leading bytes of [`CapturedFrame::data`] must be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet II frame starting at byte 0.
    Ethernet,
    /// No link-layer header: the data starts with an IPv4/IPv6 header.
    RawIp,
    /// BSD loopback (`DLT_NULL`/`DLT_LOOP`): a 4-byte address-family header
    /// followed by an IPv4/IPv6 packet. macOS/BSD loopback and Windows Npcap
    /// loopback adapters.
    Loopback,
    /// Linux cooked capture v1 (`DLT_LINUX_SLL`, 16-byte header), e.g. the
    /// `any` pseudo-interface.
    LinuxSll,
    /// Linux cooked capture v2 (`DLT_LINUX_SLL2`, 20-byte header).
    LinuxSll2,
}

/// An owned frame as received from the capture backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Time the frame was captured; see the module docs for accuracy.
    pub timestamp: SystemTime,
    /// Name of the interface the frame was captured on.
    pub interface: Arc<str>,
    pub link_type: LinkType,
    /// Length of the frame on the wire (may exceed `data.len()`).
    pub original_len: usize,
    /// Captured bytes, starting with the header described by `link_type`.
    pub data: Vec<u8>,
}

impl CapturedFrame {
    /// Number of bytes captured (`data.len()`).
    pub fn captured_len(&self) -> usize {
        self.data.len()
    }

    /// Whether the capture was cut short of the on-the-wire frame.
    pub fn is_truncated(&self) -> bool {
        self.captured_len() < self.original_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(original_len: usize) -> CapturedFrame {
        CapturedFrame {
            timestamp: SystemTime::UNIX_EPOCH,
            interface: Arc::from("eth0"),
            link_type: LinkType::Ethernet,
            original_len,
            data: vec![0; 42],
        }
    }

    #[test]
    fn captured_len_matches_data() {
        assert_eq!(frame(42).captured_len(), 42);
    }

    #[test]
    fn truncation_is_detected() {
        assert!(!frame(42).is_truncated());
        assert!(frame(1500).is_truncated());
    }
}
