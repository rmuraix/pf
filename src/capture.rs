//! libpcap capture backend. Yields owned [`CapturedFrame`]s; see
//! [`crate::frame`] for the metadata provided.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use pcap::{Active, BreakLoop, Device, Error as PcapError, IfFlags, Linktype};

use crate::frame::{CapturedFrame, LinkType};

/// Read timeout. libpcap blocks at most this long, so callers can poll for
/// shutdown without busy-waiting.
const READ_TIMEOUT_MS: i32 = 200;
/// Maximum bytes captured per frame (large enough for any frame, incl. jumbo).
const SNAPLEN: i32 = 65535;

pub struct Capture {
    name: Arc<str>,
    link_type: LinkType,
    host_ips: Vec<IpAddr>,
    cap: pcap::Capture<Active>,
}

/// Wakes a blocked [`Capture::next_frame`] from another thread (e.g. a Ctrl-C
/// handler). `next_frame` then returns `Ok(None)`.
///
/// Needed because libpcap does not return on the read timeout on every
/// platform when the interface is idle (Linux), so a shutdown flag alone
/// would not be noticed until the next packet arrives.
pub struct StopHandle(BreakLoop);

impl StopHandle {
    pub fn stop(&self) {
        self.0.breakloop();
    }
}

/// Maps a libpcap link-layer type to a supported [`LinkType`].
fn link_type_from(linktype: Linktype) -> Option<LinkType> {
    match linktype {
        Linktype::ETHERNET => Some(LinkType::Ethernet),
        Linktype::NULL | Linktype::LOOP => Some(LinkType::Loopback),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => Some(LinkType::RawIp),
        Linktype::LINUX_SLL => Some(LinkType::LinuxSll),
        Linktype::LINUX_SLL2 => Some(LinkType::LinuxSll2),
        _ => None,
    }
}

/// Non-loopback addresses of all interfaces that are up.
fn host_ips(devices: &[Device]) -> Vec<IpAddr> {
    devices
        .iter()
        .filter(|d| d.flags.if_flags.contains(IfFlags::UP))
        .flat_map(|d| d.addresses.iter().map(|a| a.addr))
        .filter(|ip| !ip.is_loopback())
        .collect()
}

/// Converts a libpcap timestamp (seconds, microseconds) to [`SystemTime`].
fn timestamp(secs: u64, micros: u32) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::new(secs, micros.saturating_mul(1000))
}

impl Capture {
    pub fn open(iface_name: &str) -> anyhow::Result<Self> {
        let devices = Device::list().context("pf: unable to list network interfaces")?;
        let device = devices
            .iter()
            .find(|d| d.name == iface_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No such network interface: {}", iface_name))?;

        let cap = pcap::Capture::from_device(device)
            .and_then(|c| {
                c.snaplen(SNAPLEN)
                    .timeout(READ_TIMEOUT_MS)
                    // Deliver frames as they arrive instead of batching until
                    // the timeout (BPF/macOS batches otherwise).
                    .immediate_mode(true)
                    .open()
            })
            .map_err(|e| anyhow::anyhow!("pf: unable to open capture on {}: {}", iface_name, e))?;

        let linktype = cap.get_datalink();
        let link_type = link_type_from(linktype).ok_or_else(|| {
            let name = linktype.get_name().unwrap_or_else(|_| "unknown".into());
            anyhow::anyhow!(
                "pf: unsupported link-layer type {} ({}) on {}",
                name,
                linktype.0,
                iface_name
            )
        })?;

        Ok(Self {
            link_type,
            name: Arc::from(iface_name),
            host_ips: host_ips(&devices),
            cap,
        })
    }

    pub fn interface_name(&self) -> &str {
        &self.name
    }

    pub fn host_ips(&self) -> Vec<IpAddr> {
        self.host_ips.clone()
    }

    pub fn stop_handle(&mut self) -> StopHandle {
        StopHandle(self.cap.breakloop_handle())
    }

    /// Waits for a frame. `Ok(None)` means the read timeout (200 ms) elapsed
    /// or [`StopHandle::stop`] was called, so callers should check for
    /// shutdown and call again.
    pub fn next_frame(&mut self) -> anyhow::Result<Option<CapturedFrame>> {
        match self.cap.next_packet() {
            Ok(packet) => {
                let ts = packet.header.ts;
                Ok(Some(CapturedFrame {
                    timestamp: timestamp(
                        u64::try_from(ts.tv_sec).unwrap_or(0),
                        u32::try_from(ts.tv_usec).unwrap_or(0),
                    ),
                    interface: Arc::clone(&self.name),
                    link_type: self.link_type,
                    original_len: packet.header.len as usize,
                    data: packet.data.to_vec(),
                }))
            }
            // `NoMorePackets` is what libpcap reports after `breakloop`.
            Err(PcapError::TimeoutExpired | PcapError::NoMorePackets) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("pf: unable to receive packet: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_link_types_are_mapped() {
        assert_eq!(link_type_from(Linktype::ETHERNET), Some(LinkType::Ethernet));
        assert_eq!(link_type_from(Linktype::NULL), Some(LinkType::Loopback));
        assert_eq!(link_type_from(Linktype::LOOP), Some(LinkType::Loopback));
        assert_eq!(link_type_from(Linktype::RAW), Some(LinkType::RawIp));
        assert_eq!(link_type_from(Linktype::IPV4), Some(LinkType::RawIp));
        assert_eq!(link_type_from(Linktype::IPV6), Some(LinkType::RawIp));
        assert_eq!(
            link_type_from(Linktype::LINUX_SLL),
            Some(LinkType::LinuxSll)
        );
        assert_eq!(
            link_type_from(Linktype::LINUX_SLL2),
            Some(LinkType::LinuxSll2)
        );
    }

    #[test]
    fn unsupported_link_types_are_not_guessed_as_ethernet() {
        // 802.11, PPP, Bluetooth HCI, and an unknown value.
        for lt in [105, 9, 187, 9999] {
            assert_eq!(link_type_from(Linktype(lt)), None, "DLT {lt}");
        }
    }

    #[test]
    fn timestamp_keeps_microseconds() {
        assert_eq!(
            timestamp(10, 250_000),
            SystemTime::UNIX_EPOCH + Duration::from_millis(10_250)
        );
    }

    #[test]
    fn host_ips_skip_loopback_and_down_interfaces() {
        let dev = |name: &str, flags: IfFlags, ip: &str| Device {
            name: name.into(),
            desc: None,
            addresses: vec![pcap::Address {
                addr: ip.parse().unwrap(),
                netmask: None,
                broadcast_addr: None,
                dst_addr: None,
            }],
            flags: pcap::DeviceFlags {
                if_flags: flags,
                connection_status: pcap::ConnectionStatus::Unknown,
            },
        };
        let devices = [
            dev("lo", IfFlags::UP | IfFlags::LOOPBACK, "127.0.0.1"),
            dev("eth0", IfFlags::UP, "10.0.0.2"),
            dev("eth1", IfFlags::empty(), "10.0.1.2"),
        ];
        assert_eq!(
            host_ips(&devices),
            vec!["10.0.0.2".parse::<IpAddr>().unwrap()]
        );
    }
}
