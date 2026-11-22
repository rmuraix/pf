//! `pnet::datalink` capture backend. Yields owned [`CapturedFrame`]s; see
//! [`crate::frame`] for what metadata is (not) available.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pnet::datalink::{
    self, Channel::Ethernet, Config as DlConfig, DataLinkReceiver, NetworkInterface,
};

use crate::frame::{CapturedFrame, LinkType};

pub struct Capture {
    name: Arc<str>,
    link_type: LinkType,
    rx: Box<dyn DataLinkReceiver>,
}

/// Link type of the frames pnet delivers for an interface.
///
/// On macOS/iOS pnet's BPF backend does not deliver Ethernet frames for
/// loopback (zeroed 14-byte placeholder header + IP) and for point-to-point
/// (TUN) interfaces (bare IP). Everywhere else frames are Ethernet.
fn link_type(interface: &NetworkInterface) -> LinkType {
    link_type_for(
        cfg!(any(target_os = "macos", target_os = "ios")),
        interface.is_up(),
        interface.is_broadcast(),
        interface.is_loopback(),
        interface.is_point_to_point(),
    )
}

fn link_type_for(
    bsd: bool,
    up: bool,
    broadcast: bool,
    loopback: bool,
    point_to_point: bool,
) -> LinkType {
    if !(bsd && up && !broadcast) {
        LinkType::Ethernet
    } else if loopback {
        LinkType::Loopback
    } else if point_to_point {
        LinkType::RawIp
    } else {
        LinkType::Ethernet
    }
}

impl Capture {
    pub fn open(iface_name: &str) -> anyhow::Result<Self> {
        let interface: NetworkInterface = datalink::interfaces()
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == iface_name)
            .ok_or_else(|| anyhow::anyhow!("No such network interface: {}", iface_name))?;

        let cfg = DlConfig {
            read_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        };

        let rx = match datalink::channel(&interface, cfg) {
            Ok(Ethernet(_tx, rx)) => rx,
            Ok(_) => return Err(anyhow::anyhow!("pf: unhandled channel type")),
            Err(e) => return Err(anyhow::anyhow!("pf: unable to create channel: {}", e)),
        };

        Ok(Self {
            link_type: link_type(&interface),
            name: Arc::from(interface.name.as_str()),
            rx,
        })
    }

    pub fn interface_name(&self) -> &str {
        &self.name
    }

    pub fn host_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();
        for interface in datalink::interfaces() {
            if !interface.ips.is_empty() && interface.is_up() {
                for ip_net in interface.ips {
                    if !ip_net.ip().is_loopback() {
                        ips.push(ip_net.ip());
                    }
                }
            }
        }
        ips
    }

    /// Waits up to the read timeout (200 ms); `Ok(None)` means it elapsed
    /// without a frame, so callers can check for shutdown.
    pub fn next_frame(&mut self) -> anyhow::Result<Option<CapturedFrame>> {
        match self.rx.next() {
            Ok(packet) => Ok(Some(CapturedFrame {
                // pnet provides no capture time; see `crate::frame`.
                timestamp: SystemTime::now(),
                interface: Arc::clone(&self.name),
                link_type: self.link_type,
                data: packet.to_vec(),
            })),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(anyhow::anyhow!("pf: unable to receive packet: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_bsd_is_always_ethernet() {
        assert_eq!(
            link_type_for(false, true, false, true, false),
            LinkType::Ethernet
        );
        assert_eq!(
            link_type_for(false, true, false, false, true),
            LinkType::Ethernet
        );
    }

    #[test]
    fn bsd_loopback_and_tun_are_special() {
        assert_eq!(
            link_type_for(true, true, false, true, false),
            LinkType::Loopback
        );
        assert_eq!(
            link_type_for(true, true, false, false, true),
            LinkType::RawIp
        );
        // Loopback wins over point-to-point.
        assert_eq!(
            link_type_for(true, true, false, true, true),
            LinkType::Loopback
        );
    }

    #[test]
    fn bsd_regular_down_or_broadcast_is_ethernet() {
        assert_eq!(
            link_type_for(true, true, true, false, false),
            LinkType::Ethernet
        );
        assert_eq!(
            link_type_for(true, true, false, false, false),
            LinkType::Ethernet
        );
        assert_eq!(
            link_type_for(true, false, false, true, false),
            LinkType::Ethernet
        );
        assert_eq!(
            link_type_for(true, true, true, true, false),
            LinkType::Ethernet
        );
    }
}
