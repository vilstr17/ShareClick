//! Zero-config peer discovery over mDNS (`_shareclick._udp.local.`).
//!
//! The server advertises its name + port; a client can find it without anyone
//! typing an IP address. Discovery only locates the peer — the encrypted
//! handshake still authenticates it, so an imposter advertising the same
//! service cannot impersonate the real server without the PSK.

#![cfg(feature = "native")]

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE_TYPE: &str = "_shareclick._udp.local.";

/// Keeps the advertised service alive; drop to stop advertising.
pub struct Advertiser {
    _daemon: ServiceDaemon,
}

/// Advertise this server so clients can discover it by name.
pub fn advertise(name: &str, port: u16, id: &str) -> anyhow::Result<Advertiser> {
    let daemon = ServiceDaemon::new()?;
    let host_name = format!("{name}.local.");
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        name,
        &host_name,
        "",
        port,
        &[("id", id)] as &[(&str, &str)],
    )?
    .enable_addr_auto();
    daemon.register(info)?;
    tracing::info!(%name, port, "advertising on mDNS as {SERVICE_TYPE}");
    Ok(Advertiser { _daemon: daemon })
}

/// Browse for a ShareClick server for up to `timeout`, returning the preferred
/// usable address. A resolved service may advertise several physical, VPN and
/// virtual adapters, so callers must not depend on hash-set iteration order.
pub fn discover(timeout: Duration) -> anyhow::Result<Option<SocketAddr>> {
    Ok(list(timeout)?.into_iter().next().map(|(_, addr, _)| addr))
}

/// List every usable address for every server seen within `timeout`, ordered so
/// ordinary LAN IPv4 addresses are attempted before less likely interfaces.
pub fn list(timeout: Duration) -> anyhow::Result<Vec<(String, SocketAddr, String)>> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse(SERVICE_TYPE)?;
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let id = info
                    .get_property_val_str("id")
                    .unwrap_or_default()
                    .to_string();
                let fullname = info.get_fullname().to_string();
                for addr in usable_addresses(&info) {
                    if seen.insert((fullname.clone(), addr, id.clone())) {
                        out.push((fullname.clone(), addr, id.clone()));
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    out.sort_by(|a, b| {
        address_rank(a.1.ip())
            .cmp(&address_rank(b.1.ip()))
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.to_string().cmp(&b.1.to_string()))
    });
    Ok(out)
}

fn usable_addresses(info: &ServiceInfo) -> Vec<SocketAddr> {
    info.get_addresses()
        .iter()
        .copied()
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast())
        // A link-local IPv6 address needs an interface scope ID, which mDNS's
        // IpAddr set does not carry. Trying it without a scope can never work.
        .filter(|ip| !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()))
        .map(|ip| SocketAddr::new(ip, info.get_port()))
        .collect()
}

fn address_rank(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) if v4.is_private() => 0,
        IpAddr::V4(v4) if !v4.is_link_local() => 1,
        IpAddr::V6(_) => 2,
        IpAddr::V4(_) => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_addresses_sort_before_virtual_or_link_local_candidates() {
        assert!(
            address_rank("192.168.1.5".parse().unwrap())
                < address_rank("169.254.1.5".parse().unwrap())
        );
        assert!(
            address_rank("10.0.0.5".parse().unwrap())
                < address_rank("2001:db8::5".parse().unwrap())
        );
    }
}
