//! shareclick (minimal) — control one computer's mouse from another over the LAN.
//!
//! One-way and mouse-only: the `send` machine captures its physical mouse and
//! streams it (encrypted UDP) to the `recv` machine, which injects it as real
//! input. Toggle control with F12 or by holding both Shift keys.

mod capture;
mod crypto;
mod emit;
mod proto;
mod transport;

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

/// Default UDP port.
const DEFAULT_PORT: u16 = 24800;
/// While idle, an empty batch is sent this often so the receiver knows we're
/// still here (and so we notice nothing needs draining).
const KEEPALIVE: Duration = Duration::from_millis(500);
/// The receiver gives up if no packet arrives for this long.
const PEER_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound on events per datagram, so a high-polling-rate mouse can't
/// produce packets larger than the receive buffer.
const MAX_EVENTS_PER_PACKET: usize = 64;

#[derive(Parser)]
#[command(
    name = "shareclick",
    version,
    about = "Control another computer's mouse over the LAN"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture this machine's mouse and send it to a receiver.
    Send {
        /// Receiver address, e.g. 192.168.1.20 (a `host:port` overrides --port).
        ip: String,
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Pairing secret; must match the receiver.
        #[arg(long, default_value = "shareclick")]
        psk: String,
    },
    /// Receive mouse input and inject it locally.
    Recv {
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
        #[arg(long, default_value = "shareclick")]
        psk: String,
    },
}

fn main() -> anyhow::Result<()> {
    // rdev's Windows low-level mouse hook reports per-monitor-aware cursor
    // coordinates; match enigo's DPI mode so injected motion scales correctly
    // on scaled displays.
    #[cfg(windows)]
    let _ = enigo::set_dpi_awareness();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Send { ip, port, psk } => send(resolve(&ip, port)?, &psk),
        Command::Recv { port, psk } => recv(port, &psk),
    }
}

/// Resolve a bare host or `host:port` to a socket address.
fn resolve(host_port: &str, default_port: u16) -> anyhow::Result<SocketAddr> {
    let with_port = |h: &str| -> String {
        if h.contains(':') {
            h.to_string()
        } else {
            format!("{h}:{default_port}")
        }
    };
    // A literal `host:port` wins over the flag.
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        with_port(host_port)
    };
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve address {host_port}"))
}

/// Capture this machine's mouse and stream it to the receiver.
fn send(addr: SocketAddr, psk: &str) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(addr)?;
    let mut channel = transport::initiator(socket, psk.as_bytes())?;
    tracing::info!(%addr, "receiver connected; press F12 or hold both Shift keys to toggle control");

    let active = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<proto::MouseEvent>();
    let cap = active.clone();
    std::thread::spawn(move || {
        if let Err(e) = capture::run(tx, cap) {
            tracing::error!(%e, "capture thread stopped");
        }
    });

    let mut last_send = Instant::now();
    loop {
        let batch = drain_batch(&rx);
        if !batch.is_empty() {
            channel.send(&batch)?;
            last_send = Instant::now();
        } else if last_send.elapsed() >= KEEPALIVE {
            channel.send(&[])?; // keep-alive
            last_send = Instant::now();
        } else {
            std::thread::sleep(Duration::from_micros(500));
        }
    }
}

/// Receive mouse input and inject it locally.
fn recv(port: u16, psk: &str) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    tracing::info!(%port, "listening for a sender…");
    let mut channel = transport::responder(socket, psk.as_bytes())?;
    tracing::info!("sender connected; its mouse now drives this machine");

    #[cfg(target_os = "macos")]
    tracing::info!("if nothing moves: grant Accessibility permission to this app");

    let mut injector = emit::Injector::new()?;
    let mut last_packet = Instant::now();
    let mut buf = [0u8; 2048];
    loop {
        match channel.recv(&mut buf)? {
            Some(events) => {
                last_packet = Instant::now();
                for ev in events {
                    if let Err(e) = injector.apply(ev) {
                        tracing::warn!(%e, "inject failed");
                    }
                }
            }
            None if last_packet.elapsed() > PEER_TIMEOUT => {
                anyhow::bail!("sender timed out")
            }
            None => {}
        }
    }
}

/// Drain one bounded batch and fold consecutive motion events together, so a
/// high-polling-rate mouse can't outpace the receiver with tiny datagrams.
fn drain_batch(rx: &Receiver<proto::MouseEvent>) -> Vec<proto::MouseEvent> {
    let mut batch = Vec::new();
    while batch.len() < MAX_EVENTS_PER_PACKET {
        let Ok(event) = rx.try_recv() else {
            break;
        };
        match (batch.last_mut(), event) {
            (
                Some(proto::MouseEvent::Move {
                    dx: last_dx,
                    dy: last_dy,
                }),
                proto::MouseEvent::Move { dx, dy },
            ) => {
                *last_dx = last_dx.saturating_add(dx);
                *last_dy = last_dy.saturating_add(dy);
            }
            (_, event) => batch.push(event),
        }
    }
    batch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::MouseEvent;

    #[test]
    fn resolve_appends_the_default_port() {
        assert_eq!(
            resolve("127.0.0.1", 24800).unwrap().port(),
            24800
        );
        assert_eq!(
            resolve("127.0.0.1:9999", 24800).unwrap().port(),
            9999
        );
    }

    #[test]
    fn batch_coalesces_motion_without_reordering_buttons() {
        let (tx, rx) = mpsc::channel();
        tx.send(MouseEvent::Move { dx: 2, dy: 3 }).unwrap();
        tx.send(MouseEvent::Move { dx: 4, dy: -1 }).unwrap();
        tx.send(MouseEvent::Button {
            button: proto::LEFT,
            pressed: true,
        })
        .unwrap();
        tx.send(MouseEvent::Move { dx: -2, dy: 5 }).unwrap();

        assert_eq!(
            drain_batch(&rx),
            vec![
                MouseEvent::Move { dx: 6, dy: 2 },
                MouseEvent::Button {
                    button: proto::LEFT,
                    pressed: true,
                },
                MouseEvent::Move { dx: -2, dy: 5 },
            ]
        );
    }

    #[test]
    fn batch_is_bounded() {
        // Alternate moves with buttons so nothing coalesces.
        let (tx, rx) = mpsc::channel();
        for i in 0..(MAX_EVENTS_PER_PACKET + 6) {
            if i % 2 == 0 {
                tx.send(MouseEvent::Move { dx: 1, dy: 1 }).unwrap();
            } else {
                tx.send(MouseEvent::Button {
                    button: proto::LEFT,
                    pressed: true,
                })
                .unwrap();
            }
        }
        assert_eq!(drain_batch(&rx).len(), MAX_EVENTS_PER_PACKET);
        assert_eq!(drain_batch(&rx).len(), 6);
    }
}