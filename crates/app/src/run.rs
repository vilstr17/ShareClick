//! Server (`serve`) and client (`connect`) run loops wiring capture + transport
//! + injection + encryption together. Native-only (needs input capture).
//!
//! Session bring-up:
//!  1. A TCP handshake (X25519 + PSK) authenticates the peers and derives two
//!     encrypted sessions — one for the UDP input channel, one for the TCP bulk
//!     channel (clipboard + files).
//!  2. The input session keys the UDP channel; the bulk session keys the TCP
//!     connection. From then on every byte on the wire is authenticated
//!     ChaCha20-Poly1305.

#![cfg(feature = "native")]

use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shareclick_protocol::crypto::{Role, Session};
use shareclick_protocol::{BulkMsg, ClipboardData, Edge, InputEvent, InputMsg};

/// A batch that releases every modifier key on the client. Sent on every
/// control hand-off so a modifier held during the switch can't stay stuck down
/// on the other machine (the classic "Alt+Tab / Ctrl stuck" bug).
fn release_all_modifiers() -> InputMsg {
    use shareclick_protocol::Key::{LAlt, LCtrl, LMeta, LShift, RAlt, RCtrl, RMeta, RShift};
    InputMsg::Events(vec![
        InputEvent::Key {
            key: LCtrl,
            pressed: false,
        },
        InputEvent::Key {
            key: RCtrl,
            pressed: false,
        },
        InputEvent::Key {
            key: LAlt,
            pressed: false,
        },
        InputEvent::Key {
            key: RAlt,
            pressed: false,
        },
        InputEvent::Key {
            key: LShift,
            pressed: false,
        },
        InputEvent::Key {
            key: RShift,
            pressed: false,
        },
        InputEvent::Key {
            key: LMeta,
            pressed: false,
        },
        InputEvent::Key {
            key: RMeta,
            pressed: false,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crossing_maps_to_opposite_edge() {
        assert_eq!(opposite(Edge::Right), Edge::Left);
        assert_eq!(opposite(Edge::Left), Edge::Right);
        assert_eq!(opposite(Edge::Top), Edge::Bottom);
        assert_eq!(opposite(Edge::Bottom), Edge::Top);
        // Leave the server's RIGHT edge at y=432 → enter the client's LEFT edge
        // at y=432 on a 2560×1440 screen.
        assert_eq!(
            entry_point(opposite(Edge::Right), 432, 2560, 1440),
            (2, 432)
        );
        // Leave BOTTOM at x=1440 → enter TOP at x=1440 on a 1920×1080 screen.
        assert_eq!(
            entry_point(opposite(Edge::Bottom), 1440, 1920, 1080),
            (1440, 2)
        );
    }

    #[test]
    fn input_batch_coalesces_motion_without_reordering_buttons() {
        let (tx, rx) = mpsc::channel();
        tx.send(InputEvent::MouseMove { dx: 2, dy: 3 }).unwrap();
        tx.send(InputEvent::MouseMove { dx: 4, dy: -1 }).unwrap();
        tx.send(InputEvent::MouseButton {
            button: shareclick_protocol::MouseButton::Left,
            pressed: true,
        })
        .unwrap();
        tx.send(InputEvent::MouseMove { dx: -2, dy: 5 }).unwrap();

        assert_eq!(
            drain_input_batch(&rx),
            vec![
                InputEvent::MouseMove { dx: 6, dy: 2 },
                InputEvent::MouseButton {
                    button: shareclick_protocol::MouseButton::Left,
                    pressed: true,
                },
                InputEvent::MouseMove { dx: -2, dy: 5 },
            ]
        );
    }

    #[test]
    fn input_batch_is_bounded() {
        let (tx, rx) = mpsc::channel();
        for _ in 0..70 {
            tx.send(InputEvent::Key {
                key: shareclick_protocol::Key::A,
                pressed: true,
            })
            .unwrap();
        }

        assert_eq!(drain_input_batch(&rx).len(), MAX_INPUT_EVENTS_PER_PACKET);
        assert_eq!(drain_input_batch(&rx).len(), 6);
    }
}

/// The client enters from the edge opposite the one the server's cursor left by
/// (leave the Mac's right edge → arrive at the PC's left edge).
fn opposite(e: Edge) -> Edge {
    match e {
        Edge::Left => Edge::Right,
        Edge::Right => Edge::Left,
        Edge::Top => Edge::Bottom,
        Edge::Bottom => Edge::Top,
    }
}

use crate::bulk::BulkConn;
use crate::capture;
use crate::clipboard;
use crate::config::Config;
use crate::control::Control;
use crate::discovery;
use crate::edge::{client_return_span, entry_point, map_to_client, perp_dim, EdgeConfig};
use crate::filexfer::FileReceiver;
use crate::status;
use crate::transport::InputChannel;

/// Everything one symmetric peer session shares between the capture thread,
/// the bulk (Hello/clipboard) thread and the input pump. Both machines build
/// exactly the same thing — there is no server/client asymmetry at runtime.
#[derive(Clone)]
struct Shared {
    control: Arc<Control>,
    /// (edge config, arrangement offset) — LIVE: the peer's Hello can install
    /// or update it (configure the layout once, on either machine).
    arrangement: Arc<Mutex<(EdgeConfig, i32)>>,
    /// My bordered edge (where the peer's screen sits). LIVE, like above.
    border: Arc<Mutex<Option<Edge>>>,
    /// The peer's screen size (LIVE, learned from its Hello).
    peer_screen: Arc<Mutex<(u32, u32)>>,
    /// My own screen size.
    screen: (u32, u32),
    /// Outgoing bulk-channel sender (set once the bulk thread is up) — lets the
    /// pump push a refreshed Hello when the user re-arranges mid-session.
    hello_tx: Arc<Mutex<Option<mpsc::Sender<BulkMsg>>>>,
    /// Cleared by the bulk reader when the authenticated TCP session closes so
    /// the UDP pump can return and pairing can reconnect cleanly.
    session_alive: Arc<AtomicBool>,
    device_id: String,
}

/// Build the shared state from the local config (arrangement may be absent —
/// the peer's Hello can supply it later).
fn build_shared(cfg: &Config) -> Shared {
    let (sw, sh) = screen_size(cfg);
    tracing::info!(width = sw, height = sh, "screen size (auto-detected)");
    let border = cfg.machine(&cfg.name).and_then(|m| {
        if m.right.is_some() {
            Some(Edge::Right)
        } else if m.left.is_some() {
            Some(Edge::Left)
        } else if m.top.is_some() {
            Some(Edge::Top)
        } else if m.bottom.is_some() {
            Some(Edge::Bottom)
        } else {
            None
        }
    });
    let edges = match (cfg.machine(&cfg.name), cfg.auto_edge_switch) {
        (Some(m), true) => EdgeConfig::new(
            sw,
            sh,
            m.left.is_some(),
            m.right.is_some(),
            m.top.is_some(),
            m.bottom.is_some(),
        ),
        _ => EdgeConfig::none(),
    };
    let peer_screen = cfg
        .machines
        .iter()
        .find(|m| m.name != cfg.name)
        .and_then(|m| m.screen)
        .unwrap_or((1920, 1080));
    Shared {
        control: Arc::new(Control::new()),
        arrangement: Arc::new(Mutex::new((edges, cfg.offset))),
        border: Arc::new(Mutex::new(border)),
        peer_screen: Arc::new(Mutex::new(peer_screen)),
        screen: (sw, sh),
        hello_tx: Arc::new(Mutex::new(None)),
        session_alive: Arc::new(AtomicBool::new(false)),
        device_id: cfg
            .device_id
            .clone()
            .unwrap_or_else(|| Config::ensure_device_id(&Config::default_path())),
    }
}

/// Start the one process-wide capture loop used across peer reconnects.
fn start_capture(sh: &Shared) -> Receiver<InputEvent> {
    let (tx, rx) = mpsc::channel();
    let c = sh.control.clone();
    let arr = sh.arrangement.clone();
    let ps = sh.peer_screen.clone();
    let screen = sh.screen;
    std::thread::spawn(move || {
        if let Err(error) = capture::run(tx, c, arr, screen, ps) {
            tracing::error!(%error, "capture thread stopped");
        }
    });
    rx
}

/// My own Hello: name + screen + my arrangement (so a peer with none adopts it).
/// `refresh` = the user just re-arranged; the peer must adopt unconditionally.
fn my_hello(cfg_name: &str, sh: &Shared, refresh: bool) -> BulkMsg {
    BulkMsg::Hello {
        version: shareclick_protocol::PROTOCOL_VERSION,
        device_id: sh.device_id.clone(),
        name: cfg_name.to_string(),
        screen: sh.screen,
        edge: *sh.border.lock().unwrap(),
        offset: sh.arrangement.lock().unwrap().1,
        refresh,
    }
}

/// Reload the arrangement from the config (the settings window saved while we
/// were running) into the live shared state, and tell the peer so it adopts.
/// This is what makes "connect first, arrange after" work without restarts.
fn reload_arrangement(cfg_name: &str, sh: &Shared) {
    let Ok(cfg) = Config::load(&Config::default_path()) else {
        return;
    };
    let fresh = build_shared(&cfg);
    *sh.border.lock().unwrap() = *fresh.border.lock().unwrap();
    *sh.arrangement.lock().unwrap() = *fresh.arrangement.lock().unwrap();
    if let Some(tx) = sh.hello_tx.lock().unwrap().as_ref() {
        let _ = tx.send(my_hello(cfg_name, sh, true));
    }
    tracing::info!("arrangement reloaded from settings and sent to the peer");
}

/// Load the config or explain how to create one.
fn load_config() -> anyhow::Result<Config> {
    let path = Config::default_path();
    if !path.exists() {
        anyhow::bail!(
            "no config at {} — run `shareclick init-config` and edit the PSK + layout first",
            path.display()
        );
    }
    Config::load(&path)
}

/// This machine's screen size. Always prefer the LIVE OS-detected size so a
/// stale value in the config can never break edge detection or the offset math;
/// a config `screen` is only a fallback when detection isn't available.
fn screen_size(cfg: &Config) -> (u32, u32) {
    crate::emit::main_display_size()
        .ok()
        .or_else(|| cfg.machine(&cfg.name).and_then(|m| m.screen))
        .unwrap_or((1920, 1080))
}

fn resolve(addr: &str) -> anyhow::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve address {addr}"))
}

/// Zero-config auto-pairing: advertise ourselves and search for a peer on the
/// LAN, then connect automatically — no IP, no manual matching. If both sides
/// have an explicit `role`, that decides who serves; otherwise a deterministic
/// name tiebreaker makes exactly one side the server. The client retries until
/// the server is up, so start order doesn't matter.
#[cfg(feature = "native")]
pub fn pair() -> anyhow::Result<()> {
    let cfg = match load_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            status::needs_setup(error.to_string());
            return Err(error);
        }
    };
    let me = cfg.name.clone();
    let port = cfg.port;

    // Claim the port before reporting that pairing started. This also prevents
    // a tray opened alongside the login service from starting a second pairing
    // loop that would compete for the same peer.
    let bind_addr = resolve(&format!("0.0.0.0:{port}"))?;
    let listener = TcpListener::bind(bind_addr).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "ShareClick is already listening on port {port}; another instance is probably running"
            )
        } else {
            anyhow::anyhow!("cannot listen on {bind_addr}: {error}")
        }
    })?;
    status::pairing("Listening on the local network and looking for another ShareClick device.");
    tracing::info!(name = %me, "auto-pairing: listening, advertising and searching…");

    let my_id = Config::ensure_device_id(&Config::default_path());
    let advert = discovery::advertise(&cfg.name, bind_addr.port(), &my_id)
        .map_err(|error| tracing::warn!(%error, "mDNS advertise failed"))
        .ok();
    loop {
        let peers = match discovery::list(Duration::from_secs(2)) {
            Ok(peers) => peers,
            Err(error) => {
                status::error(format!("Local network discovery failed: {error}"));
                tracing::warn!(%error, "mDNS discovery failed; retrying");
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        // Identity = stable device id (never the name; names can collide or be
        // renamed to "mac (2)" by mDNS). Skip ourselves by id.
        if let Some((fullname, _, peer_id)) = peers
            .iter()
            .find(|(_, _, id)| !id.is_empty() && id.as_str() != my_id)
        {
            let peer = fullname.split('.').next().unwrap_or("peer").to_string();
            // Deterministic tiebreaker on the ids: exactly one side dials.
            if my_id > *peer_id {
                // The dialer must not also run `serve_listener`: both paths
                // install a global input hook, so the old design processed
                // every Windows mouse event twice. Keep this advertisement
                // alive, release the listening socket, and reuse one capture
                // runtime for all reconnect attempts.
                drop(listener);
                let sh = build_shared(&cfg);
                let rx = start_capture(&sh);
                return dial_discovered(&cfg, &my_id, peer_id, &sh, &rx, advert);
            }
            status::peer_found(
                peer.clone(),
                Some(peer_id.clone()),
                "incoming connection".into(),
            );
            tracing::info!(%peer, "peer discovered — waiting for its incoming connection");
            drop(advert);
            return serve_listener(listener, bind_addr, cfg);
        } else {
            status::pairing(
                "Listening on the local network. Open ShareClick on the other computer with the same pairing code.",
            );
            tracing::info!("no peer found yet; still searching… (the peer may still find US)");
        }
    }
}

/// Re-discover and reconnect to the selected peer while keeping one capture
/// loop and one shared control state for the lifetime of the process.
fn dial_discovered(
    cfg: &Config,
    my_id: &str,
    peer_id: &str,
    sh: &Shared,
    rx: &Receiver<InputEvent>,
    _advert: Option<discovery::Advertiser>,
) -> anyhow::Result<()> {
    loop {
        let peers = match discovery::list(Duration::from_secs(2)) {
            Ok(peers) => peers,
            Err(error) => {
                status::error(format!("Local network discovery failed: {error}"));
                tracing::warn!(%error, "mDNS discovery failed; retrying");
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        let candidates: Vec<_> = peers
            .iter()
            .filter(|(_, _, id)| id == peer_id && id.as_str() != my_id)
            .map(|(name, addr, id)| (name.clone(), *addr, id.clone()))
            .collect();
        if candidates.is_empty() {
            status::pairing("The paired computer is offline. Waiting for it to reappear.");
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        for (fullname, addr, id) in candidates {
            let peer = fullname.split('.').next().unwrap_or("peer").to_string();
            status::peer_found(peer.clone(), Some(id), addr.to_string());
            tracing::info!(%peer, %addr, "peer discovered — dialing");
            if let Err(error) = connect_session(cfg, addr, sh, rx) {
                tracing::warn!(%addr, %error, "candidate connection ended");
                status::disconnected(format!(
                    "Connection to {peer} ended: {error}. Reconnecting automatically."
                ));
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Persist a peer's reported screen size into our config, so the settings window
/// can show the real remote resolution. The client reports it on connect (like
/// Deskflow's DINF message).
fn record_peer_screen(name: &str, screen: (u32, u32)) {
    let path = Config::default_path();
    if let Ok(mut cfg) = Config::load(&path) {
        if let Some(m) = cfg.machines.iter_mut().find(|m| m.name == name) {
            if m.screen != Some(screen) {
                m.screen = Some(screen);
                let _ = cfg.save(&path);
                tracing::info!(%name, width = screen.0, height = screen.1, "recorded peer screen size");
            }
        }
    }
}

/// Persist an adopted arrangement: my machine gets the peer on `my_edge`, the
/// peer machine gets the reciprocal, and the offset is stored — so the layout
/// survives restarts even though it was only ever configured on the peer.
fn record_peer_layout(peer: &str, my_edge: Edge, my_offset: i32) {
    let path = Config::default_path();
    let Ok(mut cfg) = Config::load(&path) else {
        return;
    };
    let me = cfg.name.clone();
    let set = |m: &mut crate::config::Machine, e: Edge, n: &str| {
        m.left = None;
        m.right = None;
        m.top = None;
        m.bottom = None;
        match e {
            Edge::Left => m.left = Some(n.into()),
            Edge::Right => m.right = Some(n.into()),
            Edge::Top => m.top = Some(n.into()),
            Edge::Bottom => m.bottom = Some(n.into()),
        }
    };
    let peer_owned = peer.to_string();
    for m in cfg.machines.iter_mut() {
        if m.name == me {
            set(m, my_edge, &peer_owned);
        } else if m.name == peer_owned {
            set(m, opposite(my_edge), &me);
        }
    }
    cfg.offset = my_offset;
    let _ = cfg.save(&path);
}

/// Wire clipboard + file sync onto one (already-encrypted) bulk connection.
/// Blocks on the reader loop; returns when the peer disconnects.
/// `adopt` = always take the peer's arrangement (the dialer does; the listener
/// only takes it when it has none of its own).
fn serve_bulk(
    conn: BulkConn,
    hello: Option<BulkMsg>,
    sh: Shared,
    adopt: bool,
) -> anyhow::Result<()> {
    let last = clipboard::shared_last();
    let (out_tx, out_rx) = mpsc::channel::<BulkMsg>();
    let (in_tx, in_rx) = mpsc::channel::<ClipboardData>();

    // Send our own screen size first (client → server), before any other frame,
    // so the encrypted send-counter stays in sync with the peer's recv-counter.
    if let Some(h) = hello {
        let _ = out_tx.send(h);
    }
    // Let the input pump push refreshed Hellos (live re-arrangement).
    *sh.hello_tx.lock().unwrap() = Some(out_tx.clone());

    let mut wconn = conn.try_clone()?;
    std::thread::spawn(move || {
        while let Ok(msg) = out_rx.recv() {
            if wconn.send(&msg).is_err() {
                break;
            }
        }
    });
    let _clipboard_sync = clipboard::start(out_tx, in_rx, last);

    let mut receiver = FileReceiver::new("received");
    let mut rconn = conn;
    let result = loop {
        match rconn.recv() {
            Ok(BulkMsg::Clipboard(data)) => {
                let _ = in_tx.send(data);
            }
            Ok(
                msg @ (BulkMsg::FileBegin { .. }
                | BulkMsg::FileChunk { .. }
                | BulkMsg::FileEnd { .. }),
            ) => {
                if let Err(e) = receiver.handle(&msg) {
                    tracing::warn!(error = %e, "file receive failed");
                }
            }
            // Peer's Hello: its screen size (kept LIVE for the offset maths,
            // Deskflow's DINF pattern) and optionally its monitor arrangement —
            // adopt the mirrored version so the layout is only ever configured
            // on ONE machine.
            Ok(BulkMsg::Hello {
                version,
                device_id,
                name,
                screen,
                edge,
                offset,
                refresh,
            }) => {
                if version != shareclick_protocol::PROTOCOL_VERSION {
                    anyhow::bail!("peer protocol changed during the session: {version}");
                }
                status::peer_identified(name.clone(), Some(device_id));
                tracing::info!(peer = %name, width = screen.0, height = screen.1, "peer reported its screen size (Hello)");
                *sh.peer_screen.lock().unwrap() = screen;
                record_peer_screen(&name, screen);
                if let Some(their_edge) = edge {
                    let have_own = sh.border.lock().unwrap().is_some();
                    if refresh || adopt || !have_own {
                        let my_edge = opposite(their_edge);
                        let my_offset = -offset;
                        *sh.border.lock().unwrap() = Some(my_edge);
                        *sh.arrangement.lock().unwrap() = (
                            EdgeConfig::new(
                                sh.screen.0,
                                sh.screen.1,
                                my_edge == Edge::Left,
                                my_edge == Edge::Right,
                                my_edge == Edge::Top,
                                my_edge == Edge::Bottom,
                            ),
                            my_offset,
                        );
                        record_peer_layout(&name, my_edge, my_offset);
                        tracing::info!(
                            ?my_edge,
                            my_offset,
                            "adopted the peer's monitor arrangement"
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(error) => break Err(error),
        }
    };
    // Release the last long-lived sender for this session so the bulk writer
    // and clipboard worker can terminate before a reconnect installs new ones.
    *sh.hello_tx.lock().unwrap() = None;
    result
}

/// The SYMMETRIC input pump — identical on both machines. Injects the peer's
/// forwarded input, forwards ours while our pointer is away, and translates
/// capture-thread state flips into `PointerEnter` / `PointerEnd` messages.
struct PeerInputGuard<'a> {
    control: &'a Control,
}

impl Drop for PeerInputGuard<'_> {
    fn drop(&mut self) {
        self.control.peer_connected.store(false, Ordering::Release);
        self.control.my_away.store(false, Ordering::Release);
        self.control.peer_away.store(false, Ordering::Release);
        self.control.host_armed.store(false, Ordering::Release);
        *self.control.entry.lock().unwrap() = None;
        *self.control.return_to.lock().unwrap() = None;
        *self.control.send_peer_home.lock().unwrap() = None;
        *self.control.host_span.lock().unwrap() = None;
    }
}

/// Pointer ownership transitions are small but essential. UDP may lose an
/// individual datagram, so send a few identical copies. The receiver treats
/// repeated transitions idempotently.
fn send_pointer_control(udp: &InputChannel, peer: SocketAddr, msg: InputMsg) {
    for _ in 0..3 {
        if let Err(error) = udp.send_to(msg.clone(), peer) {
            tracing::warn!(%error, "failed to send pointer control transition");
            break;
        }
    }
}

const MAX_INPUT_EVENTS_PER_PACKET: usize = 64;

/// Drain one bounded UDP batch and fold consecutive motion events together.
/// This prevents high-polling-rate mice from producing oversized datagrams
/// that exceed the receiver's fixed buffer and are discarded as lag spikes.
fn drain_input_batch(rx: &Receiver<InputEvent>) -> Vec<InputEvent> {
    let mut batch = Vec::new();
    while batch.len() < MAX_INPUT_EVENTS_PER_PACKET {
        let Ok(event) = rx.try_recv() else {
            break;
        };
        match (batch.last_mut(), event) {
            (
                Some(InputEvent::MouseMove {
                    dx: last_dx,
                    dy: last_dy,
                }),
                InputEvent::MouseMove { dx, dy },
            ) => {
                *last_dx = last_dx.saturating_add(dx);
                *last_dy = last_dy.saturating_add(dy);
            }
            (_, event) => batch.push(event),
        }
    }
    batch
}

fn run_peer_input(
    udp: &InputChannel,
    rx: &Receiver<InputEvent>,
    sh: &Shared,
    cfg_name: &str,
    mut peer: Option<SocketAddr>,
) -> anyhow::Result<()> {
    let control = &sh.control;
    // Fresh session: no peer is attached yet. Edge crossings / hotkey pushes
    // stay disabled until the first packet from the peer proves it is live
    // (otherwise the local cursor would be hidden with nowhere to go).
    control.peer_connected.store(false, Ordering::Relaxed);
    let _control_guard = PeerInputGuard { control };
    let waiting_since = std::time::Instant::now();
    let mut last_peer_packet = waiting_since;
    let mut input_confirmed = false;
    let mut injector = crate::emit::Injector::new()?;
    let mut prev_my_away = false;
    let mut last_keepalive = std::time::Instant::now();
    let mut cfg_mtime = std::fs::metadata(Config::default_path())
        .and_then(|m| m.modified())
        .ok();
    let mut cfg_ticks: u32 = 0;
    let mut buf = [0u8; 2048];
    loop {
        if !sh.session_alive.load(Ordering::Relaxed) {
            anyhow::bail!("authenticated bulk channel closed");
        }
        // "Connect first, arrange after": watch the config; when the settings
        // window saves, reload the arrangement live + push it to the peer.
        cfg_ticks += 1;
        if cfg_ticks > 1500 {
            cfg_ticks = 0;
            let m = std::fs::metadata(Config::default_path())
                .and_then(|m| m.modified())
                .ok();
            if m != cfg_mtime {
                cfg_mtime = m;
                reload_arrangement(cfg_name, sh);
            }
        }
        // ---- receive from the peer ----
        if let Ok(Some((pkt, from))) = udp.recv(&mut buf) {
            last_peer_packet = std::time::Instant::now();
            control.peer_connected.store(true, Ordering::Release);
            if peer != Some(from) {
                tracing::info!(%from, "peer input channel online");
                peer = Some(from);
            }
            if !input_confirmed {
                input_confirmed = true;
                status::connected(from.to_string());
            }
            match pkt.msg {
                InputMsg::Ping { nonce, echo_nanos } => {
                    let _ = udp.send_to(InputMsg::Pong { nonce, echo_nanos }, from);
                }
                // The peer's physical input drives MY real cursor.
                InputMsg::Events(events) => {
                    for ev in events {
                        if let Err(e) = injector.apply(ev) {
                            tracing::warn!(error = %e, "inject failed");
                        }
                    }
                }
                // The peer's pointer arrives on my screen.
                InputMsg::PointerEnter { edge, pos, span } => {
                    // Repeated copies of the same transition are expected.
                    // Only the first may warp the cursor or disarm return.
                    if !control.peer_away.swap(true, Ordering::AcqRel) {
                        if control.my_away.swap(false, Ordering::Relaxed) {
                            prev_my_away = false; // crossed paths: mine implicitly came home
                        }
                        control.host_armed.store(false, Ordering::Relaxed);
                        *control.host_span.lock().unwrap() = Some((edge, span));
                        let (ex, ey) = entry_point(edge, pos, sh.screen.0, sh.screen.1);
                        let _ = injector.move_to(ex, ey);
                        tracing::info!(?edge, ex, ey, "peer pointer entered my screen");
                    }
                }
                InputMsg::Pong { .. } => {}
                // An away-state ends.
                InputMsg::PointerEnd { pos } => {
                    if control.my_away.swap(false, Ordering::Relaxed) {
                        prev_my_away = false;
                        let border = sh.border.lock().unwrap().unwrap_or(Edge::Right);
                        *control.return_to.lock().unwrap() = pos.map(|p| (border, p));
                        // macOS re-shows + warps in capture; elsewhere warp here.
                        #[cfg(not(target_os = "macos"))]
                        if let Some(p) = pos {
                            let (ex, ey) = entry_point(border, p, sh.screen.0, sh.screen.1);
                            let _ = injector.move_to(ex, ey);
                        }
                        tracing::info!("my pointer came home");
                    } else if control.peer_away.swap(false, Ordering::Relaxed) {
                        *control.host_span.lock().unwrap() = None;
                        tracing::info!("peer reclaimed its pointer");
                    }
                }
            }
        } else {
            let timeout_from = if input_confirmed {
                last_peer_packet
            } else {
                waiting_since
            };
            if timeout_from.elapsed() > Duration::from_secs(15) {
                anyhow::bail!("peer input channel timed out");
            }
        }

        // Time-based keep-alive instead of loop-count timing. Scheduler load
        // and input traffic can change loop frequency by orders of magnitude.
        if last_keepalive.elapsed() >= Duration::from_secs(1) {
            last_keepalive = std::time::Instant::now();
            if let Some(p) = peer {
                let _ = udp.send_to(
                    InputMsg::Ping {
                        nonce: 0,
                        echo_nanos: 0,
                    },
                    p,
                );
            }
        }

        // ---- capture: the visiting pointer crossed home ----
        if let Some(perp) = control.send_peer_home.lock().unwrap().take() {
            if let Some(p) = peer {
                let _ = udp.send_to(release_all_modifiers(), p);
                let msg = if perp == i32::MAX {
                    InputMsg::PointerEnd { pos: None } // hotkey: no position
                } else {
                    let (_, offset) = *sh.arrangement.lock().unwrap();
                    let ps = *sh.peer_screen.lock().unwrap();
                    let border = sh.border.lock().unwrap().unwrap_or(Edge::Right);
                    let cdim = perp_dim(border, ps.0, ps.1);
                    InputMsg::PointerEnd {
                        pos: Some(map_to_client(perp, offset, cdim)),
                    }
                };
                send_pointer_control(udp, p, msg);
            }
            *control.host_span.lock().unwrap() = None;
        }

        // ---- capture: my pointer went away / was reclaimed ----
        let my_away = control.my_away.load(Ordering::Relaxed);
        if my_away != prev_my_away {
            if let Some(p) = peer {
                let _ = udp.send_to(release_all_modifiers(), p);
                if my_away {
                    let (_, offset) = *sh.arrangement.lock().unwrap();
                    let ps = *sh.peer_screen.lock().unwrap();
                    let (edge_out, pos, span) = match *control.entry.lock().unwrap() {
                        Some((edge, perp)) => {
                            let cdim = perp_dim(edge, ps.0, ps.1);
                            let sdim = perp_dim(edge, sh.screen.0, sh.screen.1) as i32;
                            (
                                edge,
                                map_to_client(perp, offset, cdim),
                                client_return_span(offset, sdim, cdim as i32),
                            )
                        }
                        None => {
                            // Hotkey push: enter at the peer's centre.
                            let border = sh.border.lock().unwrap().unwrap_or(Edge::Right);
                            let cdim = perp_dim(border, ps.0, ps.1);
                            let sdim = perp_dim(border, sh.screen.0, sh.screen.1) as i32;
                            (
                                border,
                                cdim as i32 / 2,
                                client_return_span(offset, sdim, cdim as i32),
                            )
                        }
                    };
                    send_pointer_control(
                        udp,
                        p,
                        InputMsg::PointerEnter {
                            edge: opposite(edge_out),
                            pos,
                            span,
                        },
                    );
                } else {
                    // Hotkey reclaim — tell the peer the visit ended.
                    send_pointer_control(udp, p, InputMsg::PointerEnd { pos: None });
                }
            }
            prev_my_away = my_away;
        }

        // ---- forward my captured input while my pointer is away ----
        let batch = drain_input_batch(rx);
        if !batch.is_empty() {
            if let Some(p) = peer {
                let _ = udp.send_to(InputMsg::Events(batch), p);
            }
        } else {
            std::thread::sleep(Duration::from_micros(500));
        }
    }
}

/// Listener peer: accepts the connection. At runtime both sides are identical
/// (symmetric ShareMouse-style control) — "server" only means "listens".
pub fn serve(bind: &str) -> anyhow::Result<()> {
    let cfg = match load_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            status::needs_setup(error.to_string());
            return Err(error);
        }
    };
    let bind_addr = resolve(bind)?;
    let listener = TcpListener::bind(bind_addr)?;
    status::pairing("Listening for another ShareClick device on the local network.");
    serve_listener(listener, bind_addr, cfg)
}

fn serve_listener(listener: TcpListener, bind_addr: SocketAddr, cfg: Config) -> anyhow::Result<()> {
    let psk = cfg.psk.clone().into_bytes();
    tracing::info!(%bind_addr, name = %cfg.name, "listening; both machines' mice/keyboards work — push through the shared edge");
    tracing::info!("grant Accessibility permission on macOS for capture to work");

    let sh = build_shared(&cfg);

    // Capture runs once, globally. Both peers capture their own input.
    let rx = start_capture(&sh);

    // Advertise over mDNS so peers can find us without an IP.
    let my_id = Config::ensure_device_id(&Config::default_path());
    let _advert = discovery::advertise(&cfg.name, bind_addr.port(), &my_id)
        .map_err(|e| tracing::warn!(error = %e, "mDNS advertise failed"))
        .ok();

    loop {
        let (stream, remote_addr) = listener.accept()?;
        let peer_ip = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        status::authenticating(remote_addr.to_string());
        let (conn, input_sess) = match BulkConn::handshake(stream, &psk, Role::Responder) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%peer_ip, error = %e, "handshake/auth failed; check the PSK");
                status::error(format!(
                    "Could not authenticate {remote_addr}. Check that both computers use the same pairing code."
                ));
                continue;
            }
        };
        let shutdown = conn.shutdown_handle()?;
        tracing::info!(%peer_ip, "peer authenticated (encrypted session established)");
        status::pairing("Peer authenticated. Verifying the encrypted input channel.");
        sh.session_alive.store(true, Ordering::Release);

        // Bulk channel: clipboard/files + Hello exchange (we send ours too, so
        // the dialer can adopt our arrangement).
        let hello = my_hello(&cfg.name, &sh, false);
        let sh_bulk = sh.clone();
        let bulk_thread = std::thread::spawn(move || {
            // Listener only adopts the peer's layout when it has none itself.
            let result = serve_bulk(conn, Some(hello), sh_bulk.clone(), false);
            sh_bulk.session_alive.store(false, Ordering::Release);
            if let Err(error) = result {
                tracing::warn!(%error, "bulk channel closed");
            }
        });

        // Encrypted UDP input channel for this session.
        let udp = InputChannel::bind(bind_addr, None)?.with_cipher(Arc::new(input_sess));
        udp.set_read_timeout(Some(Duration::from_millis(1)))?;
        if let Err(e) = run_peer_input(&udp, &rx, &sh, &cfg.name, None) {
            tracing::warn!(error = %e, "input session ended; awaiting a new peer");
            status::disconnected(format!(
                "Connection ended: {e}. Waiting for the peer to reconnect."
            ));
        }
        let _ = shutdown.shutdown(Shutdown::Both);
        let _ = bulk_thread.join();
        status::pairing("Previous connection ended. Listening for the peer to reconnect.");
    }
}

/// Client: receives input batches and injects them locally. `server` overrides
/// the config's `server_host`; either may omit the port (config `port` used).
pub fn connect(server: Option<&str>) -> anyhow::Result<()> {
    let cfg = match load_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            status::needs_setup(error.to_string());
            return Err(error);
        }
    };
    let with_port = |h: &str| -> String {
        if h.contains(':') {
            h.to_string()
        } else {
            format!("{h}:{}", cfg.port)
        }
    };
    let server_addr = match server
        .map(|s| s.to_string())
        .or_else(|| cfg.server_host.clone())
    {
        Some(host) => resolve(&with_port(&host))?,
        None => {
            tracing::info!("no server configured; searching via mDNS (3s)…");
            discovery::discover(Duration::from_secs(3))?.ok_or_else(|| {
                anyhow::anyhow!("no server found via mDNS; pass a host or set `server_host`")
            })?
        }
    };
    let sh = build_shared(&cfg);
    let rx = start_capture(&sh);
    let result = connect_session(&cfg, server_addr, &sh, &rx);
    if let Err(error) = &result {
        status::disconnected(format!("Connection ended: {error}"));
    }
    result
}

/// Establish one dialer session using an already-running capture loop. Keeping
/// capture outside this function lets automatic reconnect reuse the same OS
/// hook instead of installing another global hook on every attempt.
fn connect_session(
    cfg: &Config,
    server_addr: SocketAddr,
    sh: &Shared,
    rx: &Receiver<InputEvent>,
) -> anyhow::Result<()> {
    tracing::info!(%server_addr, name = %cfg.name, "connecting; grant Accessibility permission on macOS");
    status::authenticating(server_addr.to_string());

    // Handshake over TCP first, then key both channels from it.
    let stream = TcpStream::connect_timeout(&server_addr, Duration::from_secs(4))?;
    let (conn, input_sess): (BulkConn, Session) =
        BulkConn::handshake(stream, cfg.psk.as_bytes(), Role::Initiator)?;
    let shutdown = conn.shutdown_handle()?;
    tracing::info!("authenticated with peer (encrypted session established)");
    status::pairing("Peer authenticated. Verifying the encrypted input channel.");
    sh.session_alive.store(true, Ordering::Release);

    // Bulk channel: clipboard/files + Hello exchange. The dialer adopts the
    // listener's arrangement, so you only configure the layout on one machine.
    let hello = my_hello(&cfg.name, sh, false);
    let sh_bulk = sh.clone();
    let bulk_thread = std::thread::spawn(move || {
        if let Err(e) = serve_bulk(conn, Some(hello), sh_bulk.clone(), true) {
            tracing::warn!(error = %e, "bulk channel closed");
        }
        sh_bulk.session_alive.store(false, Ordering::Release);
    });

    // Encrypted UDP input channel; announce ourselves so the listener learns
    // our address, then run the same symmetric pump as the listener.
    let channel = InputChannel::bind("0.0.0.0:0".parse().unwrap(), Some(server_addr))?
        .with_cipher(Arc::new(input_sess));
    channel.set_read_timeout(Some(Duration::from_millis(1)))?;
    channel.send(InputMsg::Ping {
        nonce: 0,
        echo_nanos: 0,
    })?;

    let result = run_peer_input(&channel, rx, sh, &cfg.name, Some(server_addr));
    // If UDP failed first, close TCP so the bulk reader and clipboard session
    // cannot leak into the next reconnect attempt.
    let _ = shutdown.shutdown(Shutdown::Both);
    let _ = bulk_thread.join();
    result
}
