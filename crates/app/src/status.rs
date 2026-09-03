//! Cross-process pairing status for the tray and Settings window.
//!
//! Settings runs as a separate process, so an in-memory flag would lie. The
//! active networking process writes a small, secret-free snapshot next to the
//! config and refreshes its timestamp. Readers treat stale snapshots as a
//! disconnected runtime.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;

#[cfg(any(feature = "tray", feature = "gui"))]
const STALE_AFTER: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingPhase {
    NeedsSetup,
    Pairing,
    Connected,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSnapshot {
    pub phase: PairingPhase,
    pub peer_name: Option<String>,
    pub peer_id: Option<String>,
    pub peer_address: Option<String>,
    pub detail: Option<String>,
    #[serde(default)]
    updated_unix_ms: u64,
    #[serde(default)]
    owner_pid: u32,
}

impl PairingSnapshot {
    fn new(phase: PairingPhase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            peer_name: None,
            peer_id: None,
            peer_address: None,
            detail: Some(detail.into()),
            updated_unix_ms: now_unix_ms(),
            owner_pid: std::process::id(),
        }
    }
}

fn status_path() -> std::path::PathBuf {
    Config::default_path().with_file_name("status.toml")
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn read_file() -> Option<PairingSnapshot> {
    let text = std::fs::read_to_string(status_path()).ok()?;
    toml::from_str(&text).ok()
}

fn write_file(snapshot: &PairingSnapshot) {
    let path = status_path();
    let result = (|| -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, toml::to_string(snapshot)?)?;
        Ok(())
    })();
    if let Err(error) = result {
        tracing::warn!(%error, "could not persist pairing status");
    }
}

fn update(
    phase: PairingPhase,
    peer_name: Option<String>,
    peer_id: Option<String>,
    peer_address: Option<String>,
    detail: impl Into<String>,
) {
    let previous = read_file();
    let snapshot = PairingSnapshot {
        phase,
        peer_name: peer_name.or_else(|| previous.as_ref().and_then(|s| s.peer_name.clone())),
        peer_id: peer_id.or_else(|| previous.as_ref().and_then(|s| s.peer_id.clone())),
        peer_address: peer_address
            .or_else(|| previous.as_ref().and_then(|s| s.peer_address.clone())),
        detail: Some(detail.into()),
        updated_unix_ms: now_unix_ms(),
        owner_pid: std::process::id(),
    };
    write_file(&snapshot);
}

pub fn needs_setup(detail: impl Into<String>) {
    write_file(&PairingSnapshot::new(PairingPhase::NeedsSetup, detail));
}

pub fn pairing(detail: impl Into<String>) {
    update(PairingPhase::Pairing, None, None, None, detail);
    start_heartbeat();
}

pub fn peer_found(name: String, id: Option<String>, address: String) {
    update(
        PairingPhase::Pairing,
        Some(name),
        id,
        Some(address),
        "Peer found. Establishing an encrypted session.",
    );
}

pub fn authenticating(address: String) {
    update(
        PairingPhase::Pairing,
        None,
        None,
        Some(address),
        "Peer found. Verifying the pairing code and protocol version.",
    );
}

pub fn peer_identified(name: String, id: Option<String>) {
    let phase = read_file()
        .map(|snapshot| snapshot.phase)
        .unwrap_or(PairingPhase::Pairing);
    update(
        phase,
        Some(name),
        id,
        None,
        if phase == PairingPhase::Connected {
            "Encrypted pairing and input channel are active."
        } else {
            "Peer authenticated. Verifying the input channel."
        },
    );
}

pub fn connected(address: String) {
    update(
        PairingPhase::Connected,
        None,
        None,
        Some(address),
        "Encrypted pairing and input channel are active.",
    );
}

pub fn disconnected(detail: impl Into<String>) {
    update(PairingPhase::Disconnected, None, None, None, detail);
}

pub fn error(detail: impl Into<String>) {
    update(PairingPhase::Error, None, None, None, detail);
}

/// Refresh liveness only when this process still owns the status file. This
/// prevents a failed duplicate tray process from keeping another process's
/// stale state alive.
pub fn touch() {
    let Some(mut snapshot) = read_file() else {
        return;
    };
    if snapshot.owner_pid != std::process::id() {
        return;
    }
    snapshot.updated_unix_ms = now_unix_ms();
    write_file(&snapshot);
}

fn start_heartbeat() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_secs(2));
            touch();
        });
    });
}

#[cfg(any(feature = "tray", feature = "gui"))]
pub fn snapshot() -> PairingSnapshot {
    let config_result = Config::load(&Config::default_path());
    if let Err(error) = config_result {
        return PairingSnapshot::new(
            PairingPhase::NeedsSetup,
            format!("Open Settings and save a valid configuration: {error}"),
        );
    }

    let Some(mut snapshot) = read_file() else {
        return PairingSnapshot::new(
            PairingPhase::Disconnected,
            "ShareClick is configured but automatic pairing is not running.",
        );
    };

    if snapshot.phase == PairingPhase::NeedsSetup {
        snapshot.phase = PairingPhase::Disconnected;
        snapshot.detail = Some("Settings are valid. Start automatic pairing.".into());
        return snapshot;
    }

    let age_ms = now_unix_ms().saturating_sub(snapshot.updated_unix_ms);
    if matches!(
        snapshot.phase,
        PairingPhase::Pairing | PairingPhase::Connected
    ) && age_ms > STALE_AFTER.as_millis() as u64
    {
        snapshot.phase = PairingPhase::Disconnected;
        snapshot.detail =
            Some("The ShareClick networking process is not reporting. Start pairing again.".into());
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_snapshot_does_not_contain_peer_or_secret_data() {
        let snapshot = PairingSnapshot::new(PairingPhase::Pairing, "searching");
        assert_eq!(snapshot.phase, PairingPhase::Pairing);
        assert!(snapshot.peer_name.is_none());
        assert!(snapshot.peer_id.is_none());
        assert!(snapshot.peer_address.is_none());
    }
}
