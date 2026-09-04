//! Bidirectional clipboard synchronization over the bulk channel (text +
//! images).
//!
//! One serialized owner handles both directions for each peer connection. On
//! macOS the tray event loop performs this work on the main thread; other
//! platforms use one cancellable worker.
//!
//! Echo suppression: whenever we *set* the clipboard from a remote message (or
//! send a local change), we remember a fingerprint of it so the watcher does
//! not bounce it straight back into an infinite loop.

#![cfg(feature = "native")]

use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
#[cfg(not(target_os = "macos"))]
use std::time::Duration;

use arboard::{Clipboard, ImageData};
use shareclick_protocol::{BulkMsg, ClipboardData};

/// A cheap fingerprint of the current clipboard, used to detect real changes
/// and to suppress echoes.
#[derive(Clone, PartialEq)]
pub(crate) enum Fingerprint {
    Text(String),
    Image(u64),
}

/// Shared "last known clipboard" used to suppress echoes.
pub(crate) type LastSeen = Arc<Mutex<Option<Fingerprint>>>;

fn hash_image(width: u32, height: u32, rgba: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    width.hash(&mut h);
    height.hash(&mut h);
    rgba.hash(&mut h);
    h.finish()
}

pub(crate) struct SyncGuard {
    alive: Arc<AtomicBool>,
}

impl Drop for SyncGuard {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}

fn apply_remote(clipboard: &mut Clipboard, data: ClipboardData, last: &LastSeen) {
    match data {
        ClipboardData::Text(text) => {
            *last.lock().unwrap() = Some(Fingerprint::Text(text.clone()));
            if let Err(e) = clipboard.set_text(text) {
                tracing::warn!(error = %e, "failed to set clipboard text");
            }
        }
        ClipboardData::Image {
            width,
            height,
            rgba,
        } => {
            *last.lock().unwrap() = Some(Fingerprint::Image(hash_image(width, height, &rgba)));
            let img = ImageData {
                width: width as usize,
                height: height as usize,
                bytes: Cow::Owned(rgba),
            };
            if let Err(e) = clipboard.set_image(img) {
                tracing::warn!(error = %e, "failed to set clipboard image");
            }
        }
    }
}

/// Run one serialized clipboard cycle. Keeping reads and writes on one owner
/// avoids racing two native clipboard handles during reconnects.
fn sync_once(
    clipboard: &mut Clipboard,
    out: &Sender<BulkMsg>,
    inbox: &Receiver<ClipboardData>,
    last: &LastSeen,
) -> bool {
    loop {
        match inbox.try_recv() {
            Ok(data) => apply_remote(clipboard, data, last),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => return false,
        }
    }

    // Text takes priority; fall back to an image if there's no text.
    if let Ok(text) = clipboard.get_text() {
        if !text.is_empty() {
            let fp = Fingerprint::Text(text.clone());
            let mut guard = last.lock().unwrap();
            if guard.as_ref() != Some(&fp) {
                *guard = Some(fp);
                drop(guard);
                return out
                    .send(BulkMsg::Clipboard(ClipboardData::Text(text)))
                    .is_ok();
            }
            return true;
        }
    }
    if let Ok(img) = clipboard.get_image() {
        let (w, h) = (img.width as u32, img.height as u32);
        let rgba = img.bytes.into_owned();
        let fp = Fingerprint::Image(hash_image(w, h, &rgba));
        let mut guard = last.lock().unwrap();
        if guard.as_ref() != Some(&fp) {
            *guard = Some(fp);
            drop(guard);
            return out
                .send(BulkMsg::Clipboard(ClipboardData::Image {
                    width: w,
                    height: h,
                    rgba,
                }))
                .is_ok();
        }
    }
    true
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn start(
    out: Sender<BulkMsg>,
    inbox: Receiver<ClipboardData>,
    last: LastSeen,
) -> SyncGuard {
    let alive = Arc::new(AtomicBool::new(true));
    let worker_alive = alive.clone();
    std::thread::spawn(move || {
        let mut clipboard = match Clipboard::new() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "clipboard unavailable; sync disabled");
                return;
            }
        };
        while worker_alive.load(Ordering::Acquire) && sync_once(&mut clipboard, &out, &inbox, &last)
        {
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    SyncGuard { alive }
}

#[cfg(all(target_os = "macos", feature = "tray"))]
struct MacSession {
    out: Sender<BulkMsg>,
    inbox: Receiver<ClipboardData>,
    last: LastSeen,
    alive: Arc<AtomicBool>,
}

#[cfg(all(target_os = "macos", feature = "tray"))]
static MAC_SESSION: std::sync::OnceLock<Mutex<Option<MacSession>>> = std::sync::OnceLock::new();

#[cfg(all(target_os = "macos", feature = "tray"))]
static MAC_CLIPBOARD: std::sync::OnceLock<Mutex<Option<Clipboard>>> = std::sync::OnceLock::new();

#[cfg(all(target_os = "macos", feature = "tray"))]
pub(crate) fn start(
    out: Sender<BulkMsg>,
    inbox: Receiver<ClipboardData>,
    last: LastSeen,
) -> SyncGuard {
    let alive = Arc::new(AtomicBool::new(true));
    *MAC_SESSION.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(MacSession {
        out,
        inbox,
        last,
        alive: alive.clone(),
    });
    SyncGuard { alive }
}

/// macOS AppKit objects, including NSPasteboard, must be touched on the main
/// thread. The tray event loop calls this function at the polling cadence.
#[cfg(all(target_os = "macos", feature = "tray"))]
pub(crate) fn poll_main_thread() {
    let mut session_slot = MAC_SESSION.get_or_init(|| Mutex::new(None)).lock().unwrap();
    let Some(session) = session_slot.as_mut() else {
        return;
    };
    if !session.alive.load(Ordering::Acquire) {
        *session_slot = None;
        return;
    }

    let mut clipboard_slot = MAC_CLIPBOARD
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap();
    if clipboard_slot.is_none() {
        match Clipboard::new() {
            Ok(clipboard) => *clipboard_slot = Some(clipboard),
            Err(error) => {
                tracing::warn!(%error, "clipboard unavailable; sync disabled");
                session.alive.store(false, Ordering::Release);
                *session_slot = None;
                return;
            }
        }
    }

    let keep_running = sync_once(
        clipboard_slot.as_mut().unwrap(),
        &session.out,
        &session.inbox,
        &session.last,
    );
    if !keep_running {
        session.alive.store(false, Ordering::Release);
        *session_slot = None;
    }
}

#[cfg(all(target_os = "macos", not(feature = "tray")))]
pub(crate) fn start(
    _out: Sender<BulkMsg>,
    _inbox: Receiver<ClipboardData>,
    _last: LastSeen,
) -> SyncGuard {
    tracing::warn!("macOS clipboard sync requires the tray event loop; sync disabled");
    SyncGuard {
        alive: Arc::new(AtomicBool::new(false)),
    }
}

/// Convenience to build a fresh shared echo-suppression cell.
pub(crate) fn shared_last() -> LastSeen {
    Arc::new(Mutex::new(None))
}
