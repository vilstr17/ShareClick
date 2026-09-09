//! Mouse capture using `rdev`'s global grab.
//!
//! A toggle hotkey flips the shared `active` flag:
//!  * **active**   → mouse events are forwarded to the receiver and swallowed
//!    locally, so this machine doesn't react while you drive the other one.
//!  * **inactive** → events pass straight through to this machine, nothing sent.
//!
//! rdev reports **absolute** cursor positions; we convert to relative deltas
//! so the receiver's cursor tracks motion without coupling to screen geometry.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use rdev::{Event, EventType};

use crate::proto::{self, MouseEvent};

/// Hotkey that toggles control (works well on Windows/Linux, where it is a
/// real F-key).
pub const TOGGLE_KEY: rdev::Key = rdev::Key::F12;

// macOS cursor capture (the Deskflow technique): while control is handed over,
// hide the local cursor and disconnect the physical device from the cursor so
// CoreGraphics keeps reporting native relative deltas. See
// references/macos-cursor-capture.md.
#[cfg(target_os = "macos")]
mod mac_cursor {
    use std::os::raw::{c_char, c_void};

    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGMainDisplayID() -> u32;
        fn CGDisplayHideCursor(display: u32) -> i32;
        fn CGDisplayShowCursor(display: u32) -> i32;
        fn CGAssociateMouseAndMouseCursorPosition(connected: bool) -> i32;
        fn CGGetLastMouseDelta(delta_x: *mut i32, delta_y: *mut i32);
        fn CGSetLocalEventsSuppressionInterval(seconds: f64) -> i32;
        fn _CGSDefaultConnection() -> i32;
        fn CGSSetConnectionProperty(
            cid: i32,
            target: i32,
            key: CFStringRef,
            value: CFTypeRef,
        ) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const c_void,
            s: *const c_char,
            enc: u32,
        ) -> CFStringRef;
        fn CFRelease(cf: CFTypeRef);
        static kCFBooleanTrue: CFTypeRef;
    }

    pub fn zero_suppression() {
        unsafe {
            CGSetLocalEventsSuppressionInterval(0.0);
        }
    }
    fn set_bg_cursor_property() {
        unsafe {
            let key = CFStringCreateWithCString(
                std::ptr::null(),
                c"SetsCursorInBackground".as_ptr(),
                0, // kCFStringEncodingMacRoman
            );
            if !key.is_null() {
                let conn = _CGSDefaultConnection();
                CGSSetConnectionProperty(conn, conn, key, kCFBooleanTrue);
                CFRelease(key);
            }
        }
    }
    pub fn hide_cursor() {
        set_bg_cursor_property();
        unsafe {
            CGDisplayHideCursor(CGMainDisplayID());
            // Keep the local cursor fixed while physical mouse/trackpad events
            // continue carrying native relative X/Y deltas. Reconstructing
            // those deltas from absolute positions is unreliable on scaled
            // Retina displays.
            CGAssociateMouseAndMouseCursorPosition(false);
        }
    }
    pub fn show_cursor() {
        set_bg_cursor_property();
        unsafe {
            CGDisplayShowCursor(CGMainDisplayID());
            CGAssociateMouseAndMouseCursorPosition(true);
        }
    }
    pub fn last_mouse_delta() -> (i32, i32) {
        let mut dx = 0;
        let mut dy = 0;
        unsafe {
            CGGetLastMouseDelta(&mut dx, &mut dy);
        }
        (dx, dy)
    }
}

/// Start capturing in the current thread. Blocks until the grab loop errors.
/// Captured [`MouseEvent`]s are sent on `tx` only while `active` is set.
pub fn run(tx: Sender<MouseEvent>, active: Arc<AtomicBool>) -> anyhow::Result<()> {
    // grab's callback is `Fn` (not `FnMut`) so mutable state lives behind locks.
    // Deltas on non-macOS are reconstructed from absolute positions.
    #[cfg(not(target_os = "macos"))]
    let last_pos: Mutex<Option<(f64, f64)>> = Mutex::new(None);
    // Buttons currently held, so a toggle-off can't leave one stuck on the
    // receiver (bit per button id).
    let pressed: Mutex<u8> = Mutex::new(0);
    #[cfg(target_os = "macos")]
    let was_active = AtomicBool::new(false);
    #[cfg(target_os = "macos")]
    mac_cursor::zero_suppression();

    // Reliable escape hotkey: BOTH Shift keys held together also toggles.
    // Works on every keyboard and (unlike F12 on macOS, which is a media key)
    // is captured reliably by rdev. This is the "get me unstuck" combo.
    let lshift = AtomicBool::new(false);
    let rshift = AtomicBool::new(false);
    let combo_done = AtomicBool::new(false);

    let callback = move |event: Event| -> Option<Event> {
        // --- toggle hotkeys ---
        match event.event_type {
            EventType::KeyPress(rdev::Key::ShiftLeft) => lshift.store(true, Ordering::Relaxed),
            EventType::KeyRelease(rdev::Key::ShiftLeft) => {
                lshift.store(false, Ordering::Relaxed);
                combo_done.store(false, Ordering::Relaxed);
            }
            EventType::KeyPress(rdev::Key::ShiftRight) => rshift.store(true, Ordering::Relaxed),
            EventType::KeyRelease(rdev::Key::ShiftRight) => {
                rshift.store(false, Ordering::Relaxed);
                combo_done.store(false, Ordering::Relaxed);
            }
            _ => {}
        }
        let mut toggled = false;
        if lshift.load(Ordering::Relaxed)
            && rshift.load(Ordering::Relaxed)
            && !combo_done.swap(true, Ordering::Relaxed)
        {
            toggled = true;
        }
        if let EventType::KeyPress(k) = event.event_type {
            if k == TOGGLE_KEY {
                toggled = true;
            }
        }
        if toggled {
            let now = !active.load(Ordering::Relaxed);
            active.store(now, Ordering::Relaxed);
            tracing::info!(now, "control toggled");
            if !now {
                // Release anything still held so nothing stays stuck remotely.
                for b in 0..5 {
                    let mut p = pressed.lock().unwrap();
                    if *p & (1 << b) != 0 {
                        *p &= !(1 << b);
                        drop(p);
                        let _ = tx.send(MouseEvent::Button {
                            button: b,
                            pressed: false,
                        });
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                let was = was_active.swap(now, Ordering::Relaxed);
                if now && !was {
                    mac_cursor::hide_cursor();
                } else if !now && was {
                    mac_cursor::show_cursor();
                }
            }
        }

        let is_active = active.load(Ordering::Relaxed);

        let mapped = match event.event_type {
            EventType::MouseMove { x, y } => {
                #[cfg(target_os = "macos")]
                {
                    let _ = (x, y);
                    if is_active {
                        // With the hardware device disconnected from the local
                        // cursor, CoreGraphics supplies the real device deltas.
                        let (dx, dy) = mac_cursor::last_mouse_delta();
                        if dx == 0 && dy == 0 {
                            None
                        } else {
                            Some(MouseEvent::Move { dx, dy })
                        }
                    } else {
                        None
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let mut lp = last_pos.lock().unwrap();
                    let e = (*lp).map(|(px, py)| MouseEvent::Move {
                        dx: (x - px).round() as i32,
                        dy: (y - py).round() as i32,
                    });
                    *lp = Some((x, y));
                    e
                }
            }
            EventType::ButtonPress(b) => {
                let id = to_button_id(b);
                *pressed.lock().unwrap() |= 1 << id;
                Some(MouseEvent::Button {
                    button: id,
                    pressed: true,
                })
            }
            EventType::ButtonRelease(b) => {
                let id = to_button_id(b);
                *pressed.lock().unwrap() &= !(1 << id);
                Some(MouseEvent::Button {
                    button: id,
                    pressed: false,
                })
            }
            EventType::Wheel { delta_x, delta_y } => Some(MouseEvent::Scroll {
                dx: delta_x as f32,
                dy: delta_y as f32,
            }),
            _ => None,
        };

        if is_active {
            if let Some(ev) = mapped {
                let _ = tx.send(ev);
            }
            // Swallow every local event while driving the other machine —
            // keyboard presses must not hit this machine's apps.
            None
        } else {
            Some(event) // let this machine handle it normally
        }
    };

    rdev::grab(callback).map_err(|e| anyhow::anyhow!("input capture failed: {e:?}"))?;
    Ok(())
}

/// Map an rdev button to the wire id used in `proto`.
fn to_button_id(b: rdev::Button) -> u8 {
    match b {
        rdev::Button::Left => proto::LEFT,
        rdev::Button::Right => proto::RIGHT,
        rdev::Button::Middle => proto::MIDDLE,
        // Back/forward side buttons.
        rdev::Button::Unknown(0) => proto::BACK,
        rdev::Button::Unknown(_) => proto::FORWARD,
    }
}