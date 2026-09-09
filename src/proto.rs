//! Mouse-event wire format.
//!
//! Hand-rolled little-endian encoding keeps the packets tiny and the
//! dependency list short. An empty batch is a valid packet and doubles as a
//! keep-alive.

/// One forwarded mouse event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MouseEvent {
    /// Relative pointer motion.
    Move { dx: i32, dy: i32 },
    /// Button transition.
    Button { button: u8, pressed: bool },
    /// Scroll wheel deltas.
    Scroll { dx: f32, dy: f32 },
}

/// Button IDs used on the wire.
pub const LEFT: u8 = 0;
pub const RIGHT: u8 = 1;
pub const MIDDLE: u8 = 2;
pub const BACK: u8 = 3;
pub const FORWARD: u8 = 4;

const TAG_MOVE: u8 = 1;
const TAG_BUTTON: u8 = 2;
const TAG_SCROLL: u8 = 3;

/// Encode a batch of events into wire bytes.
pub fn encode(events: &[MouseEvent]) -> Vec<u8> {
    let mut out = Vec::with_capacity(events.len() * 9);
    for ev in events {
        match *ev {
            MouseEvent::Move { dx, dy } => {
                out.push(TAG_MOVE);
                out.extend_from_slice(&dx.to_le_bytes());
                out.extend_from_slice(&dy.to_le_bytes());
            }
            MouseEvent::Button { button, pressed } => {
                out.push(TAG_BUTTON);
                out.push(button);
                out.push(pressed as u8);
            }
            MouseEvent::Scroll { dx, dy } => {
                out.push(TAG_SCROLL);
                out.extend_from_slice(&dx.to_le_bytes());
                out.extend_from_slice(&dy.to_le_bytes());
            }
        }
    }
    out
}

/// Decode wire bytes back into events. Returns `None` on malformed input.
pub fn decode(bytes: &[u8]) -> Option<Vec<MouseEvent>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            TAG_MOVE if i + 9 <= bytes.len() => {
                out.push(MouseEvent::Move {
                    dx: i32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?),
                    dy: i32::from_le_bytes(bytes[i + 5..i + 9].try_into().ok()?),
                });
                i += 9;
            }
            TAG_BUTTON if i + 3 <= bytes.len() => {
                out.push(MouseEvent::Button {
                    button: bytes[i + 1],
                    pressed: bytes[i + 2] != 0,
                });
                i += 3;
            }
            TAG_SCROLL if i + 9 <= bytes.len() => {
                out.push(MouseEvent::Scroll {
                    dx: f32::from_le_bytes(bytes[i + 1..i + 5].try_into().ok()?),
                    dy: f32::from_le_bytes(bytes[i + 5..i + 9].try_into().ok()?),
                });
                i += 9;
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let events = vec![
            MouseEvent::Move { dx: -3, dy: 7 },
            MouseEvent::Button {
                button: LEFT,
                pressed: true,
            },
            MouseEvent::Scroll { dx: 0.0, dy: -1.5 },
        ];
        assert_eq!(decode(&encode(&events)), Some(events));
    }

    #[test]
    fn empty_batch_is_a_valid_keepalive() {
        assert_eq!(decode(&encode(&[])), Some(vec![]));
    }

    #[test]
    fn truncated_packet_is_rejected() {
        assert_eq!(decode(&[TAG_MOVE, 1, 2]), None);
        assert_eq!(decode(&[0xff]), None);
    }
}