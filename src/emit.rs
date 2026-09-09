//! Mouse injection using `enigo`.
//!
//! Requires Accessibility permission on macOS.

use enigo::{Axis, Button, Coordinate, Direction, Enigo, Mouse, Settings};

use crate::proto::{self, MouseEvent};

pub struct Injector {
    enigo: Enigo,
}

impl Injector {
    pub fn new() -> anyhow::Result<Self> {
        let enigo = Enigo::new(&Settings::default())
            .map_err(|e| anyhow::anyhow!("failed to init input injector: {e:?}"))?;
        Ok(Self { enigo })
    }

    /// Apply one mouse event locally.
    pub fn apply(&mut self, ev: MouseEvent) -> anyhow::Result<()> {
        match ev {
            MouseEvent::Move { dx, dy } => {
                self.enigo
                    .move_mouse(dx, dy, Coordinate::Rel)
                    .map_err(|e| anyhow::anyhow!("move_mouse: {e:?}"))?;
            }
            MouseEvent::Button { button, pressed } => {
                let dir = if pressed {
                    Direction::Press
                } else {
                    Direction::Release
                };
                self.enigo
                    .button(to_enigo_button(button), dir)
                    .map_err(|e| anyhow::anyhow!("button: {e:?}"))?;
            }
            MouseEvent::Scroll { dx, dy } => {
                if dy.abs() >= 1.0 {
                    self.enigo
                        .scroll(-(dy as i32), Axis::Vertical)
                        .map_err(|e| anyhow::anyhow!("scroll v: {e:?}"))?;
                }
                if dx.abs() >= 1.0 {
                    self.enigo
                        .scroll(dx as i32, Axis::Horizontal)
                        .map_err(|e| anyhow::anyhow!("scroll h: {e:?}"))?;
                }
            }
        }
        Ok(())
    }
}

fn to_enigo_button(b: u8) -> Button {
    match b {
        proto::LEFT => Button::Left,
        proto::RIGHT => Button::Right,
        proto::MIDDLE => Button::Middle,
        proto::BACK => Button::Back,
        _ => Button::Forward,
    }
}