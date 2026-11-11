//! The terminal emulator: escape-sequence parsing, the cell grid, scrollback, selection and
//! input encoding. It wraps `alacritty_terminal` and exposes plain data, so the renderer, the
//! transports and the server agent do not depend on it.

mod keys;
mod mouse;
mod theme;
mod vt;

pub use keys::{KeyMods, encode_key};
pub use mouse::{MouseAction, encode_mouse};
pub use theme::{Color, Theme};
pub use vt::{CellView, CursorShape, CursorView, Damage, LineDamage, Modes, SelectionKind, Vt, VtEvent};
