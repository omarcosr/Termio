//! Mouse reports for programs that asked for them (xterm 1000/1002/1003, SGR 1006 or legacy).

use crate::keys::KeyMods;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseAction {
    /// Button 0 left, 1 middle, 2 right.
    Press(u8),
    Release(u8),
    /// Motion with this button held, or none.
    Motion(Option<u8>),
    WheelUp,
    WheelDown,
}

/// The report for `action` at the zero-based cell (`column`, `line`). Legacy encoding cannot
/// address cells past 222, so those reports are dropped.
pub fn encode_mouse(action: MouseAction, column: usize, line: usize, mods: KeyMods, sgr: bool) -> Option<Vec<u8>> {
    let (mut code, release) = match action {
        MouseAction::Press(button) => (button.min(2), false),
        MouseAction::Release(button) => (button.min(2), true),
        MouseAction::Motion(Some(button)) => (32 + button.min(2), false),
        MouseAction::Motion(None) => (35, false),
        MouseAction::WheelUp => (64, false),
        MouseAction::WheelDown => (65, false),
    };
    code += 4 * mods.shift as u8 + 8 * mods.alt as u8 + 16 * mods.ctrl as u8;
    if sgr {
        return Some(format!("\x1b[<{code};{};{}{}", column + 1, line + 1, if release { 'm' } else { 'M' }).into_bytes());
    }
    if column > 222 || line > 222 {
        return None;
    }
    // Legacy reports name no button on release.
    let code = if release { 3 + (code & !3) } else { code };
    Some(vec![0x1b, b'[', b'M', 32 + code, 33 + column as u8, 33 + line as u8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgr_and_legacy_reports() {
        let none = KeyMods::default();
        assert_eq!(encode_mouse(MouseAction::Press(0), 4, 2, none, true).unwrap(), b"\x1b[<0;5;3M");
        assert_eq!(encode_mouse(MouseAction::Release(2), 0, 0, none, true).unwrap(), b"\x1b[<2;1;1m");
        assert_eq!(encode_mouse(MouseAction::WheelDown, 9, 9, KeyMods { ctrl: true, ..none }, true).unwrap(), b"\x1b[<81;10;10M");
        assert_eq!(encode_mouse(MouseAction::Motion(Some(0)), 1, 1, none, true).unwrap(), b"\x1b[<32;2;2M");
        assert_eq!(encode_mouse(MouseAction::Press(0), 0, 0, none, false).unwrap(), b"\x1b[M !!");
        assert_eq!(encode_mouse(MouseAction::Release(0), 0, 0, none, false).unwrap(), b"\x1b[M#!!");
        assert_eq!(encode_mouse(MouseAction::Press(0), 300, 0, none, false), None);
    }
}
