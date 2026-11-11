//! Key presses as the bytes a terminal sends, following xterm's defaults.

/// Modifier keys held with a key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyMods {
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
}

impl KeyMods {
    fn any(self) -> bool {
        self.shift || self.alt || self.ctrl
    }

    /// xterm's modifier parameter: 1 + shift 1 + alt 2 + ctrl 4.
    fn parameter(self) -> u8 {
        1 + self.shift as u8 + 2 * self.alt as u8 + 4 * self.ctrl as u8
    }
}

/// `CSI 1 ; m <final>` with modifiers, else `SS3 <final>` in application mode or `CSI <final>`.
fn cursor_key(last: char, mods: KeyMods, application: bool) -> Vec<u8> {
    if mods.any() {
        format!("\x1b[1;{}{last}", mods.parameter()).into_bytes()
    } else if application {
        format!("\x1bO{last}").into_bytes()
    } else {
        format!("\x1b[{last}").into_bytes()
    }
}

/// `CSI n ~`, or `CSI n ; m ~` with modifiers.
fn tilde_key(number: u8, mods: KeyMods) -> Vec<u8> {
    if mods.any() { format!("\x1b[{number};{}~", mods.parameter()).into_bytes() } else { format!("\x1b[{number}~").into_bytes() }
}

fn function_key(number: u8, mods: KeyMods) -> Option<Vec<u8>> {
    Some(match number {
        1..=4 => {
            let last = (b'P' + number - 1) as char;
            if mods.any() { format!("\x1b[1;{}{last}", mods.parameter()).into_bytes() } else { format!("\x1bO{last}").into_bytes() }
        }
        5 => tilde_key(15, mods),
        6..=10 => tilde_key(number + 11, mods),
        11..=14 => tilde_key(number + 12, mods),
        15..=16 => tilde_key(number + 13, mods),
        17..=20 => tilde_key(number + 14, mods),
        _ => return None,
    })
}

/// The control character Ctrl makes of `ch`, as on a VT keyboard.
fn control(ch: char) -> Option<u8> {
    match ch {
        'a'..='z' => Some(ch as u8 - b'a' + 1),
        'A'..='Z' => Some(ch as u8 - b'A' + 1),
        '@' | ' ' | '2' => Some(0),
        '[' | '3' => Some(0x1b),
        '\\' | '4' => Some(0x1c),
        ']' | '5' => Some(0x1d),
        '^' | '6' => Some(0x1e),
        '_' | '7' | '/' | '-' => Some(0x1f),
        '?' | '8' => Some(0x7f),
        _ => None,
    }
}

/// The bytes for a key press given as a DOM `key` value, or `None` for keys that send nothing
/// (bare modifiers, media keys). `application_cursor` is DECCKM.
pub fn encode_key(key: &str, mods: KeyMods, application_cursor: bool) -> Option<Vec<u8>> {
    let escaped = |mut bytes: Vec<u8>| {
        if mods.alt {
            bytes.insert(0, 0x1b);
        }
        bytes
    };
    let mut chars = key.chars();
    if let (Some(ch), None) = (chars.next(), chars.next()) {
        // AltGr arrives as Ctrl+Alt with the composed character: that is text, not a chord.
        let alt_gr = mods.ctrl && mods.alt && !ch.is_ascii_alphabetic();
        if mods.ctrl && !alt_gr {
            return control(ch).map(|code| escaped(vec![code]));
        }
        let text = ch.to_string().into_bytes();
        return Some(if alt_gr { text } else { escaped(text) });
    }
    Some(match key {
        "Enter" => escaped(vec![b'\r']),
        "Backspace" => escaped(vec![if mods.ctrl { 0x08 } else { 0x7f }]),
        "Tab" if mods.shift => b"\x1b[Z".to_vec(),
        "Tab" => escaped(vec![b'\t']),
        "Escape" => escaped(vec![0x1b]),
        "ArrowUp" => cursor_key('A', mods, application_cursor),
        "ArrowDown" => cursor_key('B', mods, application_cursor),
        "ArrowRight" => cursor_key('C', mods, application_cursor),
        "ArrowLeft" => cursor_key('D', mods, application_cursor),
        "Home" => cursor_key('H', mods, application_cursor),
        "End" => cursor_key('F', mods, application_cursor),
        "Insert" => tilde_key(2, mods),
        "Delete" => tilde_key(3, mods),
        "PageUp" => tilde_key(5, mods),
        "PageDown" => tilde_key(6, mods),
        _ => return function_key(key.strip_prefix('F')?.parse().ok()?, mods),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: KeyMods = KeyMods { shift: false, alt: false, ctrl: false };
    const CTRL: KeyMods = KeyMods { shift: false, alt: false, ctrl: true };
    const ALT: KeyMods = KeyMods { shift: false, alt: true, ctrl: false };
    const SHIFT: KeyMods = KeyMods { shift: true, alt: false, ctrl: false };

    fn key(name: &str, mods: KeyMods) -> Option<String> {
        encode_key(name, mods, false).map(|bytes| String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn text_and_control_characters() {
        assert_eq!(key("a", NONE).as_deref(), Some("a"));
        assert_eq!(key("ç", NONE).as_deref(), Some("ç"));
        assert_eq!(key("c", CTRL).as_deref(), Some("\x03"));
        assert_eq!(key("C", KeyMods { shift: true, ..CTRL }).as_deref(), Some("\x03"));
        assert_eq!(key("[", CTRL).as_deref(), Some("\x1b"));
        assert_eq!(key(" ", CTRL).as_deref(), Some("\0"));
        assert_eq!(key("x", ALT).as_deref(), Some("\x1bx"));
        assert_eq!(key("1", CTRL), None);
    }

    #[test]
    fn alt_gr_composes_text_instead_of_a_chord() {
        let alt_gr = KeyMods { shift: false, alt: true, ctrl: true };
        assert_eq!(key("@", alt_gr).as_deref(), Some("@"));
        assert_eq!(key("€", alt_gr).as_deref(), Some("€"));
        assert_eq!(key("c", alt_gr).as_deref(), Some("\x1b\x03"));
    }

    #[test]
    fn editing_and_cursor_keys() {
        assert_eq!(key("Enter", NONE).as_deref(), Some("\r"));
        assert_eq!(key("Backspace", NONE).as_deref(), Some("\x7f"));
        assert_eq!(key("Backspace", CTRL).as_deref(), Some("\x08"));
        assert_eq!(key("Tab", SHIFT).as_deref(), Some("\x1b[Z"));
        assert_eq!(key("ArrowUp", NONE).as_deref(), Some("\x1b[A"));
        assert_eq!(encode_key("ArrowUp", NONE, true).unwrap(), b"\x1bOA");
        assert_eq!(key("ArrowLeft", CTRL).as_deref(), Some("\x1b[1;5D"));
        assert_eq!(key("Home", SHIFT).as_deref(), Some("\x1b[1;2H"));
        assert_eq!(key("Delete", NONE).as_deref(), Some("\x1b[3~"));
        assert_eq!(key("PageDown", ALT).as_deref(), Some("\x1b[6;3~"));
    }

    #[test]
    fn function_keys_and_keys_that_send_nothing() {
        assert_eq!(key("F1", NONE).as_deref(), Some("\x1bOP"));
        assert_eq!(key("F4", SHIFT).as_deref(), Some("\x1b[1;2S"));
        assert_eq!(key("F5", NONE).as_deref(), Some("\x1b[15~"));
        assert_eq!(key("F10", NONE).as_deref(), Some("\x1b[21~"));
        assert_eq!(key("F11", NONE).as_deref(), Some("\x1b[23~"));
        assert_eq!(key("F12", CTRL).as_deref(), Some("\x1b[24;5~"));
        assert_eq!(key("Shift", SHIFT), None);
        assert_eq!(key("Control", CTRL), None);
        assert_eq!(key("AudioVolumeUp", NONE), None);
    }
}
