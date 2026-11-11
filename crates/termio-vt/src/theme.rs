use alacritty_terminal::vte::ansi::NamedColor;

/// An opaque sRGB colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    pub const fn hex(value: u32) -> Self {
        Self::new((value >> 16) as u8, (value >> 8) as u8, value as u8)
    }

    /// Two thirds of the brightness: SGR 2 (faint).
    pub fn dim(self) -> Self {
        Self::new((self.r as u16 * 2 / 3) as u8, (self.g as u16 * 2 / 3) as u8, (self.b as u16 * 2 / 3) as u8)
    }
}

/// The colours a terminal starts with; programs may override palette entries at run time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Theme {
    pub foreground: Color,
    pub background: Color,
    pub cursor: Color,
    pub selection: Color,
    /// ANSI colours 0–15.
    pub ansi: [Color; 16],
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            foreground: Color::hex(0xd8dee9),
            background: Color::hex(0x101216),
            cursor: Color::hex(0xe5e9f0),
            selection: Color::hex(0x33415e),
            ansi: [
                Color::hex(0x1c1f26),
                Color::hex(0xe06c75),
                Color::hex(0x98c379),
                Color::hex(0xe5c07b),
                Color::hex(0x61afef),
                Color::hex(0xc678dd),
                Color::hex(0x56b6c2),
                Color::hex(0xabb2bf),
                Color::hex(0x5c6370),
                Color::hex(0xff7b86),
                Color::hex(0xb1e18b),
                Color::hex(0xf2d08a),
                Color::hex(0x7cc0ff),
                Color::hex(0xd99cf0),
                Color::hex(0x6fd3e0),
                Color::hex(0xffffff),
            ],
        }
    }
}

impl Theme {
    /// Palette entry `index` of the 256-colour table.
    pub fn indexed(&self, index: u8) -> Color {
        match index {
            0..=15 => self.ansi[index as usize],
            16..=231 => {
                let cube = index - 16;
                let level = |step: u8| if step == 0 { 0 } else { 55 + step * 40 };
                Color::new(level(cube / 36), level(cube / 6 % 6), level(cube % 6))
            }
            _ => {
                let grey = 8 + (index - 232) * 10;
                Color::new(grey, grey, grey)
            }
        }
    }

    pub(crate) fn named(&self, color: NamedColor) -> Color {
        match color as usize {
            index @ 0..=15 => self.ansi[index],
            256 => self.foreground,
            257 => self.background,
            258 => self.cursor,
            index @ 259..=266 => self.ansi[index - 259].dim(),
            267 => self.ansi[15],
            _ => self.foreground.dim(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_256_colour_table_follows_xterm() {
        let theme = Theme::default();
        assert_eq!(theme.indexed(16), Color::new(0, 0, 0));
        assert_eq!(theme.indexed(21), Color::new(0, 0, 255));
        assert_eq!(theme.indexed(196), Color::new(255, 0, 0));
        assert_eq!(theme.indexed(231), Color::new(255, 255, 255));
        assert_eq!(theme.indexed(232), Color::new(8, 8, 8));
        assert_eq!(theme.indexed(255), Color::new(238, 238, 238));
        assert_eq!(theme.indexed(1), theme.ansi[1]);
    }
}
