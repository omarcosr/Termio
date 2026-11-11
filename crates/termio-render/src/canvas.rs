/// An opaque sRGB colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rgb(pub u8, pub u8, pub u8);

/// A pixel rectangle; empty when either side is not positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    pub fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }

    pub fn union(self, other: Rect) -> Rect {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = (self.x + self.w).max(other.x + other.w);
        let bottom = (self.y + self.h).max(other.y + other.h);
        Rect::new(x, y, right - x, bottom - y)
    }

    pub fn intersect(self, other: Rect) -> Rect {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = (self.x + self.w).min(other.x + other.w);
        let bottom = (self.y + self.h).min(other.y + other.h);
        Rect::new(x, y, (right - x).max(0), (bottom - y).max(0))
    }
}

/// The frame a session paints into: BGRA, packed rows, always opaque.
pub struct Canvas {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

/// sRGB byte → linear light in 12 bits, and linear light (12 bits) → sRGB byte.
fn gamma_tables() -> &'static ([u16; 256], [u8; 4096]) {
    static TABLES: std::sync::OnceLock<([u16; 256], [u8; 4096])> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut to_linear = [0u16; 256];
        for (value, slot) in to_linear.iter_mut().enumerate() {
            let s = value as f32 / 255.0;
            let l = if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) };
            *slot = (l * 65535.0).round() as u16;
        }
        let mut to_srgb = [0u8; 4096];
        for (value, slot) in to_srgb.iter_mut().enumerate() {
            let l = value as f32 / 4095.0;
            let s = if l <= 0.003_130_8 { l * 12.92 } else { 1.055 * l.powf(1.0 / 2.4) - 0.055 };
            *slot = (s * 255.0).round() as u8;
        }
        (to_linear, to_srgb)
    })
}

impl Canvas {
    pub fn new(width: u32, height: u32) -> Self {
        let mut canvas = Self { width: 0, height: 0, pixels: Vec::new() };
        canvas.resize(width, height);
        canvas
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width as i32, self.height as i32)
    }

    /// Changes the size; the content is undefined until repainted.
    pub fn resize(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        self.pixels.clear();
        self.pixels.resize(width as usize * height as usize * 4, 255);
    }

    pub fn fill_rect(&mut self, rect: Rect, color: Rgb) {
        let rect = rect.intersect(self.bounds());
        if rect.is_empty() {
            return;
        }
        let stride = self.width as usize * 4;
        let bgra = [color.2, color.1, color.0, 255];
        for y in rect.y..rect.y + rect.h {
            let start = y as usize * stride + rect.x as usize * 4;
            for pixel in self.pixels[start..start + rect.w as usize * 4].as_chunks_mut::<4>().0 {
                *pixel = bgra;
            }
        }
    }

    /// Blends an 8-bit coverage mask in `color`; `glyph` is the box the mask covers.
    /// Blends an 8-bit coverage mask of `color` into the canvas, clipped to `clip`.
    pub fn draw_mask(&mut self, glyph: Rect, mask: &[u8], color: Rgb, clip: Rect) {
        let area = glyph.intersect(clip).intersect(self.bounds());
        if area.is_empty() || mask.len() < glyph.w as usize * glyph.h as usize {
            return;
        }
        let stride = self.width as usize * 4;
        for py in area.y..area.y + area.h {
            let source = (py - glyph.y) as usize * glyph.w as usize + (area.x - glyph.x) as usize;
            let target = py as usize * stride + area.x as usize * 4;
            let row = &mut self.pixels[target..target + area.w as usize * 4];
            for (pixel, &coverage) in row.as_chunks_mut::<4>().0.iter_mut().zip(&mask[source..source + area.w as usize]) {
                match coverage {
                    0 => {}
                    255 => pixel[..3].copy_from_slice(&[color.2, color.1, color.0]),
                    _ => {
                        // Blend in linear light. Mixing sRGB values directly makes antialiased
                        // edges too dark for light text on a dark background: strokes look thin
                        // and soft, which read as blurry letters.
                        let (to_linear, to_srgb) = gamma_tables();
                        let a = coverage as u32;
                        let inverse = 255 - a;
                        let mix = |ink: u8, under: u8| {
                            let value = (to_linear[ink as usize] as u32 * a + to_linear[under as usize] as u32 * inverse) / 255;
                            to_srgb[(value >> 4) as usize]
                        };
                        pixel[0] = mix(color.2, pixel[0]);
                        pixel[1] = mix(color.1, pixel[1]);
                        pixel[2] = mix(color.0, pixel[2]);
                    }
                }
            }
        }
    }

    /// Blends RGBA subpixel coverage of `color`: each channel by its own sample, in linear light.
    pub fn draw_subpixel(&mut self, glyph: Rect, mask: &[u8], color: Rgb, clip: Rect) {
        let area = glyph.intersect(clip).intersect(self.bounds());
        if area.is_empty() || mask.len() < glyph.w as usize * glyph.h as usize * 4 {
            return;
        }
        let mix = |ink: u8, under: u8, a: u8| -> u8 {
            match a {
                0 => under,
                255 => ink,
                _ => {
                    // Straight sRGB mixing, as GDI and DirectWrite's own blending of light text
                    // on dark backgrounds effectively do: linear-light mixing makes light strokes
                    // swell and looked bold and smeared.
                    let a = a as u32;
                    ((ink as u32 * a + under as u32 * (255 - a) + 127) / 255) as u8
                }
            }
        };
        let stride = self.width as usize * 4;
        for py in area.y..area.y + area.h {
            let source = ((py - glyph.y) as usize * glyph.w as usize + (area.x - glyph.x) as usize) * 4;
            let target = py as usize * stride + area.x as usize * 4;
            let row = &mut self.pixels[target..target + area.w as usize * 4];
            for (pixel, sample) in row.as_chunks_mut::<4>().0.iter_mut().zip(mask[source..source + area.w as usize * 4].as_chunks::<4>().0) {
                // Canvas pixels are BGRA; samples are R, G, B.
                pixel[2] = mix(color.0, pixel[2], sample[0]);
                pixel[1] = mix(color.1, pixel[1], sample[1]);
                pixel[0] = mix(color.2, pixel[0], sample[2]);
            }
        }
    }

    /// Blends straight-alpha RGBA pixels (colour glyphs); `glyph` is the box the pixels cover.
    pub fn draw_rgba(&mut self, glyph: Rect, data: &[u8], clip: Rect) {
        let area = glyph.intersect(clip).intersect(self.bounds());
        if area.is_empty() || data.len() < glyph.w as usize * glyph.h as usize * 4 {
            return;
        }
        let stride = self.width as usize * 4;
        for py in area.y..area.y + area.h {
            let source = ((py - glyph.y) as usize * glyph.w as usize + (area.x - glyph.x) as usize) * 4;
            let target = py as usize * stride + area.x as usize * 4;
            let row = &mut self.pixels[target..target + area.w as usize * 4];
            let pixels = data[source..source + area.w as usize * 4].as_chunks::<4>().0;
            for (pixel, rgba) in row.as_chunks_mut::<4>().0.iter_mut().zip(pixels) {
                let a = rgba[3] as u32;
                if a == 0 {
                    continue;
                }
                let inverse = 255 - a;
                pixel[0] = ((rgba[2] as u32 * a + pixel[0] as u32 * inverse + 127) / 255) as u8;
                pixel[1] = ((rgba[1] as u32 * a + pixel[1] as u32 * inverse + 127) / 255) as u8;
                pixel[2] = ((rgba[0] as u32 * a + pixel[2] as u32 * inverse + 127) / 255) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_union_and_intersection() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        assert_eq!(a.union(b), Rect::new(0, 0, 15, 15));
        assert_eq!(a.intersect(b), Rect::new(5, 5, 5, 5));
        assert!(a.intersect(Rect::new(20, 20, 5, 5)).is_empty());
        assert_eq!(Rect::default().union(b), b);
    }

    #[test]
    fn fill_and_mask_clip_to_the_canvas() {
        let mut canvas = Canvas::new(4, 2);
        canvas.fill_rect(Rect::new(-2, -2, 4, 3), Rgb(10, 20, 30));
        assert_eq!(&canvas.pixels()[..4], &[30, 20, 10, 255]);
        assert_eq!(&canvas.pixels()[8..12], &[255, 255, 255, 255]);
        canvas.draw_mask(Rect::new(3, 1, 4, 4), &[255; 16], Rgb(1, 2, 3), canvas.bounds());
        assert_eq!(&canvas.pixels()[28..32], &[3, 2, 1, 255]);
        canvas.draw_mask(Rect::new(0, 0, 1, 1), &[128], Rgb(0, 0, 0), canvas.bounds());
        // Half coverage blends in linear light: half of (30, 20, 10) is brighter than 15, 10, 5.
        assert_eq!(&canvas.pixels()[..4], &[19, 11, 5, 255]);
    }
}
