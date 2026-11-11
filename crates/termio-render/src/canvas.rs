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
                        let a = coverage as u32;
                        let inverse = 255 - a;
                        pixel[0] = ((color.2 as u32 * a + pixel[0] as u32 * inverse + 127) / 255) as u8;
                        pixel[1] = ((color.1 as u32 * a + pixel[1] as u32 * inverse + 127) / 255) as u8;
                        pixel[2] = ((color.0 as u32 * a + pixel[2] as u32 * inverse + 127) / 255) as u8;
                    }
                }
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
        assert_eq!(&canvas.pixels()[..4], &[15, 10, 5, 255]);
    }
}
