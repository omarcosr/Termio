//! Fonts and the glyph cache: system monospace faces found with fontdb, rasterized by swash.

use crate::canvas::{Canvas, Rect, Rgb};
use std::collections::HashMap;
use std::sync::Arc;
use swash::scale::image::Content;
use swash::scale::{Render, ScaleContext, Source, StrikeWith};
use swash::zeno::{Angle, Format, Transform};
use swash::{CacheKey, FontRef};

/// Families tried in order when the user picked none (or theirs is missing).
const MONOSPACE: &[&str] = &["Cascadia Mono", "Cascadia Code", "JetBrains Mono", "Consolas", "DejaVu Sans Mono", "Liberation Mono", "Noto Sans Mono", "Droid Sans Mono"];
/// Faces tried first for characters the terminal font lacks, before scanning every font.
const FALLBACK: &[&str] = &[
    "Segoe UI Symbol",
    "Segoe UI Emoji",
    "Noto Color Emoji",
    "Microsoft YaHei",
    "MS Gothic",
    "Malgun Gothic",
    "Noto Sans CJK SC",
    "Noto Sans Symbols2",
    "DejaVu Sans",
    "Segoe UI",
];

const SYNTHETIC_BOLD: u8 = 1;
const SYNTHETIC_ITALIC: u8 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GlyphStyle {
    pub bold: bool,
    pub italic: bool,
}

impl GlyphStyle {
    fn index(self) -> usize {
        self.bold as usize | (self.italic as usize) << 1
    }
}

/// Cell geometry of the terminal font at one pixel size.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FontMetrics {
    pub size: f32,
    pub cell_w: u32,
    pub cell_h: u32,
    /// Baseline, in pixels below the top of the cell.
    pub baseline: i32,
    pub underline_y: i32,
    pub strikeout_y: i32,
    pub stroke: i32,
}

pub struct Glyph {
    /// `data` holds RGBA subpixel coverage (alpha unused) instead of one byte per pixel.
    pub subpixel: bool,
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
    /// `data` is straight-alpha RGBA instead of a coverage mask.
    pub color: bool,
    pub data: Vec<u8>,
}

struct Face {
    /// The font file and face index, for rasterizers that open files themselves (DirectWrite).
    #[cfg_attr(not(windows), allow(dead_code))]
    file: Option<(std::path::PathBuf, u32)>,
    #[cfg_attr(not(windows), allow(dead_code))]
    emoji: bool,
    data: Arc<dyn AsRef<[u8]> + Send + Sync>,
    offset: u32,
    key: CacheKey,
}

impl Face {
    fn font(&self) -> FontRef<'_> {
        FontRef { data: (*self.data).as_ref(), offset: self.offset, key: self.key }
    }
}

#[derive(Clone, Copy)]
struct Resolved {
    face: usize,
    glyph: u16,
    synthetic: u8,
}

pub struct Fonts {
    db: fontdb::Database,
    family: Option<String>,
    faces: Vec<Face>,
    loaded: HashMap<fontdb::ID, usize>,
    /// The terminal face per style and what it has to fake.
    primary: [Option<(usize, u8)>; 4],
    fallback: HashMap<char, Option<usize>>,
    resolved: HashMap<(char, GlyphStyle), Option<Resolved>>,
    glyphs: HashMap<(usize, u16, u32, u8), Option<Glyph>>,
    scale: ScaleContext,
    #[cfg(windows)]
    dwrite: Option<crate::dwrite::DirectWrite>,
}

impl Fonts {
    /// Loads the system fonts; `family` is preferred over the built-in monospace list.
    pub fn new(family: Option<&str>) -> Self {
        let mut db = fontdb::Database::new();
        db.load_system_fonts();
        // fontdb knows no Android font directories: without these the terminal had no font at
        // all and drew only the cursor. Droid Sans Mono is the monospace face every Android ships.
        #[cfg(target_os = "android")]
        {
            for dir in ["/system/fonts", "/product/fonts"] {
                db.load_fonts_dir(dir);
            }
            db.set_monospace_family("Droid Sans Mono");
            db.set_sans_serif_family("Roboto");
        }
        Self::with_database(db, family)
    }

    pub fn with_database(db: fontdb::Database, family: Option<&str>) -> Self {
        Self {
            db,
            family: family.map(str::to_owned),
            faces: Vec::new(),
            loaded: HashMap::new(),
            primary: [None; 4],
            fallback: HashMap::new(),
            resolved: HashMap::new(),
            glyphs: HashMap::new(),
            scale: ScaleContext::new(),
            #[cfg(windows)]
            dwrite: crate::dwrite::DirectWrite::new(),
        }
    }

    /// Switches the terminal family; cached glyphs of the old one are dropped.
    pub fn set_family(&mut self, family: Option<&str>) {
        self.family = family.map(str::to_owned);
        self.primary = [None; 4];
        self.resolved.clear();
        self.glyphs.clear();
    }

    fn load(&mut self, id: fontdb::ID) -> Option<usize> {
        if let Some(&index) = self.loaded.get(&id) {
            return Some(index);
        }
        // SAFETY: font files are mapped read-only; fontdb's contract is that they are not
        // modified while mapped, which holds for installed system fonts.
        let (data, face_index) = unsafe { self.db.make_shared_face_data(id) }?;
        let font = FontRef::from_index((*data).as_ref(), face_index as usize)?;
        let (offset, key) = (font.offset, font.key);
        let info = self.db.face(id);
        let file = info.and_then(|info| match &info.source {
            fontdb::Source::File(path) | fontdb::Source::SharedFile(path, _) => Some((path.clone(), info.index)),
            fontdb::Source::Binary(_) => None,
        });
        let emoji = info.is_some_and(|info| info.families.iter().any(|(name, _)| name.contains("Emoji")));
        self.faces.push(Face { file, emoji, data, offset, key });
        self.loaded.insert(id, self.faces.len() - 1);
        Some(self.faces.len() - 1)
    }

    fn primary(&mut self, style: GlyphStyle) -> Option<(usize, u8)> {
        if let Some(found) = self.primary[style.index()] {
            return Some(found);
        }
        let mut families: Vec<fontdb::Family<'_>> = Vec::new();
        if let Some(family) = &self.family {
            families.push(fontdb::Family::Name(family));
        }
        families.extend(MONOSPACE.iter().map(|name| fontdb::Family::Name(name)));
        families.push(fontdb::Family::Monospace);
        let query = fontdb::Query {
            families: &families,
            weight: if style.bold { fontdb::Weight::BOLD } else { fontdb::Weight::NORMAL },
            stretch: fontdb::Stretch::Normal,
            style: if style.italic { fontdb::Style::Italic } else { fontdb::Style::Normal },
        };
        let id = self.db.query(&query)?;
        let info = self.db.face(id)?;
        let mut synthetic = 0;
        // A font without a bold face keeps its regular weight: faked bold smears the stems of
        // a hinted terminal font into blobs (`ls` colours are bold), and colour already marks it.
        if style.bold && info.weight.0 < 600 {
            synthetic |= SYNTHETIC_BOLD;
        }
        if style.italic && info.style == fontdb::Style::Normal {
            synthetic |= SYNTHETIC_ITALIC;
        }
        let face = self.load(id)?;
        self.primary[style.index()] = Some((face, synthetic));
        Some((face, synthetic))
    }

    fn covers(&self, id: fontdb::ID, ch: char) -> bool {
        self.db
            .with_face_data(id, |data, index| FontRef::from_index(data, index as usize).is_some_and(|font| font.charmap().map(ch) != 0))
            .unwrap_or(false)
    }

    fn fallback(&mut self, ch: char) -> Option<usize> {
        if let Some(&cached) = self.fallback.get(&ch) {
            return cached;
        }
        let named = FALLBACK.iter().filter_map(|name| {
            self.db.query(&fontdb::Query { families: &[fontdb::Family::Name(name)], ..fontdb::Query::default() })
        });
        let id = named
            .chain(self.db.faces().map(|face| face.id))
            .collect::<Vec<_>>()
            .into_iter()
            .find(|&id| self.covers(id, ch));
        let face = id.and_then(|id| self.load(id));
        self.fallback.insert(ch, face);
        face
    }

    fn resolve(&mut self, ch: char, style: GlyphStyle) -> Option<Resolved> {
        if let Some(&cached) = self.resolved.get(&(ch, style)) {
            return cached;
        }
        let mut found = None;
        if let Some((face, synthetic)) = self.primary(style) {
            let glyph = self.faces[face].font().charmap().map(ch);
            if glyph != 0 {
                found = Some(Resolved { face, glyph, synthetic });
            }
        }
        if found.is_none()
            && let Some(face) = self.fallback(ch)
        {
            let glyph = self.faces[face].font().charmap().map(ch);
            if glyph != 0 {
                found = Some(Resolved { face, glyph, synthetic: 0 });
            }
        }
        self.resolved.insert((ch, style), found);
        found
    }

    /// Cell geometry at `size` pixels per em. Falls back to a plausible grid when no font loads.
    pub fn metrics(&mut self, size: f32) -> FontMetrics {
        let Some((face, _)) = self.primary(GlyphStyle::default()) else {
            let cell_h = (size * 1.3).ceil().max(1.0) as u32;
            return FontMetrics {
                size,
                cell_w: (size * 0.6).ceil().max(1.0) as u32,
                cell_h,
                baseline: (size).ceil() as i32,
                underline_y: cell_h as i32 - 2,
                strikeout_y: cell_h as i32 / 2,
                stroke: 1,
            };
        };
        let font = self.faces[face].font();
        let metrics = font.metrics(&[]).scale(size);
        let advance = font.glyph_metrics(&[]).scale(size).advance_width(font.charmap().map('M'));
        let cell_h = (metrics.ascent + metrics.descent + metrics.leading).ceil().max(1.0) as u32;
        let baseline = (metrics.ascent + metrics.leading / 2.0).round() as i32;
        let stroke = metrics.stroke_size.round().max(1.0) as i32;
        FontMetrics {
            size,
            cell_w: advance.round().max(1.0) as u32,
            cell_h,
            baseline,
            underline_y: ((baseline as f32 - metrics.underline_offset).round() as i32).clamp(baseline + 1, cell_h as i32 - stroke),
            strikeout_y: ((baseline as f32 - metrics.strikeout_offset).round() as i32).clamp(0, cell_h as i32 - stroke),
            stroke,
        }
    }

    /// The rasterized glyph of `ch`, from the terminal font or the first font that has it.
    pub fn glyph(&mut self, ch: char, style: GlyphStyle, size: f32) -> Option<&Glyph> {
        let resolved = self.resolve(ch, style)?;
        let key = (resolved.face, resolved.glyph, (size * 64.0) as u32, resolved.synthetic);
        #[cfg(windows)]
        if !self.glyphs.contains_key(&key) && !self.faces[resolved.face].emoji
            && let (Some(dwrite), Some((path, index))) = (self.dwrite.as_mut(), self.faces[resolved.face].file.as_ref())
            && let Some(glyph) = dwrite.glyph(resolved.face, path, *index, resolved.glyph, size, false, resolved.synthetic & SYNTHETIC_ITALIC != 0)
        {
            self.glyphs.insert(key, Some(glyph));
        }
        if !self.glyphs.contains_key(&key) {
            let font = self.faces[resolved.face].font();
            let mut scaler = self.scale.builder(font).size(size).hint(true).build();
            let mut render = Render::new(&[Source::ColorOutline(0), Source::ColorBitmap(StrikeWith::BestFit), Source::Outline]);
            // Subpixel (ClearType-like) coverage: three samples per pixel, one for each of the
            // RGB stripes of an LCD, triple the horizontal resolution of a grey mask.
            render.format(Format::Subpixel);
            if resolved.synthetic & SYNTHETIC_ITALIC != 0 {
                render.transform(Some(Transform::skew(Angle::from_degrees(12.0), Angle::from_degrees(0.0))));
            }
            let glyph = render.render(&mut scaler, resolved.glyph).map(|image| Glyph {
                left: image.placement.left,
                top: image.placement.top,
                width: image.placement.width,
                height: image.placement.height,
                color: image.content == Content::Color,
                subpixel: image.content == Content::SubpixelMask,
                data: image.data,
            });
            self.glyphs.insert(key, glyph);
        }
        self.glyphs.get(&key)?.as_ref()
    }

    /// Draws `ch` with its origin at the left of the cell whose top-left corner is (`x`, `y`).
    #[allow(clippy::too_many_arguments)]
    pub fn draw(&mut self, canvas: &mut Canvas, ch: char, style: GlyphStyle, metrics: &FontMetrics, x: i32, y: i32, color: Rgb, clip: Rect) {
        let Some(glyph) = self.glyph(ch, style, metrics.size) else {
            return;
        };
        let area = Rect::new(x + glyph.left, y + metrics.baseline - glyph.top, glyph.width as i32, glyph.height as i32);
        if glyph.color {
            canvas.draw_rgba(area, &glyph.data, clip);
        } else if glyph.subpixel {
            canvas.draw_subpixel(area, &glyph.data, color, clip);
        } else {
            canvas.draw_mask(area, &glyph.data, color, clip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_monospace_font_gives_a_grid_and_glyphs() {
        let mut fonts = Fonts::new(None);
        let metrics = fonts.metrics(16.0);
        assert!(metrics.cell_w >= 6 && metrics.cell_w <= 16, "{metrics:?}");
        assert!(metrics.cell_h >= 14 && metrics.cell_h <= 32, "{metrics:?}");
        assert!(metrics.baseline > 0 && metrics.baseline < metrics.cell_h as i32);
        let glyph = fonts.glyph('A', GlyphStyle::default(), 16.0).expect("the terminal font has an A");
        assert!(glyph.width > 0 && glyph.height > 0 && !glyph.color);
        assert!(glyph.data.iter().any(|&coverage| coverage > 0));
        assert!(!glyph.subpixel || glyph.data.len() == glyph.width as usize * glyph.height as usize * 4);
        assert!(fonts.glyph(' ', GlyphStyle::default(), 16.0).is_none_or(|space| space.data.iter().all(|&c| c == 0)));
        assert!(fonts.glyph('A', GlyphStyle { bold: true, italic: true }, 16.0).is_some());
    }

    #[test]
    fn drawing_a_glyph_changes_pixels_inside_the_clip_only() {
        let mut fonts = Fonts::new(None);
        let metrics = fonts.metrics(16.0);
        let mut canvas = Canvas::new(metrics.cell_w * 2, metrics.cell_h);
        canvas.fill_rect(canvas.bounds(), Rgb(0, 0, 0));
        let cell = Rect::new(0, 0, metrics.cell_w as i32, metrics.cell_h as i32);
        fonts.draw(&mut canvas, 'W', GlyphStyle::default(), &metrics, 0, 0, Rgb(255, 255, 255), cell);
        let lit = |x0: u32, x1: u32| {
            (0..metrics.cell_h).any(|y| (x0..x1).any(|x| canvas.pixels()[((y * canvas.width() + x) * 4) as usize] > 0))
        };
        assert!(lit(0, metrics.cell_w));
        assert!(!lit(metrics.cell_w, metrics.cell_w * 2));
    }
}
