//! Glyphs rasterized by DirectWrite, the engine behind Windows Terminal and the rest of the
//! system: its hinting and ClearType filtering are what Windows text looks like, which a
//! portable rasterizer does not match at terminal sizes.

use crate::raster::Glyph;
use std::collections::HashMap;
use std::path::Path;
use windows::Win32::Graphics::DirectWrite::*;
use windows::core::{HSTRING, PCWSTR};

pub struct DirectWrite {
    factory: IDWriteFactory,
    faces: HashMap<(usize, bool, bool), Option<IDWriteFontFace>>,
}

// SAFETY: the factory is created shared (free-threaded) and the faces are only used behind the
// `Fonts` mutex, one thread at a time.
unsafe impl Send for DirectWrite {}

impl DirectWrite {
    pub fn new() -> Option<Self> {
        // SAFETY: plain factory creation.
        let factory: IDWriteFactory = unsafe { DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED) }.ok()?;
        Some(Self { factory, faces: HashMap::new() })
    }

    fn face(&mut self, slot: usize, path: &Path, index: u32, bold: bool, italic: bool) -> Option<IDWriteFontFace> {
        self.faces
            .entry((slot, bold, italic))
            .or_insert_with(|| {
                let wide = HSTRING::from(path.as_os_str());
                // SAFETY: the path outlives the calls; out-parameters are locals.
                unsafe {
                    let file = self.factory.CreateFontFileReference(PCWSTR(wide.as_ptr()), None).ok()?;
                    let (mut supported, mut file_type, mut face_type, mut count) = (Default::default(), DWRITE_FONT_FILE_TYPE_UNKNOWN, DWRITE_FONT_FACE_TYPE_UNKNOWN, 0u32);
                    file.Analyze(&mut supported, &mut file_type, Some(&mut face_type), &mut count).ok()?;
                    if !supported.as_bool() {
                        return None;
                    }
                    let mut simulations = DWRITE_FONT_SIMULATIONS_NONE;
                    if bold {
                        simulations |= DWRITE_FONT_SIMULATIONS_BOLD;
                    }
                    if italic {
                        simulations |= DWRITE_FONT_SIMULATIONS_OBLIQUE;
                    }
                    self.factory.CreateFontFace(face_type, &[Some(file)], index, simulations).ok()
                }
            })
            .clone()
    }

    /// ClearType coverage of one glyph at `size` pixels per em, as RGBA subpixel samples.
    #[allow(clippy::too_many_arguments)]
    pub fn glyph(&mut self, slot: usize, path: &Path, index: u32, glyph: u16, size: f32, bold: bool, italic: bool) -> Option<Glyph> {
        let face = self.face(slot, path, index, bold, italic)?;
        let indices = [glyph];
        let advances = [0f32];
        let offsets = [DWRITE_GLYPH_OFFSET::default()];
        let run = DWRITE_GLYPH_RUN {
            fontFace: std::mem::ManuallyDrop::new(Some(face)),
            fontEmSize: size,
            glyphCount: 1,
            glyphIndices: indices.as_ptr(),
            glyphAdvances: advances.as_ptr(),
            glyphOffsets: offsets.as_ptr(),
            isSideways: false.into(),
            bidiLevel: 0,
        };
        // SAFETY: the run's arrays outlive the analysis; the face reference is released below.
        let result = unsafe {
            (|| {
                let analysis = self
                    .factory
                    .CreateGlyphRunAnalysis(&run, 1.0, None, DWRITE_RENDERING_MODE_NATURAL_SYMMETRIC, DWRITE_MEASURING_MODE_NATURAL, 0.0, 0.0)
                    .ok()?;
                let bounds = analysis.GetAlphaTextureBounds(DWRITE_TEXTURE_CLEARTYPE_3x1).ok()?;
                let (width, height) = ((bounds.right - bounds.left).max(0) as u32, (bounds.bottom - bounds.top).max(0) as u32);
                if width == 0 || height == 0 {
                    return Some(Glyph { subpixel: true, left: 0, top: 0, width: 0, height: 0, color: false, data: Vec::new() });
                }
                let mut rgb = vec![0u8; width as usize * height as usize * 3];
                analysis.CreateAlphaTexture(DWRITE_TEXTURE_CLEARTYPE_3x1, &bounds, &mut rgb).ok()?;
                let data = rgb.as_chunks::<3>().0.iter().flat_map(|&[r, g, b]| [r, g, b, 0]).collect();
                Some(Glyph { subpixel: true, left: bounds.left, top: -bounds.top, width, height, color: false, data })
            })()
        };
        drop(std::mem::ManuallyDrop::into_inner(run.fontFace));
        result
    }
}
