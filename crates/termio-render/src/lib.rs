//! CPU terminal rasterizer and the presenters that hand its frames to a Tarve `<surface>`.

mod canvas;
// The COM interface in there keeps its Windows method names.
#[cfg(windows)]
#[allow(non_snake_case)]
mod dxgi;
mod frames;
mod presenter;
mod raster;

pub use canvas::{Canvas, Rect, Rgb};
pub use presenter::{PresentError, Presenter, SurfaceKind, open_presenter};
pub use raster::{FontMetrics, Fonts, Glyph, GlyphStyle};
