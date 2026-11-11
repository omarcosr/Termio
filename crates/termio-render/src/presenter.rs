use crate::canvas::{Canvas, Rect};
use std::fmt;

#[derive(Debug)]
pub enum PresentError {
    /// The `<surface>` no longer exists.
    Gone,
    Unsupported(String),
    Backend(String),
}

impl fmt::Display for PresentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresentError::Gone => f.write_str("the surface is gone"),
            PresentError::Unsupported(message) | PresentError::Backend(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PresentError {}

/// Shows a session's frames in one Tarve `<surface>`. Used from the session's render thread only.
pub trait Presenter: Send {
    fn resize(&mut self, width: u32, height: u32) -> Result<(), PresentError>;
    /// `dirty` is what changed since the last present; `None` is the whole frame.
    fn present(&mut self, canvas: &Canvas, dirty: Option<Rect>) -> Result<(), PresentError>;
}

/// The `handleType` of a surface's `ready` event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceKind {
    /// `TarveFrames`: pictures composed by the UI.
    Frames,
    /// `ISwapChainPanelNative`: a composition swap chain under the UI (Windows, D3D11).
    SwapChainPanel,
}

impl SurfaceKind {
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(SurfaceKind::Frames),
            1 => Some(SurfaceKind::SwapChainPanel),
            _ => None,
        }
    }
}

pub fn open_presenter(kind: SurfaceKind, handle: u64, width: u32, height: u32) -> Result<Box<dyn Presenter>, PresentError> {
    match kind {
        SurfaceKind::Frames => Ok(Box::new(crate::frames::FramesPresenter::new(handle)?)),
        #[cfg(windows)]
        SurfaceKind::SwapChainPanel => Ok(Box::new(crate::dxgi::DxgiPresenter::new(handle, width, height)?)),
        #[cfg(not(windows))]
        SurfaceKind::SwapChainPanel => {
            let _ = (width, height);
            Err(PresentError::Unsupported("swap chain panels exist on Windows only".into()))
        }
    }
}
