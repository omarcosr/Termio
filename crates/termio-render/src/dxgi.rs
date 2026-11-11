//! `ISwapChainPanelNative`: a composition swap chain this crate owns, shown under the Tarve UI.
//! Frames are uploaded from the CPU canvas and presented on the session's render thread; Tarve
//! draws no frame of its own for them.

use crate::canvas::{Canvas, Rect};
use crate::presenter::{PresentError, Presenter};
use std::ffi::c_void;
use windows::Win32::Foundation::{HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE, D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BOX, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION, D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext,
    ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_ALPHA_MODE_IGNORE, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_UNKNOWN, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory2, DXGI_CREATE_FACTORY_FLAGS, DXGI_PRESENT, DXGI_PRESENT_PARAMETERS, DXGI_SCALING_STRETCH, DXGI_SWAP_CHAIN_DESC1,
    DXGI_SWAP_CHAIN_FLAG, DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL, DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGIFactory2, IDXGISwapChain1,
};
use windows::core::{HRESULT, IUnknown, IUnknown_Vtbl, Interface, interface};

/// `windows.ui.xaml.media.dxinterop.h`'s panel interface, which Tarve's surface handle implements.
#[interface("F92F19D2-3ADE-45A6-A20C-F6F1EA90554B")]
unsafe trait ISwapChainPanelNative: IUnknown {
    fn SetSwapChain(&self, swap_chain: *mut c_void) -> HRESULT;
}

const BUFFERS: u32 = 2;

pub struct DxgiPresenter {
    panel: ISwapChainPanelNative,
    context: ID3D11DeviceContext,
    chain: IDXGISwapChain1,
    width: u32,
    height: u32,
    /// What the frame before this one changed: the back buffer is two presents old.
    previous: Option<Rect>,
    /// Presents left that must upload everything.
    full_frames: u32,
}

// SAFETY: the presenter is created on one thread and then used by the render thread alone; the
// D3D11 immediate context is never used by two threads at once, and the panel is free-threaded.
unsafe impl Send for DxgiPresenter {}

fn backend(context: &str, error: windows::core::Error) -> PresentError {
    PresentError::Backend(format!("{context}: {error}"))
}

fn create_device(driver: D3D_DRIVER_TYPE) -> windows::core::Result<(ID3D11Device, ID3D11DeviceContext)> {
    let mut device = None;
    let mut context = None;
    // SAFETY: both out pointers are valid for the call.
    unsafe {
        D3D11CreateDevice(
            None,
            driver,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )?;
    }
    Ok((device.expect("D3D11CreateDevice succeeded"), context.expect("D3D11CreateDevice succeeded")))
}

impl DxgiPresenter {
    pub fn new(handle: u64, width: u32, height: u32) -> Result<Self, PresentError> {
        if handle == 0 {
            return Err(PresentError::Backend("null swap chain panel".into()));
        }
        let raw = handle as usize as *mut c_void;
        // SAFETY: `handle` is the ISwapChainPanelNative* of a live surface's `ready` event; cloning adds a reference.
        let panel = unsafe { ISwapChainPanelNative::from_raw_borrowed(&raw) }
            .ok_or_else(|| PresentError::Backend("null swap chain panel".into()))?
            .clone();
        let (device, context) = create_device(D3D_DRIVER_TYPE_HARDWARE)
            .or_else(|_| create_device(D3D_DRIVER_TYPE_WARP))
            .map_err(|error| backend("D3D11CreateDevice", error))?;
        // SAFETY: plain factory creation.
        let factory: IDXGIFactory2 =
            unsafe { CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0)) }.map_err(|error| backend("CreateDXGIFactory2", error))?;
        let (width, height) = (width.max(1), height.max(1));
        let desc = DXGI_SWAP_CHAIN_DESC1 {
            Width: width,
            Height: height,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            BufferCount: BUFFERS,
            Scaling: DXGI_SCALING_STRETCH,
            SwapEffect: DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL,
            AlphaMode: DXGI_ALPHA_MODE_IGNORE,
            ..Default::default()
        };
        // SAFETY: the device and descriptor are valid.
        let chain = unsafe { factory.CreateSwapChainForComposition(&device, &desc, None) }
            .map_err(|error| backend("CreateSwapChainForComposition", error))?;
        // SAFETY: the panel is alive (we hold a reference) and the chain pointer is valid.
        unsafe { panel.SetSwapChain(chain.as_raw()) }.ok().map_err(|error| backend("SetSwapChain", error))?;
        Ok(Self { panel, context, chain, width, height, previous: None, full_frames: BUFFERS })
    }
}

impl Presenter for DxgiPresenter {
    fn resize(&mut self, width: u32, height: u32) -> Result<(), PresentError> {
        let (width, height) = (width.max(1), height.max(1));
        if (width, height) == (self.width, self.height) {
            return Ok(());
        }
        // SAFETY: no back buffer reference outlives `present`, so the buffers can be resized.
        unsafe { self.chain.ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, DXGI_SWAP_CHAIN_FLAG(0)) }
            .map_err(|error| backend("ResizeBuffers", error))?;
        self.width = width;
        self.height = height;
        self.previous = None;
        self.full_frames = BUFFERS;
        Ok(())
    }

    fn present(&mut self, canvas: &Canvas, dirty: Option<Rect>) -> Result<(), PresentError> {
        if canvas.width() != self.width || canvas.height() != self.height {
            self.resize(canvas.width(), canvas.height())?;
        }
        let bounds = canvas.bounds();
        let dirty = match dirty {
            Some(rect) if self.full_frames == 0 => Some(rect.intersect(bounds)),
            _ => None,
        };
        // The back buffer missed the previous frame's changes as well as this one's.
        let upload = match (dirty, self.previous) {
            (Some(now), Some(before)) => now.union(before),
            _ => bounds,
        };
        if upload.is_empty() {
            return Ok(());
        }
        // SAFETY: buffer 0 is the back buffer of a flip-model chain.
        let target: ID3D11Texture2D = unsafe { self.chain.GetBuffer(0) }.map_err(|error| backend("GetBuffer", error))?;
        let region = D3D11_BOX {
            left: upload.x as u32,
            top: upload.y as u32,
            front: 0,
            right: (upload.x + upload.w) as u32,
            bottom: (upload.y + upload.h) as u32,
            back: 1,
        };
        let stride = canvas.width() as usize * 4;
        let offset = upload.y as usize * stride + upload.x as usize * 4;
        // SAFETY: `region` lies inside the canvas, so every row read starts inside `pixels` and spans
        // `upload.w` pixels at a pitch of one canvas row.
        unsafe {
            self.context.UpdateSubresource(&target, 0, Some(&region), canvas.pixels()[offset..].as_ptr().cast(), stride as u32, 0);
        }
        drop(target);
        let result = match dirty {
            Some(rect) if !rect.is_empty() => {
                let mut rects = [RECT { left: rect.x, top: rect.y, right: rect.x + rect.w, bottom: rect.y + rect.h }];
                let parameters = DXGI_PRESENT_PARAMETERS { DirtyRectsCount: 1, pDirtyRects: rects.as_mut_ptr(), ..Default::default() };
                // SAFETY: `parameters` points at `rects`, which outlives the call.
                unsafe { self.chain.Present1(1, DXGI_PRESENT(0), &parameters) }
            }
            // SAFETY: a plain present of the whole buffer.
            _ => unsafe { self.chain.Present(1, DXGI_PRESENT(0)) },
        };
        result.ok().map_err(|error| backend("Present", error))?;
        self.previous = dirty;
        self.full_frames = self.full_frames.saturating_sub(1);
        Ok(())
    }
}

impl Drop for DxgiPresenter {
    fn drop(&mut self) {
        // SAFETY: the panel ignores calls once its element is gone.
        let _ = unsafe { self.panel.SetSwapChain(std::ptr::null_mut()) };
    }
}
