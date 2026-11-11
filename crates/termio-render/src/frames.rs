//! `TarveFrames`: frames go to `tarve_surface_present` of the Tarve runtime loaded in this process.

use crate::canvas::{Canvas, Rect};
use crate::presenter::{PresentError, Presenter};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type PresentFn = unsafe extern "C" fn(u64, *const u8, u32, u32, u32, u32) -> i32;

const FORMAT_BGRX: u32 = 3;
/// The UI composes each picture in a frame of its own, so more than this is wasted work.
const MIN_INTERVAL: Duration = Duration::from_millis(8);

fn host_present() -> Option<PresentFn> {
    static PRESENT: OnceLock<Option<PresentFn>> = OnceLock::new();
    *PRESENT.get_or_init(find_host_present)
}

#[cfg(windows)]
fn find_host_present() -> Option<PresentFn> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::GetProcAddress;
    use windows::Win32::System::ProcessStatus::EnumProcessModules;
    use windows::Win32::System::Threading::GetCurrentProcess;
    use windows::core::s;

    let mut modules = vec![HMODULE::default(); 2048];
    let mut needed = 0u32;
    let bytes = (modules.len() * size_of::<HMODULE>()) as u32;
    // SAFETY: the buffer holds `bytes` bytes and `needed` is a valid out pointer.
    unsafe { EnumProcessModules(GetCurrentProcess(), modules.as_mut_ptr(), bytes, &mut needed) }.ok()?;
    let count = (needed as usize / size_of::<HMODULE>()).min(modules.len());
    modules[..count].iter().find_map(|&module| {
        // SAFETY: `module` is a module of this process and the name is NUL-terminated.
        let symbol = unsafe { GetProcAddress(module, s!("tarve_surface_present")) }?;
        // SAFETY: the Tarve runtime exports this symbol with the `PresentFn` signature.
        Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, PresentFn>(symbol) })
    })
}

#[cfg(unix)]
fn find_host_present() -> Option<PresentFn> {
    use std::ffi::{c_int, c_void};

    unsafe extern "C" fn visit(info: *mut libc::dl_phdr_info, _size: usize, data: *mut c_void) -> c_int {
        // SAFETY: the loader passes a valid entry; an empty name is the main program.
        let name = unsafe { (*info).dlpi_name };
        let name = if name.is_null() || unsafe { *name } == 0 { std::ptr::null() } else { name };
        // SAFETY: RTLD_NOLOAD only returns objects that are already loaded.
        let object = unsafe { libc::dlopen(name, libc::RTLD_NOLOAD | libc::RTLD_LAZY) };
        if object.is_null() {
            return 0;
        }
        // SAFETY: `object` is a live handle and the name is NUL-terminated.
        let symbol = unsafe { libc::dlsym(object, c"tarve_surface_present".as_ptr()) };
        unsafe { libc::dlclose(object) };
        if symbol.is_null() {
            return 0;
        }
        // SAFETY: `data` is the out pointer `find_host_present` passed.
        unsafe { *(data as *mut *mut c_void) = symbol };
        1
    }

    let mut symbol: *mut c_void = std::ptr::null_mut();
    // SAFETY: `visit` only writes through the pointer to `symbol`, which outlives the call.
    unsafe { libc::dl_iterate_phdr(Some(visit), (&raw mut symbol).cast()) };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: the Tarve runtime exports this symbol with the `PresentFn` signature.
    Some(unsafe { std::mem::transmute::<*mut c_void, PresentFn>(symbol) })
}

pub struct FramesPresenter {
    handle: u64,
    present: PresentFn,
    last: Option<Instant>,
}

impl FramesPresenter {
    pub fn new(handle: u64) -> Result<Self, PresentError> {
        let present = host_present()
            .ok_or_else(|| PresentError::Unsupported("tarve_surface_present is not loaded in this process".into()))?;
        Ok(Self { handle, present, last: None })
    }
}

impl Presenter for FramesPresenter {
    fn resize(&mut self, _width: u32, _height: u32) -> Result<(), PresentError> {
        Ok(())
    }

    fn present(&mut self, canvas: &Canvas, _dirty: Option<Rect>) -> Result<(), PresentError> {
        if let Some(last) = self.last {
            let elapsed = last.elapsed();
            if elapsed < MIN_INTERVAL {
                std::thread::sleep(MIN_INTERVAL - elapsed);
            }
        }
        // SAFETY: the canvas holds width × height × 4 bytes, which the runtime copies before returning.
        let code = unsafe {
            (self.present)(self.handle, canvas.pixels().as_ptr(), canvas.width(), canvas.height(), canvas.width() * 4, FORMAT_BGRX)
        };
        self.last = Some(Instant::now());
        match code {
            0 => Ok(()),
            -1 => Err(PresentError::Gone),
            code => Err(PresentError::Backend(format!("tarve_surface_present returned {code}"))),
        }
    }
}
