//! The C ABI the UI loads (`app/core/plugin.ts` declares the same symbols). Every entry point
//! catches panics: unwinding into the JavaScript runtime is undefined behaviour.
//!
//! Return codes: 0 or a positive count on success; -1 unknown session; -2 invalid argument;
//! -3 the operation failed (details arrive as an event or in the response); -100 internal panic.

use crate::echo::EchoSession;
use crate::events;
use crate::session::{KeyEvent, PointerEvent, PointerPhase, registry};
use crate::surface::Message;
use crate::terminal::TerminalSession;
use serde_json::{Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use termio_render::{SurfaceKind, open_presenter};
use termio_transport::local::{LocalOptions, LocalPty};

pub const ABI_VERSION: u32 = 1;

const UNKNOWN_SESSION: i32 = -1;
const INVALID: i32 = -2;
const FAILED: i32 = -3;
const PANICKED: i32 = -100;

/// A response that did not fit the caller's buffer, kept for `termio_take_response`.
static OVERFLOW: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn guard(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(PANICKED)
}

/// # Safety
/// `pointer` is null or points to `length` readable bytes.
unsafe fn bytes<'a>(pointer: *const u8, length: u32) -> Option<&'a [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { std::slice::from_raw_parts(pointer, length as usize) })
}

/// # Safety
/// As [`bytes`].
unsafe fn text<'a>(pointer: *const u8, length: u32) -> Option<&'a str> {
    std::str::from_utf8(unsafe { bytes(pointer, length) }?).ok()
}

fn respond(response: &Value, out: *mut u8, capacity: u32) -> i32 {
    let body = response.to_string().into_bytes();
    if out.is_null() || body.len() > capacity as usize {
        let needed = body.len() as i32;
        *OVERFLOW.lock().unwrap_or_else(|p| p.into_inner()) = Some(body);
        return -needed;
    }
    // SAFETY: the caller gave `capacity` writable bytes and the body fits.
    unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), out, body.len()) };
    body.len() as i32
}

fn call(request: &Value) -> Result<Value, String> {
    let operation = request["op"].as_str().ok_or("missing op")?;
    match operation {
        "session.open" => {
            let kind = request["kind"].as_str().ok_or("missing kind")?;
            let id = match kind {
                "echo" => registry().open(|_, surface| Ok(EchoSession::new(surface.invalidator.clone())))?,
                "local" => {
                    let options = LocalOptions {
                        program: request["program"].as_str().map(str::to_owned),
                        args: request["args"].as_array().map(|args| args.iter().filter_map(|arg| arg.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
                        cwd: request["cwd"].as_str().map(str::to_owned),
                    };
                    registry().open(|id, surface| {
                        let session = TerminalSession::new(id, surface.invalidator.clone());
                        let pty = LocalPty::spawn(&options, 80, 24, session.clone()).map_err(|error| format!("could not start the shell: {error}"))?;
                        session.attach(Box::new(pty));
                        Ok(session)
                    })?
                }
                other => return Err(format!("unknown session kind '{other}'")),
            };
            Ok(json!({ "id": id }))
        }
        "session.close" => {
            let id = request["id"].as_u64().ok_or("missing id")? as u32;
            Ok(json!({ "closed": registry().close(id) }))
        }
        "session.stats" => {
            let id = request["id"].as_u64().ok_or("missing id")? as u32;
            let frames = registry().with(id, |entry| entry.surface.frames.load(Ordering::Relaxed)).ok_or("unknown session")?;
            Ok(json!({ "frames": frames }))
        }
        "session.text" => {
            let id = request["id"].as_u64().ok_or("missing id")? as u32;
            let lines = registry().with(id, |entry| entry.session.screen()).ok_or("unknown session")?;
            Ok(json!({ "lines": lines }))
        }
        other => crate::app::call(other, request).unwrap_or_else(|| Err(format!("unknown op '{other}'"))),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn termio_abi_version() -> u32 {
    ABI_VERSION
}

/// Starts the core. `wake` is called from a core thread whenever events are waiting; the UI
/// then calls [`termio_drain_events`] on its own thread.
#[unsafe(no_mangle)]
pub extern "C" fn termio_init(wake: Option<events::WakeFn>) -> i32 {
    guard(|| match wake {
        Some(wake) => {
            events::init(wake);
            0
        }
        // No wake: the UI polls the queue (runtimes without thread-safe callbacks).
        None => 0,
    })
}

/// Copies queued events into `buffer` as JSON lines. Returns the bytes written, 0 when there
/// are none, or minus the size the next event needs.
///
/// # Safety
/// `buffer` points to `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn termio_drain_events(buffer: *mut u8, capacity: u32) -> i32 {
    guard(|| {
        if buffer.is_null() {
            return INVALID;
        }
        // SAFETY: the caller's contract.
        events::drain(unsafe { std::slice::from_raw_parts_mut(buffer, capacity as usize) })
    })
}

/// Runs a control request (`{"op": …}` JSON) and writes `{"ok": true, …}` or
/// `{"ok": false, "error": …}` to `out`. Returns the response length, or minus that length when
/// it does not fit (then fetch it with [`termio_take_response`]).
///
/// # Safety
/// `request` points to `length` readable bytes and `out` to `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn termio_call(request: *const u8, length: u32, out: *mut u8, capacity: u32) -> i32 {
    guard(|| {
        // SAFETY: the caller's contract.
        let Some(request) = (unsafe { bytes(request, length) }) else {
            return INVALID;
        };
        let response = match serde_json::from_slice::<Value>(request).map_err(|error| error.to_string()).and_then(|value| call(&value)) {
            Ok(mut value) => {
                value["ok"] = json!(true);
                value
            }
            Err(error) => json!({ "ok": false, "error": error }),
        };
        respond(&response, out, capacity)
    })
}

/// The response of the last [`termio_call`] that did not fit. Returns its length, 0 when there
/// is none, or minus its length when `capacity` is still too small.
///
/// # Safety
/// `out` points to `capacity` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn termio_take_response(out: *mut u8, capacity: u32) -> i32 {
    guard(|| {
        let mut overflow = OVERFLOW.lock().unwrap_or_else(|p| p.into_inner());
        let Some(body) = overflow.as_ref() else {
            return 0;
        };
        if out.is_null() || body.len() > capacity as usize {
            return -(body.len() as i32);
        }
        // SAFETY: the caller gave `capacity` writable bytes and the body fits.
        unsafe { std::ptr::copy_nonoverlapping(body.as_ptr(), out, body.len()) };
        let length = body.len() as i32;
        *overflow = None;
        length
    })
}

/// Shows the session in the `<surface>` whose `ready` event gave `handle`. `kind`: 0
/// `TarveFrames`, 1 `ISwapChainPanelNative`. Sizes are device pixels.
#[unsafe(no_mangle)]
pub extern "C" fn termio_surface_attach(session: u32, handle: u64, kind: u32, width: u32, height: u32, scale: f32) -> i32 {
    guard(|| {
        let Some(kind) = SurfaceKind::from_code(kind) else {
            return INVALID;
        };
        let presenter = match open_presenter(kind, handle, width, height) {
            Ok(presenter) => presenter,
            Err(error) => {
                events::emit(json!({ "type": "surface.error", "session": session, "message": error.to_string() }));
                return FAILED;
            }
        };
        registry()
            .with(session, |entry| {
                let _ = entry.surface.tx.send(Message::Attach { presenter, width, height, scale });
                0
            })
            .unwrap_or(UNKNOWN_SESSION)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn termio_surface_resize(session: u32, width: u32, height: u32, scale: f32) -> i32 {
    guard(|| {
        registry()
            .with(session, |entry| {
                let _ = entry.surface.tx.send(Message::Resize { width, height, scale });
                0
            })
            .unwrap_or(UNKNOWN_SESSION)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn termio_surface_detach(session: u32) -> i32 {
    guard(|| {
        registry()
            .with(session, |entry| {
                let _ = entry.surface.tx.send(Message::Detach);
                0
            })
            .unwrap_or(UNKNOWN_SESSION)
    })
}

/// A key event as a DOM `key` value (UTF-8). `mods`: 1 shift, 2 alt, 4 ctrl, 8 meta.
///
/// # Safety
/// `key` points to `key_length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn termio_key(session: u32, down: u32, key: *const u8, key_length: u32, mods: u32) -> i32 {
    guard(|| {
        // SAFETY: the caller's contract.
        let Some(key) = (unsafe { text(key, key_length) }) else {
            return INVALID;
        };
        let event = KeyEvent { down: down != 0, key, mods };
        registry()
            .with(session, |entry| {
                entry.session.key(&event);
                0
            })
            .unwrap_or(UNKNOWN_SESSION)
    })
}

/// Text that is not a key press: a paste or an IME commit (UTF-8).
///
/// # Safety
/// `pointer` points to `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn termio_text(session: u32, pointer: *const u8, length: u32) -> i32 {
    guard(|| {
        // SAFETY: the caller's contract.
        let Some(text) = (unsafe { text(pointer, length) }) else {
            return INVALID;
        };
        registry()
            .with(session, |entry| {
                entry.session.text(text);
                0
            })
            .unwrap_or(UNKNOWN_SESSION)
    })
}

/// A pointer event in device pixels relative to the surface. `phase`: 0 down, 1 up, 2 wheel, 3 move.
#[unsafe(no_mangle)]
pub extern "C" fn termio_pointer(session: u32, phase: u32, x: f32, y: f32, button: i32, delta_y: f32, mods: u32) -> i32 {
    guard(|| {
        let phase = match phase {
            0 => PointerPhase::Down,
            1 => PointerPhase::Up,
            2 => PointerPhase::Wheel,
            3 => PointerPhase::Move,
            _ => return INVALID,
        };
        let event = PointerEvent { phase, x, y, button, delta_y, mods };
        registry()
            .with(session, |entry| {
                entry.session.pointer(&event);
                0
            })
            .unwrap_or(UNKNOWN_SESSION)
    })
}
