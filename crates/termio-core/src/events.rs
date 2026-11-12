//! Core → UI events, one JSON document each, through Tarve's plugin event channel: the app hands
//! [`init`] the address of `tarve_plugin_emit`, which copies the bytes, may be called from any
//! thread and wakes the UI like any native event. Events before `init` are dropped.

use serde_json::Value;
use std::ffi::c_char;
use std::sync::OnceLock;

/// `int32_t tarve_plugin_emit(const char *channel, const uint8_t *data, size_t len)`.
pub type EmitFn = unsafe extern "C" fn(*const c_char, *const u8, usize) -> i32;

/// The channel the UI listens on (`ctx.events("termio.events")` in app/core/plugin.ts).
pub const CHANNEL: &std::ffi::CStr = c"termio.events";

static EMIT: OnceLock<EmitFn> = OnceLock::new();

/// Sets where events go; later calls are ignored.
pub fn init(emit: EmitFn) {
    EMIT.get_or_init(|| emit);
}

pub fn emit(event: Value) {
    let Some(emit) = EMIT.get() else { return };
    let bytes = event.to_string();
    // SAFETY: Tarve's emit is thread-safe and copies `len` bytes; the channel is NUL-terminated.
    unsafe { emit(CHANNEL.as_ptr(), bytes.as_ptr(), bytes.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static SEEN: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record(channel: *const c_char, data: *const u8, len: usize) -> i32 {
        // SAFETY: what `emit` passes.
        let channel = unsafe { std::ffi::CStr::from_ptr(channel) }.to_string_lossy().into_owned();
        let text = String::from_utf8(unsafe { std::slice::from_raw_parts(data, len) }.to_vec()).unwrap();
        SEEN.lock().unwrap().push((channel, text));
        0
    }

    #[test]
    fn events_go_to_the_termio_channel_as_json_in_order() {
        init(record);
        emit(json!({ "type": "test.a" }));
        emit(json!({ "type": "test.b", "text": "x" }));
        // Sessions in other tests emit too.
        let seen: Vec<_> = SEEN.lock().unwrap().iter().filter(|(_, text)| text.contains("\"test.")).cloned().collect();
        assert_eq!(seen, vec![
            ("termio.events".into(), r#"{"type":"test.a"}"#.into()),
            ("termio.events".into(), r#"{"text":"x","type":"test.b"}"#.into()),
        ]);
    }
}
