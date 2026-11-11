//! The clipboard a session copies to and pastes from. Tarve exposes no clipboard API to the app,
//! so the core talks to the system directly; tests substitute their own.

pub trait Clipboard: Send + Sync {
    fn set(&self, text: &str) -> Result<(), String>;
    /// The text on the clipboard, or `None` when it holds none.
    fn get(&self) -> Result<Option<String>, String>;
}

pub struct SystemClipboard;

#[cfg(not(target_os = "android"))]
impl Clipboard for SystemClipboard {
    fn set(&self, text: &str) -> Result<(), String> {
        arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text)).map_err(|error| error.to_string())
    }

    fn get(&self) -> Result<Option<String>, String> {
        match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.get_text()) {
            Ok(text) => Ok(Some(text)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Android: the framework's ClipboardManager over JNI. The core lives in the activity's process
/// but gets no JNIEnv from Tarve, so it finds the process' Java VM and the application itself.
#[cfg(target_os = "android")]
impl Clipboard for SystemClipboard {
    fn set(&self, text: &str) -> Result<(), String> {
        android::set(text).map_err(|error| format!("clipboard: {error}"))
    }

    fn get(&self) -> Result<Option<String>, String> {
        android::get().map_err(|error| format!("clipboard: {error}"))
    }
}

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JObject, JString, JValue};
    use jni::{JNIEnv, JavaVM};
    use std::sync::OnceLock;

    type GetCreatedVms = unsafe extern "system" fn(*mut *mut jni::sys::JavaVM, jni::sys::jsize, *mut jni::sys::jsize) -> jni::sys::jint;

    /// The process' VM: `JNI_GetCreatedJavaVMs` from libnativehelper (Android 12+) or libart.
    fn vm() -> Result<&'static JavaVM, String> {
        static VM: OnceLock<Result<JavaVM, String>> = OnceLock::new();
        VM.get_or_init(|| {
            for library in [c"libnativehelper.so", c"libart.so"] {
                // SAFETY: the libraries are already loaded in every app process; RTLD_NOLOAD only finds them.
                let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
                if handle.is_null() {
                    continue;
                }
                // SAFETY: a live handle and a NUL-terminated name.
                let symbol = unsafe { libc::dlsym(handle, c"JNI_GetCreatedJavaVMs".as_ptr()) };
                if symbol.is_null() {
                    continue;
                }
                // SAFETY: the symbol has this signature (jni.h).
                let get: GetCreatedVms = unsafe { std::mem::transmute(symbol) };
                let mut raw = std::ptr::null_mut();
                let mut count = 0;
                // SAFETY: room for one VM; Android runs exactly one.
                if unsafe { get(&mut raw, 1, &mut count) } == 0 && count > 0 && !raw.is_null() {
                    // SAFETY: a VM the runtime handed out, alive for the life of the process.
                    return unsafe { JavaVM::from_raw(raw) }.map_err(|error| error.to_string());
                }
            }
            Err("the Java VM is not reachable".into())
        })
        .as_ref()
        .map_err(Clone::clone)
    }

    fn manager<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JObject<'local>> {
        let app = env.call_static_method("android/app/ActivityThread", "currentApplication", "()Landroid/app/Application;", &[])?.l()?;
        let name = env.new_string("clipboard")?;
        env.call_method(&app, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", &[JValue::Object(&name)])?.l()
    }

    /// Runs `body` on this thread attached to the VM, turning a Java exception into its message.
    fn with_env<T>(body: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>) -> Result<T, String> {
        let mut env = vm()?.attach_current_thread_permanently().map_err(|error| error.to_string())?;
        let result = env.with_local_frame(16, |env| body(env));
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
        result.map_err(|error| error.to_string())
    }

    pub fn set(text: &str) -> Result<(), String> {
        with_env(|env| {
            let manager = manager(env)?;
            let label = env.new_string("Termio")?;
            let text = env.new_string(text)?;
            let clip = env
                .call_static_method(
                    "android/content/ClipData",
                    "newPlainText",
                    "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;",
                    &[JValue::Object(&label), JValue::Object(&text)],
                )?
                .l()?;
            env.call_method(&manager, "setPrimaryClip", "(Landroid/content/ClipData;)V", &[JValue::Object(&clip)])?;
            Ok(())
        })
    }

    pub fn get() -> Result<Option<String>, String> {
        with_env(|env| {
            let manager = manager(env)?;
            let clip = env.call_method(&manager, "getPrimaryClip", "()Landroid/content/ClipData;", &[])?.l()?;
            if clip.is_null() {
                return Ok(None);
            }
            if env.call_method(&clip, "getItemCount", "()I", &[])?.i()? == 0 {
                return Ok(None);
            }
            let item = env.call_method(&clip, "getItemAt", "(I)Landroid/content/ClipData$Item;", &[JValue::Int(0)])?.l()?;
            let app = env.call_static_method("android/app/ActivityThread", "currentApplication", "()Landroid/app/Application;", &[])?.l()?;
            let text = env.call_method(&item, "coerceToText", "(Landroid/content/Context;)Ljava/lang/CharSequence;", &[JValue::Object(&app)])?.l()?;
            if text.is_null() {
                return Ok(None);
            }
            let text = env.call_method(&text, "toString", "()Ljava/lang/String;", &[])?.l()?;
            let text: String = env.get_string(&JString::from(text))?.into();
            Ok(Some(text))
        })
    }
}
