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
    use crate::android::{application, with_env};
    use jni::objects::{JString, JValue};

    pub fn set(text: &str) -> Result<(), String> {
        with_env(|env| {
            let app = application(env)?;
            let name = env.new_string("clipboard")?;
            let manager = env.call_method(&app, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", &[JValue::Object(&name)])?.l()?;
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
            let app = application(env)?;
            let name = env.new_string("clipboard")?;
            let manager = env.call_method(&app, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", &[JValue::Object(&name)])?.l()?;
            let clip = env.call_method(&manager, "getPrimaryClip", "()Landroid/content/ClipData;", &[])?.l()?;
            if clip.is_null() || env.call_method(&clip, "getItemCount", "()I", &[])?.i()? == 0 {
                return Ok(None);
            }
            let item = env.call_method(&clip, "getItemAt", "(I)Landroid/content/ClipData$Item;", &[JValue::Int(0)])?.l()?;
            let text = env.call_method(&item, "coerceToText", "(Landroid/content/Context;)Ljava/lang/CharSequence;", &[JValue::Object(&app)])?.l()?;
            if text.is_null() {
                return Ok(None);
            }
            let text = env.call_method(&text, "toString", "()Ljava/lang/String;", &[])?.l()?;
            Ok(Some(env.get_string(&JString::from(text))?.into()))
        })
    }
}
