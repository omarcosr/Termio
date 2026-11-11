//! The clipboard a session copies to and pastes from. Tarve exposes no clipboard API to the app,
//! so the core talks to the system directly; tests substitute their own.

pub trait Clipboard: Send + Sync {
    fn set(&self, text: &str) -> Result<(), String>;
    /// The text on the clipboard, or `None` when it holds none.
    fn get(&self) -> Result<Option<String>, String>;
}

pub struct SystemClipboard;

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
