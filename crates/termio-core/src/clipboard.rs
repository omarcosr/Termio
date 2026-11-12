//! The clipboard a session copies to and pastes from. Tarve owns the system clipboard, so the
//! core hands both to the app: a copy is a `clipboard.copy` event, a paste a `clipboard.paste`
//! event the app answers by typing the clipboard's text into the session. Tests substitute their own.

use crate::events;
use serde_json::json;

pub trait Clipboard: Send + Sync {
    fn set(&self, text: &str) -> Result<(), String>;
    /// The text on the clipboard, or `None` when it holds none or arrives later.
    fn get(&self) -> Result<Option<String>, String>;
}

/// The app's clipboard (Tarve's `clipboard`), reached through events of `session`.
pub struct HostClipboard {
    pub session: u32,
}

impl Clipboard for HostClipboard {
    fn set(&self, text: &str) -> Result<(), String> {
        events::emit(json!({ "type": "clipboard.copy", "session": self.session, "message": text }));
        Ok(())
    }

    fn get(&self) -> Result<Option<String>, String> {
        events::emit(json!({ "type": "clipboard.paste", "session": self.session }));
        Ok(None)
    }
}
