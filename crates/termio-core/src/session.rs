//! The sessions the UI opened, by id.

use crate::surface::{Message, Scene, Surface};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const MOD_SHIFT: u32 = 1;
pub const MOD_ALT: u32 = 2;
pub const MOD_CTRL: u32 = 4;
pub const MOD_META: u32 = 8;

/// A key press or release, as a DOM `key` value.
pub struct KeyEvent<'a> {
    pub down: bool,
    pub key: &'a str,
    pub mods: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerPhase {
    Down,
    Up,
    Wheel,
    Move,
}

/// A pointer event in device pixels relative to the session's surface.
pub struct PointerEvent {
    pub phase: PointerPhase,
    pub x: f32,
    pub y: f32,
    pub button: i32,
    /// Wheel turn in layout pixels; positive scrolls toward newer output.
    pub delta_y: f32,
    pub mods: u32,
}

pub trait Session: Send + Sync {
    fn scene(self: Arc<Self>) -> Arc<dyn Scene>;
    fn key(&self, event: &KeyEvent<'_>);
    /// Text that did not come from a key: paste, IME commit.
    fn text(&self, text: &str);
    fn pointer(&self, event: &PointerEvent);
    /// The text on screen now, one string per line, without trailing blanks.
    fn screen(&self) -> Vec<String>;
    /// Highlights every match of `query` (case-insensitive) on screen and in scrollback; returns how many.
    fn search(&self, _query: &str) -> usize {
        0
    }
    /// Moves to the next (or previous) match.
    fn search_step(&self, _backwards: bool) {}
    fn search_clear(&self) {}
    fn close(&self);
}

pub struct Entry {
    pub session: Arc<dyn Session>,
    pub surface: Surface,
}

#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<u32, Entry>>,
    next: AtomicU32,
}

pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}

impl Registry {
    /// Registers the session `build` makes and starts its render thread.
    pub fn open<S: Session + 'static>(&self, build: impl FnOnce(u32, &Surface) -> Result<Arc<S>, String>) -> Result<u32, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let mut surface = Surface::new();
        let session = build(id, &surface)?;
        surface.start(id, session.clone().scene());
        self.lock().insert(id, Entry { session, surface });
        Ok(id)
    }

    pub fn with<R>(&self, id: u32, action: impl FnOnce(&Entry) -> R) -> Option<R> {
        self.lock().get(&id).map(action)
    }

    pub fn close(&self, id: u32) -> bool {
        let Some(entry) = self.lock().remove(&id) else {
            return false;
        };
        entry.session.close();
        let _ = entry.surface.tx.send(Message::Quit);
        true
    }

    /// Asks every session to lay out again (the terminal font changed).
    pub fn relayout_all(&self) {
        for entry in self.lock().values() {
            let _ = entry.surface.tx.send(crate::surface::Message::Relayout);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, Entry>> {
        self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
