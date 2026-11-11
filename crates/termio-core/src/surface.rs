//! One render thread per session: it owns the canvas and the presenter, paints what the
//! session's scene says changed and presents it. It sleeps until something invalidates it, so
//! an idle terminal presents no frames.

use crate::events;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use termio_render::{Canvas, Fonts, PresentError, Presenter, Rect};

/// What a session draws. Called on the render thread only.
pub trait Scene: Send + Sync {
    /// The surface has this size in device pixels at `scale` device pixels per layout pixel.
    fn layout(&self, width: u32, height: u32, scale: f32, fonts: &mut Fonts);
    /// Paints what changed since the last call (everything when `full`) and returns its bounds.
    fn paint(&self, canvas: &mut Canvas, fonts: &mut Fonts, full: bool) -> Option<Rect>;
}

pub enum Message {
    Attach { presenter: Box<dyn Presenter>, width: u32, height: u32, scale: f32 },
    Resize { width: u32, height: u32, scale: f32 },
    Detach,
    /// Lay out again at the current size: the font or its size changed.
    Relayout,
    Dirty,
    Quit,
}

/// Asks the render thread for a frame; any number of calls before it runs make one frame.
#[derive(Clone)]
pub struct Invalidator {
    tx: Sender<Message>,
    pending: Arc<AtomicBool>,
}

impl Invalidator {
    pub fn invalidate(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            let _ = self.tx.send(Message::Dirty);
        }
    }
}

pub struct Surface {
    pub tx: Sender<Message>,
    pub invalidator: Invalidator,
    /// Frames presented, for diagnostics and the idle check.
    pub frames: Arc<AtomicU64>,
    rx: Option<Receiver<Message>>,
}

/// The fonts every session shares: one glyph cache for the process.
pub fn fonts() -> &'static Mutex<Fonts> {
    static FONTS: OnceLock<Mutex<Fonts>> = OnceLock::new();
    FONTS.get_or_init(|| Mutex::new(Fonts::new(None)))
}

impl Surface {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        let invalidator = Invalidator { tx: tx.clone(), pending: Arc::new(AtomicBool::new(false)) };
        Self { tx, invalidator, frames: Arc::new(AtomicU64::new(0)), rx: Some(rx) }
    }

    /// Starts the render thread for `scene`. Call once.
    pub fn start(&mut self, session: u32, scene: Arc<dyn Scene>) {
        let rx = self.rx.take().expect("a surface starts once");
        let pending = self.invalidator.pending.clone();
        let frames = self.frames.clone();
        std::thread::Builder::new()
            .name(format!("termio-render-{session}"))
            .spawn(move || run(session, scene, rx, pending, frames))
            .expect("spawn the render thread");
    }
}

fn run(session: u32, scene: Arc<dyn Scene>, rx: Receiver<Message>, pending: Arc<AtomicBool>, frames: Arc<AtomicU64>) {
    let mut canvas = Canvas::new(0, 0);
    let mut presenter: Option<Box<dyn Presenter>> = None;
    let mut full = true;
    // The UI hears once per attach that pixels are on screen.
    let mut announce = false;
    let mut size = (0u32, 0u32, 1.0f32);
    let report = |error: &PresentError| {
        events::emit(json!({ "type": "surface.error", "session": session, "message": error.to_string() }));
    };
    while let Ok(first) = rx.recv() {
        let mut quit = false;
        for message in std::iter::once(first).chain(rx.try_iter()) {
            match message {
                Message::Attach { presenter: attached, width, height, scale } => {
                    size = (width, height, scale);
                    canvas.resize(width, height);
                    scene.layout(width, height, scale, &mut fonts().lock().unwrap_or_else(|p| p.into_inner()));
                    presenter = Some(attached);
                    full = true;
                    announce = true;
                }
                Message::Resize { width, height, scale } => {
                    size = (width, height, scale);
                    canvas.resize(width, height);
                    scene.layout(width, height, scale, &mut fonts().lock().unwrap_or_else(|p| p.into_inner()));
                    if let Some(active) = presenter.as_mut() && let Err(error) = active.resize(width, height) {
                        report(&error);
                        presenter = None;
                    }
                    full = true;
                }
                Message::Detach => presenter = None,
                Message::Relayout => {
                    if size.0 > 0 {
                        scene.layout(size.0, size.1, size.2, &mut fonts().lock().unwrap_or_else(|p| p.into_inner()));
                    }
                    full = true;
                }
                Message::Dirty => {}
                Message::Quit => quit = true,
            }
        }
        if quit {
            break;
        }
        pending.store(false, Ordering::Release);
        let Some(active) = presenter.as_mut() else { continue };
        if canvas.width() == 0 || canvas.height() == 0 {
            continue;
        }
        let dirty = scene.paint(&mut canvas, &mut fonts().lock().unwrap_or_else(|p| p.into_inner()), full);
        let result = match (full, dirty) {
            (true, _) => active.present(&canvas, None),
            (false, Some(rect)) if !rect.is_empty() => active.present(&canvas, Some(rect)),
            _ => continue,
        };
        match result {
            Ok(()) => {
                full = false;
                frames.fetch_add(1, Ordering::Relaxed);
                if let Some(path) = std::env::var_os("TERMIO_CANVAS_DUMP") && frames.load(Ordering::Relaxed) >= 40 {
                    // Diagnostics: the exact pixels handed to the presenter, as a BGRA dump.
                    let _ = std::fs::write(&path, [&canvas.width().to_le_bytes()[..], &canvas.height().to_le_bytes()[..], canvas.pixels()].concat());
                }
                if std::mem::take(&mut announce) {
                    events::emit(json!({ "type": "surface.ready", "session": session }));
                }
            }
            Err(PresentError::Gone) => presenter = None,
            Err(error) => {
                report(&error);
                presenter = None;
            }
        }
    }
}
