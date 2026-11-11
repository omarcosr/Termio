//! A diagnostic session that draws what is typed, with no terminal behind it: it exercises the
//! surface, font and input paths on their own (`session.open` with `kind: "echo"`).

use crate::session::{KeyEvent, PointerEvent, Session};
use crate::surface::{Invalidator, Scene};
use std::sync::{Arc, Mutex};
use termio_render::{Canvas, Fonts, GlyphStyle, Rect, Rgb};

const BACKGROUND: Rgb = Rgb(0x10, 0x12, 0x16);
const FOREGROUND: Rgb = Rgb(0xd8, 0xde, 0xe9);
const FONT_SIZE: f32 = 14.0;

pub struct EchoSession {
    text: Mutex<String>,
    scale: Mutex<f32>,
    invalidator: Invalidator,
}

impl EchoSession {
    pub fn new(invalidator: Invalidator) -> Arc<Self> {
        Arc::new(Self { text: Mutex::new(String::new()), scale: Mutex::new(1.0), invalidator })
    }

    fn edit(&self, change: impl FnOnce(&mut String)) {
        change(&mut self.text.lock().unwrap_or_else(|p| p.into_inner()));
        self.invalidator.invalidate();
    }
}

impl Session for EchoSession {
    fn scene(self: Arc<Self>) -> Arc<dyn Scene> {
        self
    }

    fn key(&self, event: &KeyEvent<'_>) {
        if !event.down {
            return;
        }
        match event.key {
            "Enter" => self.edit(|text| text.push('\n')),
            "Backspace" => self.edit(|text| {
                text.pop();
            }),
            key if key.chars().count() == 1 => self.edit(|text| text.push_str(key)),
            _ => {}
        }
    }

    fn text(&self, text: &str) {
        self.edit(|current| current.push_str(text));
    }

    fn pointer(&self, _event: &PointerEvent) {}

    fn screen(&self) -> Vec<String> {
        self.text.lock().unwrap_or_else(|p| p.into_inner()).lines().map(str::to_owned).collect()
    }

    fn close(&self) {}
}

impl Scene for EchoSession {
    fn layout(&self, _width: u32, _height: u32, scale: f32, _fonts: &mut Fonts) {
        *self.scale.lock().unwrap_or_else(|p| p.into_inner()) = scale;
    }

    fn paint(&self, canvas: &mut Canvas, fonts: &mut Fonts, _full: bool) -> Option<Rect> {
        let scale = *self.scale.lock().unwrap_or_else(|p| p.into_inner());
        let metrics = fonts.metrics(FONT_SIZE * scale);
        let bounds = canvas.bounds();
        canvas.fill_rect(bounds, BACKGROUND);
        let columns = (canvas.width() / metrics.cell_w).max(1) as i32;
        let (mut column, mut row) = (0, 0);
        for ch in self.text.lock().unwrap_or_else(|p| p.into_inner()).chars() {
            if ch == '\n' || column == columns {
                column = 0;
                row += 1;
                if ch == '\n' {
                    continue;
                }
            }
            let (x, y) = (column * metrics.cell_w as i32, row * metrics.cell_h as i32);
            fonts.draw(canvas, ch, GlyphStyle::default(), &metrics, x, y, FOREGROUND, bounds);
            column += 1;
        }
        let caret = Rect::new(column * metrics.cell_w as i32, row * metrics.cell_h as i32, 2.max(metrics.stroke), metrics.cell_h as i32);
        canvas.fill_rect(caret, FOREGROUND);
        Some(bounds)
    }
}
