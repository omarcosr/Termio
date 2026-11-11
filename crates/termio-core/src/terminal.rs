//! A terminal session: the emulator fed by a transport, painted cell by cell, with keyboard,
//! paste and pointer input encoded for the program on the other end.

use crate::clipboard::{Clipboard, SystemClipboard};
use crate::events;
use crate::session::{KeyEvent, MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT, PointerEvent, PointerPhase, Session};
use crate::surface::{Invalidator, Scene};
use serde_json::json;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use termio_render::{Canvas, FontMetrics, Fonts, GlyphStyle, Rect, Rgb};
use termio_transport::{Sink, Transport};
use termio_vt::{
    CellView, Color, CursorShape, CursorView, Damage, KeyMods, MouseAction, SelectionKind, Theme, Vt, VtEvent, encode_key, encode_mouse,
};

/// Font size and inner margin, in layout pixels.
const FONT_SIZE: f32 = 13.0;
const PADDING: f32 = 6.0;
const SCROLLBACK: usize = 10_000;
/// Tarve reports the wheel in layout pixels: 100 per notch, which scrolls three lines.
const WHEEL_NOTCH_PIXELS: f32 = 100.0;
const WHEEL_LINES_PER_NOTCH: f32 = 3.0;
const MULTI_CLICK: Duration = Duration::from_millis(400);

fn rgb(color: Color) -> Rgb {
    Rgb(color.r, color.g, color.b)
}

fn key_mods(bits: u32) -> KeyMods {
    KeyMods { shift: bits & MOD_SHIFT != 0, alt: bits & MOD_ALT != 0, ctrl: bits & MOD_CTRL != 0 }
}

struct Click {
    at: Instant,
    line: usize,
    column: usize,
    count: u8,
}

struct State {
    vt: Vt,
    metrics: Option<FontMetrics>,
    padding: i32,
    /// Row buffer reused between paints.
    cells: Vec<CellView>,
    /// Where the cursor was painted last, so that line is repainted when it leaves.
    cursor_line: Option<usize>,
    /// The mouse button held, when the program is not the one receiving it.
    selecting: bool,
    /// The button being reported to the program.
    reported: Option<u8>,
    last_click: Option<Click>,
    wheel: f32,
}

struct Link {
    transport: Option<Box<dyn Transport>>,
    /// Bytes for the program that arrived before the transport was attached.
    pending: Vec<u8>,
}

pub struct TerminalSession {
    id: u32,
    clipboard: Box<dyn Clipboard>,
    state: Mutex<State>,
    link: Mutex<Link>,
    invalidator: Invalidator,
}

/// A cell under a pointer position.
struct Hit {
    line: usize,
    column: usize,
    right_half: bool,
}

impl TerminalSession {
    pub fn new(id: u32, invalidator: Invalidator) -> Arc<Self> {
        Self::with_clipboard(id, invalidator, Box::new(SystemClipboard))
    }

    pub fn with_clipboard(id: u32, invalidator: Invalidator, clipboard: Box<dyn Clipboard>) -> Arc<Self> {
        Arc::new(Self {
            id,
            clipboard,
            state: Mutex::new(State {
                vt: Vt::new(80, 24, Theme::default(), SCROLLBACK),
                metrics: None,
                padding: 0,
                cells: Vec::new(),
                cursor_line: None,
                selecting: false,
                reported: None,
                last_click: None,
                wheel: 0.0,
            }),
            link: Mutex::new(Link { transport: None, pending: Vec::new() }),
            invalidator,
        })
    }

    /// Connects the transport and sends what the emulator already answered: a transport may
    /// deliver output (ConPTY's cursor query) before this is called.
    pub fn attach(&self, transport: Box<dyn Transport>) {
        let mut link = self.link();
        let pending = std::mem::take(&mut link.pending);
        if !pending.is_empty() {
            self.report(transport.write(&pending));
        }
        link.transport = Some(transport);
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn link(&self) -> MutexGuard<'_, Link> {
        self.link.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn report(&self, result: std::io::Result<()>) {
        if let Err(error) = result {
            events::emit(json!({ "type": "session.error", "session": self.id, "message": error.to_string() }));
        }
    }

    /// Sends bytes to the program.
    fn send(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut link = self.link();
        match &link.transport {
            Some(transport) => self.report(transport.write(bytes)),
            None => link.pending.extend_from_slice(bytes),
        }
    }

    fn copy(&self, text: &str) {
        if let Err(error) = self.clipboard.set(text) {
            events::emit(json!({ "type": "session.error", "session": self.id, "message": format!("clipboard: {error}") }));
        }
    }

    fn paste_clipboard(&self) {
        match self.clipboard.get() {
            Ok(Some(text)) => self.text(&text),
            // An empty or non-text clipboard is not an error worth reporting.
            Ok(None) => {}
            Err(error) => events::emit(json!({ "type": "session.error", "session": self.id, "message": format!("clipboard: {error}") })),
        }
    }

    fn hit(state: &State, x: f32, y: f32) -> Option<Hit> {
        let metrics = state.metrics?;
        let (columns, lines) = state.vt.size();
        let column = (x - state.padding as f32) / metrics.cell_w as f32;
        let line = (y - state.padding as f32) / metrics.cell_h as f32;
        Some(Hit {
            line: (line.max(0.0) as usize).min(lines - 1),
            column: (column.max(0.0) as usize).min(columns - 1),
            right_half: column.max(0.0).fract() >= 0.5,
        })
    }

    fn wheel(&self, event: &PointerEvent) {
        let mut state = self.state();
        // Multiplying first keeps a whole notch (100 px) at exactly three lines.
        state.wheel += event.delta_y * WHEEL_LINES_PER_NOTCH / WHEEL_NOTCH_PIXELS;
        let lines = state.wheel.trunc() as i32;
        if lines == 0 {
            return;
        }
        state.wheel -= lines as f32;
        let modes = state.vt.modes();
        let mods = key_mods(event.mods);
        let mut bytes = Vec::new();
        if modes.mouse() && !mods.shift {
            if let Some(hit) = Self::hit(&state, event.x, event.y) {
                let action = if lines < 0 { MouseAction::WheelUp } else { MouseAction::WheelDown };
                for _ in 0..lines.unsigned_abs() {
                    bytes.extend(encode_mouse(action, hit.column, hit.line, mods, modes.sgr_mouse).unwrap_or_default());
                }
            }
        } else if modes.alternate_screen && modes.alternate_scroll {
            // Full-screen programs without mouse support scroll with the cursor keys.
            let key = if lines < 0 { "ArrowUp" } else { "ArrowDown" };
            for _ in 0..lines.unsigned_abs() {
                bytes.extend(encode_key(key, KeyMods::default(), modes.application_cursor).unwrap_or_default());
            }
        } else {
            // A wheel turn toward the user (positive delta) shows newer output.
            state.vt.scroll(-lines);
        }
        drop(state);
        self.send(&bytes);
        self.invalidator.invalidate();
    }

    fn press(&self, event: &PointerEvent) {
        let mut state = self.state();
        let Some(hit) = Self::hit(&state, event.x, event.y) else { return };
        let modes = state.vt.modes();
        let mods = key_mods(event.mods);
        let button = event.button.clamp(0, 2) as u8;
        if modes.mouse() && !mods.shift {
            state.reported = Some(button);
            let bytes = encode_mouse(MouseAction::Press(button), hit.column, hit.line, mods, modes.sgr_mouse).unwrap_or_default();
            drop(state);
            return self.send(&bytes);
        }
        match button {
            0 => {
                let now = Instant::now();
                let count = match &state.last_click {
                    Some(last) if now.duration_since(last.at) < MULTI_CLICK && (last.line, last.column) == (hit.line, hit.column) => last.count % 3 + 1,
                    _ => 1,
                };
                state.last_click = Some(Click { at: now, line: hit.line, column: hit.column, count });
                let kind = match count {
                    1 => SelectionKind::Simple,
                    2 => SelectionKind::Word,
                    _ => SelectionKind::Line,
                };
                state.vt.select(kind, hit.line, hit.column, hit.right_half);
                state.selecting = true;
                drop(state);
                self.invalidator.invalidate();
            }
            // Middle and right buttons paste, as terminals on every platform do.
            _ => {
                drop(state);
                self.paste_clipboard();
            }
        }
    }

    fn motion(&self, event: &PointerEvent) {
        let mut state = self.state();
        let Some(hit) = Self::hit(&state, event.x, event.y) else { return };
        let modes = state.vt.modes();
        if state.selecting {
            state.vt.select_to(hit.line, hit.column, hit.right_half);
            drop(state);
            return self.invalidator.invalidate();
        }
        let wanted = match state.reported {
            Some(_) => modes.mouse_drag || modes.mouse_motion,
            None => modes.mouse_motion,
        };
        if wanted {
            let action = MouseAction::Motion(state.reported);
            let bytes = encode_mouse(action, hit.column, hit.line, key_mods(event.mods), modes.sgr_mouse).unwrap_or_default();
            drop(state);
            self.send(&bytes);
        }
    }

    fn release(&self, event: &PointerEvent) {
        let mut state = self.state();
        state.selecting = false;
        let Some(button) = state.reported.take() else { return };
        let Some(hit) = Self::hit(&state, event.x, event.y) else { return };
        let modes = state.vt.modes();
        let bytes = encode_mouse(MouseAction::Release(button), hit.column, hit.line, key_mods(event.mods), modes.sgr_mouse).unwrap_or_default();
        drop(state);
        self.send(&bytes);
    }
}

impl Sink for TerminalSession {
    fn data(&self, bytes: &[u8]) {
        let events = self.state().vt.feed(bytes);
        for event in events {
            match event {
                VtEvent::Reply(reply) => self.send(&reply),
                VtEvent::Title(title) => events::emit(json!({ "type": "session.title", "session": self.id, "title": title })),
                VtEvent::ResetTitle => events::emit(json!({ "type": "session.title", "session": self.id, "title": "" })),
                VtEvent::Bell => events::emit(json!({ "type": "session.bell", "session": self.id })),
                VtEvent::Clipboard(text) => self.copy(&text),
            }
        }
        self.invalidator.invalidate();
    }

    fn closed(&self, reason: Option<String>) {
        events::emit(json!({ "type": "session.closed", "session": self.id, "reason": reason }));
    }

    fn status(&self, status: &str) {
        events::emit(json!({ "type": "session.status", "session": self.id, "status": status }));
    }

    fn notice(&self, kind: &str, detail: &str) {
        events::emit(json!({ "type": "session.notice", "session": self.id, "kind": kind, "detail": detail }));
    }
}

impl Session for TerminalSession {
    fn scene(self: Arc<Self>) -> Arc<dyn Scene> {
        self
    }

    fn key(&self, event: &KeyEvent<'_>) {
        if !event.down || event.mods & MOD_META != 0 {
            return;
        }
        let mods = key_mods(event.mods);
        let mut state = self.state();
        // A key press ends a run of clicks: the next click starts counting again.
        state.last_click = None;
        let modes = state.vt.modes();
        let selection = state.vt.selection_text();
        // Copy: Ctrl+Shift+C always, plain Ctrl+C while something is selected.
        if mods.ctrl && !mods.alt && event.key.eq_ignore_ascii_case("c") && (mods.shift || selection.is_some()) {
            state.vt.clear_selection();
            drop(state);
            if let Some(text) = selection {
                self.copy(&text);
            }
            return self.invalidator.invalidate();
        }
        if (mods.ctrl && mods.shift && event.key.eq_ignore_ascii_case("v")) || (mods.shift && !mods.ctrl && event.key == "Insert") {
            drop(state);
            return self.paste_clipboard();
        }
        if mods.shift && !mods.ctrl && !modes.alternate_screen && matches!(event.key, "PageUp" | "PageDown") {
            let page = state.vt.size().1.saturating_sub(1).max(1) as i32;
            state.vt.scroll(if event.key == "PageUp" { page } else { -page });
            drop(state);
            return self.invalidator.invalidate();
        }
        let Some(bytes) = encode_key(event.key, mods, modes.application_cursor) else { return };
        // Typing returns to the live screen and drops the selection.
        state.vt.scroll_to_bottom();
        state.vt.clear_selection();
        drop(state);
        self.send(&bytes);
        self.invalidator.invalidate();
    }

    fn text(&self, text: &str) {
        let mut state = self.state();
        let bracketed = state.vt.modes().bracketed_paste;
        state.vt.scroll_to_bottom();
        drop(state);
        let normalized = text.replace("\r\n", "\r").replace('\n', "\r");
        if bracketed {
            // The end marker inside pasted text would let it escape the paste.
            let body = normalized.replace("\x1b[201~", "");
            self.send(format!("\x1b[200~{body}\x1b[201~").as_bytes());
        } else {
            self.send(normalized.as_bytes());
        }
        self.invalidator.invalidate();
    }

    fn pointer(&self, event: &PointerEvent) {
        match event.phase {
            PointerPhase::Wheel => self.wheel(event),
            PointerPhase::Down => self.press(event),
            PointerPhase::Move => self.motion(event),
            PointerPhase::Up => self.release(event),
        }
    }

    fn screen(&self) -> Vec<String> {
        let state = self.state();
        (0..state.vt.size().1).map(|line| state.vt.row_text(line)).collect()
    }

    fn close(&self) {
        if let Some(transport) = self.link().transport.take() {
            transport.close();
        }
    }
}

impl Scene for TerminalSession {
    fn layout(&self, width: u32, height: u32, scale: f32, fonts: &mut Fonts) {
        let metrics = fonts.metrics(FONT_SIZE * scale);
        let padding = (PADDING * scale).round() as i32;
        let columns = ((width as i32 - 2 * padding) / metrics.cell_w as i32).max(1) as usize;
        let lines = ((height as i32 - 2 * padding) / metrics.cell_h as i32).max(1) as usize;
        {
            let mut state = self.state();
            state.metrics = Some(metrics);
            state.padding = padding;
            state.vt.resize(columns, lines, metrics.cell_w as u16, metrics.cell_h as u16);
        }
        if let Some(transport) = &self.link().transport {
            self.report(transport.resize(columns as u16, lines as u16, width.min(u16::MAX as u32) as u16, height.min(u16::MAX as u32) as u16));
        }
        events::emit(json!({ "type": "session.size", "session": self.id, "columns": columns, "lines": lines }));
    }

    fn paint(&self, canvas: &mut Canvas, fonts: &mut Fonts, full: bool) -> Option<Rect> {
        let mut state = self.state();
        let metrics = state.metrics?;
        let theme = state.vt.theme();
        let (_, line_count) = state.vt.size();
        let cursor = state.vt.cursor();
        // Always taken, so the grid starts counting changes again from this frame.
        let damage = state.vt.take_damage();
        let everything = full || damage == Damage::Full;
        let mut lines: Vec<usize> = match (everything, damage) {
            (false, Damage::Lines(changed)) => changed.iter().map(|line| line.line).collect(),
            _ => (0..line_count).collect(),
        };
        if everything {
            // Also covers the margin around the grid.
            canvas.fill_rect(canvas.bounds(), rgb(theme.background));
        }
        // The line the cursor left and the one it is on now.
        for line in [state.cursor_line, cursor.map(|cursor| cursor.line)].into_iter().flatten() {
            if line < line_count && !lines.contains(&line) {
                lines.push(line);
            }
        }
        state.cursor_line = cursor.map(|cursor| cursor.line);
        let mut cells = std::mem::take(&mut state.cells);
        let mut dirty = Rect::default();
        for &line in &lines {
            state.vt.row(line, &mut cells);
            let on_line = cursor.filter(|cursor| cursor.line == line);
            dirty = dirty.union(paint_line(canvas, fonts, &metrics, &theme, state.padding, line, &cells, on_line));
        }
        state.cells = cells;
        if everything {
            Some(canvas.bounds())
        } else if dirty.is_empty() {
            None
        } else {
            Some(dirty)
        }
    }
}

fn glyph_style(cell: &CellView) -> GlyphStyle {
    GlyphStyle { bold: cell.bold, italic: cell.italic }
}

fn drawable(cell: &CellView) -> bool {
    !cell.spacer && cell.ch != ' ' && cell.ch != '\0'
}

/// Paints one grid line across the full canvas width and returns the strip it covered.
#[allow(clippy::too_many_arguments)]
fn paint_line(
    canvas: &mut Canvas,
    fonts: &mut Fonts,
    metrics: &FontMetrics,
    theme: &Theme,
    padding: i32,
    line: usize,
    cells: &[CellView],
    cursor: Option<CursorView>,
) -> Rect {
    let (cell_w, cell_h) = (metrics.cell_w as i32, metrics.cell_h as i32);
    let y = padding + line as i32 * cell_h;
    let strip = Rect::new(0, y, canvas.width() as i32, cell_h);
    canvas.fill_rect(strip, rgb(theme.background));

    // Backgrounds, one rectangle per run of equal colour.
    let mut column = 0;
    while column < cells.len() {
        let background = cells[column].bg;
        let start = column;
        while column < cells.len() && cells[column].bg == background {
            column += 1;
        }
        if background != theme.background {
            canvas.fill_rect(Rect::new(padding + start as i32 * cell_w, y, (column - start) as i32 * cell_w, cell_h), rgb(background));
        }
    }

    for (column, cell) in cells.iter().enumerate() {
        if cell.spacer {
            continue;
        }
        let x = padding + column as i32 * cell_w;
        let area = Rect::new(x, y, if cell.wide { cell_w * 2 } else { cell_w }, cell_h);
        let color = rgb(cell.fg);
        if drawable(cell) {
            fonts.draw(canvas, cell.ch, glyph_style(cell), metrics, x, y, color, area);
            if let Some(mark) = cell.combining {
                fonts.draw(canvas, mark, glyph_style(cell), metrics, x, y, color, area);
            }
        }
        if cell.underline {
            canvas.fill_rect(Rect::new(x, y + metrics.underline_y, area.w, metrics.stroke), color);
        }
        if cell.strikeout {
            canvas.fill_rect(Rect::new(x, y + metrics.strikeout_y, area.w, metrics.stroke), color);
        }
    }

    if let Some(cursor) = cursor
        && let Some(cell) = cells.get(cursor.column)
    {
        let x = padding + cursor.column as i32 * cell_w;
        let area = Rect::new(x, y, if cell.wide { cell_w * 2 } else { cell_w }, cell_h);
        let color = rgb(theme.cursor);
        let thickness = (metrics.stroke * 2).max(2);
        match cursor.shape {
            CursorShape::Block => {
                canvas.fill_rect(area, color);
                if drawable(cell) {
                    fonts.draw(canvas, cell.ch, glyph_style(cell), metrics, x, y, rgb(theme.background), area);
                }
            }
            CursorShape::Beam => canvas.fill_rect(Rect::new(x, y, thickness, cell_h), color),
            CursorShape::Underline => canvas.fill_rect(Rect::new(x, y + cell_h - thickness, area.w, thickness), color),
            CursorShape::HollowBlock => {
                let edge = metrics.stroke.max(1);
                canvas.fill_rect(Rect::new(x, y, area.w, edge), color);
                canvas.fill_rect(Rect::new(x, y + cell_h - edge, area.w, edge), color);
                canvas.fill_rect(Rect::new(x, y, edge, cell_h), color);
                canvas.fill_rect(Rect::new(x + area.w - edge, y, edge, cell_h), color);
            }
        }
    }
    strip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surface::Surface;

    #[derive(Clone, Default)]
    struct Recorder {
        written: Arc<Mutex<Vec<u8>>>,
        size: Arc<Mutex<Option<(u16, u16)>>>,
    }

    impl Recorder {
        /// What was sent to the program since the last call.
        fn take(&self) -> String {
            String::from_utf8(std::mem::take(&mut *self.written.lock().unwrap())).unwrap()
        }
    }

    impl Transport for Recorder {
        fn write(&self, bytes: &[u8]) -> std::io::Result<()> {
            self.written.lock().unwrap().extend_from_slice(bytes);
            Ok(())
        }

        fn resize(&self, columns: u16, lines: u16, _width: u16, _height: u16) -> std::io::Result<()> {
            *self.size.lock().unwrap() = Some((columns, lines));
            Ok(())
        }

        fn close(&self) {}
    }

    #[derive(Clone, Default)]
    struct FakeClipboard(Arc<Mutex<Option<String>>>);

    impl Clipboard for FakeClipboard {
        fn set(&self, text: &str) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(text.to_owned());
            Ok(())
        }

        fn get(&self) -> Result<Option<String>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    struct Fixture {
        session: Arc<TerminalSession>,
        program: Recorder,
        clipboard: FakeClipboard,
        /// Keeps the invalidation channel open.
        _surface: Surface,
    }

    const NONE: u32 = 0;

    impl Fixture {
        /// A session in an 800×400 surface, with the transport attached.
        fn new() -> Self {
            let fixture = Self::detached();
            fixture.session.attach(Box::new(fixture.program.clone()));
            fixture.layout(800, 400);
            fixture
        }

        fn detached() -> Self {
            let surface = Surface::new();
            let clipboard = FakeClipboard::default();
            let session = TerminalSession::with_clipboard(1, surface.invalidator.clone(), Box::new(clipboard.clone()));
            Self { session, program: Recorder::default(), clipboard, _surface: surface }
        }

        fn layout(&self, width: u32, height: u32) {
            Scene::layout(&*self.session, width, height, 1.0, &mut Fonts::new(None));
        }

        fn feed(&self, bytes: &[u8]) {
            self.session.data(bytes);
        }

        fn key(&self, key: &str, mods: u32) {
            self.session.key(&KeyEvent { down: true, key, mods });
        }

        /// A point inside the left or right half of a cell, in surface pixels.
        fn at(&self, column: usize, line: usize, right_half: bool) -> (f32, f32) {
            let (metrics, padding) = {
                let state = self.session.state();
                (state.metrics.unwrap(), state.padding)
            };
            let x = padding as f32 + (column as f32 + if right_half { 0.75 } else { 0.25 }) * metrics.cell_w as f32;
            let y = padding as f32 + (line as f32 + 0.5) * metrics.cell_h as f32;
            (x, y)
        }

        fn pointer(&self, phase: PointerPhase, (x, y): (f32, f32), button: i32, mods: u32) {
            self.session.pointer(&PointerEvent { phase, x, y, button, delta_y: 0.0, mods });
        }

        fn click(&self, column: usize, line: usize, button: i32, mods: u32) {
            self.pointer(PointerPhase::Down, self.at(column, line, false), button, mods);
            self.pointer(PointerPhase::Up, self.at(column, line, false), button, mods);
        }

        /// A wheel turn over the cell at column 2, line 1.
        fn wheel(&self, delta_y: f32) {
            let (x, y) = self.at(2, 1, false);
            self.session.pointer(&PointerEvent { phase: PointerPhase::Wheel, x, y, button: -1, delta_y, mods: NONE });
        }
    }

    #[test]
    fn answers_given_before_the_transport_exists_are_sent_once_it_is_attached() {
        // ConPTY asks for the cursor position before it runs anything.
        let fixture = Fixture::detached();
        fixture.feed(b"\x1b[6n");
        assert_eq!(fixture.program.take(), "");
        fixture.session.attach(Box::new(fixture.program.clone()));
        assert_eq!(fixture.program.take(), "\x1b[1;1R");
    }

    #[test]
    fn keys_follow_the_modes_the_program_set() {
        let fixture = Fixture::new();
        fixture.key("a", NONE);
        fixture.key("ArrowUp", NONE);
        assert_eq!(fixture.program.take(), "a\x1b[A");
        fixture.feed(b"\x1b[?1h");
        fixture.key("ArrowUp", NONE);
        assert_eq!(fixture.program.take(), "\x1bOA");
        fixture.session.key(&KeyEvent { down: false, key: "a", mods: NONE });
        fixture.key("a", MOD_META);
        fixture.key("Shift", MOD_SHIFT);
        assert_eq!(fixture.program.take(), "", "releases, meta chords and bare modifiers send nothing");
    }

    #[test]
    fn pasted_text_is_bracketed_on_request_and_cannot_end_the_paste_itself() {
        let fixture = Fixture::new();
        fixture.session.text("a\r\nb\nc");
        assert_eq!(fixture.program.take(), "a\rb\rc");
        fixture.feed(b"\x1b[?2004h");
        fixture.session.text("x\x1b[201~y");
        assert_eq!(fixture.program.take(), "\x1b[200~xy\x1b[201~");
    }

    #[test]
    fn a_drag_selects_and_ctrl_c_copies_it_instead_of_interrupting() {
        let fixture = Fixture::new();
        fixture.feed(b"hello world");
        fixture.pointer(PointerPhase::Down, fixture.at(0, 0, false), 0, NONE);
        fixture.pointer(PointerPhase::Move, fixture.at(4, 0, true), 0, NONE);
        fixture.pointer(PointerPhase::Up, fixture.at(4, 0, true), 0, NONE);
        fixture.key("c", MOD_CTRL);
        assert_eq!(fixture.clipboard.get().unwrap().as_deref(), Some("hello"));
        assert_eq!(fixture.program.take(), "", "a copy is not sent to the program");
        fixture.key("c", MOD_CTRL);
        assert_eq!(fixture.program.take(), "\x03", "with nothing selected Ctrl+C interrupts");
    }

    #[test]
    fn a_double_click_selects_the_word_and_a_triple_click_the_line() {
        let fixture = Fixture::new();
        fixture.feed(b"hello world");
        fixture.click(7, 0, 0, NONE);
        fixture.click(7, 0, 0, NONE);
        fixture.key("C", MOD_CTRL | MOD_SHIFT);
        assert_eq!(fixture.clipboard.get().unwrap().as_deref(), Some("world"));
        fixture.click(7, 0, 0, NONE);
        fixture.click(7, 0, 0, NONE);
        fixture.click(7, 0, 0, NONE);
        fixture.key("C", MOD_CTRL | MOD_SHIFT);
        assert_eq!(fixture.clipboard.get().unwrap().as_deref(), Some("hello world\n"));
    }

    #[test]
    fn the_paste_shortcuts_and_the_right_button_send_the_clipboard() {
        let fixture = Fixture::new();
        fixture.key("V", MOD_CTRL | MOD_SHIFT);
        assert_eq!(fixture.program.take(), "", "an empty clipboard pastes nothing");
        fixture.clipboard.set("pasted").unwrap();
        fixture.key("V", MOD_CTRL | MOD_SHIFT);
        fixture.key("Insert", MOD_SHIFT);
        fixture.click(3, 3, 2, NONE);
        assert_eq!(fixture.program.take(), "pastedpastedpasted");
    }

    #[test]
    fn the_wheel_scrolls_history_reports_to_mouse_programs_or_moves_the_cursor() {
        let fixture = Fixture::new();
        let lines = fixture.session.screen().len();
        for number in 0..lines * 3 {
            fixture.feed(format!("line {number}\r\n").as_bytes());
        }
        let top = fixture.session.screen()[0].clone();
        fixture.wheel(-100.0);
        let scrolled = fixture.session.screen()[0].clone();
        let number = |line: &str| line.trim_start_matches("line ").parse::<usize>().unwrap();
        assert_eq!(number(&scrolled) + 3, number(&top), "one notch away from the user shows three older lines");
        assert_eq!(fixture.program.take(), "");
        fixture.key("a", NONE);
        assert_eq!(fixture.session.screen()[0], top, "typing returns to the live screen");
        fixture.program.take();

        fixture.feed(b"\x1b[?1000h\x1b[?1006h");
        fixture.wheel(-100.0);
        assert_eq!(fixture.program.take(), "\x1b[<64;3;2M".repeat(3));

        fixture.feed(b"\x1b[?1000l\x1b[?1049h");
        fixture.wheel(100.0);
        assert_eq!(fixture.program.take(), "\x1b[B".repeat(3));
    }

    #[test]
    fn mouse_presses_go_to_programs_that_asked_unless_shift_is_held() {
        let fixture = Fixture::new();
        fixture.feed(b"some text\x1b[?1000h\x1b[?1006h");
        fixture.click(4, 2, 0, NONE);
        assert_eq!(fixture.program.take(), "\x1b[<0;5;3M\x1b[<0;5;3m");
        fixture.pointer(PointerPhase::Down, fixture.at(0, 0, false), 0, MOD_SHIFT);
        fixture.pointer(PointerPhase::Move, fixture.at(3, 0, true), 0, MOD_SHIFT);
        fixture.pointer(PointerPhase::Up, fixture.at(3, 0, true), 0, MOD_SHIFT);
        assert_eq!(fixture.program.take(), "", "shift keeps the mouse for selecting");
        fixture.key("C", MOD_CTRL | MOD_SHIFT);
        assert_eq!(fixture.clipboard.get().unwrap().as_deref(), Some("some"));
    }

    #[test]
    fn a_resize_reaches_the_grid_and_the_program() {
        let fixture = Fixture::new();
        let wide = fixture.program.size.lock().unwrap().expect("the first layout sized the program");
        fixture.layout(400, 200);
        let narrow = fixture.program.size.lock().unwrap().unwrap();
        assert!(narrow.0 < wide.0 && narrow.1 < wide.1, "{wide:?} -> {narrow:?}");
        assert_eq!(fixture.session.screen().len(), narrow.1 as usize);
        assert_eq!(fixture.session.state().vt.size(), (narrow.0 as usize, narrow.1 as usize));
    }

    /// Pixel checks on a painted frame. The font is whatever this machine has, so the test looks
    /// at properties (where ink and fills are) rather than comparing against a stored image.
    #[test]
    fn a_painted_frame_has_backgrounds_ink_and_a_cursor_and_repaints_only_changed_lines() {
        let fixture = Fixture::new();
        let mut fonts = Fonts::new(None);
        let mut canvas = Canvas::new(800, 400);
        let theme = Theme::default();
        let (metrics, padding) = {
            let state = fixture.session.state();
            (state.metrics.unwrap(), state.padding)
        };
        let (cell_w, cell_h) = (metrics.cell_w as i32, metrics.cell_h as i32);
        let pixel = |canvas: &Canvas, x: i32, y: i32| {
            let offset = ((y as u32 * canvas.width() + x as u32) * 4) as usize;
            let bgra = &canvas.pixels()[offset..offset + 3];
            Rgb(bgra[2], bgra[1], bgra[0])
        };
        // Whether any pixel of a cell differs from `ground`.
        let inked = |canvas: &Canvas, column: i32, line: i32, ground: Rgb| {
            let (left, top) = (padding + column * cell_w, padding + line * cell_h);
            (top..top + cell_h).any(|y| (left..left + cell_w).any(|x| pixel(canvas, x, y) != ground))
        };

        // Line 0: "A", a blank, a space on a red background, an underlined blank. Cursor on line 2.
        fixture.feed(b"A \x1b[41m \x1b[0m\x1b[4m \x1b[0m\r\n\r\n");
        let dirty = Scene::paint(&*fixture.session, &mut canvas, &mut fonts, true);
        assert_eq!(dirty, Some(canvas.bounds()), "a full paint covers the canvas");
        let background = rgb(theme.background);
        assert_eq!(pixel(&canvas, 1, 1), background, "the margin is the theme background");
        assert_eq!(pixel(&canvas, 799, 399), background);
        assert!(inked(&canvas, 0, 0, background), "the A left ink in its cell");
        assert!(!inked(&canvas, 1, 0, background), "a blank cell stays empty");
        assert_eq!(pixel(&canvas, padding + 2 * cell_w + 1, padding + 1), rgb(theme.ansi[1]), "SGR 41 fills the cell");
        assert_eq!(
            pixel(&canvas, padding + 3 * cell_w + 1, padding + metrics.underline_y),
            rgb(theme.foreground),
            "an underlined blank still gets its line"
        );
        assert_eq!(pixel(&canvas, padding + 1, padding + 2 * cell_h + 1), rgb(theme.cursor), "the block cursor fills its cell");

        // One more character on the cursor's line: only that strip is repainted.
        fixture.feed(b"x");
        let dirty = Scene::paint(&*fixture.session, &mut canvas, &mut fonts, false).expect("the new character is damage");
        assert_eq!((dirty.y, dirty.h), (padding + 2 * cell_h, cell_h), "{dirty:?}");
        assert!(inked(&canvas, 0, 2, background), "the x is drawn where the cursor was");
        assert_eq!(pixel(&canvas, padding + cell_w + 1, padding + 2 * cell_h + 1), rgb(theme.cursor), "the cursor moved right");
    }

    /// Emulator throughput under a flood, the cost behind `cat` of a large file. A performance
    /// gate in release builds (`bun run check:perf`): below the floor, a fast server could
    /// outrun the terminal. Debug builds only check that it works.
    #[test]
    fn flood() {
        let fixture = Fixture::new();
        let chunk = "the quick brown fox jumps over the lazy dog 0123456789\r\n".repeat(1024).into_bytes();
        let megabytes = if cfg!(debug_assertions) { 4 } else { 100 };
        let started = Instant::now();
        let mut fed = 0;
        while fed < megabytes * 1024 * 1024 {
            fixture.feed(&chunk);
            fed += chunk.len();
        }
        let seconds = started.elapsed().as_secs_f64();
        let rate = megabytes as f64 / seconds;
        println!("fed {megabytes} MB in {seconds:.2} s: {rate:.0} MB/s");
        // Measured at about 80 MB/s on the development machine; the floor leaves room for slower CI.
        if !cfg!(debug_assertions) {
            assert!(rate >= 25.0, "emulator throughput fell to {rate:.1} MB/s");
        }
    }
}
