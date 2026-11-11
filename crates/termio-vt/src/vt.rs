use crate::theme::{Color, Theme};
use alacritty_terminal::Term;
use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, TermDamage, TermMode};
use alacritty_terminal::vte::ansi::{self, Processor};
use std::sync::{Arc, Mutex};

/// Something the terminal asks its owner to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VtEvent {
    /// Bytes to send back to the program: answers to status and colour queries.
    Reply(Vec<u8>),
    Title(String),
    ResetTitle,
    Bell,
    /// The program set the clipboard (OSC 52).
    Clipboard(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineDamage {
    pub line: usize,
    /// First and last changed column, inclusive.
    pub left: usize,
    pub right: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Damage {
    Full,
    Lines(Vec<LineDamage>),
}

/// One cell as it should be drawn: colours are resolved, inverse and selection applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellView {
    pub ch: char,
    /// The first combining character on the cell, if any.
    pub combining: Option<char>,
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikeout: bool,
    /// The cell holds a double-width character and owns the next cell too.
    pub wide: bool,
    /// The cell is the second half of a wide character: draw nothing.
    pub spacer: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorShape {
    Block,
    Underline,
    Beam,
    HollowBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorView {
    /// Visible line and column.
    pub line: usize,
    pub column: usize,
    pub shape: CursorShape,
}

/// The modes that change how input is sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Modes {
    pub application_cursor: bool,
    pub bracketed_paste: bool,
    /// The program wants mouse presses and releases.
    pub mouse_clicks: bool,
    /// The program wants motion while a button is held.
    pub mouse_drag: bool,
    /// The program wants all motion.
    pub mouse_motion: bool,
    pub sgr_mouse: bool,
    pub alternate_screen: bool,
    /// On the alternate screen the wheel sends cursor keys.
    pub alternate_scroll: bool,
    pub focus_events: bool,
}

impl Modes {
    pub fn mouse(&self) -> bool {
        self.mouse_clicks || self.mouse_drag || self.mouse_motion
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionKind {
    /// Character by character.
    Simple,
    /// Whole words.
    Word,
    /// Whole lines.
    Line,
}

struct Size {
    columns: usize,
    lines: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.lines
    }

    fn screen_lines(&self) -> usize {
        self.lines
    }

    fn columns(&self) -> usize {
        self.columns
    }
}

struct Shared {
    events: Vec<VtEvent>,
    theme: Theme,
    window: WindowSize,
}

/// Collects what the terminal reports while it parses.
#[derive(Clone)]
struct Listener(Arc<Mutex<Shared>>);

impl Listener {
    fn shared(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        let mut shared = self.shared();
        let event = match event {
            Event::PtyWrite(text) => VtEvent::Reply(text.into_bytes()),
            Event::Title(title) => VtEvent::Title(title),
            Event::ResetTitle => VtEvent::ResetTitle,
            Event::Bell => VtEvent::Bell,
            Event::ClipboardStore(_, text) => VtEvent::Clipboard(text),
            Event::ColorRequest(index, format) => {
                let color = match index {
                    0..=255 => shared.theme.indexed(index as u8),
                    256 => shared.theme.foreground,
                    257 => shared.theme.background,
                    _ => shared.theme.cursor,
                };
                VtEvent::Reply(format(ansi::Rgb { r: color.r, g: color.g, b: color.b }).into_bytes())
            }
            Event::TextAreaSizeRequest(format) => VtEvent::Reply(format(shared.window).into_bytes()),
            // Reading the local clipboard is never granted to the remote program.
            _ => return,
        };
        shared.events.push(event);
    }
}

/// A terminal: feed it the program's output, read back cells to draw and bytes to send.
pub struct Vt {
    term: Term<Listener>,
    parser: Processor,
    shared: Arc<Mutex<Shared>>,
    columns: usize,
    lines: usize,
    /// Changes the grid does not track itself: selection, theme.
    stale: bool,
}

impl Vt {
    pub fn new(columns: usize, lines: usize, theme: Theme, scrollback: usize) -> Self {
        let (columns, lines) = (columns.max(1), lines.max(1));
        let window = WindowSize { num_lines: lines as u16, num_cols: columns as u16, cell_width: 0, cell_height: 0 };
        let shared = Arc::new(Mutex::new(Shared { events: Vec::new(), theme, window }));
        let config = Config { scrolling_history: scrollback, ..Config::default() };
        let term = Term::new(config, &Size { columns, lines }, Listener(shared.clone()));
        Self { term, parser: Processor::new(), shared, columns, lines, stale: true }
    }

    fn shared(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Parses program output and returns what it asked of the owner, in order.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<VtEvent> {
        self.parser.advance(&mut self.term, bytes);
        std::mem::take(&mut self.shared().events)
    }

    pub fn size(&self) -> (usize, usize) {
        (self.columns, self.lines)
    }

    /// Changes the grid size; `cell_width`/`cell_height` (pixels) answer size queries.
    pub fn resize(&mut self, columns: usize, lines: usize, cell_width: u16, cell_height: u16) {
        let (columns, lines) = (columns.max(1), lines.max(1));
        self.shared().window = WindowSize { num_lines: lines as u16, num_cols: columns as u16, cell_width, cell_height };
        if (columns, lines) != (self.columns, self.lines) {
            self.columns = columns;
            self.lines = lines;
            self.term.resize(Size { columns, lines });
            self.stale = true;
        }
    }

    pub fn set_theme(&mut self, theme: Theme) {
        self.shared().theme = theme;
        self.stale = true;
    }

    /// What changed since the last call.
    pub fn take_damage(&mut self) -> Damage {
        let damage = match self.term.damage() {
            TermDamage::Full => Damage::Full,
            TermDamage::Partial(lines) => {
                Damage::Lines(lines.map(|line| LineDamage { line: line.line, left: line.left, right: line.right }).collect())
            }
        };
        self.term.reset_damage();
        if std::mem::take(&mut self.stale) { Damage::Full } else { damage }
    }

    /// The cells of visible line `line`, left to right, into `out`.
    pub fn row(&self, line: usize, out: &mut Vec<CellView>) {
        out.clear();
        if line >= self.lines {
            return;
        }
        let shared = self.shared();
        let theme = &shared.theme;
        let grid = self.term.grid();
        let grid_line = Line(line as i32 - grid.display_offset() as i32);
        let colors = self.term.colors();
        let selection = self.term.selection.as_ref().and_then(|selection| selection.to_range(&self.term));
        let resolve = |color: ansi::Color| match color {
            ansi::Color::Spec(rgb) => Color::new(rgb.r, rgb.g, rgb.b),
            ansi::Color::Named(name) => colors[name].map_or_else(|| theme.named(name), |rgb| Color::new(rgb.r, rgb.g, rgb.b)),
            ansi::Color::Indexed(index) => {
                colors[index as usize].map_or_else(|| theme.indexed(index), |rgb| Color::new(rgb.r, rgb.g, rgb.b))
            }
        };
        let row = &grid[grid_line];
        for column in 0..self.columns {
            let cell = &row[Column(column)];
            let flags = cell.flags;
            let (mut fg, mut bg) = (resolve(cell.fg), resolve(cell.bg));
            if flags.contains(Flags::DIM) {
                fg = fg.dim();
            }
            if flags.contains(Flags::INVERSE) {
                std::mem::swap(&mut fg, &mut bg);
            }
            if flags.contains(Flags::HIDDEN) {
                fg = bg;
            }
            if selection.is_some_and(|range| range.contains(Point::new(grid_line, Column(column)))) {
                bg = theme.selection;
            }
            out.push(CellView {
                ch: cell.c,
                combining: cell.zerowidth().and_then(|extra| extra.first().copied()),
                fg,
                bg,
                bold: flags.contains(Flags::BOLD),
                italic: flags.contains(Flags::ITALIC),
                underline: flags.intersects(Flags::ALL_UNDERLINES),
                strikeout: flags.contains(Flags::STRIKEOUT),
                wide: flags.contains(Flags::WIDE_CHAR),
                spacer: flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER),
            });
        }
    }

    /// One character per column of grid line `line` (negative is history), for search: the
    /// spacer half of a wide character is `\0`, so indices are columns.
    pub fn grid_chars(&self, line: i32) -> Vec<char> {
        let grid = self.term.grid();
        if line >= self.lines as i32 || line < -(grid.history_size() as i32) {
            return Vec::new();
        }
        let row = &grid[Line(line)];
        (0..self.columns)
            .map(|column| {
                let cell = &row[Column(column)];
                if cell.flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER) { '\0' } else { cell.c }
            })
            .collect()
    }

    /// Lines of scrollback above the screen.
    pub fn history(&self) -> usize {
        self.term.grid().history_size()
    }

    /// Repaints everything on the next frame (overlays such as search highlights changed).
    pub fn mark_dirty(&mut self) {
        self.stale = true;
    }

    /// Scrolls so grid line `line` is on screen, roughly a third from the top.
    pub fn reveal(&mut self, line: i32) {
        let visible = line + self.display_offset() as i32;
        if visible >= 0 && (visible as usize) < self.lines {
            return;
        }
        let target = (self.lines as i32 / 3 - line).clamp(0, self.history() as i32);
        let delta = target - self.display_offset() as i32;
        self.term.scroll_display(Scroll::Delta(delta));
        self.stale = true;
    }

    /// The text of visible line `line` without trailing blanks.
    pub fn row_text(&self, line: usize) -> String {
        let mut cells = Vec::new();
        self.row(line, &mut cells);
        let mut text: String = cells.iter().filter(|cell| !cell.spacer).map(|cell| cell.ch).collect();
        text.truncate(text.trim_end().len());
        text
    }

    /// The cursor, unless it is hidden or scrolled out of view.
    pub fn cursor(&self) -> Option<CursorView> {
        let content = self.term.renderable_content();
        let shape = match content.cursor.shape {
            ansi::CursorShape::Block => CursorShape::Block,
            ansi::CursorShape::Underline => CursorShape::Underline,
            ansi::CursorShape::Beam => CursorShape::Beam,
            ansi::CursorShape::HollowBlock => CursorShape::HollowBlock,
            ansi::CursorShape::Hidden => return None,
        };
        let line = content.cursor.point.line.0 + content.display_offset as i32;
        if line < 0 || line as usize >= self.lines {
            return None;
        }
        Some(CursorView { line: line as usize, column: content.cursor.point.column.0, shape })
    }

    pub fn theme(&self) -> Theme {
        self.shared().theme.clone()
    }

    pub fn modes(&self) -> Modes {
        let mode = *self.term.mode();
        Modes {
            application_cursor: mode.contains(TermMode::APP_CURSOR),
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            mouse_clicks: mode.contains(TermMode::MOUSE_REPORT_CLICK),
            mouse_drag: mode.contains(TermMode::MOUSE_DRAG),
            mouse_motion: mode.contains(TermMode::MOUSE_MOTION),
            sgr_mouse: mode.contains(TermMode::SGR_MOUSE),
            alternate_screen: mode.contains(TermMode::ALT_SCREEN),
            alternate_scroll: mode.contains(TermMode::ALTERNATE_SCROLL),
            focus_events: mode.contains(TermMode::FOCUS_IN_OUT),
        }
    }

    /// Lines of history above the view right now.
    pub fn display_offset(&self) -> usize {
        self.term.grid().display_offset()
    }

    /// Scrolls the view through history: positive is toward older output.
    pub fn scroll(&mut self, lines: i32) {
        self.term.scroll_display(Scroll::Delta(lines));
    }

    pub fn scroll_to_bottom(&mut self) {
        self.term.scroll_display(Scroll::Bottom);
    }

    fn point(&self, line: usize, column: usize) -> Point {
        let line = line.min(self.lines - 1) as i32 - self.display_offset() as i32;
        Point::new(Line(line), Column(column.min(self.columns - 1)))
    }

    /// Starts a selection at a visible cell; `right_half` says which side of the cell was hit.
    pub fn select(&mut self, kind: SelectionKind, line: usize, column: usize, right_half: bool) {
        let kind = match kind {
            SelectionKind::Simple => SelectionType::Simple,
            SelectionKind::Word => SelectionType::Semantic,
            SelectionKind::Line => SelectionType::Lines,
        };
        let side = if right_half { Side::Right } else { Side::Left };
        self.term.selection = Some(Selection::new(kind, self.point(line, column), side));
        self.stale = true;
    }

    /// Moves the end of the selection.
    pub fn select_to(&mut self, line: usize, column: usize, right_half: bool) {
        let point = self.point(line, column);
        if let Some(selection) = self.term.selection.as_mut() {
            selection.update(point, if right_half { Side::Right } else { Side::Left });
            self.stale = true;
        }
    }

    pub fn clear_selection(&mut self) {
        if self.term.selection.take().is_some() {
            self.stale = true;
        }
    }

    pub fn selection_text(&self) -> Option<String> {
        self.term.selection_to_string().filter(|text| !text.is_empty())
    }

    /// The first and last selected cells as (visible line, column): a line above the screen
    /// (in the scrollback) is negative, one below it is `lines` or more.
    pub fn selection_bounds(&self) -> Option<((i32, usize), (i32, usize))> {
        let range = self.term.selection.as_ref()?.to_range(&self.term)?;
        let offset = self.display_offset() as i32;
        Some(((range.start.line.0 + offset, range.start.column.0), (range.end.line.0 + offset, range.end.column.0)))
    }

    /// Selects character by character from one visible cell to another, whichever comes first.
    pub fn select_range(&mut self, from: (usize, usize), to: (usize, usize)) {
        let (first, last) = if (from.0, from.1) <= (to.0, to.1) { (from, to) } else { (to, from) };
        self.select(SelectionKind::Simple, first.0, first.1, false);
        self.select_to(last.0, last.1, true);
    }

    /// Selects every line on the screen down to the last one with text.
    pub fn select_all(&mut self) {
        let columns = self.columns;
        let last = (0..self.lines).rev().find(|&line| !self.row_text(line).trim().is_empty()).unwrap_or(0);
        self.select(SelectionKind::Line, 0, 0, false);
        self.select_to(last, columns - 1, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vt(columns: usize, lines: usize) -> Vt {
        let mut vt = Vt::new(columns, lines, Theme::default(), 100);
        assert_eq!(vt.take_damage(), Damage::Full);
        vt
    }

    #[test]
    fn text_colours_and_attributes_reach_the_cells() {
        let mut vt = vt(20, 4);
        vt.feed(b"hi \x1b[1;31mred\x1b[0m \x1b[7mrev\x1b[0m \x1b[38;2;1;2;3mrgb");
        assert_eq!(vt.row_text(0), "hi red rev rgb");
        let mut cells = Vec::new();
        vt.row(0, &mut cells);
        let theme = Theme::default();
        assert_eq!((cells[0].fg, cells[0].bg, cells[0].bold), (theme.foreground, theme.background, false));
        assert_eq!((cells[3].fg, cells[3].bold), (theme.ansi[1], true));
        assert_eq!((cells[7].fg, cells[7].bg), (theme.background, theme.foreground));
        assert_eq!(cells[11].fg, Color::new(1, 2, 3));
        assert_eq!(vt.cursor(), Some(CursorView { line: 0, column: 14, shape: CursorShape::Block }));
    }

    #[test]
    fn damage_names_the_lines_that_changed() {
        let mut vt = vt(10, 5);
        vt.feed(b"\x1b[3;2Hab");
        match vt.take_damage() {
            Damage::Lines(lines) => {
                let changed: Vec<usize> = lines.iter().map(|line| line.line).collect();
                assert!(changed.contains(&2), "{changed:?}");
                assert!(!changed.contains(&4), "{changed:?}");
            }
            Damage::Full => panic!("two characters damaged the whole screen"),
        }
        // With nothing new, only the cursor's own cell is reported: the grid always damages it.
        assert_eq!(vt.take_damage(), Damage::Lines(vec![LineDamage { line: 2, left: 3, right: 3 }]));
    }

    #[test]
    fn queries_are_answered_and_titles_reported() {
        let mut vt = vt(10, 3);
        let events = vt.feed(b"\x1b[6n\x1b]0;build\x07\x07");
        assert_eq!(events, vec![VtEvent::Reply(b"\x1b[1;1R".to_vec()), VtEvent::Title("build".into()), VtEvent::Bell]);
    }

    #[test]
    fn wide_characters_take_two_cells() {
        let mut vt = vt(10, 2);
        vt.feed("a日b".as_bytes());
        let mut cells = Vec::new();
        vt.row(0, &mut cells);
        assert!(cells[1].wide && cells[2].spacer && !cells[3].spacer);
        assert_eq!(vt.row_text(0), "a日b");
    }

    #[test]
    fn modes_follow_the_program() {
        let mut vt = vt(10, 3);
        assert_eq!(vt.modes(), Modes { alternate_scroll: true, ..Modes::default() });
        vt.feed(b"\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[?1049h");
        let modes = vt.modes();
        assert!(modes.application_cursor && modes.bracketed_paste && modes.mouse_clicks && modes.sgr_mouse && modes.alternate_screen);
        assert!(modes.mouse());
    }

    #[test]
    fn scrollback_selection_and_resize() {
        let mut vt = vt(10, 3);
        vt.feed(b"one\r\ntwo\r\nthree\r\nfour");
        assert_eq!(vt.row_text(0), "two");
        vt.scroll(1);
        assert_eq!((vt.display_offset(), vt.row_text(0)), (1, "one".to_owned()));
        assert_eq!(vt.cursor(), None, "the cursor line scrolled out of view");
        vt.select(SelectionKind::Simple, 0, 0, false);
        vt.select_to(1, 1, true);
        assert_eq!(vt.selection_text().as_deref(), Some("one\ntw"));
        assert_eq!(vt.take_damage(), Damage::Full);
        vt.clear_selection();
        vt.scroll_to_bottom();
        vt.resize(6, 2, 8, 16);
        assert_eq!(vt.size(), (6, 2));
        assert_eq!(vt.row_text(1), "four");
        assert_eq!(vt.feed(b"\x1b[18t"), vec![VtEvent::Reply(b"\x1b[8;2;6t".to_vec())]);
    }
}
