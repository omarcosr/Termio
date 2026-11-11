//! The emulator's screen as protocol rows: runs of equally styled text.

use termio_proto::{Row, Run};
use termio_vt::{CellView, Color, Theme, Vt};

fn rgb(color: Color) -> u32 {
    (color.r as u32) << 16 | (color.g as u32) << 8 | color.b as u32
}

fn flags(cell: &CellView) -> u8 {
    cell.bold as u8 | (cell.italic as u8) << 1 | (cell.underline as u8) << 2 | (cell.strikeout as u8) << 3
}

/// One row as runs, without the trailing blank cells a line usually ends with.
pub fn row(cells: &[CellView], theme: &Theme) -> Row {
    let mut runs: Row = Vec::new();
    for cell in cells.iter().filter(|cell| !cell.spacer) {
        let (fg, bg, style) = (rgb(cell.fg), rgb(cell.bg), flags(cell));
        let ch = if cell.ch == '\0' { ' ' } else { cell.ch };
        match runs.last_mut() {
            Some(run) if run.fg == fg && run.bg == bg && run.flags == style => run.text.push(ch),
            _ => runs.push(Run { text: ch.to_string(), fg, bg, flags: style }),
        }
        if let (Some(mark), Some(run)) = (cell.combining, runs.last_mut()) {
            run.text.push(mark);
        }
    }
    let background = rgb(theme.background);
    while let Some(run) = runs.last_mut() {
        if run.bg != background || run.flags & 0b1100 != 0 {
            break;
        }
        let kept = run.text.trim_end_matches(' ').len();
        if kept == 0 {
            runs.pop();
        } else {
            run.text.truncate(kept);
            break;
        }
    }
    runs
}

/// Every visible row and the cursor.
pub fn snapshot(vt: &Vt) -> (Vec<Row>, Option<(u16, u16)>) {
    let theme = vt.theme();
    let (_, lines) = vt.size();
    let mut cells = Vec::new();
    let rows = (0..lines)
        .map(|line| {
            vt.row(line, &mut cells);
            row(&cells, &theme)
        })
        .collect();
    (rows, vt.cursor().map(|cursor| (cursor.line as u16, cursor.column as u16)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_become_runs_without_trailing_blanks() {
        let mut vt = Vt::new(20, 3, Theme::default(), 0);
        vt.feed("hi \x1b[31mred\x1b[0m 日本  ".as_bytes());
        let (rows, cursor) = snapshot(&vt);
        let texts: Vec<&str> = rows[0].iter().map(|run| run.text.as_str()).collect();
        assert_eq!(texts, ["hi ", "red", " 日本"]);
        assert_eq!(rows[0][1].fg, rgb(Theme::default().ansi[1]));
        assert!(rows[1].is_empty() && rows[2].is_empty());
        // "hi " 3 + "red" 3 + " " 1 + two wide characters 4 + "  " 2.
        assert_eq!(cursor, Some((0, 13)));
    }

    /// What the client sees must be what the agent's emulator holds: replaying a frame into a
    /// fresh emulator reproduces the text and colours.
    #[test]
    fn a_replayed_frame_reproduces_the_screen() {
        let mut source = Vt::new(30, 4, Theme::default(), 0);
        source.feed(b"\x1b[1;32mok\x1b[0m done\r\n\x1b[44m blue \x1b[0m\r\nlast");
        let (rows, cursor) = snapshot(&source);
        let frame = termio_proto::Frame { seq: 1, columns: 30, lines: 4, full: true, rows: rows.iter().cloned().enumerate().map(|(i, r)| (i as u16, r)).collect(), cursor, title: None, input_seq: 0 };
        let mut client = Vt::new(30, 4, Theme::default(), 0);
        client.feed(&termio_proto::replay(&frame));
        for line in 0..4 {
            assert_eq!(client.row_text(line), source.row_text(line));
        }
        assert_eq!(snapshot(&client).0, rows, "colours and styles survive too");
        assert_eq!(client.cursor().map(|c| (c.line as u16, c.column as u16)), cursor);
    }
}
