//! The Termio agent protocol: what a client and the agent on the server say to each other.
//!
//! The agent runs the terminal emulator next to the shell and sends the *screen*, not the
//! byte stream: each frame carries only the rows that changed since the previous frame, as
//! runs of equally styled text. The agent sends at most one frame per acknowledgement, so on a
//! slow link a flood of output (a big `cat`, `yes`) costs one screenful per round trip instead
//! of every byte, and Ctrl+C reaches the program at once because input never queues behind
//! output.
//!
//! Wire format: every message is a u32 big-endian length, a flags byte (bit 0: deflated) and a
//! postcard body. Bodies over 256 bytes are deflated.

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

pub const VERSION: u32 = 1;
/// Larger messages are refused: a frame of a 500×200 screen fits with room to spare.
pub const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const DEFLATE_FROM: usize = 256;

/// Text with one style, part of a row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub text: String,
    /// 0xRRGGBB.
    pub fg: u32,
    pub bg: u32,
    /// Bit 0 bold, 1 italic, 2 underline, 3 strikeout.
    pub flags: u8,
}

pub type Row = Vec<Run>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub seq: u64,
    pub columns: u16,
    pub lines: u16,
    /// Every row is included: the receiver starts from nothing.
    pub full: bool,
    /// Changed rows by index.
    pub rows: Vec<(u16, Row)>,
    /// Row and column, or `None` when hidden.
    pub cursor: Option<(u16, u16)>,
    pub title: Option<String>,
    /// The latest input the agent has written to the shell, for the client's echo bookkeeping.
    pub input_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMsg {
    /// First message on a connection. `token` proves the client is the one the agent was
    /// started for; `resume` asks for the session that is already running.
    Hello { version: u32, token: Vec<u8>, columns: u16, lines: u16 },
    Input { seq: u64, bytes: Vec<u8> },
    Resize { columns: u16, lines: u16 },
    /// The client applied this frame: the agent may send the next.
    Ack { seq: u64 },
    /// Detach: the session keeps running for the next connection.
    Bye,
    /// End the session: the agent kills the shell, whatever it is running.
    Terminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMsg {
    Welcome { version: u32, resumed: bool },
    Frame(Frame),
    /// The shell exited.
    Exit { code: Option<u32> },
    Refused(String),
}

#[derive(Debug)]
pub enum ProtoError {
    Io(std::io::Error),
    TooLarge(usize),
    Decode(String),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Io(error) => write!(f, "{error}"),
            ProtoError::TooLarge(size) => write!(f, "message of {size} bytes is too large"),
            ProtoError::Decode(error) => write!(f, "malformed message: {error}"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<std::io::Error> for ProtoError {
    fn from(error: std::io::Error) -> Self {
        ProtoError::Io(error)
    }
}

/// A message ready to write: length, flags, body.
pub fn encode<T: Serialize>(message: &T) -> Vec<u8> {
    let body = postcard::to_stdvec(message).expect("protocol messages serialize");
    let (flags, body) = if body.len() > DEFLATE_FROM {
        let mut encoder = DeflateEncoder::new(Vec::with_capacity(body.len() / 3), Compression::fast());
        encoder.write_all(&body).expect("deflate to memory");
        (1u8, encoder.finish().expect("deflate to memory"))
    } else {
        (0u8, body)
    };
    let mut out = Vec::with_capacity(body.len() + 5);
    out.extend_from_slice(&(body.len() as u32 + 1).to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&body);
    out
}

/// Decodes the flags byte and body of one message (what follows the length).
pub fn decode<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, ProtoError> {
    let (&flags, body) = payload.split_first().ok_or_else(|| ProtoError::Decode("empty message".into()))?;
    let inflated;
    let body = if flags & 1 != 0 {
        let mut out = Vec::new();
        DeflateDecoder::new(body).take(MAX_MESSAGE as u64 + 1).read_to_end(&mut out)?;
        if out.len() > MAX_MESSAGE {
            return Err(ProtoError::TooLarge(out.len()));
        }
        inflated = out;
        &inflated[..]
    } else {
        body
    };
    postcard::from_bytes(body).map_err(|error| ProtoError::Decode(error.to_string()))
}

/// Reads one message from an async stream; `None` at a clean end of stream.
pub async fn read<T, R>(reader: &mut R) -> Result<Option<T>, ProtoError>
where
    T: for<'de> Deserialize<'de>,
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut length = [0u8; 4];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err(ProtoError::TooLarge(length));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    decode(&payload).map(Some)
}

pub async fn write<T, W>(writer: &mut W, message: &T) -> Result<usize, ProtoError>
where
    T: Serialize,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let bytes = encode(message);
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(bytes.len())
}

/// The rows of `next` that differ from `previous` (all of them when the sizes differ).
pub fn diff(previous: &[Row], next: &[Row]) -> Vec<(u16, Row)> {
    next.iter()
        .enumerate()
        .filter(|(index, row)| previous.len() != next.len() || previous.get(*index) != Some(row))
        .map(|(index, row)| (index as u16, row.clone()))
        .collect()
}

/// Turns a frame into the escape sequences that draw it on an xterm-compatible terminal, so a
/// client can feed it to its own emulator and keep its renderer unchanged.
/// The agent's emulator colours: its default foreground and background and ANSI 0–15. Replay
/// turns them back into "default" and palette codes, so the client's colour scheme applies to a
/// resumable session too instead of the agent's fixed RGB values.
pub const AGENT_FOREGROUND: u32 = 0xd8dee9;
pub const AGENT_BACKGROUND: u32 = 0x101216;
pub const AGENT_ANSI: [u32; 16] = [
    0x1c1f26, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xabb2bf, 0x5c6370, 0xff7b86, 0xb1e18b, 0xf2d08a, 0x7cc0ff, 0xd99cf0, 0x6fd3e0, 0xffffff,
];

/// SGR parameters for one colour: `base` 30 for foreground, 40 for background.
fn sgr_color(out: &mut Vec<u8>, color: u32, base: u32, default: u32) {
    if color == default {
        let _ = write!(out, ";{}", base + 9);
    } else if let Some(index) = AGENT_ANSI.iter().position(|&ansi| ansi == color) {
        let code = if index < 8 { base + index as u32 } else { base + 60 + index as u32 - 8 };
        let _ = write!(out, ";{code}");
    } else {
        let _ = write!(out, ";{};2;{};{};{}", base + 8, color >> 16, (color >> 8) & 0xff, color & 0xff);
    }
}

pub fn replay(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.rows.len() * 96);
    // Hide the cursor while painting, so it never flickers through the rows.
    out.extend_from_slice(b"\x1b[?25l");
    if frame.full {
        out.extend_from_slice(b"\x1b[0m\x1b[2J");
    }
    for (index, row) in &frame.rows {
        let _ = write!(out, "\x1b[{};1H\x1b[0m\x1b[2K", index + 1);
        for run in row {
            out.extend_from_slice(b"\x1b[0");
            sgr_color(&mut out, run.fg, 30, AGENT_FOREGROUND);
            sgr_color(&mut out, run.bg, 40, AGENT_BACKGROUND);
            for (bit, code) in [(1, "1"), (2, "3"), (4, "4"), (8, "9")] {
                if run.flags & bit != 0 {
                    out.push(b';');
                    out.extend_from_slice(code.as_bytes());
                }
            }
            out.push(b'm');
            out.extend_from_slice(run.text.as_bytes());
        }
        out.extend_from_slice(b"\x1b[0m");
    }
    if let Some((line, column)) = frame.cursor {
        let _ = write!(out, "\x1b[{};{}H\x1b[?25h", line + 1, column + 1);
    }
    if let Some(title) = &frame.title {
        let clean: String = title.chars().filter(|ch| !ch.is_control()).collect();
        let _ = write!(out, "\x1b]0;{clean}\x07");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Run {
        Run { text: text.into(), fg: 0xd8dee9, bg: 0x101216, flags: 0 }
    }

    #[test]
    fn messages_survive_the_wire_and_big_ones_are_compressed() {
        let small = ClientMsg::Input { seq: 7, bytes: b"ls\r".to_vec() };
        let bytes = encode(&small);
        assert_eq!(bytes[4], 0, "small messages go as they are");
        assert_eq!(decode::<ClientMsg>(&bytes[4..]).unwrap(), small);

        let rows: Vec<(u16, Row)> = (0..40).map(|line| (line, vec![run(&"the same text again ".repeat(6))])).collect();
        let frame = ServerMsg::Frame(Frame { seq: 1, columns: 120, lines: 40, full: true, rows, cursor: Some((3, 4)), title: Some("t".into()), input_seq: 7 });
        let bytes = encode(&frame);
        assert_eq!(bytes[4], 1);
        assert!(bytes.len() < 1500, "a repetitive screen deflates to {} bytes", bytes.len());
        assert_eq!(decode::<ServerMsg>(&bytes[4..]).unwrap(), frame);
        assert!(decode::<ServerMsg>(&[1, 0xff, 0xfe]).is_err(), "garbage is an error, not a panic");
    }

    #[tokio::test]
    async fn framed_streams_read_back_in_order() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        write(&mut a, &ClientMsg::Ack { seq: 1 }).await.unwrap();
        write(&mut a, &ClientMsg::Bye).await.unwrap();
        drop(a);
        assert_eq!(read::<ClientMsg, _>(&mut b).await.unwrap(), Some(ClientMsg::Ack { seq: 1 }));
        assert_eq!(read::<ClientMsg, _>(&mut b).await.unwrap(), Some(ClientMsg::Bye));
        assert_eq!(read::<ClientMsg, _>(&mut b).await.unwrap(), None);
    }

    #[test]
    fn diff_names_changed_rows_only() {
        let before = vec![vec![run("a")], vec![run("b")], vec![run("c")]];
        let mut after = before.clone();
        after[1] = vec![run("B")];
        assert_eq!(diff(&before, &after), vec![(1, vec![run("B")])]);
        assert_eq!(diff(&before[..2], &after).len(), 3, "a size change resends everything");
    }

    #[test]
    fn replay_positions_rows_styles_and_the_cursor() {
        let bold = Run { text: "hi".into(), fg: 0xff0000, bg: 0x000000, flags: 1 | 4 };
        let frame = Frame { seq: 2, columns: 10, lines: 3, full: false, rows: vec![(2, vec![bold])], cursor: Some((2, 2)), title: Some("x\x07y".into()), input_seq: 0 };
        let text = String::from_utf8(replay(&frame)).unwrap();
        assert!(text.contains("\x1b[3;1H"));
        assert!(text.contains("\x1b[0;38;2;255;0;0;48;2;0;0;0;1;4mhi"));
        let themed = Frame { rows: vec![(0, vec![Run { text: "x".into(), fg: AGENT_ANSI[4], bg: AGENT_BACKGROUND, flags: 0 }])], ..frame.clone() };
        assert!(String::from_utf8(replay(&themed)).unwrap().contains("\x1b[0;34;49mx"), "palette and default colours replay as codes");
        assert!(text.ends_with("\x1b[3;3H\x1b[?25h\x1b]0;xy\x07"), "{text:?}");
    }
}
