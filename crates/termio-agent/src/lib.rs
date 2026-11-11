//! The Termio agent: runs next to the shell on the server, keeps the terminal state there and
//! sends screen updates to the client over QUIC (or over the SSH channel when UDP is blocked).
//!
//! Why it beats a plain SSH session on a bad link:
//! - The session outlives the connection: a dropped link, a changed IP or a laptop that slept
//!   reconnects to the same shell, with the screen as it is now.
//! - QUIC migrates across networks and has no head-of-line blocking; BBR keeps throughput up on
//!   long, lossy paths.
//! - Output is sent as screen state, at most one frame per acknowledgement: a flood costs a
//!   screenful per round trip, so the link stays free for keystrokes.

pub mod client;
mod screen;
pub mod tls;

use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use screen::snapshot;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use termio_proto::{ClientMsg, Frame, Row, ServerMsg, VERSION, diff};
use termio_vt::{Theme, Vt, VtEvent};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

/// Frames are spaced at least this far apart: a 60 Hz ceiling, so even a local link is not
/// flooded with screens nobody can see.
const MIN_FRAME_INTERVAL: Duration = Duration::from_millis(16);
/// How long a session waits for its client to come back.
pub const RESUME_WINDOW: Duration = Duration::from_secs(15 * 60);

struct State {
    vt: Vt,
    title: Option<String>,
    /// The screen changed since the last frame.
    dirty: bool,
    exited: Option<Option<u32>>,
    input_seq: u64,
}

/// A shell in a pseudo-terminal with the emulator that tracks its screen.
pub struct Session {
    state: Mutex<State>,
    changed: Notify,
    writer: Mutex<Box<dyn Write + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
}

fn default_shell() -> CommandBuilder {
    if let Ok(shell) = std::env::var("TERMIO_AGENT_SHELL") {
        let mut parts = shell.split_whitespace();
        let mut command = CommandBuilder::new(parts.next().unwrap_or("sh"));
        command.args(parts);
        return command;
    }
    if cfg!(windows) {
        CommandBuilder::new("powershell.exe")
    } else {
        let mut command = CommandBuilder::new(std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()));
        command.arg("-l");
        command
    }
}

impl Session {
    pub fn start(columns: u16, lines: u16) -> std::io::Result<Arc<Self>> {
        Self::start_with(default_shell(), columns, lines)
    }

    pub fn start_with(mut command: CommandBuilder, columns: u16, lines: u16) -> std::io::Result<Arc<Self>> {
        let other = |error: anyhow_like::Error| std::io::Error::other(error.0);
        let size = PtySize { rows: lines.max(1), cols: columns.max(1), pixel_width: 0, pixel_height: 0 };
        let pair = native_pty_system().openpty(size).map_err(|e| other(e.into()))?;
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        if let Some(home) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }) {
            command.cwd(home);
        }
        let mut child = pair.slave.spawn_command(command).map_err(|e| other(e.into()))?;
        drop(pair.slave);
        let killer = child.clone_killer();
        let mut reader = pair.master.try_clone_reader().map_err(|e| other(e.into()))?;
        let writer = pair.master.take_writer().map_err(|e| other(e.into()))?;
        let session = Arc::new(Self {
            state: Mutex::new(State { vt: Vt::new(columns as usize, lines as usize, Theme::default(), 2000), title: None, dirty: true, exited: None, input_seq: 0 }),
            changed: Notify::new(),
            writer: Mutex::new(writer),
            master: Mutex::new(pair.master),
            killer: Mutex::new(killer),
        });
        let feed = session.clone();
        std::thread::Builder::new().name("termio-agent-pty".into()).spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                feed.output(&buffer[..read]);
            }
        })?;
        let watch = session.clone();
        std::thread::Builder::new().name("termio-agent-wait".into()).spawn(move || {
            let code = child.wait().ok().map(|status| status.exit_code());
            watch.state().exited = Some(code);
            watch.changed.notify_one();
        })?;
        Ok(session)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn output(&self, bytes: &[u8]) {
        let mut state = self.state();
        for event in state.vt.feed(bytes) {
            match event {
                // Answers to the program's queries go straight back: the client is not asked.
                VtEvent::Reply(reply) => self.write(&reply),
                VtEvent::Title(title) => state.title = Some(title),
                VtEvent::ResetTitle => state.title = Some(String::new()),
                VtEvent::Bell | VtEvent::Clipboard(_) => {}
            }
        }
        state.dirty = true;
        drop(state);
        self.changed.notify_one();
    }

    fn write(&self, bytes: &[u8]) {
        let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        let _ = writer.write_all(bytes);
        let _ = writer.flush();
    }

    fn input(&self, seq: u64, bytes: &[u8]) {
        self.write(bytes);
        let mut state = self.state();
        state.input_seq = state.input_seq.max(seq);
    }

    fn resize(&self, columns: u16, lines: u16) {
        let (columns, lines) = (columns.max(1), lines.max(1));
        let size = PtySize { rows: lines, cols: columns, pixel_width: 0, pixel_height: 0 };
        let _ = self.master.lock().unwrap_or_else(|p| p.into_inner()).resize(size);
        let mut state = self.state();
        state.vt.resize(columns as usize, lines as usize, 0, 0);
        state.dirty = true;
        drop(state);
        self.changed.notify_one();
    }

    pub fn kill(&self) {
        let _ = self.killer.lock().unwrap_or_else(|p| p.into_inner()).kill();
    }

    pub fn exited(&self) -> Option<Option<u32>> {
        self.state().exited
    }

    /// The current screen, for a frame.
    fn take(&self) -> Snapshot {
        let mut state = self.state();
        state.dirty = false;
        let (rows, cursor) = snapshot(&state.vt);
        let (columns, lines) = state.vt.size();
        Snapshot { rows, cursor, title: state.title.take(), input_seq: state.input_seq, size: (columns as u16, lines as u16) }
    }
}

struct Snapshot {
    rows: Vec<Row>,
    cursor: Option<(u16, u16)>,
    title: Option<String>,
    input_seq: u64,
    size: (u16, u16),
}

/// What a connection carries: the agent's side of one attached client.
pub enum Ended {
    /// The client said goodbye or the connection dropped: the session waits for it.
    Detached,
    /// The shell exited: the session is over.
    Exited,
}

/// Serves one client on an established stream until it leaves or the shell exits.
pub async fn attach<R, W>(session: Arc<Session>, mut reader: R, writer: &mut W, resumed: bool) -> Ended
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    if termio_proto::write(writer, &ServerMsg::Welcome { version: VERSION, resumed }).await.is_err() {
        return Ended::Detached;
    }
    // Reading is not cancellation-safe, so it runs on its own task and hands over whole messages.
    let (tx, mut incoming) = mpsc::unbounded_channel();
    let reading = tokio::spawn(async move {
        while let Ok(Some(message)) = termio_proto::read::<ClientMsg, _>(&mut reader).await {
            if tx.send(message).is_err() {
                break;
            }
        }
    });
    let mut sent: Vec<Row> = Vec::new();
    let mut size = (0u16, 0u16);
    let mut seq = 0u64;
    let mut unacked: Option<u64> = None;
    let mut last = Instant::now() - MIN_FRAME_INTERVAL;
    let mut first = true;
    let ended = loop {
        let exited = session.exited();
        let dirty = session.state().dirty;
        // One frame in flight at a time: on a slow link the screen catches up a round trip
        // later with its newest state, instead of every intermediate one queueing up.
        let ready = unacked.is_none() && (dirty || first || exited.is_some());
        if ready && last.elapsed() >= MIN_FRAME_INTERVAL {
            let Snapshot { rows, cursor, title, input_seq, size: now } = session.take();
            let full = first || now != size;
            let changed = if full { rows.iter().cloned().enumerate().map(|(i, row)| (i as u16, row)).collect() } else { diff(&sent, &rows) };
            if full || !changed.is_empty() || title.is_some() {
                seq += 1;
                let frame = Frame { seq, columns: now.0, lines: now.1, full, rows: changed, cursor, title, input_seq };
                if termio_proto::write(writer, &ServerMsg::Frame(frame)).await.is_err() {
                    break Ended::Detached;
                }
                trace(format_args!("frame {seq} sent (exited: {exited:?})"));
                unacked = Some(seq);
                last = Instant::now();
            }
            sent = rows;
            size = now;
            first = false;
            if let Some(code) = exited {
                let written = termio_proto::write(writer, &ServerMsg::Exit { code }).await;
                trace(format_args!("exit {code:?} written: {:?}", written.is_ok()));
                break Ended::Exited;
            }
            continue;
        }
        let wait = if ready { MIN_FRAME_INTERVAL.saturating_sub(last.elapsed()) } else { Duration::from_secs(3600) };
        tokio::select! {
            message = incoming.recv() => match message {
                Some(ClientMsg::Input { seq, bytes }) => session.input(seq, &bytes),
                Some(ClientMsg::Resize { columns, lines }) => session.resize(columns, lines),
                Some(ClientMsg::Ack { seq }) => {
                    trace(format_args!("ack {seq} (waiting for {unacked:?})"));
                    if unacked == Some(seq) {
                        unacked = None;
                    }
                }
                Some(ClientMsg::Hello { .. }) => {}
                // The exit this causes is reported like any other, then the session ends.
                Some(ClientMsg::Terminate) => session.kill(),
                Some(ClientMsg::Bye) | None => break Ended::Detached,
            },
            _ = session.changed.notified() => {}
            _ = tokio::time::sleep(wait) => {}
        }
    };
    // After an exit the reader stays until the connection closes: dropping the stream now would
    // tell the client to stop sending, and its acknowledgement of the last frame would fail
    // before it reads the exit that follows.
    if matches!(ended, Ended::Detached) {
        reading.abort();
    }
    ended
}

/// Diagnostics to stderr when `TERMIO_TRACE` is set.
fn trace(message: std::fmt::Arguments<'_>) {
    if std::env::var_os("TERMIO_TRACE").is_some() {
        eprintln!("[agent {:?}] {message}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() % 100_000).unwrap_or(0));
    }
}

/// What the agent prints for the client that started it: where to connect and how to prove it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendezvous {
    pub port: u16,
    pub token: Vec<u8>,
    /// SHA-256 of the agent's self-signed certificate: the client pins it.
    pub cert: Vec<u8>,
}

impl Rendezvous {
    pub const PREFIX: &'static str = "TERMIO-AGENT";

    pub fn line(&self) -> String {
        format!("{} {} {} {} {}", Self::PREFIX, VERSION, self.port, hex::encode(&self.token), hex::encode(&self.cert))
    }

    /// Finds the rendezvous line in the agent's output (a login shell may print a banner first).
    pub fn parse(output: &str) -> Option<Self> {
        output.lines().find_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != Self::PREFIX || parts.next()?.parse::<u32>().ok()? != VERSION {
                return None;
            }
            Some(Self { port: parts.next()?.parse().ok()?, token: hex::decode(parts.next()?).ok()?, cert: hex::decode(parts.next()?).ok()? })
        })
    }
}

/// A running QUIC agent: one session, many connections over its life.
pub struct Agent {
    pub rendezvous: Rendezvous,
    pub local: SocketAddr,
    pub done: tokio::task::JoinHandle<()>,
}

/// Starts a session and serves it over QUIC on `bind`. The session ends when the shell exits,
/// or when no client has been attached for `RESUME_WINDOW`.
pub async fn serve(bind: SocketAddr, command: Option<CommandBuilder>) -> std::io::Result<Agent> {
    let (server, cert) = tls::server_config()?;
    let endpoint = quinn::Endpoint::server(server, bind)?;
    let local = endpoint.local_addr()?;
    let mut token = vec![0u8; 16];
    getrandom::fill(&mut token).map_err(|error| std::io::Error::other(error.to_string()))?;
    let rendezvous = Rendezvous { port: local.port(), token: token.clone(), cert };
    let session = match command {
        Some(command) => Session::start_with(command, 80, 24)?,
        None => Session::start(80, 24)?,
    };
    let done = tokio::spawn(async move {
        let mut attached_once = false;
        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => incoming,
                _ = tokio::time::sleep(RESUME_WINDOW) => None,
                _ = wait_exit(&session) => None,
            };
            let Some(incoming) = incoming else { break };
            let Ok(connection) = incoming.await else { continue };
            let Ok((send, mut recv)) = connection.accept_bi().await else { continue };
            let hello = tokio::time::timeout(Duration::from_secs(10), termio_proto::read::<ClientMsg, _>(&mut recv)).await;
            let Ok(Ok(Some(ClientMsg::Hello { version, token: offered, columns, lines }))) = hello else {
                connection.close(1u32.into(), b"expected hello");
                continue;
            };
            let mut send = send;
            if offered != token || version != VERSION {
                let _ = termio_proto::write(&mut send, &ServerMsg::Refused("wrong token or version".into())).await;
                last_word(send, &connection).await;
                continue;
            }
            session.resize(columns, lines);
            let ended = attach(session.clone(), recv, &mut send, attached_once).await;
            attached_once = true;
            if matches!(ended, Ended::Exited) {
                last_word(send, &connection).await;
                break;
            }
        }
        session.kill();
        endpoint.wait_idle().await;
    });
    Ok(Agent { rendezvous, local, done })
}

/// Closing a QUIC connection discards data still in flight, so after a final message the agent
/// finishes the stream and lets the client close, which it does as soon as it reads it.
async fn last_word(mut send: quinn::SendStream, connection: &quinn::Connection) {
    let _ = send.finish();
    let closed = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
    trace(format_args!("last word: client closed: {:?}", closed.map(|reason| reason.to_string())));
    connection.close(0u32.into(), b"bye");
}

async fn wait_exit(session: &Session) {
    loop {
        if session.exited().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// `portable_pty` reports errors as `anyhow::Error`; this keeps that crate out of our API.
mod anyhow_like {
    pub struct Error(pub String);
    impl<E: std::fmt::Display> From<E> for Error {
        fn from(error: E) -> Self {
            Error(error.to_string())
        }
    }
}
