//! A shell on this machine behind a pseudo-terminal (ConPTY on Windows, a pty elsewhere).

use crate::{Sink, Transport};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

/// What to run. Empty fields take the platform's defaults.
#[derive(Clone, Debug, Default)]
pub struct LocalOptions {
    pub program: Option<String>,
    pub args: Vec<String>,
    pub cwd: Option<String>,
}

pub struct LocalPty {
    master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn default_program() -> String {
    if let Ok(shell) = std::env::var("TERMIO_SHELL") {
        return shell;
    }
    if cfg!(windows) { "powershell.exe".into() } else { std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()) }
}

fn size(columns: u16, lines: u16, width: u16, height: u16) -> PtySize {
    PtySize { rows: lines.max(1), cols: columns.max(1), pixel_width: width, pixel_height: height }
}

impl LocalPty {
    /// Starts the program in a pty of `columns` × `lines` cells; its output goes to `sink`.
    pub fn spawn(options: &LocalOptions, columns: u16, lines: u16, sink: Arc<dyn Sink>) -> io::Result<Self> {
        let pair = native_pty_system().openpty(size(columns, lines, 0, 0)).map_err(other)?;
        let mut command = CommandBuilder::new(options.program.clone().unwrap_or_else(default_program));
        command.args(&options.args);
        if let Some(cwd) = options.cwd.clone().or_else(|| std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).ok()) {
            command.cwd(cwd);
        }
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        let mut child = pair.slave.spawn_command(command).map_err(other)?;
        drop(pair.slave);
        let killer = child.clone_killer();
        let mut reader = pair.master.try_clone_reader().map_err(other)?;
        let writer = pair.master.take_writer().map_err(other)?;

        let output = sink.clone();
        std::thread::Builder::new().name("termio-pty-read".into()).spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => output.data(&buffer[..read]),
                }
            }
        })?;
        // The reader does not always see end-of-file when the program exits (ConPTY keeps the
        // pipe open), so the exit itself is what closes the session.
        std::thread::Builder::new().name("termio-pty-wait".into()).spawn(move || {
            let reason = match child.wait() {
                Ok(status) if status.success() => None,
                Ok(status) => Some(format!("exited with code {}", status.exit_code())),
                Err(error) => Some(error.to_string()),
            };
            sink.closed(reason);
        })?;
        Ok(Self { master: Mutex::new(pair.master), writer: Mutex::new(writer), killer: Mutex::new(killer) })
    }
}

impl Transport for LocalPty {
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        writer.write_all(bytes)?;
        writer.flush()
    }

    fn resize(&self, columns: u16, lines: u16, width: u16, height: u16) -> io::Result<()> {
        self.master.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).resize(size(columns, lines, width, height)).map_err(other)
    }

    fn close(&self) {
        let _ = self.killer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{Sender, channel};
    use std::time::Duration;

    struct Collect {
        output: Mutex<Vec<u8>>,
        closed: Mutex<Sender<Option<String>>>,
    }

    impl Sink for Collect {
        fn data(&self, bytes: &[u8]) {
            self.output.lock().unwrap().extend_from_slice(bytes);
        }

        fn closed(&self, reason: Option<String>) {
            let _ = self.closed.lock().unwrap().send(reason);
        }
    }

    #[test]
    fn a_program_runs_in_the_pty_and_its_exit_closes_the_channel() {
        let (tx, rx) = channel();
        let sink = Arc::new(Collect { output: Mutex::new(Vec::new()), closed: Mutex::new(tx) });
        let options = if cfg!(windows) {
            LocalOptions { program: Some("cmd.exe".into()), args: vec!["/c".into(), "echo termio-ok".into()], cwd: None }
        } else {
            LocalOptions { program: Some("/bin/sh".into()), args: vec!["-c".into(), "echo termio-ok".into()], cwd: None }
        };
        let pty = LocalPty::spawn(&options, 80, 24, sink.clone()).expect("spawn");
        pty.resize(100, 30, 800, 480).expect("resize");
        // ConPTY asks where the cursor is and runs nothing until a terminal answers; the test
        // plays the terminal's part, as the emulator does in a session.
        let mut answered = false;
        let mut closed = None;
        for _ in 0..1000 {
            if let Ok(reason) = rx.recv_timeout(Duration::from_millis(20)) {
                closed = Some(reason);
                break;
            }
            if !answered && sink.output.lock().unwrap().windows(4).any(|bytes| bytes == b"\x1b[6n") {
                pty.write(b"\x1b[1;1R").expect("answer the cursor query");
                answered = true;
            }
        }
        let reason = closed.unwrap_or_else(|| {
            panic!("the program did not exit; output so far: {:?}", String::from_utf8_lossy(&sink.output.lock().unwrap()))
        });
        assert_eq!(reason, None);
        // Output can trail the exit by a moment.
        for _ in 0..50 {
            if String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("termio-ok") {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("output was {:?}", String::from_utf8_lossy(&sink.output.lock().unwrap()));
    }
}
