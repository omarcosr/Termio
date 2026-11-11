//! Byte channels between a terminal and a shell: a local pseudo-terminal, SSH, and the QUIC
//! agent link. Each delivers what the far end sends to a [`Sink`] on a thread of its own.

pub mod agent;
pub mod keys;
pub mod local;
pub mod ssh;

use std::io;

/// Receives a transport's output. Called from the transport's reader thread.
pub trait Sink: Send + Sync + 'static {
    fn data(&self, bytes: &[u8]);
    /// The channel ended; `reason` says why when it was not a clean exit.
    fn closed(&self, reason: Option<String>);
    /// Progress of a connection: `connecting`, `authenticating`, `connected`, `reconnecting`.
    fn status(&self, _status: &str) {}
    /// Something worth showing about the link: `latency` (ms), `reconnect`, `forward.up`,
    /// `forward.error`.
    fn notice(&self, _kind: &str, _detail: &str) {}
}

/// The sending half of a shell channel.
pub trait Transport: Send + Sync {
    fn write(&self, bytes: &[u8]) -> io::Result<()>;
    /// The terminal now has this many cells, in a window of this many pixels.
    fn resize(&self, columns: u16, lines: u16, width: u16, height: u16) -> io::Result<()>;
    fn close(&self);
}
