//! The client side of an agent session: connect, keep connecting after a drop, and turn frames
//! into bytes for the local emulator.

use crate::{Rendezvous, tls};
use std::net::SocketAddr;
use std::time::Duration;
use termio_proto::{ClientMsg, ServerMsg, VERSION};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// What the session reports back to its owner.
pub trait Events: Send + Sync + 'static {
    /// Bytes for the local emulator (a frame, replayed as escape sequences).
    fn screen(&self, bytes: &[u8]);
    /// `connecting`, `connected`, `reconnecting`.
    fn status(&self, status: &str);
    /// Keystroke-to-screen time in ms.
    fn latency(&self, ms: u64);
    /// Wire bytes received so far: what the link actually carried.
    fn received(&self, _bytes: u64) {}
    /// The session ended: the shell exited (`None` is a clean exit) or the agent is gone.
    fn ended(&self, reason: Option<String>);
}

pub enum Command {
    Input(Vec<u8>),
    Resize(u16, u16),
    /// Leave the session running on the server (detach).
    Detach,
    /// End it.
    Close,
}

enum Outcome {
    /// The link dropped: reconnect and resume.
    Lost(String),
    Done(Option<String>),
}

async fn connection(endpoint: &quinn::Endpoint, address: SocketAddr, rendezvous: &Rendezvous) -> Result<quinn::Connection, String> {
    let config = tls::client_config(&rendezvous.cert).map_err(|error| error.to_string())?;
    let connecting = endpoint.connect_with(config, address, "termio-agent").map_err(|error| error.to_string())?;
    match tokio::time::timeout(Duration::from_secs(8), connecting).await {
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("no answer over UDP".into()),
    }
}

struct Pending {
    seq: u64,
    at: Instant,
}

/// What a session carries from one connection to the next.
struct Carry {
    size: (u16, u16),
    input_seq: u64,
    received: u64,
    /// The last connection reached the agent and was welcomed.
    welcomed: bool,
}

/// Reconnection pacing. A connection that came up resets it, so a session that drops now and
/// then over a long day reconnects as fast after the hundredth drop as after the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Failed attempts in a row.
    pub attempts: u32,
    pub delay: Duration,
}

impl Backoff {
    const FIRST: Duration = Duration::from_millis(500);
    const LONGEST: Duration = Duration::from_secs(15);
    /// About the agent's resume window: past it there is nothing left to reconnect to.
    const GIVE_UP: u32 = 70;

    pub fn new() -> Self {
        Self { attempts: 0, delay: Self::FIRST }
    }

    /// A connection came up.
    pub fn connected(&mut self) {
        *self = Self::new();
    }

    /// An attempt failed: how long to wait before the next, or `None` to give up.
    pub fn failed(&mut self) -> Option<Duration> {
        self.attempts += 1;
        if self.attempts > Self::GIVE_UP {
            return None;
        }
        let wait = self.delay;
        self.delay = (self.delay * 2).min(Self::LONGEST);
        Some(wait)
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

async fn session(
    endpoint: &quinn::Endpoint,
    address: SocketAddr,
    rendezvous: &Rendezvous,
    carry: &mut Carry,
    events: &dyn Events,
    commands: &mut mpsc::UnboundedReceiver<Command>,
) -> Outcome {
    let Carry { size, input_seq, received, welcomed } = carry;
    *welcomed = false;
    let connection = match connection(endpoint, address, rendezvous).await {
        Ok(connection) => connection,
        Err(error) => return Outcome::Lost(error),
    };
    let Ok((mut send, mut recv)) = connection.open_bi().await else { return Outcome::Lost("could not open a stream".into()) };
    let hello = ClientMsg::Hello { version: VERSION, token: rendezvous.token.clone(), columns: size.0, lines: size.1 };
    if termio_proto::write(&mut send, &hello).await.is_err() {
        return Outcome::Lost("the agent did not answer".into());
    }
    let (tx, mut incoming) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        loop {
            match termio_proto::read::<ServerMsg, _>(&mut recv).await {
                Ok(Some(message)) => {
                    if tx.send(Ok(message)).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = tx.send(Err(error.to_string()));
                    break;
                }
            }
        }
    });
    let mut pending: Option<Pending> = None;
    let outcome = loop {
        tokio::select! {
            message = incoming.recv() => match message {
                Some(Ok(ServerMsg::Welcome { .. })) => {
                    *welcomed = true;
                    events.status("connected");
                }
                Some(Ok(ServerMsg::Frame(frame))) => {
                    *received += termio_proto::encode(&ServerMsg::Frame(frame.clone())).len() as u64;
                    events.received(*received);
                    events.screen(&termio_proto::replay(&frame));
                    if let Some(waiting) = &pending && frame.input_seq >= waiting.seq {
                        events.latency(waiting.at.elapsed().as_millis() as u64);
                        pending = None;
                    }
                    if termio_proto::write(&mut send, &ClientMsg::Ack { seq: frame.seq }).await.is_err() {
                        break settle(&mut incoming).await;
                    }
                }
                Some(Ok(ServerMsg::Exit { code })) => break Outcome::Done(code.filter(|code| *code != 0).map(|code| format!("exited with code {code}"))),
                Some(Ok(ServerMsg::Refused(reason))) => break Outcome::Done(Some(format!("the agent refused the connection: {reason}"))),
                Some(Err(error)) => break Outcome::Lost(error),
                None => break Outcome::Lost(connection.close_reason().map_or_else(|| "the link dropped".into(), |reason| reason.to_string())),
            },
            command = commands.recv() => match command {
                Some(Command::Input(bytes)) => {
                    *input_seq += 1;
                    if pending.is_none() {
                        pending = Some(Pending { seq: *input_seq, at: Instant::now() });
                    }
                    if termio_proto::write(&mut send, &ClientMsg::Input { seq: *input_seq, bytes }).await.is_err() {
                        break settle(&mut incoming).await;
                    }
                }
                Some(Command::Resize(columns, lines)) => {
                    *size = (columns, lines);
                    let _ = termio_proto::write(&mut send, &ClientMsg::Resize { columns, lines }).await;
                }
                Some(Command::Detach) => {
                    let _ = termio_proto::write(&mut send, &ClientMsg::Bye).await;
                    connection.close(0u32.into(), b"detach");
                    break Outcome::Done(Some("detached".into()));
                }
                Some(Command::Close) | None => {
                    // Closing the tab ends the shell on the server, whatever it is running.
                    let _ = termio_proto::write(&mut send, &ClientMsg::Terminate).await;
                    await_exit(&mut incoming).await;
                    break Outcome::Done(None);
                }
            },
        }
    };
    reader.abort();
    if matches!(outcome, Outcome::Done(_)) {
        connection.close(0u32.into(), b"done");
    }
    outcome
}

/// A write failed. That can mean the link dropped, or that the agent is done and stopped
/// reading: its final messages (the exit, a refusal) may already be queued, so they decide.
async fn settle(incoming: &mut mpsc::UnboundedReceiver<Result<ServerMsg, String>>) -> Outcome {
    let verdict = async {
        while let Some(message) = incoming.recv().await {
            match message {
                Ok(ServerMsg::Exit { code }) => return Outcome::Done(code.filter(|code| *code != 0).map(|code| format!("exited with code {code}"))),
                Ok(ServerMsg::Refused(reason)) => return Outcome::Done(Some(format!("the agent refused the connection: {reason}"))),
                Ok(_) => {}
                Err(error) => return Outcome::Lost(error),
            }
        }
        Outcome::Lost("the link dropped".into())
    };
    tokio::time::timeout(Duration::from_secs(2), verdict).await.unwrap_or_else(|_| Outcome::Lost("the link dropped".into()))
}

/// Waits briefly for the agent to confirm the shell is gone: closing the connection before that
/// could discard the request still in flight.
async fn await_exit(incoming: &mut mpsc::UnboundedReceiver<Result<ServerMsg, String>>) {
    let confirmed = async {
        while let Some(message) = incoming.recv().await {
            if matches!(message, Ok(ServerMsg::Exit { .. }) | Err(_)) {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), confirmed).await;
}

/// Ends a session while the link is down: one short attempt to reach the agent and tell it.
/// When the agent is unreachable it ends the session itself after its resume window.
async fn terminate(endpoint: &quinn::Endpoint, address: SocketAddr, rendezvous: &Rendezvous, size: (u16, u16)) {
    let attempt = async {
        let connection = connection(endpoint, address, rendezvous).await.ok()?;
        let (mut send, mut recv) = connection.open_bi().await.ok()?;
        let hello = ClientMsg::Hello { version: VERSION, token: rendezvous.token.clone(), columns: size.0, lines: size.1 };
        termio_proto::write(&mut send, &hello).await.ok()?;
        termio_proto::write(&mut send, &ClientMsg::Terminate).await.ok()?;
        while let Ok(Some(message)) = termio_proto::read::<ServerMsg, _>(&mut recv).await {
            if matches!(message, ServerMsg::Exit { .. }) {
                break;
            }
        }
        connection.close(0u32.into(), b"terminate");
        Some(())
    };
    let _ = tokio::time::timeout(Duration::from_secs(4), attempt).await;
}

/// Ends a session that no client ever attached to, such as one whose tab closed while the agent
/// was starting: otherwise its shell would wait out the resume window.
pub async fn terminate_session(address: SocketAddr, rendezvous: &Rendezvous) {
    let bind: SocketAddr = if address.is_ipv6() { "[::]:0".parse().expect("valid") } else { "0.0.0.0:0".parse().expect("valid") };
    let Ok(endpoint) = quinn::Endpoint::client(bind) else { return };
    terminate(&endpoint, address, rendezvous, (80, 24)).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

/// Runs a session until it ends, reconnecting after every drop with backoff. Input typed while
/// the link is down is dropped, as a terminal does when its line is cut.
pub async fn run(address: SocketAddr, rendezvous: Rendezvous, columns: u16, lines: u16, events: std::sync::Arc<dyn Events>, mut commands: mpsc::UnboundedReceiver<Command>) {
    let bind: SocketAddr = if address.is_ipv6() { "[::]:0".parse().expect("valid") } else { "0.0.0.0:0".parse().expect("valid") };
    let endpoint = match quinn::Endpoint::client(bind) {
        Ok(endpoint) => endpoint,
        Err(error) => return events.ended(Some(format!("UDP: {error}"))),
    };
    let mut carry = Carry { size: (columns.max(1), lines.max(1)), input_seq: 0, received: 0, welcomed: false };
    let mut backoff = Backoff::new();
    events.status("connecting");
    loop {
        match session(&endpoint, address, &rendezvous, &mut carry, &*events, &mut commands).await {
            Outcome::Done(reason) => {
                events.ended(reason);
                // Give the close a moment to reach the agent; never hold the caller for longer.
                let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
                return;
            }
            Outcome::Lost(reason) => {
                if carry.welcomed {
                    backoff.connected();
                }
                let Some(delay) = backoff.failed() else {
                    return events.ended(Some(format!("gave up reconnecting: {reason}")));
                };
                events.status("reconnecting");
                let deadline = tokio::time::sleep(delay);
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        command = commands.recv() => match command {
                            Some(Command::Close) | None => {
                                terminate(&endpoint, address, &rendezvous, carry.size).await;
                                return events.ended(None);
                            }
                            Some(Command::Detach) => return events.ended(Some("detached".into())),
                            Some(Command::Resize(columns, lines)) => carry.size = (columns, lines),
                            Some(Command::Input(_)) => {}
                        },
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_caps_and_starts_over_after_a_connection() {
        let mut backoff = Backoff::new();
        let waits: Vec<u64> = (0..7).map(|_| backoff.failed().unwrap().as_millis() as u64).collect();
        assert_eq!(waits, [500, 1000, 2000, 4000, 8000, 15000, 15000]);
        backoff.connected();
        assert_eq!(backoff.failed(), Some(Duration::from_millis(500)), "a drop after a good connection retries quickly");
        // A long day of occasional drops never runs out of attempts.
        for _ in 0..500 {
            backoff.connected();
            assert!(backoff.failed().is_some());
        }
        // Only an agent that stays unreachable is given up on.
        let mut gone = Backoff::new();
        assert!((0..70).all(|_| gone.failed().is_some()));
        assert_eq!(gone.failed(), None);
    }
}
