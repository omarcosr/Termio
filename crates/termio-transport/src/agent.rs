//! A shell through the Termio agent: SSH starts the agent on the server and learns where it
//! listens, then the session runs over QUIC and survives drops, sleep and network changes.
//! When the agent is not installed, or UDP cannot get through, it falls back to a plain SSH
//! shell and says so.

use crate::ssh::{SshShell, Target, Verifier, exec_until, runtime};
use crate::{Sink, Transport};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use termio_agent::Rendezvous;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use termio_agent::client::{Command, Events, reachable, run, terminate_session};
use tokio::sync::mpsc;

/// Starts the agent wherever it is installed and prints its rendezvous line.
pub const START: &str = "A=$(command -v termio-agent || echo \"$HOME/.termio/bin/termio-agent\"); [ -x \"$A\" ] && exec \"$A\" serve || echo TERMIO-AGENT-MISSING";

struct Adapter(Arc<dyn Sink>);

impl Events for Adapter {
    fn screen(&self, bytes: &[u8]) {
        self.0.data(bytes);
    }
    fn status(&self, status: &str) {
        self.0.status(status);
    }
    fn latency(&self, ms: u64) {
        self.0.notice("latency", &ms.to_string());
    }
    fn ended(&self, reason: Option<String>) {
        self.0.closed(reason);
    }
}

enum Link {
    /// Not decided yet: input waits here.
    Starting(Vec<Vec<u8>>, Option<(u16, u16)>),
    Agent(mpsc::UnboundedSender<Command>),
    Ssh(SshShell),
    Closed,
}

/// What the startup task does once it knows how the session will run.
enum Next {
    Run(SocketAddr, Rendezvous, u16, u16, mpsc::UnboundedReceiver<Command>),
    Terminate(SocketAddr, Rendezvous),
    Nothing,
}

pub struct AgentShell {
    link: Arc<Mutex<Link>>,
}

/// A spare agent per server, started in the background after a session comes up: the next tab
/// to that server attaches to it over QUIC alone and skips the SSH login and agent start, the
/// slowest part of opening a session on a distant link. An unused spare ends by itself after the
/// agent's resume window.
type Spares = HashMap<String, (SocketAddr, Rendezvous, Instant)>;
static SPARES: Mutex<Option<Spares>> = Mutex::new(None);
/// Spares older than this are not trusted to still be waiting (the agent gives up at 15 min).
const SPARE_AGE: Duration = Duration::from_secs(10 * 60);

fn spare_key(target: &Target) -> String {
    format!("{}@{}:{}", target.user, target.host, target.port)
}

fn take_spare(target: &Target) -> Option<(SocketAddr, Rendezvous)> {
    let mut spares = SPARES.lock().unwrap_or_else(|p| p.into_inner());
    let (address, rendezvous, at) = spares.get_or_insert_with(HashMap::new).remove(&spare_key(target))?;
    (at.elapsed() < SPARE_AGE).then_some((address, rendezvous))
}

async fn start_agent(target: &Target, verifier: Arc<dyn Verifier>) -> Result<(SocketAddr, Rendezvous), String> {
    let output = exec_until(target, verifier, START, Rendezvous::PREFIX).await?;
    if output.contains("TERMIO-AGENT-MISSING") {
        return Err("termio-agent is not installed on this server; using plain SSH".into());
    }
    let rendezvous = Rendezvous::parse(&output).ok_or_else(|| "the agent did not start; using plain SSH".to_owned())?;
    let address = resolve(&target.host, rendezvous.port).ok_or_else(|| format!("cannot resolve {}", target.host))?;
    Ok((address, rendezvous))
}

/// Starts the next tab's spare unless one is already waiting.
fn refill_spare(target: Target, verifier: Arc<dyn Verifier>) {
    if SPARES.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).contains_key(&spare_key(&target)) {
        return;
    }
    runtime().spawn(async move {
        if let Ok((address, rendezvous)) = start_agent(&target, verifier).await {
            let replaced = SPARES.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).insert(spare_key(&target), (address, rendezvous, Instant::now()));
            if let Some((address, rendezvous, _)) = replaced {
                terminate_session(address, &rendezvous).await;
            }
        }
    });
}

fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

impl AgentShell {
    pub fn connect(target: Target, columns: u16, lines: u16, verifier: Arc<dyn Verifier>, sink: Arc<dyn Sink>) -> Self {
        let link = Arc::new(Mutex::new(Link::Starting(Vec::new(), None)));
        let shared = link.clone();
        runtime().spawn(async move {
            sink.status("connecting");
            let started = if target.jump.is_some() {
                Err("the agent needs a direct route to the server; using SSH through the jump host".to_owned())
            } else {
                match take_spare(&target) {
                    Some((address, rendezvous)) if reachable(address, &rendezvous, Duration::from_millis(1500)).await => Ok((address, rendezvous)),
                    _ => start_agent(&target, verifier.clone()).await,
                }
            };
            if started.is_ok() && std::env::var_os("TERMIO_NO_SPARE").is_none() {
                refill_spare(target.clone(), verifier.clone());
            }
            // Decide under the lock, act after it: a guard must not live across an await.
            let next = {
                let mut link = shared.lock().unwrap_or_else(|p| p.into_inner());
                match (std::mem::replace(&mut *link, Link::Closed), started) {
                    // The tab closed while the agent was starting. The agent is already
                    // running, detached, on the server: tell it to end its shell now rather than
                    // leave it waiting out the resume window for a client that will never come.
                    (Link::Closed, Ok((address, rendezvous))) => Next::Terminate(address, rendezvous),
                    (Link::Closed, Err(_)) => Next::Nothing,
                    (Link::Starting(queued, size), Ok((address, rendezvous))) => {
                        let (columns, lines) = size.unwrap_or((columns, lines));
                        sink.notice("transport", "agent");
                        let (tx, rx) = mpsc::unbounded_channel();
                        for bytes in queued {
                            let _ = tx.send(Command::Input(bytes));
                        }
                        *link = Link::Agent(tx);
                        Next::Run(address, rendezvous, columns, lines, rx)
                    }
                    (Link::Starting(queued, size), Err(reason)) => {
                        let (columns, lines) = size.unwrap_or((columns, lines));
                        sink.notice("transport", "ssh");
                        sink.notice("agent", &reason);
                        let shell = SshShell::connect(target, columns, lines, verifier, sink.clone());
                        for bytes in queued {
                            let _ = shell.write(&bytes);
                        }
                        *link = Link::Ssh(shell);
                        Next::Nothing
                    }
                    // Only the startup task leaves `Starting`.
                    (other, _) => {
                        *link = other;
                        Next::Nothing
                    }
                }
            };
            match next {
                Next::Run(address, rendezvous, columns, lines, rx) => run(address, rendezvous, columns, lines, Arc::new(Adapter(sink)), rx).await,
                Next::Terminate(address, rendezvous) => {
                    terminate_session(address, &rendezvous).await;
                    sink.closed(None);
                }
                Next::Nothing => {}
            }
        });
        Self { link }
    }
}

impl Transport for AgentShell {
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        match &mut *self.link.lock().unwrap_or_else(|p| p.into_inner()) {
            Link::Starting(queued, _) => queued.push(bytes.to_vec()),
            Link::Agent(tx) => {
                let _ = tx.send(Command::Input(bytes.to_vec()));
            }
            Link::Ssh(shell) => shell.write(bytes)?,
            Link::Closed => return Err(io::Error::new(io::ErrorKind::NotConnected, "the session is closed")),
        }
        Ok(())
    }

    fn resize(&self, columns: u16, lines: u16, width: u16, height: u16) -> io::Result<()> {
        match &mut *self.link.lock().unwrap_or_else(|p| p.into_inner()) {
            Link::Starting(_, size) => *size = Some((columns, lines)),
            Link::Agent(tx) => {
                let _ = tx.send(Command::Resize(columns, lines));
            }
            Link::Ssh(shell) => shell.resize(columns, lines, width, height)?,
            Link::Closed => {}
        }
        Ok(())
    }

    fn close(&self) {
        let mut link = self.link.lock().unwrap_or_else(|p| p.into_inner());
        match std::mem::replace(&mut *link, Link::Closed) {
            Link::Agent(tx) => {
                let _ = tx.send(Command::Close);
            }
            Link::Ssh(shell) => shell.close(),
            Link::Starting(..) | Link::Closed => {}
        }
    }
}
