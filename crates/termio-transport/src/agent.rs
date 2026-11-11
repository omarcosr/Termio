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
use termio_agent::client::{Command, Events, run, terminate_session};
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
                exec_until(&target, verifier.clone(), START, Rendezvous::PREFIX).await.and_then(|output| {
                    if output.contains("TERMIO-AGENT-MISSING") {
                        return Err("termio-agent is not installed on this server; using plain SSH".into());
                    }
                    let rendezvous = Rendezvous::parse(&output).ok_or_else(|| "the agent did not start; using plain SSH".to_owned())?;
                    let address = resolve(&target.host, rendezvous.port).ok_or_else(|| format!("cannot resolve {}", target.host))?;
                    Ok((address, rendezvous))
                })
            };
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
