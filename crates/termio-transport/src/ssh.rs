//! An interactive shell over SSH. One task per connection runs on a shared tokio runtime: it
//! connects (through a jump host when asked), checks the host key with the caller, signs in,
//! opens a pty and pumps bytes both ways. The UI side only queues commands, so it never blocks.
//!
//! Tuned for long, slow links: TCP_NODELAY so keystrokes are not held back, zlib compression
//! offered first, and keepalives that notice a dead link in under a minute.

use crate::{Sink, Transport};
use russh::client::{self, AuthResult, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Preferred, compression};
use std::borrow::Cow;
use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// The runtime every SSH connection shares.
pub fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("termio-ssh")
            .enable_all()
            .build()
            .expect("start the SSH runtime")
    })
}

#[derive(Clone)]
pub enum Auth {
    Password(Zeroizing<String>),
    /// OpenSSH or PEM private key text.
    Key { private: Zeroizing<String>, passphrase: Option<Zeroizing<String>> },
    /// The keys the running ssh-agent holds (OpenSSH's pipe on Windows, $SSH_AUTH_SOCK elsewhere).
    Agent,
}

#[derive(Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Vec<Auth>,
    /// Reach this target through another SSH server (ProxyJump).
    pub jump: Option<Box<Target>>,
    pub forwards: Vec<Forward>,
}

/// What the caller is asked about a server's key.
#[derive(Clone, Debug)]
pub struct HostKey {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// The `known_hosts` key text.
    pub openssh: String,
}

/// Decides whether to trust a server key. Answer through the sender, from any thread; dropping
/// it rejects.
pub trait Verifier: Send + Sync + 'static {
    fn verify(&self, key: HostKey, answer: oneshot::Sender<bool>);
}

enum Command {
    Write(Vec<u8>),
    Resize(u32, u32, u32, u32),
    Close,
}

/// The UI's half of an SSH shell.
pub struct SshShell {
    commands: mpsc::UnboundedSender<Command>,
}

impl Transport for SshShell {
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        self.commands.send(Command::Write(bytes.to_vec())).map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "the connection is closed"))
    }

    fn resize(&self, columns: u16, lines: u16, width: u16, height: u16) -> io::Result<()> {
        let _ = self.commands.send(Command::Resize(columns as u32, lines as u32, width as u32, height as u32));
        Ok(())
    }

    fn close(&self) {
        let _ = self.commands.send(Command::Close);
    }
}

struct Client {
    verifier: Arc<dyn Verifier>,
    host: String,
    port: u16,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let key = server.public_key();
        let request = HostKey {
            host: self.host.clone(),
            port: self.port,
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            openssh: key.to_openssh().unwrap_or_default(),
        };
        let (answer, decision) = oneshot::channel();
        self.verifier.verify(request, answer);
        Ok(decision.await.unwrap_or(false))
    }
}

fn config() -> Arc<client::Config> {
    let preferred = Preferred { compression: Cow::Borrowed(&[compression::ZLIB_LEGACY, compression::ZLIB, compression::NONE]), ..Preferred::default() };
    Arc::new(client::Config {
        preferred,
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..Default::default()
    })
}

fn fail(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}: {error}")
}

async fn authenticate(handle: &mut Handle<Client>, target: &Target) -> Result<(), String> {
    if target.auth.is_empty() {
        return Err(format!("no password or key for {}@{}", target.user, target.host));
    }
    let mut last = String::from("the server refused every method");
    for method in &target.auth {
        let result = match method {
            Auth::Password(password) => handle.authenticate_password(&target.user, password.as_str()).await,
            Auth::Key { private, passphrase } => {
                let key = match crate::keys::load(private, passphrase.as_ref().map(|p| p.as_str())) {
                    Ok(key) => key,
                    Err(error) => {
                        last = error;
                        continue;
                    }
                };
                let hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
                handle.authenticate_publickey(&target.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await
            }
            Auth::Agent => {
                match agent_sign_in(handle, &target.user).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => last = "the ssh-agent's keys were not accepted".into(),
                    Err(error) => last = error,
                }
                continue;
            }
        };
        match result {
            Ok(AuthResult::Success) => return Ok(()),
            Ok(AuthResult::Failure { .. }) => {
                last = match method {
                    Auth::Password(_) => "wrong password".into(),
                    Auth::Key { .. } => "the server did not accept the key".into(),
                    Auth::Agent => "the ssh-agent's keys were not accepted".into(),
                }
            }
            Err(error) => return Err(fail("authentication", error)),
        }
    }
    Err(last)
}

/// Tries every key the running ssh-agent offers. `Ok(false)` when none was accepted.
async fn agent_sign_in(handle: &mut Handle<Client>, user: &str) -> Result<bool, String> {
    #[cfg(windows)]
    let mut agent = russh::keys::agent::client::AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await.map_err(|error| fail("ssh-agent", error))?;
    #[cfg(unix)]
    let mut agent = russh::keys::agent::client::AgentClient::connect_env().await.map_err(|error| fail("ssh-agent", error))?;
    let identities = agent.request_identities().await.map_err(|error| fail("ssh-agent", error))?;
    for identity in identities {
        let result = handle.authenticate_publickey_with(user, identity.public_key().into_owned(), None, &mut agent).await;
        if let Ok(AuthResult::Success) = result {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Connects to `target`, through its jump host if it has one. Returns the session handle and
/// the jump connections, which must stay alive as long as it does.
async fn connect(target: &Target, verifier: Arc<dyn Verifier>, sink: &dyn Sink) -> Result<(Handle<Client>, Vec<Handle<Client>>), String> {
    let client = Client { verifier: verifier.clone(), host: target.host.clone(), port: target.port };
    let (mut handle, hops) = match &target.jump {
        None => {
            let address = (target.host.as_str(), target.port);
            let handle = client::connect(config(), address, client).await.map_err(|error| fail(&format!("connect to {}:{}", target.host, target.port), error))?;
            (handle, Vec::new())
        }
        Some(jump) => {
            let (via, mut hops) = Box::pin(connect(jump, verifier, sink)).await?;
            let channel = via
                .channel_open_direct_tcpip(target.host.clone(), target.port as u32, "127.0.0.1", 0)
                .await
                .map_err(|error| fail(&format!("open {}:{} through {}", target.host, target.port, jump.host), error))?;
            hops.push(via);
            let handle = client::connect_stream(config(), channel.into_stream(), client).await.map_err(|error| fail(&format!("connect to {}", target.host), error))?;
            (handle, hops)
        }
    };
    sink.status("authenticating");
    authenticate(&mut handle, target).await?;
    Ok((handle, hops))
}

/// A local port carried to an address the server can reach (`ssh -L`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

/// How one connection attempt ended.
enum Ended {
    /// The user closed it, or the shell exited: `Some` carries a non-zero exit.
    Done(Option<String>),
    /// The link dropped after the shell was up: worth reconnecting.
    Lost(String),
    /// It never came up (refused key, wrong password): retrying would not help.
    Failed(String),
}

/// Pty size, kept across reconnects.
#[derive(Clone, Copy)]
struct Size(u32, u32, u32, u32);

/// Keystroke-to-echo time: what a person typing on a slow link actually feels.
struct Latency {
    sent: Option<tokio::time::Instant>,
    average: Option<f64>,
    reported: Option<tokio::time::Instant>,
}

impl Latency {
    fn echo(&mut self, sink: &dyn Sink) {
        let Some(sent) = self.sent.take() else { return };
        let sample = sent.elapsed().as_secs_f64() * 1000.0;
        let average = self.average.map_or(sample, |average| average * 0.7 + sample * 0.3);
        self.average = Some(average);
        if self.reported.is_none_or(|at| at.elapsed() > Duration::from_millis(800)) {
            self.reported = Some(tokio::time::Instant::now());
            sink.notice("latency", &format!("{}", average.round() as u64));
        }
    }
}

fn forward(handle: Arc<Handle<Client>>, rule: Forward, sink: Arc<dyn Sink>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let label = format!("{}:{}:{}", rule.local_port, rule.remote_host, rule.remote_port);
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", rule.local_port)).await {
            Ok(listener) => listener,
            Err(error) => return sink.notice("forward.error", &format!("{label} {error}")),
        };
        sink.notice("forward.up", &label);
        while let Ok((mut socket, peer)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            let handle = handle.clone();
            let rule = rule.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                match handle.channel_open_direct_tcpip(rule.remote_host.clone(), rule.remote_port as u32, peer.ip().to_string(), peer.port() as u32).await {
                    Ok(channel) => {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
                    }
                    Err(error) => sink.notice("forward.error", &format!("{}:{}:{} {error}", rule.local_port, rule.remote_host, rule.remote_port)),
                }
            });
        }
    })
}

async fn session(target: &Target, size: &mut Size, verifier: Arc<dyn Verifier>, sink: &Arc<dyn Sink>, commands: &mut mpsc::UnboundedReceiver<Command>) -> Ended {
    let (handle, _hops) = match connect(target, verifier, &**sink).await {
        Ok(connected) => connected,
        Err(error) => return Ended::Failed(error),
    };
    let handle = Arc::new(handle);
    let mut channel = match handle.channel_open_session().await {
        Ok(channel) => channel,
        Err(error) => return Ended::Lost(fail("open a session", error)),
    };
    let Size(columns, lines, width, height) = *size;
    if let Err(error) = channel.request_pty(false, "xterm-256color", columns, lines, width, height, &[]).await {
        return Ended::Lost(fail("request a terminal", error));
    }
    if let Err(error) = channel.request_shell(false).await {
        return Ended::Lost(fail("start the shell", error));
    }
    let forwards: Vec<_> = target.forwards.iter().map(|rule| forward(handle.clone(), rule.clone(), sink.clone())).collect();
    let stop = |forwards: &[tokio::task::JoinHandle<()>]| forwards.iter().for_each(|task| task.abort());
    sink.status("connected");
    let mut latency = Latency { sent: None, average: None, reported: None };
    let mut exit = None;
    let ended = loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Write(bytes)) => {
                    if latency.sent.is_none() {
                        latency.sent = Some(tokio::time::Instant::now());
                    }
                    if let Err(error) = channel.data_bytes(bytes).await {
                        break Ended::Lost(fail("send", error));
                    }
                }
                Some(Command::Resize(columns, lines, width, height)) => {
                    *size = Size(columns, lines, width, height);
                    let _ = channel.window_change(columns, lines, width, height).await;
                }
                Some(Command::Close) | None => {
                    let _ = channel.eof().await;
                    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                    break Ended::Done(None);
                }
            },
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) => {
                    latency.echo(&**sink);
                    sink.data(&data);
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => sink.data(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(exit_status),
                Some(ChannelMsg::Eof) => {}
                Some(ChannelMsg::Close) | None => {
                    break if exit.is_none() && handle.is_closed() {
                        Ended::Lost("the connection was lost".into())
                    } else {
                        Ended::Done(exit.filter(|code| *code != 0).map(|code| format!("exited with code {code}")))
                    };
                }
                Some(_) => {}
            },
        }
    };
    stop(&forwards);
    ended
}

/// Connects, and after a dropped link connects again with backoff until the user closes the
/// tab: on a flaky or long link the session comes back by itself.
async fn run(target: Target, columns: u32, lines: u32, verifier: Arc<dyn Verifier>, sink: Arc<dyn Sink>, mut commands: mpsc::UnboundedReceiver<Command>) -> Option<String> {
    let mut size = Size(columns, lines, 0, 0);
    let mut delay = Duration::from_secs(1);
    let mut connected_once = false;
    loop {
        sink.status(if connected_once { "reconnecting" } else { "connecting" });
        let ended = session(&target, &mut size, verifier.clone(), &sink, &mut commands).await;
        // A link that came up and then dropped starts the backoff over: a session that drops
        // now and then all day reconnects as fast the tenth time as the first.
        if matches!(ended, Ended::Lost(_)) {
            delay = Duration::from_secs(1);
        }
        match ended {
            Ended::Done(reason) => return reason,
            Ended::Failed(reason) if !connected_once => return Some(reason),
            Ended::Failed(reason) | Ended::Lost(reason) => {
                connected_once = true;
                sink.notice("reconnect", &format!("{reason}; retrying in {} s", delay.as_secs()));
                sink.data(format!("\r\n\x1b[2m[termio] {reason}. Reconnecting in {} s…\x1b[0m\r\n", delay.as_secs()).as_bytes());
                // Wait out the backoff, but a close request still ends it at once.
                let deadline = tokio::time::sleep(delay);
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        command = commands.recv() => match command {
                            Some(Command::Close) | None => return None,
                            Some(Command::Resize(columns, lines, width, height)) => size = Size(columns, lines, width, height),
                            Some(Command::Write(_)) => {}
                        },
                    }
                }
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

impl SshShell {
    /// Starts connecting and returns at once; progress and output arrive on `sink`.
    pub fn connect(target: Target, columns: u16, lines: u16, verifier: Arc<dyn Verifier>, sink: Arc<dyn Sink>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        runtime().spawn(async move {
            let reason = run(target, columns.max(1) as u32, lines.max(1) as u32, verifier, sink.clone(), rx).await;
            sink.closed(reason);
        });
        Self { commands: tx }
    }
}

/// Runs `command` on the server and returns its standard output once it has printed a line
/// containing `until` or ended, whichever comes first (a program that keeps running after its
/// announcement, like the agent, does not hold the caller).
pub async fn exec_until(target: &Target, verifier: Arc<dyn Verifier>, command: &str, until: &str) -> Result<String, String> {
    let (handle, _hops) = connect(target, verifier, &Quiet).await?;
    let mut channel = handle.channel_open_session().await.map_err(|error| fail("open a channel", error))?;
    channel.exec(true, command).await.map_err(|error| fail("run the command", error))?;
    let mut output = Vec::new();
    let collect = async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    output.extend_from_slice(&data);
                    if String::from_utf8_lossy(&output).lines().any(|line| line.contains(until)) {
                        break;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(20), collect).await;
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// One entry of a remote directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub directory: bool,
    pub size: u64,
    /// Seconds since the epoch.
    pub modified: u64,
}

/// A file transfer session on its own connection, so a big copy never slows the shell.
pub struct Sftp {
    session: russh_sftp::client::SftpSession,
    _handle: Handle<Client>,
    _hops: Vec<Handle<Client>>,
}

struct Quiet;
impl Sink for Quiet {
    fn data(&self, _: &[u8]) {}
    fn closed(&self, _: Option<String>) {}
}

impl Sftp {
    pub async fn connect(target: &Target, verifier: Arc<dyn Verifier>) -> Result<Self, String> {
        let (handle, hops) = connect(target, verifier, &Quiet).await?;
        let channel = handle.channel_open_session().await.map_err(|error| fail("open a channel", error))?;
        channel.request_subsystem(true, "sftp").await.map_err(|error| fail("start SFTP", error))?;
        let session = russh_sftp::client::SftpSession::new(channel.into_stream()).await.map_err(|error| fail("SFTP", error))?;
        Ok(Self { session, _handle: handle, _hops: hops })
    }

    pub async fn home(&self) -> Result<String, String> {
        self.session.canonicalize(".").await.map_err(|error| error.to_string())
    }

    /// Directories first, then by name.
    pub async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, String> {
        let mut entries: Vec<RemoteEntry> = self
            .session
            .read_dir(path)
            .await
            .map_err(|error| error.to_string())?
            .filter(|entry| entry.file_name() != "." && entry.file_name() != "..")
            .map(|entry| {
                let meta = entry.metadata();
                RemoteEntry { name: entry.file_name(), directory: meta.is_dir(), size: meta.size.unwrap_or(0), modified: meta.mtime.unwrap_or(0) as u64 }
            })
            .collect();
        entries.sort_by(|a, b| b.directory.cmp(&a.directory).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
        Ok(entries)
    }

    /// Streams a remote file to disk; `progress` gets the bytes done so far.
    pub async fn download(&self, remote: &str, local: &std::path::Path, progress: impl Fn(u64)) -> Result<u64, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut source = self.session.open(remote).await.map_err(|error| error.to_string())?;
        let mut target = tokio::fs::File::create(local).await.map_err(|error| error.to_string())?;
        let mut buffer = vec![0u8; 256 * 1024];
        let mut done = 0u64;
        loop {
            let read = source.read(&mut buffer).await.map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            target.write_all(&buffer[..read]).await.map_err(|error| error.to_string())?;
            done += read as u64;
            progress(done);
        }
        target.flush().await.map_err(|error| error.to_string())?;
        Ok(done)
    }

    pub async fn upload(&self, local: &std::path::Path, remote: &str, progress: impl Fn(u64)) -> Result<u64, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut source = tokio::fs::File::open(local).await.map_err(|error| error.to_string())?;
        let mut target = self.session.create(remote).await.map_err(|error| error.to_string())?;
        let mut buffer = vec![0u8; 256 * 1024];
        let mut done = 0u64;
        loop {
            let read = source.read(&mut buffer).await.map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            target.write_all(&buffer[..read]).await.map_err(|error| error.to_string())?;
            done += read as u64;
            progress(done);
        }
        target.shutdown().await.map_err(|error| error.to_string())?;
        Ok(done)
    }

    pub async fn mkdir(&self, path: &str) -> Result<(), String> {
        self.session.create_dir(path).await.map_err(|error| error.to_string())
    }

    pub async fn remove(&self, path: &str, directory: bool) -> Result<(), String> {
        if directory { self.session.remove_dir(path).await } else { self.session.remove_file(path).await }.map_err(|error| error.to_string())
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        self.session.rename(from, to).await.map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::server::{self, Auth as ServerAuth, Msg, Server as _, Session};
    use russh::{Channel, ChannelId};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    /// A server that accepts one password and echoes the pty back, prefixed.
    #[derive(Clone)]
    struct Echo {
        sizes: Arc<Mutex<Vec<(u32, u32)>>>,
        /// Session channels: data on forwarded channels belongs to the forward.
        shells: Arc<Mutex<Vec<ChannelId>>>,
        /// Open session channels, until one becomes an SFTP subsystem.
        channels: Arc<Mutex<std::collections::HashMap<ChannelId, Channel<Msg>>>>,
        files: Arc<Mutex<MemoryFs>>,
        /// Whether `termio-agent serve` exists on this "server".
        agent: bool,
        /// The agents it started, to check when they end.
        agents: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    }

    impl server::Server for Echo {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for Echo {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<ServerAuth, Self::Error> {
            Ok(if user == "termio" && password == "secret" { ServerAuth::Accept } else { ServerAuth::reject() })
        }

        async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: server::ChannelOpenHandle, _session: &mut Session) -> Result<(), Self::Error> {
            self.shells.lock().unwrap().push(channel.id());
            self.channels.lock().unwrap().insert(channel.id(), channel);
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let command = String::from_utf8_lossy(command);
            if !command.contains("termio-agent") {
                session.close(channel)?;
                return Ok(());
            }
            if !self.agent {
                session.data(channel, &b"TERMIO-AGENT-MISSING\n"[..])?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }
            // The real agent, in process: a shell over QUIC on localhost.
            let shell = if cfg!(windows) { portable_pty::CommandBuilder::new("cmd.exe") } else { portable_pty::CommandBuilder::new("/bin/sh") };
            let agent = termio_agent::serve("127.0.0.1:0".parse().unwrap(), Some(shell)).await.unwrap();
            session.data(channel, format!("Last login: yesterday\n{}\n", agent.rendezvous.line()).into_bytes())?;
            session.eof(channel)?;
            self.agents.lock().unwrap().push(agent.done);
            Ok(())
        }

        async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
            self.shells.lock().unwrap().retain(|id| *id != channel);
            let stream = self.channels.lock().unwrap().remove(&channel);
            match (name, stream) {
                ("sftp", Some(stream)) => {
                    session.channel_success(channel)?;
                    let files = self.files.clone();
                    tokio::spawn(russh_sftp::server::run(stream.into_stream(), SftpServer { files, handles: Default::default(), next: 0 }));
                }
                _ => session.channel_failure(channel)?,
            }
            Ok(())
        }

        /// What a jump host does: pipe the channel to the requested address.
        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host: &str,
            port: u32,
            _: &str,
            _: u32,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            let Ok(mut socket) = tokio::net::TcpStream::connect((host, port as u16)).await else { return Ok(()) };
            reply.accept().await;
            tokio::spawn(async move {
                let mut stream = channel.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut socket).await;
            });
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _term: &str,
            columns: u32,
            lines: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.sizes.lock().unwrap().push((columns, lines));
            session.channel_success(channel)?;
            Ok(())
        }

        async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
            session.data(channel, &b"welcome\r\n"[..])?;
            Ok(())
        }

        async fn window_change_request(&mut self, _: ChannelId, columns: u32, lines: u32, _: u32, _: u32, _: &mut Session) -> Result<(), Self::Error> {
            self.sizes.lock().unwrap().push((columns, lines));
            Ok(())
        }

        async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            if !self.shells.lock().unwrap().contains(&channel) {
                return Ok(());
            }
            if data == b"drop\r" {
                // A link that dies under the shell: no exit status, no channel close.
                session.disconnect(russh::Disconnect::ByApplication, "dropped", "en")?;
                return Ok(());
            }
            if data == b"exit\r" {
                session.exit_status_request(channel, 3)?;
                session.close(channel)?;
                return Ok(());
            }
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(data);
            session.data(channel, reply)?;
            Ok(())
        }
    }

    async fn serve() -> (u16, Arc<Mutex<Vec<(u32, u32)>>>, String) {
        serve_with(false).await
    }

    async fn serve_with(agent: bool) -> (u16, Arc<Mutex<Vec<(u32, u32)>>>, String) {
        let (port, sizes, fingerprint, _) = serve_agents(agent).await;
        (port, sizes, fingerprint)
    }

    async fn serve_agents(agent: bool) -> (u16, Arc<Mutex<Vec<(u32, u32)>>>, String, Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>) {
        let key = crate::keys::load(&crate::keys::generate_ed25519("server").unwrap().0, None).unwrap();
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let agents: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
        let mut server = Echo { sizes: sizes.clone(), shells: Arc::default(), channels: Arc::default(), files: Arc::default(), agent, agents: agents.clone() };
        tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });
        (port, sizes, fingerprint, agents)
    }

    struct Answer {
        trust: bool,
        asked: Mutex<Vec<HostKey>>,
    }

    impl Verifier for Answer {
        fn verify(&self, key: HostKey, answer: oneshot::Sender<bool>) {
            self.asked.lock().unwrap().push(key);
            let _ = answer.send(self.trust);
        }
    }

    #[derive(Default)]
    struct Collect {
        output: Mutex<Vec<u8>>,
        statuses: Mutex<Vec<String>>,
        closed: Mutex<Option<Option<String>>>,
        events: AtomicUsize,
        notices: Mutex<Vec<(String, String)>>,
    }

    impl Sink for Collect {
        fn data(&self, bytes: &[u8]) {
            self.output.lock().unwrap().extend_from_slice(bytes);
            self.events.fetch_add(1, Ordering::SeqCst);
        }
        fn closed(&self, reason: Option<String>) {
            *self.closed.lock().unwrap() = Some(reason);
            self.events.fetch_add(1, Ordering::SeqCst);
        }
        fn status(&self, status: &str) {
            self.statuses.lock().unwrap().push(status.to_owned());
        }
        fn notice(&self, kind: &str, detail: &str) {
            self.notices.lock().unwrap().push((kind.to_owned(), detail.to_owned()));
        }
    }

    fn wait_for(what: &str, test: impl Fn() -> bool) {
        for _ in 0..500 {
            if test() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    fn target(port: u16, password: &str) -> Target {
        Target { host: "127.0.0.1".into(), port, user: "termio".into(), auth: vec![Auth::Password(Zeroizing::new(password.into()))], jump: None, forwards: Vec::new() }
    }

    #[test]
    fn a_shell_runs_over_ssh_with_resize_and_exit_status() {
        let (port, sizes, fingerprint) = runtime().block_on(serve());
        let verifier = Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) });
        let sink = Arc::new(Collect::default());
        let shell = SshShell::connect(target(port, "secret"), 100, 30, verifier.clone(), sink.clone());
        wait_for("the welcome", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("welcome"));
        assert_eq!(verifier.asked.lock().unwrap()[0].fingerprint, fingerprint, "the caller is shown the server's real key");
        assert_eq!(*sink.statuses.lock().unwrap(), ["connecting", "authenticating", "connected"]);

        shell.write(b"ls").unwrap();
        wait_for("the echo", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("echo:ls"));
        shell.resize(120, 40, 0, 0).unwrap();
        wait_for("the resize", || sizes.lock().unwrap().len() == 2);
        assert_eq!(*sizes.lock().unwrap(), [(100, 30), (120, 40)]);

        shell.write(b"exit\r").unwrap();
        wait_for("the close", || sink.closed.lock().unwrap().is_some());
        assert_eq!(*sink.closed.lock().unwrap(), Some(Some("exited with code 3".into())));
    }

    #[test]
    fn a_rejected_host_key_or_wrong_password_ends_the_attempt_with_a_reason() {
        let (port, _, _) = runtime().block_on(serve());
        let distrust = Arc::new(Answer { trust: false, asked: Mutex::new(Vec::new()) });
        let sink = Arc::new(Collect::default());
        let _shell = SshShell::connect(target(port, "secret"), 80, 24, distrust, sink.clone());
        wait_for("the refusal", || sink.closed.lock().unwrap().is_some());
        assert!(sink.closed.lock().unwrap().clone().unwrap().is_some(), "an untrusted server never gets a session");
        assert!(sink.output.lock().unwrap().is_empty());

        let trust = Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) });
        let sink = Arc::new(Collect::default());
        let _shell = SshShell::connect(target(port, "wrong"), 80, 24, trust, sink.clone());
        wait_for("the failure", || sink.closed.lock().unwrap().is_some());
        assert_eq!(*sink.closed.lock().unwrap(), Some(Some("wrong password".into())));
    }

    #[test]
    fn a_jump_host_carries_the_connection() {
        let (jump_port, _, _) = runtime().block_on(serve());
        let (port, _, _) = runtime().block_on(serve());
        let verifier = Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) });
        let sink = Arc::new(Collect::default());
        let mut via = target(port, "secret");
        via.jump = Some(Box::new(target(jump_port, "secret")));
        let _shell = SshShell::connect(via, 80, 24, verifier.clone(), sink.clone());
        wait_for("the welcome", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("welcome") || sink.closed.lock().unwrap().is_some());
        assert!(sink.closed.lock().unwrap().is_none(), "{:?}", sink.closed.lock().unwrap());
        let asked: Vec<u16> = verifier.asked.lock().unwrap().iter().map(|key| key.port).collect();
        assert_eq!(asked, [jump_port, port], "both servers' keys are checked, jump first");
    }

    include!("ssh_tests.rs");
}
