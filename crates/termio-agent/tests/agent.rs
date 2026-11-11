//! End to end over real QUIC on localhost: a client, the agent, and a shell in a pty.

use portable_pty::CommandBuilder;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use termio_agent::client::{Command, Events, run};
use termio_agent::{Rendezvous, serve};
use termio_vt::{Theme, Vt};
use tokio::sync::mpsc;

/// A client screen: frames replayed into an emulator, as the app does.
struct Screen {
    vt: Mutex<Vt>,
    statuses: Mutex<Vec<String>>,
    ended: Mutex<Option<Option<String>>>,
    latency: Mutex<Option<u64>>,
    received: Mutex<u64>,
}

impl Screen {
    fn new() -> Arc<Self> {
        Arc::new(Self { vt: Mutex::new(Vt::new(100, 30, Theme::default(), 0)), statuses: Mutex::default(), ended: Mutex::default(), latency: Mutex::default(), received: Mutex::default() })
    }

    fn text(&self) -> String {
        let vt = self.vt.lock().unwrap();
        (0..vt.size().1).map(|line| vt.row_text(line)).collect::<Vec<_>>().join("\n")
    }
}

impl Events for Screen {
    fn screen(&self, bytes: &[u8]) {
        self.vt.lock().unwrap().feed(bytes);
    }
    fn status(&self, status: &str) {
        self.statuses.lock().unwrap().push(status.to_owned());
    }
    fn latency(&self, ms: u64) {
        *self.latency.lock().unwrap() = Some(ms);
    }
    fn received(&self, bytes: u64) {
        *self.received.lock().unwrap() = bytes;
    }
    fn ended(&self, reason: Option<String>) {
        *self.ended.lock().unwrap() = Some(reason);
    }
}

fn shell() -> CommandBuilder {
    if cfg!(windows) { CommandBuilder::new("cmd.exe") } else { CommandBuilder::new("/bin/sh") }
}

async fn until(what: &str, timeout: Duration, test: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if test() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn client(address: SocketAddr, rendezvous: Rendezvous, screen: Arc<Screen>) -> (mpsc::UnboundedSender<Command>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run(address, rendezvous, 100, 30, screen, rx));
    (tx, task)
}

fn typed(tx: &mpsc::UnboundedSender<Command>, line: &str) {
    tx.send(Command::Input(format!("{line}\r").into_bytes())).unwrap();
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shell_runs_through_the_agent_and_survives_a_disconnect() {
    let agent = serve("127.0.0.1:0".parse().unwrap(), Some(shell())).await.unwrap();
    let line = agent.rendezvous.line();
    assert_eq!(Rendezvous::parse(&format!("Welcome to Ubuntu\n{line}\n")), Some(agent.rendezvous.clone()), "the line is found after a login banner");

    let first = Screen::new();
    let (tx, task) = client(localhost(agent.rendezvous.port), agent.rendezvous.clone(), first.clone());
    typed(&tx, "echo termio-agent-ok");
    until("the echo", Duration::from_secs(20), || first.text().lines().any(|line| line.trim() == "termio-agent-ok")).await;
    assert!(first.latency.lock().unwrap().is_some(), "typing reports keystroke-to-screen time");

    // Leave without ending the shell, then come back from a new client: same session.
    tx.send(Command::Detach).unwrap();
    task.await.unwrap();
    assert_eq!(*first.ended.lock().unwrap(), Some(Some("detached".into())));

    let second = Screen::new();
    let (tx, task) = client(localhost(agent.rendezvous.port), agent.rendezvous.clone(), second.clone());
    until("the resumed screen", Duration::from_secs(20), || second.text().contains("termio-agent-ok")).await;
    typed(&tx, "echo still-the-same-shell");
    until("the second echo", Duration::from_secs(20), || second.text().lines().any(|line| line.trim() == "still-the-same-shell")).await;

    typed(&tx, "exit");
    until("the end", Duration::from_secs(20), || second.ended.lock().unwrap().is_some()).await;
    assert_eq!(*second.ended.lock().unwrap(), Some(None), "a clean exit ends the session");
    task.await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), agent.done).await.expect("the agent stops with its shell").unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_token_or_certificate_gets_nothing() {
    let agent = serve("127.0.0.1:0".parse().unwrap(), Some(shell())).await.unwrap();
    let mut wrong_token = agent.rendezvous.clone();
    wrong_token.token[0] ^= 1;
    let screen = Screen::new();
    let (_tx, task) = client(localhost(agent.rendezvous.port), wrong_token, screen.clone());
    until("the refusal", Duration::from_secs(20), || screen.ended.lock().unwrap().is_some()).await;
    assert!(screen.ended.lock().unwrap().clone().unwrap().unwrap().contains("refused"));
    assert!(screen.text().trim().is_empty(), "no screen for a stranger");
    task.await.unwrap();

    let mut wrong_cert = agent.rendezvous.clone();
    wrong_cert.cert[0] ^= 1;
    let screen = Screen::new();
    let (tx, _task) = client(localhost(agent.rendezvous.port), wrong_cert, screen.clone());
    until("a failed handshake", Duration::from_secs(20), || screen.statuses.lock().unwrap().iter().any(|status| status == "reconnecting")).await;
    assert!(screen.text().trim().is_empty(), "an impostor certificate is never trusted");
    tx.send(Command::Close).unwrap();
}

/// Closing the tab ends the shell on the server even while a program holds the terminal: the
/// agent kills it rather than waiting for a prompt that will not come.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_tab_ends_the_remote_shell_even_mid_program() {
    let agent = serve("127.0.0.1:0".parse().unwrap(), Some(shell())).await.unwrap();
    let screen = Screen::new();
    let (tx, task) = client(localhost(agent.rendezvous.port), agent.rendezvous.clone(), screen.clone());
    let busy = if cfg!(windows) { "ping -n 600 127.0.0.1" } else { "sleep 600" };
    typed(&tx, busy);
    until("the program to start", Duration::from_secs(20), || screen.text().contains(if cfg!(windows) { "Pinging" } else { "sleep 600" }) || screen.text().contains("Disparando")).await;
    let closed_at = Instant::now();
    tx.send(Command::Close).unwrap();
    task.await.unwrap();
    assert_eq!(*screen.ended.lock().unwrap(), Some(None));
    tokio::time::timeout(Duration::from_secs(10), agent.done).await.expect("the agent ends its session when the tab closes").unwrap();
    assert!(closed_at.elapsed() < Duration::from_secs(10), "it took {:?}", closed_at.elapsed());
}

/// The shipped binary, as SSH starts it: the first line it prints is enough to connect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_binary_prints_a_rendezvous_and_serves_it() {
    use std::io::BufRead;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_termio-agent"))
        .args(["serve", "--bind", "127.0.0.1:0"])
        .env("TERMIO_AGENT_SHELL", if cfg!(windows) { "cmd.exe" } else { "/bin/sh" })
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let rendezvous = Rendezvous::parse(&line).unwrap_or_else(|| panic!("no rendezvous in {line:?}"));
    let screen = Screen::new();
    let (tx, task) = client(localhost(rendezvous.port), rendezvous, screen.clone());
    typed(&tx, "echo from-the-binary");
    until("the echo", Duration::from_secs(20), || screen.text().lines().any(|line| line.trim() == "from-the-binary")).await;
    typed(&tx, "exit");
    until("the end", Duration::from_secs(20), || screen.ended.lock().unwrap().is_some()).await;
    task.await.unwrap();
    let status = tokio::task::spawn_blocking(move || child.wait()).await.unwrap().unwrap();
    assert!(status.success(), "the agent exits with its shell");
}

/// The point of state sync: a flood of output costs screens, not bytes. The gate: the link
/// carries far less than the program wrote, and the client still ends on the final screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_output_is_sent_as_screens_not_bytes() {
    let agent = serve("127.0.0.1:0".parse().unwrap(), Some(shell())).await.unwrap();
    let screen = Screen::new();
    let (tx, _task) = client(localhost(agent.rendezvous.port), agent.rendezvous.clone(), screen.clone());
    until("the prompt", Duration::from_secs(20), || !screen.text().trim().is_empty()).await;
    let lines = 40_000;
    let (command, last) = if cfg!(windows) {
        (format!("for /l %i in (1,1,{lines}) do @echo flood line %i padding padding padding"), format!("flood line {lines} padding padding padding"))
    } else {
        (format!("i=1; while [ $i -le {lines} ]; do echo \"flood line $i padding padding padding\"; i=$((i+1)); done"), format!("flood line {lines} padding padding padding"))
    };
    let started = Instant::now();
    typed(&tx, &command);
    until("the last line", Duration::from_secs(180), || screen.text().lines().any(|line| line.trim() == last)).await;
    let seconds = started.elapsed().as_secs_f64();
    let raw = (1..=lines).map(|n| format!("flood line {n} padding padding padding\r\n").len()).sum::<usize>() as f64;
    let wire = *screen.received.lock().unwrap() as f64;
    eprintln!("flood: program wrote {:.0} KB in {seconds:.1} s, the link carried {:.0} KB ({:.1}x less, {:.0} KB/s)", raw / 1024.0, wire / 1024.0, raw / wire, wire / 1024.0 / seconds);
    assert!(wire < raw / 4.0, "the link carried {wire} bytes for {raw} bytes of output");
    tx.send(Command::Close).unwrap();
}
