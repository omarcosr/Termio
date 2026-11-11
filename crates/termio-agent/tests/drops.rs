//! A link that goes dead and comes back, through a UDP relay the test can cut. Its own test
//! binary, because it shortens QUIC's idle timeout for the whole process.

use portable_pty::CommandBuilder;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use termio_agent::client::{Command, Events, run};
use termio_agent::serve;
use termio_vt::{Theme, Vt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct Screen {
    vt: Mutex<Vt>,
    statuses: Mutex<Vec<String>>,
    ended: Mutex<Option<Option<String>>>,
}

impl Screen {
    fn text(&self) -> String {
        let vt = self.vt.lock().unwrap();
        (0..vt.size().1).map(|line| vt.row_text(line)).collect::<Vec<_>>().join("\n")
    }
    fn count(&self, status: &str) -> usize {
        self.statuses.lock().unwrap().iter().filter(|seen| *seen == status).count()
    }
}

impl Events for Screen {
    fn screen(&self, bytes: &[u8]) {
        self.vt.lock().unwrap().feed(bytes);
    }
    fn status(&self, status: &str) {
        self.statuses.lock().unwrap().push(status.to_owned());
    }
    fn latency(&self, _: u64) {}
    fn ended(&self, reason: Option<String>) {
        *self.ended.lock().unwrap() = Some(reason);
    }
}

/// Relays datagrams between one client and the agent; while `cut`, drops them all.
async fn relay(agent: SocketAddr, cut: Arc<AtomicBool>) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    back.connect(agent).await.unwrap();
    let address = front.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    let (f, b, c, k) = (front.clone(), back.clone(), client.clone(), cut.clone());
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65536];
        while let Ok((read, from)) = f.recv_from(&mut buffer).await {
            *c.lock().unwrap() = Some(from);
            if !k.load(Ordering::SeqCst) {
                let _ = b.send(&buffer[..read]).await;
            }
        }
    });
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65536];
        while let Ok(read) = back.recv(&mut buffer).await {
            let to = *client.lock().unwrap();
            if let (Some(to), false) = (to, cut.load(Ordering::SeqCst)) {
                let _ = front.send_to(&buffer[..read], to).await;
            }
        }
    });
    address
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_survives_repeated_drops_and_closing_while_down_ends_it() {
    // SAFETY: set before any QUIC endpoint exists, in a test binary with this one test.
    unsafe { std::env::set_var("TERMIO_QUIC_IDLE_MS", "1500") };
    let shell = if cfg!(windows) { CommandBuilder::new("cmd.exe") } else { CommandBuilder::new("/bin/sh") };
    let agent = serve("127.0.0.1:0".parse().unwrap(), Some(shell)).await.unwrap();
    let cut = Arc::new(AtomicBool::new(false));
    let front = relay(agent.local, cut.clone()).await;

    let screen = Arc::new(Screen { vt: Mutex::new(Vt::new(100, 30, Theme::default(), 0)), statuses: Mutex::default(), ended: Mutex::default() });
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run(front, agent.rendezvous.clone(), 100, 30, screen.clone(), rx));

    // Several drops in a row, each long enough for QUIC to give the connection up. Each time
    // the client must come back quickly: the backoff starts over after every good connection.
    for round in 1..=4 {
        until("a connection", Duration::from_secs(20), || screen.count("connected") == round).await;
        tx.send(Command::Input(format!("echo round-{round}\r").into_bytes())).unwrap();
        until("the echo", Duration::from_secs(20), || screen.text().lines().any(|line| line.trim() == format!("round-{round}"))).await;
        cut.store(true, Ordering::SeqCst);
        until("the drop to be noticed", Duration::from_secs(20), || screen.count("reconnecting") >= round).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        cut.store(false, Ordering::SeqCst);
        let back_at = Instant::now();
        until("the reconnect", Duration::from_secs(20), || screen.count("connected") == round + 1).await;
        assert!(back_at.elapsed() < Duration::from_secs(4), "round {round}: reconnecting took {:?}", back_at.elapsed());
    }
    assert!(screen.text().contains("round-1") || screen.text().contains("round-4"), "the same shell all along");

    // Down again, and the tab is closed before the link returns: once it does, the agent hears
    // about it and ends the shell.
    cut.store(true, Ordering::SeqCst);
    until("the last drop", Duration::from_secs(20), || screen.count("reconnecting") >= 5).await;
    let restore = cut.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        restore.store(false, Ordering::SeqCst);
    });
    tx.send(Command::Close).unwrap();
    task.await.unwrap();
    assert_eq!(*screen.ended.lock().unwrap(), Some(None));
    tokio::time::timeout(Duration::from_secs(10), agent.done).await.expect("closing while disconnected still ends the remote shell").unwrap();
}
