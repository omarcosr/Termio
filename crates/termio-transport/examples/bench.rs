//! Plain SSH against termio-agent on a real server, same machine, same moment.
//!
//!   TERMIO_BENCH_PASSWORD=... cargo run --release -p termio-transport --example bench -- root@host[:port] [--rounds N]
//!
//! Per transport: time to a usable prompt, keystroke echo latency (p50/p95 over N keys), and a
//! flood of output (`seq`): how long until the end of it is on screen and how many bytes reached
//! the terminal. Installs the agent into `~/.termio/bin` first when the server lacks it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use termio_transport::agent::AgentShell;
use termio_transport::ssh::{Auth, HostKey, Sftp, SshShell, Target, Verifier, exec_until, runtime};
use termio_transport::{Sink, Transport};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

struct Trust;
impl Verifier for Trust {
    fn verify(&self, key: HostKey, answer: oneshot::Sender<bool>) {
        eprintln!("  host key {} {}", key.algorithm, key.fingerprint);
        let _ = answer.send(true);
    }
}

#[derive(Default)]
struct Recorded {
    bytes: u64,
    text: Vec<u8>,
    last: Option<Instant>,
    transport: String,
    closed: Option<Option<String>>,
}

#[derive(Default)]
struct Probe(Mutex<Recorded>);

impl Sink for Probe {
    fn data(&self, bytes: &[u8]) {
        let mut state = self.0.lock().unwrap();
        state.bytes += bytes.len() as u64;
        state.text.extend_from_slice(bytes);
        let keep = state.text.len().saturating_sub(64 * 1024);
        state.text.drain(..keep);
        state.last = Some(Instant::now());
    }
    fn closed(&self, reason: Option<String>) {
        self.0.lock().unwrap().closed = Some(reason);
    }
    fn notice(&self, kind: &str, detail: &str) {
        if kind == "transport" {
            self.0.lock().unwrap().transport = detail.to_owned();
        }
    }
}

impl Probe {
    fn snapshot(&self) -> (u64, Option<Instant>) {
        let state = self.0.lock().unwrap();
        (state.bytes, state.last)
    }
    fn contains(&self, needle: &str) -> bool {
        String::from_utf8_lossy(&self.0.lock().unwrap().text).contains(needle)
    }
    fn clear(&self) {
        self.0.lock().unwrap().text.clear();
    }
}

fn wait_until(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

/// Waits until output has been quiet for `quiet`.
fn settle(probe: &Probe, quiet: Duration, limit: Duration) {
    let start = Instant::now();
    while start.elapsed() < limit {
        let (_, last) = probe.snapshot();
        if last.is_some_and(|last| last.elapsed() >= quiet) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

struct Result {
    name: &'static str,
    prompt_ms: f64,
    echo: Vec<f64>,
    flood_ms: f64,
    flood_bytes: u64,
    interrupt_ms: f64,
}

fn run(name: &'static str, target: &Target, rounds: usize, lines: u64) -> Option<Result> {
    eprintln!("\n== {name}");
    let probe = Arc::new(Probe::default());
    let started = Instant::now();
    let shell: Box<dyn Transport> = match name {
        "ssh" => Box::new(SshShell::connect(target.clone(), 120, 40, Arc::new(Trust), probe.clone())),
        _ => Box::new(AgentShell::connect(target.clone(), 120, 40, Arc::new(Trust), probe.clone())),
    };
    // A prompt is on screen when output arrives and then goes quiet.
    if !wait_until(Duration::from_secs(30), || probe.snapshot().0 > 0) {
        eprintln!("  no output in 30 s: {:?}", probe.0.lock().unwrap().closed);
        return None;
    }
    settle(&probe, Duration::from_millis(400), Duration::from_secs(20));
    let prompt_ms = (probe.snapshot().1.unwrap() - started).as_secs_f64() * 1000.0;
    let transport = probe.0.lock().unwrap().transport.clone();
    if name.starts_with("agent") && transport != "agent" {
        eprintln!("  the session fell back to plain SSH; not measuring it as the agent");
        shell.close();
        return None;
    }
    eprintln!("  prompt after {prompt_ms:.0} ms (transport: {})", if transport.is_empty() { "ssh" } else { &transport });

    // Echo: one key, time until the terminal changes; then erase it.
    let mut echo = Vec::new();
    for round in 0..rounds {
        let (before, _) = probe.snapshot();
        let sent = Instant::now();
        shell.write(b"x").ok()?;
        if wait_until(Duration::from_secs(5), || probe.snapshot().0 > before) {
            echo.push(sent.elapsed().as_secs_f64() * 1000.0);
        } else {
            eprintln!("  key {round}: no echo in 5 s");
        }
        // Erase it and wait for that echo too: on a slow link it would otherwise land during the
        // next sample and count as its echo.
        let (before, _) = probe.snapshot();
        shell.write(b"\x7f").ok()?;
        wait_until(Duration::from_secs(5), || probe.snapshot().0 > before);
        settle(&probe, Duration::from_millis(50), Duration::from_secs(5));
    }

    // Flood: the end marker is computed by the shell, so the typed command never matches it.
    probe.clear();
    let (before, _) = probe.snapshot();
    let sent = Instant::now();
    shell.write(format!("seq 1 {lines}; echo BENCH-$((40+2))\r").as_bytes()).ok()?;
    let done = wait_until(Duration::from_secs(300), || probe.contains("BENCH-42"));
    let flood_ms = sent.elapsed().as_secs_f64() * 1000.0;
    let flood_bytes = probe.snapshot().0 - before;
    if !done {
        eprintln!("  flood did not finish in 300 s");
    }
    eprintln!("  flood of {lines} lines: {flood_ms:.0} ms, {flood_bytes} bytes to the terminal");

    // Interrupt a flood that would never end on its own: how long until the shell answers again.
    // On plain SSH everything already in flight has to drain first.
    settle(&probe, Duration::from_millis(300), Duration::from_secs(30));
    shell.write(b"while :; do seq 1 100000; done\r").ok()?;
    std::thread::sleep(Duration::from_secs(2));
    probe.clear();
    let sent = Instant::now();
    shell.write(b"\x03").ok()?;
    shell.write(b"echo BENCH-$((40+4))\r").ok()?;
    let answered = wait_until(Duration::from_secs(300), || probe.contains("BENCH-44"));
    let interrupt_ms = sent.elapsed().as_secs_f64() * 1000.0;
    eprintln!("  ctrl+c during a flood: prompt back after {interrupt_ms:.0} ms{}", if answered { "" } else { " (gave up)" });
    settle(&probe, Duration::from_millis(300), Duration::from_secs(60));
    shell.write(b"exit\r").ok();
    std::thread::sleep(Duration::from_millis(500));
    shell.close();
    Some(Result { name, prompt_ms, echo, flood_ms, flood_bytes, interrupt_ms })
}

/// Puts the agent on the server when `~/.termio/bin` has none.
fn ensure_agent(target: &Target) {
    let check = runtime().block_on(exec_until(target, Arc::new(Trust), "test -x ~/.termio/bin/termio-agent && echo AGENT-YES || echo AGENT-NO", "AGENT-"));
    if check.as_deref().is_ok_and(|output| output.contains("AGENT-YES")) {
        return;
    }
    let binary = std::path::Path::new("dist/agent/termio-agent-linux-x64");
    eprintln!("installing the agent from {}", binary.display());
    runtime()
        .block_on(async {
            let sftp = Sftp::connect(target, Arc::new(Trust)).await?;
            let home = sftp.home().await?;
            let _ = sftp.mkdir(&format!("{home}/.termio")).await;
            let _ = sftp.mkdir(&format!("{home}/.termio/bin")).await;
            sftp.upload(binary, &format!("{home}/.termio/bin/termio-agent"), |_| {}).await?;
            exec_until(target, Arc::new(Trust), "chmod 755 ~/.termio/bin/termio-agent; echo AGENT-OK", "AGENT-OK").await
        })
        .expect("install the agent");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let destination = args.next().expect("usage: bench user@host[:port] [--rounds N] [--lines N]");
    let (mut rounds, mut lines) = (40usize, 200_000u64);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--rounds" => rounds = args.next().and_then(|value| value.parse().ok()).expect("--rounds N"),
            "--lines" => lines = args.next().and_then(|value| value.parse().ok()).expect("--lines N"),
            other => panic!("unknown flag {other}"),
        }
    }
    let (user, rest) = destination.split_once('@').expect("user@host");
    let (host, port) = rest.rsplit_once(':').map_or((rest, 22), |(host, port)| (host, port.parse().expect("port")));
    let password = std::env::var("TERMIO_BENCH_PASSWORD").expect("TERMIO_BENCH_PASSWORD");
    let target = Target { host: host.into(), port, user: user.into(), auth: vec![Auth::Password(Zeroizing::new(password))], jump: None, forwards: Vec::new() };

    let ping = Instant::now();
    let rtt = runtime().block_on(exec_until(&target, Arc::new(Trust), "echo PONG", "PONG")).map(|_| ping.elapsed());
    eprintln!("ssh exec round trip (connect + auth + command): {:?}", rtt);
    ensure_agent(&target);

    let results: Vec<Result> = ["ssh", "agent", "agent, warm"].into_iter().filter_map(|name| run(name, &target, rounds, lines)).collect();
    println!("\n| metric | {} |", results.iter().map(|result| result.name).collect::<Vec<_>>().join(" | "));
    println!("|---|{}", "---|".repeat(results.len()));
    let row = |label: &str, value: &dyn Fn(&Result) -> String| println!("| {label} | {} |", results.iter().map(value).collect::<Vec<_>>().join(" | "));
    row("prompt ready (ms)", &|r| format!("{:.0}", r.prompt_ms));
    let sorted = |r: &Result| {
        let mut echo = r.echo.clone();
        echo.sort_by(f64::total_cmp);
        echo
    };
    row("echo p50 (ms)", &|r| format!("{:.1}", percentile(&sorted(r), 0.5)));
    row("echo p95 (ms)", &|r| format!("{:.1}", percentile(&sorted(r), 0.95)));
    row("echo samples", &|r| r.echo.len().to_string());
    row(&format!("flood {lines} lines (ms)"), &|r| format!("{:.0}", r.flood_ms));
    row("flood bytes to terminal", &|r| format!("{} KB", r.flood_bytes / 1024));
    row("ctrl+c during flood, prompt back (ms)", &|r| format!("{:.0}", r.interrupt_ms));
}
