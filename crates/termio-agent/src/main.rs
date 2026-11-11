//! `termio-agent serve [--bind ADDR]`: starts a shell session, prints the rendezvous line for
//! the client that launched it over SSH, and serves the session over QUIC until the shell exits
//! or nobody reconnects for 15 minutes.

use std::io::Write;
use std::net::SocketAddr;

fn usage() -> ! {
    eprintln!("usage: termio-agent serve [--bind 0.0.0.0:0]");
    std::process::exit(2);
}

/// Lets the SSH command that started the agent finish while the agent keeps running.
#[cfg(unix)]
fn detach() {
    // SAFETY: plain libc calls on our own process; the descriptors are ours.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::setsid();
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
            libc::dup2(null, 1);
            libc::dup2(null, 2);
        }
    }
}

#[cfg(not(unix))]
fn detach() {}

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("serve") {
        usage();
    }
    let mut bind: SocketAddr = "0.0.0.0:0".parse().expect("valid address");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => bind = args.next().and_then(|value| value.parse().ok()).unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("start the runtime");
    runtime.block_on(async {
        let agent = match termio_agent::serve(bind, None).await {
            Ok(agent) => agent,
            Err(error) => {
                eprintln!("termio-agent: {error}");
                std::process::exit(1);
            }
        };
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{}", agent.rendezvous.line());
        let _ = out.flush();
        detach();
        let _ = agent.done.await;
    });
}
