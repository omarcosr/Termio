// Included into `ssh::tests`: the test server's SFTP subsystem and the tests that use the
// forward, reconnect and SFTP paths.

/// An in-memory file system behind the test server's SFTP subsystem.
#[derive(Default)]
struct MemoryFs {
    files: std::collections::BTreeMap<String, Vec<u8>>,
    dirs: std::collections::BTreeSet<String>,
}

struct SftpServer {
    files: Arc<Mutex<MemoryFs>>,
    handles: std::collections::HashMap<String, (String, bool)>,
    next: u32,
}

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle as SftpHandle, Name, OpenFlags, Status, StatusCode, Version};

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "ok".into(), language_tag: "en".into() }
}

fn attrs(directory: bool, size: u64) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(if directory { 0o040755 } else { 0o100644 });
    attrs.size = Some(size);
    attrs.mtime = Some(1_700_000_000);
    attrs
}

impl russh_sftp::server::Handler for SftpServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _: u32, _: std::collections::HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = if path == "." { "/home/termio".to_owned() } else { path };
        Ok(Name { id, files: vec![File::dummy(path)] })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<SftpHandle, Self::Error> {
        if !self.files.lock().unwrap().dirs.contains(&path) {
            return Err(StatusCode::NoSuchFile);
        }
        self.next += 1;
        let handle = format!("d{}", self.next);
        self.handles.insert(handle.clone(), (path, false));
        Ok(SftpHandle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let (path, listed) = self.handles.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if *listed {
            return Err(StatusCode::Eof);
        }
        *listed = true;
        let prefix = format!("{path}/");
        let fs = self.files.lock().unwrap();
        let child = |full: &String| full.strip_prefix(&prefix).filter(|rest| !rest.contains('/')).map(str::to_owned);
        let mut files: Vec<File> = fs.dirs.iter().filter_map(|dir| child(dir).map(|name| File::new(name, attrs(true, 0)))).collect();
        files.extend(fs.files.iter().filter_map(|(file, data)| child(file).map(|name| File::new(name, attrs(false, data.len() as u64)))));
        Ok(Name { id, files })
    }

    async fn open(&mut self, id: u32, filename: String, flags: OpenFlags, _: FileAttributes) -> Result<SftpHandle, Self::Error> {
        let mut fs = self.files.lock().unwrap();
        if flags.contains(OpenFlags::CREATE) {
            fs.files.insert(filename.clone(), Vec::new());
        } else if !fs.files.contains_key(&filename) {
            return Err(StatusCode::NoSuchFile);
        }
        self.next += 1;
        let handle = format!("f{}", self.next);
        self.handles.insert(handle.clone(), (filename, false));
        Ok(SftpHandle { id, handle })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let (path, _) = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let fs = self.files.lock().unwrap();
        let data = fs.files.get(path).ok_or(StatusCode::NoSuchFile)?;
        let start = offset as usize;
        if start >= data.len() {
            return Err(StatusCode::Eof);
        }
        Ok(Data { id, data: data[start..(start + len as usize).min(data.len())].to_vec() })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let (path, _) = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let mut fs = self.files.lock().unwrap();
        let file = fs.files.get_mut(path).ok_or(StatusCode::NoSuchFile)?;
        let end = offset as usize + data.len();
        if file.len() < end {
            file.resize(end, 0);
        }
        file[offset as usize..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let fs = self.files.lock().unwrap();
        if fs.dirs.contains(&path) {
            return Ok(Attrs { id, attrs: attrs(true, 0) });
        }
        fs.files.get(&path).map(|data| Attrs { id, attrs: attrs(false, data.len() as u64) }).ok_or(StatusCode::NoSuchFile)
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let path = self.handles.get(&handle).ok_or(StatusCode::Failure)?.0.clone();
        self.stat(id, path).await
    }

    async fn mkdir(&mut self, id: u32, path: String, _: FileAttributes) -> Result<Status, Self::Error> {
        self.files.lock().unwrap().dirs.insert(path);
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.files.lock().unwrap().files.remove(&path).map(|_| ok(id)).ok_or(StatusCode::NoSuchFile)
    }

    async fn rename(&mut self, id: u32, from: String, to: String) -> Result<Status, Self::Error> {
        let mut fs = self.files.lock().unwrap();
        let data = fs.files.remove(&from).ok_or(StatusCode::NoSuchFile)?;
        fs.files.insert(to, data);
        Ok(ok(id))
    }
}

#[test]
fn sftp_lists_uploads_downloads_and_renames() {
    let (port, _, _) = runtime().block_on(serve());
    let verifier: Arc<dyn Verifier> = Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) });
    let dir = std::env::temp_dir().join(format!("termio-sftp-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let local = dir.join("up.bin");
    let payload: Vec<u8> = (0..700_000u32).map(|n| (n * 7) as u8).collect();
    std::fs::write(&local, &payload).unwrap();
    runtime().block_on(async {
        let sftp = Sftp::connect(&target(port, "secret"), verifier).await.unwrap();
        assert_eq!(sftp.home().await.unwrap(), "/home/termio");
        sftp.mkdir("/home/termio").await.unwrap();
        sftp.mkdir("/home/termio/logs").await.unwrap();
        let progress = std::sync::atomic::AtomicU64::new(0);
        let sent = sftp.upload(&local, "/home/termio/data.bin", |done| progress.store(done, Ordering::SeqCst)).await.unwrap();
        assert_eq!(sent, payload.len() as u64);
        assert_eq!(progress.load(Ordering::SeqCst), sent);
        let listing = sftp.list("/home/termio").await.unwrap();
        let shape: Vec<(&str, bool)> = listing.iter().map(|entry| (entry.name.as_str(), entry.directory)).collect();
        assert_eq!(shape, [("logs", true), ("data.bin", false)], "directories first");
        assert_eq!(listing[1].size, payload.len() as u64);
        sftp.rename("/home/termio/data.bin", "/home/termio/renamed.bin").await.unwrap();
        let back = dir.join("down.bin");
        sftp.download("/home/termio/renamed.bin", &back, |_| {}).await.unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), payload);
        sftp.remove("/home/termio/renamed.bin", false).await.unwrap();
        assert!(sftp.list("/home/termio").await.unwrap().iter().all(|entry| entry.name != "renamed.bin"));
    });
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_local_forward_carries_tcp_to_the_remote_side() {
    // The "remote" service: echoes what it reads, upper-cased.
    let service = runtime().block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let service_port = service.local_addr().unwrap().port();
    runtime().spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut socket, _)) = service.accept().await {
            let mut buffer = [0u8; 64];
            let read = socket.read(&mut buffer).await.unwrap_or(0);
            let _ = socket.write_all(&buffer[..read].to_ascii_uppercase()).await;
        }
    });
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = free.local_addr().unwrap().port();
    drop(free);

    let (port, _, _) = runtime().block_on(serve());
    let sink = Arc::new(Collect::default());
    let mut via = target(port, "secret");
    via.forwards.push(Forward { local_port, remote_host: "127.0.0.1".into(), remote_port: service_port });
    let _shell = SshShell::connect(via, 80, 24, Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) }), sink.clone());
    wait_for("the forward", || sink.notices.lock().unwrap().iter().any(|(kind, _)| kind == "forward.up"));
    let reply = runtime().block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
        socket.write_all(b"through the tunnel").await.unwrap();
        let mut buffer = [0u8; 64];
        let read = socket.read(&mut buffer).await.unwrap();
        String::from_utf8_lossy(&buffer[..read]).into_owned()
    });
    assert_eq!(reply, "THROUGH THE TUNNEL");
}

#[test]
fn a_dropped_link_reconnects_by_itself() {
    let (port, _, _) = runtime().block_on(serve());
    let sink = Arc::new(Collect::default());
    let shell = SshShell::connect(target(port, "secret"), 80, 24, Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) }), sink.clone());
    wait_for("the welcome", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("welcome"));
    shell.write(b"drop\r").unwrap();
    wait_for("the second welcome", || String::from_utf8_lossy(&sink.output.lock().unwrap()).matches("welcome").count() == 2);
    assert_eq!(*sink.statuses.lock().unwrap(), ["connecting", "authenticating", "connected", "reconnecting", "authenticating", "connected"]);
    assert!(sink.closed.lock().unwrap().is_none(), "the tab never saw the drop as an end");
    assert!(String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("Reconnecting"));
    shell.write(b"ls").unwrap();
    wait_for("the echo after reconnecting", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("echo:ls"));
    assert!(sink.notices.lock().unwrap().iter().any(|(kind, _)| kind == "latency"), "typing reports the echo latency");
}

/// Drop after drop, each reconnect comes after the first, short delay: the backoff starts over
/// once a connection is back up.
#[test]
fn repeated_drops_each_reconnect_quickly() {
    let (port, _, _) = runtime().block_on(serve());
    let sink = Arc::new(Collect::default());
    let shell = SshShell::connect(target(port, "secret"), 80, 24, Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) }), sink.clone());
    for round in 1..=4usize {
        wait_for("the welcome", || String::from_utf8_lossy(&sink.output.lock().unwrap()).matches("welcome").count() == round);
        let started = std::time::Instant::now();
        shell.write(b"drop\r").unwrap();
        for _ in 0..1000 {
            if String::from_utf8_lossy(&sink.output.lock().unwrap()).matches("welcome").count() == round + 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(String::from_utf8_lossy(&sink.output.lock().unwrap()).matches("welcome").count(), round + 1, "round {round} never came back");
        assert!(started.elapsed() < Duration::from_millis(2500), "round {round} took {:?}", started.elapsed());
    }
    let notices = sink.notices.lock().unwrap();
    assert!(notices.iter().filter(|(kind, _)| kind == "reconnect").all(|(_, detail)| detail.ends_with("retrying in 1 s")), "{notices:?}");
}

#[test]
fn the_agent_starts_over_ssh_and_carries_the_session_over_quic() {
    use crate::agent::AgentShell;
    let (port, _, _) = runtime().block_on(serve_with(true));
    let sink = Arc::new(Collect::default());
    let shell = AgentShell::connect(target(port, "secret"), 100, 30, Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) }), sink.clone());
    wait_for("the agent", || sink.notices.lock().unwrap().iter().any(|(kind, detail)| kind == "transport" && detail == "agent"));
    shell.write(b"echo through-the-agent\r").unwrap();
    for _ in 0..1000 {
        if String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("through-the-agent") && sink.notices.lock().unwrap().iter().any(|(kind, _)| kind == "latency") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = String::from_utf8_lossy(&sink.output.lock().unwrap()).into_owned();
    assert!(output.contains("through-the-agent"), "frames reach the sink as escape sequences: {output:?}");
    assert!(output.contains("\x1b[?25l"), "it is screen state, not the raw byte stream");
    assert!(sink.statuses.lock().unwrap().iter().any(|status| status == "connected"));
    shell.close();
    wait_for("the end", || sink.closed.lock().unwrap().is_some());
}

/// The tab closes while the agent is still starting: the agent that did start on the server is
/// told to end its shell, instead of keeping it for a 15-minute resume nobody will ask for.
#[test]
fn closing_while_the_agent_starts_still_ends_the_remote_shell() {
    use crate::agent::AgentShell;
    let (port, _, _, agents) = runtime().block_on(serve_agents(true));
    let sink = Arc::new(Collect::default());
    let shell = AgentShell::connect(target(port, "secret"), 80, 24, Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) }), sink.clone());
    shell.close();
    wait_for("the agent to start anyway", || agents.lock().unwrap().len() == 1);
    let done = agents.lock().unwrap().pop().unwrap();
    runtime().block_on(async { tokio::time::timeout(Duration::from_secs(10), done).await }).expect("the agent ends its shell").unwrap();
    wait_for("the session to report its end", || sink.closed.lock().unwrap().is_some());
    assert_eq!(*sink.closed.lock().unwrap(), Some(None));
    assert!(sink.output.lock().unwrap().is_empty(), "nothing is shown for a closed tab");
}

#[test]
fn without_the_agent_the_session_falls_back_to_plain_ssh() {
    use crate::agent::AgentShell;
    let (port, _, _) = runtime().block_on(serve());
    let sink = Arc::new(Collect::default());
    let shell = AgentShell::connect(target(port, "secret"), 80, 24, Arc::new(Answer { trust: true, asked: Mutex::new(Vec::new()) }), sink.clone());
    shell.write(b"typed early").unwrap();
    wait_for("the plain shell", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("welcome"));
    assert!(sink.notices.lock().unwrap().iter().any(|(kind, detail)| kind == "agent" && detail.contains("not installed")));
    wait_for("the input typed while starting", || String::from_utf8_lossy(&sink.output.lock().unwrap()).contains("echo:typed early"));
}

/// Signs in with the running ssh-agent against a real server, only when one is configured:
/// `TERMIO_AGENT_TARGET=user@host:port` with `SSH_AUTH_SOCK` (or OpenSSH's pipe on Windows).
#[test]
fn the_ssh_agent_signs_in_against_a_real_server() {
    let Ok(destination) = std::env::var("TERMIO_AGENT_TARGET") else {
        eprintln!("skipped: no TERMIO_AGENT_TARGET");
        return;
    };
    let (user, rest) = destination.split_once('@').expect("user@host:port");
    let (host, port) = rest.rsplit_once(':').expect("host:port");
    let target = Target { host: host.into(), port: port.parse().unwrap(), user: user.into(), auth: vec![Auth::Agent], jump: None, forwards: Vec::new() };
    struct Trust;
    impl Verifier for Trust {
        fn verify(&self, _key: HostKey, answer: oneshot::Sender<bool>) {
            let _ = answer.send(true);
        }
    }
    let output = runtime().block_on(exec_until(&target, Arc::new(Trust), "echo AGENT-$((20+3))", "AGENT-23")).expect("signed in with the agent");
    assert!(output.contains("AGENT-23"));
}
