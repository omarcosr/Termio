//! The vault as the UI sees it: locking, records with their secrets held back, keys, known
//! hosts, sync with R2, and the SSH sessions built from host records.
//!
//! Secrets (host passwords, private keys, key passphrases, the R2 secret) never leave the core.
//! Listing replaces them with `has<Field>` flags; saving a record without a secret field keeps
//! the stored one, so the UI can edit a host without ever seeing its password.

use crate::events;
use crate::session::registry;
use crate::terminal::TerminalSession;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use termio_sync::{R2Config, R2Store};
use termio_transport::agent::AgentShell;
use termio_transport::ssh::{Auth, Forward, HostKey, Sftp, SshShell, Target, Verifier, runtime};
use termio_vault::{Record, Vault};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Fields that stay in the core, per record kind.
fn secret_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "host" => &["password", "keyPassphrase"],
        "key" => &["private", "passphrase"],
        "settings" => &["secretKey"],
        _ => &[],
    }
}

static VAULT: Mutex<Option<Vault>> = Mutex::new(None);
static PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static SYNCING: AtomicBool = AtomicBool::new(false);

fn vault() -> MutexGuard<'static, Option<Vault>> {
    VAULT.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn default_path() -> PathBuf {
    if let Ok(path) = std::env::var("TERMIO_VAULT") {
        return PathBuf::from(path);
    }
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("XDG_DATA_HOME").map(PathBuf::from))
        .or_else(|_| std::env::var("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("Termio").join("vault.termio")
}

fn path() -> PathBuf {
    PATH.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_else(default_path)
}

fn with_vault<R>(action: impl FnOnce(&mut Vault) -> Result<R, String>) -> Result<R, String> {
    let mut guard = vault();
    let vault = guard.as_mut().ok_or("the vault is locked")?;
    action(vault)
}

fn text<'a>(request: &'a Value, field: &str) -> Result<&'a str, String> {
    request[field].as_str().filter(|value| !value.is_empty()).ok_or_else(|| format!("missing {field}"))
}

/// A record as the UI may see it.
fn public(record: &Record) -> Value {
    let mut data = record.data.as_object().cloned().unwrap_or_default();
    for field in secret_fields(&record.kind) {
        let present = data.remove(*field).is_some_and(|value| value.as_str().is_none_or(|text| !text.is_empty()));
        let mut flag = String::from("has");
        flag.push_str(&field[..1].to_uppercase());
        flag.push_str(&field[1..]);
        data.insert(flag, json!(present));
    }
    json!({ "id": record.id, "kind": record.kind, "data": data, "updated": record.stamp.ms })
}

fn put(vault: &mut Vault, kind: &str, id: Option<&str>, data: Value) -> Result<Record, String> {
    let mut data: Map<String, Value> = match data {
        Value::Object(map) => map,
        _ => return Err("record data must be an object".into()),
    };
    // Flags the UI got back are not data.
    data.retain(|key, _| !(key.starts_with("has") && key.chars().nth(3).is_some_and(char::is_uppercase)));
    if let Some(existing) = id.and_then(|id| vault.get(id)) {
        for field in secret_fields(kind) {
            if !data.contains_key(*field) && let Some(kept) = existing.data.get(*field) {
                data.insert((*field).to_owned(), kept.clone());
            }
        }
    }
    vault.put(kind, id, Value::Object(data)).map_err(|error| error.to_string())
}

fn sync_config(vault: &Vault) -> Option<R2Config> {
    let settings = &vault.get("sync")?.data;
    let field = |name: &str| settings[name].as_str().map(str::to_owned).filter(|value| !value.is_empty());
    Some(R2Config {
        account: field("account")?,
        bucket: field("bucket")?,
        access_key: field("accessKey")?,
        secret_key: field("secretKey")?,
        endpoint: field("endpoint"),
        name: field("name").unwrap_or_else(|| "termio".into()),
    })
}

fn r2_from(request: &Value) -> Result<R2Config, String> {
    Ok(R2Config {
        account: text(request, "account")?.to_owned(),
        bucket: text(request, "bucket")?.to_owned(),
        access_key: text(request, "accessKey")?.to_owned(),
        secret_key: text(request, "secretKey")?.to_owned(),
        endpoint: request["endpoint"].as_str().filter(|value| !value.is_empty()).map(str::to_owned),
        name: request["name"].as_str().map(str::trim).filter(|value| !value.is_empty()).unwrap_or("termio").to_owned(),
    })
}

/// Runs a sync on a thread of its own; the result arrives as a `sync` event.
fn sync_in_background() {
    let Some(config) = vault().as_ref().and_then(sync_config) else { return };
    if SYNCING.swap(true, Ordering::AcqRel) {
        return;
    }
    events::emit(json!({ "type": "sync", "state": "running" }));
    std::thread::spawn(move || {
        let result = R2Store::new(&config).and_then(|store| {
            // The vault stays locked for the whole sync: a few round trips on a slow link,
            // during which edits wait rather than race the merge.
            with_vault(|vault| termio_sync::sync(vault, &store).map_err(|error| error.to_string()))
        });
        SYNCING.store(false, Ordering::Release);
        match result {
            Ok(report) => {
                events::emit(json!({ "type": "sync", "state": "done", "pulled": report.pulled, "pushed": report.pushed }));
                if report.pulled > 0 {
                    events::emit(json!({ "type": "records.changed" }));
                }
            }
            Err(error) => events::emit(json!({ "type": "sync", "state": "error", "message": error })),
        }
    });
}

/// Host keys the UI is being asked about, by request id.
struct Pending {
    answer: oneshot::Sender<bool>,
    key: HostKey,
}

static PENDING: Mutex<Option<HashMap<u64, Pending>>> = Mutex::new(None);
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

fn known_host_id(host: &str, port: u16) -> String {
    format!("known:{host}:{port}")
}

struct VaultVerifier {
    session: u32,
}

impl Verifier for VaultVerifier {
    fn verify(&self, key: HostKey, answer: oneshot::Sender<bool>) {
        let known = vault().as_ref().and_then(|vault| vault.get(&known_host_id(&key.host, key.port)).map(|record| record.data.clone()));
        let changed = match known {
            Some(data) if data["key"].as_str() == Some(key.openssh.as_str()) => {
                let _ = answer.send(true);
                return;
            }
            Some(data) => Some(data["fingerprint"].as_str().unwrap_or_default().to_owned()),
            None => None,
        };
        let request = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
        events::emit(json!({
            "type": "hostkey",
            "session": self.session,
            "request": request,
            "host": key.host,
            "port": key.port,
            "algorithm": key.algorithm,
            "fingerprint": key.fingerprint,
            "previous": changed,
        }));
        PENDING.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).insert(request, Pending { answer, key });
    }
}

fn target_from(vault: &Vault, id: &str, depth: usize) -> Result<Target, String> {
    if depth > 4 {
        return Err("jump hosts form a loop".into());
    }
    let host = vault.get(id).filter(|record| record.kind == "host").ok_or("that host no longer exists")?;
    let data = &host.data;
    let address = data["address"].as_str().filter(|value| !value.is_empty()).ok_or("the host has no address")?;
    let mut auth = Vec::new();
    if let Some(key_id) = data["key"].as_str().filter(|value| !value.is_empty()) {
        let key = vault.get(key_id).ok_or("the host's key was deleted")?;
        let private = key.data["private"].as_str().ok_or("the key record has no private key")?;
        let passphrase = key.data["passphrase"].as_str().filter(|value| !value.is_empty()).map(|value| Zeroizing::new(value.to_owned()));
        auth.push(Auth::Key { private: Zeroizing::new(private.to_owned()), passphrase });
    }
    if let Some(password) = data["password"].as_str().filter(|value| !value.is_empty()) {
        auth.push(Auth::Password(Zeroizing::new(password.to_owned())));
    }
    if data["useAgent"].as_bool() == Some(true) {
        auth.push(Auth::Agent);
    }
    let jump = match data["jump"].as_str().filter(|value| !value.is_empty()) {
        Some(jump) => Some(Box::new(target_from(vault, jump, depth + 1)?)),
        None => None,
    };
    let port = |value: &Value| value.as_u64().filter(|port| *port > 0 && *port <= 65535).map(|port| port as u16);
    let forwards = data["forwards"]
        .as_array()
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| {
                    Some(Forward {
                        local_port: port(&rule["local"])?,
                        remote_host: rule["host"].as_str().filter(|host| !host.is_empty()).unwrap_or("127.0.0.1").to_owned(),
                        remote_port: port(&rule["port"])?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Target {
        host: address.to_owned(),
        port: port(&data["port"]).unwrap_or(22),
        user: data["user"].as_str().filter(|value| !value.is_empty()).unwrap_or("root").to_owned(),
        auth,
        jump,
        forwards,
    })
}

/// Control requests about the vault, records, sync and SSH. `None` when `op` is not one of them.
pub fn call(operation: &str, request: &Value) -> Option<Result<Value, String>> {
    Some(match operation {
        "vault.status" => {
            let unlocked = vault().is_some();
            let configured = vault().as_ref().is_some_and(|vault| sync_config(vault).is_some());
            Ok(json!({ "exists": Vault::exists(&path()), "unlocked": unlocked, "path": path(), "syncConfigured": configured }))
        }
        "vault.create" => text(request, "password").and_then(|password| {
            if password.chars().count() < 8 {
                return Err("use at least 8 characters".into());
            }
            let created = Vault::create(&path(), password).map_err(|error| error.to_string())?;
            *vault() = Some(created);
            Ok(json!({}))
        }),
        "vault.unlock" => text(request, "password").and_then(|password| {
            let opened = Vault::open(&path(), password).map_err(|error| error.to_string())?;
            *vault() = Some(opened);
            sync_in_background();
            Ok(json!({}))
        }),
        "vault.lock" => {
            *vault() = None;
            Ok(json!({}))
        }
        "vault.password" => text(request, "password").and_then(|password| {
            if password.chars().count() < 8 {
                return Err("use at least 8 characters".into());
            }
            let config = with_vault(|vault| {
                vault.change_password(password).map_err(|error| error.to_string())?;
                Ok(sync_config(vault))
            })?;
            if let Some(config) = config {
                let store = R2Store::new(&config)?;
                with_vault(|vault| termio_sync::publish_envelope(vault, &store).map_err(|error| error.to_string()))?;
            }
            Ok(json!({}))
        }),
        // A new device: the vault comes from the bucket.
        "vault.join" => (|| {
            let password = text(request, "password")?;
            let config = r2_from(request)?;
            let store = R2Store::new(&config)?;
            let envelope = termio_sync::fetch_envelope(&store).map_err(|error| error.to_string())?;
            let mut joined = Vault::join(&path(), envelope, password).map_err(|error| error.to_string())?;
            let report = termio_sync::sync(&mut joined, &store).map_err(|error| error.to_string())?;
            put(&mut joined, "settings", Some("sync"), sync_settings(&config))?;
            *vault() = Some(joined);
            Ok(json!({ "pulled": report.pulled }))
        })(),
        "records.list" => with_vault(|vault| {
            let kind = text(request, "kind")?;
            Ok(json!({ "records": vault.list(kind).into_iter().map(public).collect::<Vec<_>>() }))
        }),
        "records.put" => with_vault(|vault| {
            let kind = text(request, "kind")?;
            if kind == "settings" && request["id"].as_str() == Some("sync") {
                return Err("use sync.configure".into());
            }
            let record = put(vault, kind, request["id"].as_str(), request["data"].clone())?;
            Ok(public(&record))
        })
        .inspect(|_| sync_in_background()),
        "records.remove" => with_vault(|vault| vault.remove(text(request, "id")?).map_err(|error| error.to_string()).map(|_| json!({})))
            .inspect(|_| sync_in_background()),
        "keys.generate" => with_vault(|vault| {
            let name = text(request, "name")?;
            let (private, info) = termio_transport::keys::generate_ed25519(&format!("{name} (Termio)"))?;
            let data = json!({ "name": name, "algorithm": info.algorithm, "public": info.public, "fingerprint": info.fingerprint, "private": private.as_str() });
            Ok(public(&put(vault, "key", None, data)?))
        })
        .inspect(|_| sync_in_background()),
        "keys.import" => with_vault(|vault| {
            let name = text(request, "name")?;
            let private = text(request, "private")?;
            let passphrase = request["passphrase"].as_str().filter(|value| !value.is_empty());
            let info = termio_transport::keys::inspect(private, passphrase)?;
            if info.encrypted && passphrase.is_none() {
                return Err("this key is encrypted: enter its passphrase".into());
            }
            let mut data = json!({ "name": name, "algorithm": info.algorithm, "public": info.public, "fingerprint": info.fingerprint, "private": private });
            if let Some(passphrase) = passphrase {
                data["passphrase"] = json!(passphrase);
            }
            Ok(public(&put(vault, "key", None, data)?))
        })
        .inspect(|_| sync_in_background()),
        "sync.configure" => (|| {
            let config = r2_from(request)?;
            // Check the credentials and claim the bucket before saving them.
            let store = R2Store::new(&config)?;
            let report = with_vault(|vault| {
                let report = termio_sync::sync(vault, &store).map_err(|error| error.to_string())?;
                put(vault, "settings", Some("sync"), sync_settings(&config))?;
                Ok(report)
            })?;
            Ok(json!({ "pulled": report.pulled, "pushed": report.pushed }))
        })(),
        "cloudflare.connect" => text(request, "token").and_then(|token| {
            let cloudflare = termio_sync::cloudflare::Cloudflare::new(token);
            let access_key = cloudflare.verify()?;
            let accounts = cloudflare.accounts()?;
            if accounts.is_empty() {
                return Err("this token reaches no account: give it Account Settings Read".into());
            }
            Ok(json!({ "accessKey": access_key, "secretKey": termio_sync::cloudflare::secret_key(token), "accounts": accounts }))
        }),
        "cloudflare.buckets" => (|| {
            let cloudflare = termio_sync::cloudflare::Cloudflare::new(text(request, "token")?);
            Ok(json!({ "buckets": cloudflare.buckets(text(request, "account")?)? }))
        })(),
        "cloudflare.createBucket" => (|| {
            let cloudflare = termio_sync::cloudflare::Cloudflare::new(text(request, "token")?);
            cloudflare.create_bucket(text(request, "account")?, text(request, "name")?).map(|_| json!({}))
        })(),
        "terminal.appearance" => {
            let family = request["fontFamily"].as_str().map(str::trim).filter(|family| !family.is_empty());
            crate::surface::fonts().lock().unwrap_or_else(|p| p.into_inner()).set_family(family);
            if let Some(size) = request["fontSize"].as_f64() {
                crate::terminal::set_font_size(size as f32);
            }
            crate::terminal::set_prefs(crate::terminal::Prefs {
                theme: crate::terminal::named_theme(request["theme"].as_str().unwrap_or("termio")),
                cursor: match request["cursor"].as_str() {
                    Some("beam") => Some(termio_vt::CursorShape::Beam),
                    Some("underline") => Some(termio_vt::CursorShape::Underline),
                    _ => None,
                },
                padding: request["padding"].as_f64().unwrap_or(6.0).clamp(0.0, 32.0) as f32,
            });
            registry().relayout_all();
            Ok(json!({}))
        }
        "clipboard.set" => text(request, "text").and_then(|value| {
            use crate::clipboard::Clipboard;
            crate::clipboard::SystemClipboard.set(value).map(|_| json!({}))
        }),
        "sync.vaults" => (|| {
            // The vaults in a bucket, by name, for the picker.
            use termio_sync::Store;
            let store = R2Store::new(&r2_from(request)?)?;
            let keys = store.list_vaults().map_err(|error| format!("{error:?}"))?;
            Ok(json!({ "vaults": keys.iter().map(|key| key.trim_end_matches(".vault")).collect::<Vec<_>>() }))
        })(),
        "sync.probe" => (|| {
            // Whether the bucket already holds a vault to join, or is empty and can take a new one.
            let store = R2Store::new(&r2_from(request)?)?;
            match termio_sync::fetch_envelope(&store) {
                Ok(_) => Ok(json!({ "hasVault": true })),
                Err(termio_sync::SyncError::Empty) => Ok(json!({ "hasVault": false })),
                Err(error) => Err(error.to_string()),
            }
        })(),
        "cloudflare.tokenUrl" => Ok(json!({ "url": termio_sync::cloudflare::TOKEN_URL })),
        "sync.disable" => with_vault(|vault| vault.remove("sync").map_err(|error| error.to_string()).map(|_| json!({}))),
        "sync.run" => {
            sync_in_background();
            Ok(json!({}))
        }
        "sync.settings" => with_vault(|vault| Ok(vault.get("sync").map(public).unwrap_or(Value::Null))),
        "hostkey.answer" => (|| {
            let request_id = request["request"].as_u64().ok_or("missing request")?;
            let trust = request["trust"].as_bool().unwrap_or(false);
            let pending = PENDING.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).remove(&request_id).ok_or("that question was already answered")?;
            if trust && request["remember"].as_bool().unwrap_or(true) {
                let key = &pending.key;
                with_vault(|vault| {
                    let data = json!({ "host": key.host, "port": key.port, "algorithm": key.algorithm, "fingerprint": key.fingerprint, "key": key.openssh });
                    vault.put("known_host", Some(&known_host_id(&key.host, key.port)), data).map_err(|error| error.to_string())
                })?;
                sync_in_background();
            }
            let _ = pending.answer.send(trust);
            Ok(json!({}))
        })(),
        "ssh.open" => (|| {
            let host = text(request, "host")?.to_owned();
            let (target, agent) = with_vault(|vault| {
                // Resumable sessions over QUIC unless the host opted out.
                let agent = vault.get(&host).is_none_or(|record| record.data["agent"].as_bool() != Some(false));
                Ok((target_from(vault, &host, 0)?, agent))
            })?;
            let id = registry().open(|id, surface| {
                let session = TerminalSession::new(id, surface.invalidator.clone());
                let verifier = Arc::new(VaultVerifier { session: id });
                session.set_predictive(std::env::var_os("TERMIO_NO_PREDICT").is_none());
                if agent {
                    session.attach(Box::new(AgentShell::connect(target, 80, 24, verifier, session.clone())));
                } else {
                    session.attach(Box::new(SshShell::connect(target, 80, 24, verifier, session.clone())));
                }
                Ok(session)
            })?;
            Ok(json!({ "id": id }))
        })(),
        "session.search" | "session.searchNext" | "session.searchClear" => (|| {
            let id = request["id"].as_u64().ok_or("missing id")? as u32;
            let query = request["query"].as_str().unwrap_or("").to_owned();
            let backwards = request["backwards"].as_bool().unwrap_or(false);
            let count = registry()
                .with(id, |entry| match operation {
                    "session.search" => entry.session.search(&query),
                    "session.searchNext" => {
                        entry.session.search_step(backwards);
                        0
                    }
                    _ => {
                        entry.session.search_clear();
                        0
                    }
                })
                .ok_or("unknown session")?;
            Ok(json!({ "count": count }))
        })(),
        "import.sshConfig" => (|| {
            let path = crate::sshconfig::default_path().ok_or("no home folder")?;
            let text = std::fs::read_to_string(&path).map_err(|_| format!("{} not found", path.display()))?;
            Ok(scan_reply(crate::importers::from_ssh_config(&text), &path))
        })(),
        "import.scan" => (|| {
            let (scan, path) = match request["source"].as_str().unwrap_or("") {
                "sshConfig" => {
                    let path = crate::sshconfig::default_path().ok_or("no home folder")?;
                    let text = std::fs::read_to_string(&path).map_err(|_| format!("{} not found", path.display()))?;
                    (crate::importers::from_ssh_config(&text), path)
                }
                "filezilla" => {
                    let path = crate::importers::filezilla_path().ok_or("FileZilla's sitemanager.xml was not found: is FileZilla installed for this user?")?;
                    (crate::importers::from_filezilla_file(&path)?, path)
                }
                "termius" => {
                    let dir = crate::termius::data_dir().ok_or("Termius' local data was not found: is Termius installed and started once for this user?")?;
                    (crate::termius::scan()?, dir)
                }
                other => return Err(format!("unknown import source {other}")),
            };
            Ok(scan_reply(scan, &path))
        })(),
        "import.apply" => with_vault(|vault| {
            let import_keys = request["importKeys"].as_bool().unwrap_or(false);
            // Hosts from the last scan, by key, keep the passwords the UI never saw.
            let hosts: Vec<crate::importers::Host> = match request["keys"].as_array() {
                Some(chosen) => {
                    let scanned = LAST_SCAN.lock().unwrap_or_else(|p| p.into_inner());
                    chosen.iter().filter_map(|key| key.as_str()?.parse::<usize>().ok()).filter_map(|index| scanned.get(index).cloned()).collect()
                }
                None => request["hosts"]
                    .as_array()
                    .ok_or("missing hosts")?
                    .iter()
                    .map(|host| {
                        let field = |name: &str| host[name].as_str().filter(|value| !value.is_empty()).map(str::to_owned);
                        crate::importers::Host {
                            name: field("name").unwrap_or_default(),
                            address: field("address").unwrap_or_default(),
                            user: field("user"),
                            port: host["port"].as_u64().and_then(|port| u16::try_from(port).ok()),
                            identity_file: field("identityFile"),
                            jump: field("jump"),
                            group: field("group"),
                            password: None,
                            private_key: None,
                            passphrase: None,
                            key_name: None,
                        }
                    })
                    .collect(),
            };
            let mut created: HashMap<String, String> = HashMap::new();
            let mut keys: HashMap<String, String> = HashMap::new();
            for host in &hosts {
                let mut data = json!({ "name": host.name, "address": host.address, "user": host.user, "group": host.group.as_deref().unwrap_or("Imported") });
                if let Some(port) = host.port {
                    data["port"] = json!(port);
                }
                if let Some(password) = &host.password {
                    data["password"] = json!(password);
                }
                // A key comes either from the file a scanned host points at or, for Termius, from
                // that program's own store: the scan kept both out of the UI's sight.
                let source = match (import_keys, host.private_key.clone(), host.identity_file.as_deref()) {
                    (true, Some(private), _) => Some((host.key_name.clone().unwrap_or_else(|| host.name.clone()), private, host.passphrase.clone())),
                    (true, None, Some(file)) => std::fs::read_to_string(file).ok().map(|private| {
                        let label = std::path::Path::new(file).file_name().map_or(file.to_owned(), |name| name.to_string_lossy().into_owned());
                        (label, private, None)
                    }),
                    _ => None,
                };
                if let Some((label, private, passphrase)) = source {
                    let key_id = match keys.get(&label) {
                        Some(id) => Some(id.clone()),
                        None => termio_transport::keys::inspect(&private, passphrase.as_deref()).ok().filter(|info| !info.encrypted).and_then(|info| {
                            let mut data = json!({ "name": label, "algorithm": info.algorithm, "public": info.public, "fingerprint": info.fingerprint, "private": private });
                            if let Some(passphrase) = passphrase.as_deref() {
                                data["passphrase"] = json!(passphrase);
                            }
                            let record = put(vault, "key", None, data).ok()?;
                            keys.insert(label, record.id.clone());
                            Some(record.id)
                        }),
                    };
                    if let Some(id) = key_id {
                        data["key"] = json!(id);
                    }
                }
                let record = put(vault, "host", None, data)?;
                created.insert(host.name.clone(), record.id);
            }
            // ProxyJump names become host ids once every host exists.
            for host in &hosts {
                let Some(jump) = host.jump.as_deref() else { continue };
                let (Some(id), Some(jump_id)) = (created.get(&host.name), created.get(jump)) else { continue };
                if let Some(existing) = vault.get(id) {
                    let mut data = existing.data.clone();
                    data["jump"] = json!(jump_id);
                    put(vault, "host", Some(id), data)?;
                }
            }
            LAST_SCAN.lock().unwrap_or_else(|p| p.into_inner()).clear();
            Ok(json!({ "imported": created.len() }))
        })
        .inspect(|_| sync_in_background()),
        "agent.install" => text(request, "host").and_then(|host| install_agent(host.to_owned())),
        sftp if sftp.starts_with("sftp.") => sftp_call(sftp, request),
        _ => return None,
    })
}

/// The hosts of the last import scan, passwords included; `import.apply` picks from them by key.
static LAST_SCAN: Mutex<Vec<crate::importers::Host>> = Mutex::new(Vec::new());

/// A scan as the UI sees it: every host keyed by its index, its password as a flag, and whether
/// the vault already has a host at that address.
fn scan_reply(scan: crate::importers::Scan, path: &std::path::Path) -> Value {
    let known: Vec<(String, String, u64)> = vault()
        .as_ref()
        .map(|vault| {
            vault
                .list("host")
                .iter()
                .map(|record| {
                    let data = &record.data;
                    (data["address"].as_str().unwrap_or("").to_ascii_lowercase(), data["user"].as_str().unwrap_or("").to_owned(), data["port"].as_u64().unwrap_or(22))
                })
                .collect()
        })
        .unwrap_or_default();
    let hosts: Vec<Value> = scan
        .hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            let exists = known.iter().any(|(address, user, port)| *address == host.address.to_ascii_lowercase() && user == host.user.as_deref().unwrap_or("") && *port == u64::from(host.port.unwrap_or(22)));
            json!({ "key": index.to_string(), "name": host.name, "address": host.address, "user": host.user, "port": host.port, "identityFile": host.identity_file, "jump": host.jump, "group": host.group, "hasPassword": host.password.is_some(), "hasKey": host.private_key.is_some(), "exists": exists })
        })
        .collect();
    let reply = json!({ "source": scan.source, "path": path.display().to_string(), "hosts": hosts, "skipped": scan.skipped });
    *LAST_SCAN.lock().unwrap_or_else(|p| p.into_inner()) = scan.hosts;
    reply
}

static SFTP: Mutex<Option<HashMap<u64, Arc<Sftp>>>> = Mutex::new(None);
static NEXT_SFTP: AtomicU64 = AtomicU64::new(1);

fn sftp_session(id: u64) -> Result<Arc<Sftp>, String> {
    SFTP.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).get(&id).cloned().ok_or_else(|| "that file browser is closed".to_owned())
}

/// Runs an SFTP job off the UI thread; its outcome arrives as `sftp.result` with `request`.
fn sftp_job<F>(request: u64, job: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = Result<Value, String>> + Send + 'static,
{
    runtime().spawn(async move {
        let event = match job().await {
            Ok(value) => json!({ "type": "sftp.result", "request": request, "ok": true, "value": value }),
            Err(error) => json!({ "type": "sftp.result", "request": request, "ok": false, "error": error }),
        };
        events::emit(event);
    });
}

/// The Linux agent binary that ships with the app: `TERMIO_AGENT_BINARY`, else `agent/` next to
/// the executable, else this checkout's `dist/agent/`.
fn agent_binary() -> Option<PathBuf> {
    const NAME: &str = "termio-agent-linux-x64";
    let beside = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|dir| dir.join("agent").join(NAME)));
    std::env::var_os("TERMIO_AGENT_BINARY")
        .map(PathBuf::from)
        .into_iter()
        .chain(beside)
        .chain([PathBuf::from("dist").join("agent").join(NAME)])
        .find(|path| path.is_file())
}

/// Installs the agent on a host over SFTP into `~/.termio/bin`, where sessions look for it.
/// Progress and the outcome arrive as `agent.install` events.
fn install_agent(host: String) -> Result<Value, String> {
    let target = with_vault(|vault| target_from(vault, &host, 0))?;
    let binary = agent_binary().ok_or("the agent binary is not bundled with this build")?;
    runtime().spawn(async move {
        let step = |state: &str, message: String| events::emit(json!({ "type": "agent.install", "host": host, "state": state, "message": message }));
        let result = async {
            step("checking", "Checking the server…".into());
            let verifier: Arc<dyn Verifier> = Arc::new(VaultVerifier { session: 0 });
            let arch = termio_transport::ssh::exec_until(&target, verifier.clone(), "uname -sm; echo TERMIO-END", "TERMIO-END").await?;
            if !arch.contains("Linux") || !arch.contains("x86_64") {
                return Err(format!("only Linux x86_64 servers are supported for now (this one is {})", arch.lines().next().unwrap_or("?").trim()));
            }
            step("uploading", format!("Uploading the agent ({} KB)…", std::fs::metadata(&binary).map_or(0, |meta| meta.len() / 1024)));
            let sftp = Sftp::connect(&target, verifier.clone()).await?;
            let home = sftp.home().await?;
            for dir in [format!("{home}/.termio"), format!("{home}/.termio/bin")] {
                let _ = sftp.mkdir(&dir).await;
            }
            let temporary = format!("{home}/.termio/bin/termio-agent.new");
            sftp.upload(&binary, &temporary, |_| {}).await?;
            let output = termio_transport::ssh::exec_until(
                &target,
                verifier,
                "chmod 755 ~/.termio/bin/termio-agent.new && mv -f ~/.termio/bin/termio-agent.new ~/.termio/bin/termio-agent && ~/.termio/bin/termio-agent --version 2>/dev/null; echo TERMIO-INSTALLED",
                "TERMIO-INSTALLED",
            )
            .await?;
            Ok::<_, String>(output.lines().find(|line| line.contains("termio-agent")).unwrap_or("").trim().to_owned())
        }
        .await;
        match result {
            Ok(version) => step("done", if version.is_empty() { "Agent installed".into() } else { format!("Installed {version}") }),
            Err(error) => step("error", error),
        }
    });
    Ok(json!({}))
}

fn sftp_call(operation: &str, request: &Value) -> Result<Value, String> {
    let id = request["id"].as_u64().unwrap_or(0);
    let job = request["request"].as_u64().unwrap_or(0);
    let path = |field: &str| request[field].as_str().filter(|value| !value.is_empty()).map(str::to_owned).ok_or_else(|| format!("missing {field}"));
    match operation {
        "sftp.open" => {
            let host = text(request, "host")?.to_owned();
            let target = with_vault(|vault| target_from(vault, &host, 0))?;
            let id = NEXT_SFTP.fetch_add(1, Ordering::Relaxed);
            runtime().spawn(async move {
                let result = async {
                    let sftp = Sftp::connect(&target, Arc::new(VaultVerifier { session: 0 })).await?;
                    let home = sftp.home().await?;
                    Ok::<_, String>((sftp, home))
                }
                .await;
                match result {
                    Ok((sftp, home)) => {
                        SFTP.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).insert(id, Arc::new(sftp));
                        events::emit(json!({ "type": "sftp.ready", "id": id, "home": home }));
                    }
                    Err(error) => events::emit(json!({ "type": "sftp.error", "id": id, "message": error })),
                }
            });
            Ok(json!({ "id": id }))
        }
        "sftp.close" => {
            SFTP.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(HashMap::new).remove(&id);
            Ok(json!({}))
        }
        "sftp.list" => {
            let (sftp, dir) = (sftp_session(id)?, path("path")?);
            sftp_job(job, move || async move {
                let entries = sftp.list(&dir).await?;
                Ok(json!(entries.into_iter().map(|entry| json!({ "name": entry.name, "directory": entry.directory, "size": entry.size, "modified": entry.modified })).collect::<Vec<_>>()))
            });
            Ok(json!({}))
        }
        "sftp.download" | "sftp.upload" => {
            let (sftp, remote, local) = (sftp_session(id)?, path("remote")?, PathBuf::from(path("local")?));
            let upload = operation == "sftp.upload";
            sftp_job(job, move || async move {
                let last = std::sync::Mutex::new(std::time::Instant::now());
                let progress = |done: u64| {
                    let mut last = last.lock().unwrap_or_else(|p| p.into_inner());
                    if last.elapsed() > std::time::Duration::from_millis(150) {
                        *last = std::time::Instant::now();
                        events::emit(json!({ "type": "sftp.progress", "request": job, "done": done }));
                    }
                };
                let bytes = if upload { sftp.upload(&local, &remote, progress).await? } else { sftp.download(&remote, &local, progress).await? };
                Ok(json!({ "bytes": bytes }))
            });
            Ok(json!({}))
        }
        "sftp.mkdir" => {
            let (sftp, dir) = (sftp_session(id)?, path("path")?);
            sftp_job(job, move || async move { sftp.mkdir(&dir).await.map(|_| json!({})) });
            Ok(json!({}))
        }
        "sftp.remove" => {
            let (sftp, target) = (sftp_session(id)?, path("path")?);
            let directory = request["directory"].as_bool().unwrap_or(false);
            sftp_job(job, move || async move { sftp.remove(&target, directory).await.map(|_| json!({})) });
            Ok(json!({}))
        }
        "sftp.rename" => {
            let (sftp, from, to) = (sftp_session(id)?, path("from")?, path("to")?);
            sftp_job(job, move || async move { sftp.rename(&from, &to).await.map(|_| json!({})) });
            Ok(json!({}))
        }
        _ => Err(format!("unknown op '{operation}'")),
    }
}

fn sync_settings(config: &R2Config) -> Value {
    json!({ "account": config.account, "bucket": config.bucket, "accessKey": config.access_key, "secretKey": config.secret_key, "endpoint": config.endpoint, "name": config.name })
}

/// Points the vault at another file (tests).
#[cfg(test)]
pub fn use_path(path: PathBuf) {
    *PATH.lock().unwrap() = Some(path);
    *vault() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(operation: &str, request: Value) -> Value {
        call(operation, &request).expect("a known op").unwrap_or_else(|error| panic!("{operation}: {error}"))
    }

    #[test]
    fn secrets_stay_in_the_core_and_survive_edits_from_the_ui() {
        let dir = std::env::temp_dir().join(format!("termio-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        use_path(dir.join("vault.termio"));
        assert_eq!(ok("vault.status", json!({}))["exists"], false);
        assert!(call("vault.create", &json!({ "password": "short" })).unwrap().is_err());
        ok("vault.create", json!({ "password": "long enough" }));

        let host = ok("records.put", json!({ "kind": "host", "data": { "name": "prod", "address": "10.0.0.5", "password": "hunter2" } }));
        assert_eq!(host["data"]["hasPassword"], true);
        assert!(host["data"].get("password").is_none(), "the password never goes back to the UI");
        let id = host["id"].as_str().unwrap();

        // The UI edits the name with the flags it was given and no password field.
        let mut edited = host["data"].clone();
        edited["name"] = json!("production");
        ok("records.put", json!({ "kind": "host", "id": id, "data": edited }));
        let target = with_vault(|vault| target_from(vault, id, 0)).unwrap();
        assert!(matches!(&target.auth[..], [Auth::Password(password)] if password.as_str() == "hunter2"), "the stored password is kept");
        assert_eq!((target.port, target.user.as_str()), (22, "root"));

        let key = ok("keys.generate", json!({ "name": "laptop" }));
        assert!(key["data"]["public"].as_str().unwrap().starts_with("ssh-ed25519 "));
        assert_eq!(key["data"]["hasPrivate"], true);
        assert!(key["data"].get("private").is_none());
        assert_eq!(ok("records.list", json!({ "kind": "key" }))["records"].as_array().unwrap().len(), 1);

        ok("vault.lock", json!({}));
        assert!(call("records.list", &json!({ "kind": "host" })).unwrap().is_err());
        assert!(call("vault.unlock", &json!({ "password": "wrong password" })).unwrap().is_err());
        ok("vault.unlock", json!({ "password": "long enough" }));
        assert_eq!(ok("records.list", json!({ "kind": "host" }))["records"][0]["data"]["name"], "production");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
