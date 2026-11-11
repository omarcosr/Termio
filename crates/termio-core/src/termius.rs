//! Hosts saved by Termius, read out of the app's own local data. Termius offers no export, so the
//! only honest source is what its Electron window keeps on disk: an IndexedDB in LevelDB whose
//! fields are sealed with NaCl secretbox, under a key the app leaves in the system keyring.
//!
//! The format is undocumented and can change with any Termius release, so every step here is
//! best-effort: a record that cannot be read is skipped and counted, never guessed at.

use crate::importers::{Host, Scan};
use crate::leveldb;
use crate::v8::{Decoder, Value};
use serde_json::Value as Json;
use std::path::{Path, PathBuf};
use xsalsa20poly1305::aead::{Aead, KeyInit};
use xsalsa20poly1305::{Nonce, XSalsa20Poly1305};

/// The IndexedDB stores that make a host: the host itself, its ssh settings, the identity it logs
/// in with, the key that identity holds and the folder it sits in.
const HOSTS: u16 = 21;
const CONFIGS: u16 = 6;
const IDENTITIES: u16 = 12;
const KEYS: u16 = 11;
const GROUPS: u16 = 15;

/// Where Termius keeps its IndexedDB, for this platform and install kind.
pub fn data_dir() -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        roots.push(PathBuf::from(appdata).join("Termius"));
    }
    if let Some(home) = home() {
        roots.push(home.join(".config").join("Termius"));
        roots.push(home.join("Library").join("Application Support").join("Termius"));
        // The App Store build runs inside a container named after its bundle id.
        if let Ok(listing) = std::fs::read_dir(home.join("Library").join("Containers")) {
            for entry in listing.flatten() {
                if entry.file_name().to_string_lossy().starts_with("com.termius") {
                    roots.push(entry.path().join("Data").join("Library").join("Application Support").join("Termius"));
                }
            }
        }
    }
    roots.into_iter().find_map(|root| {
        let listing = std::fs::read_dir(root.join("IndexedDB")).ok()?;
        listing.flatten().map(|entry| entry.path()).find(|path| path.extension().is_some_and(|ext| ext == "leveldb"))
    })
}

fn home() -> Option<PathBuf> {
    std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).ok().map(PathBuf::from)
}

/// The 32-byte key Termius seals its fields with: from the system keyring, or from a
/// TERMIUS_LOCAL_KEY environment variable holding the same base64 text.
fn local_key() -> Result<Vec<u8>, String> {
    if let Ok(text) = std::env::var("TERMIUS_LOCAL_KEY") {
        return unbase64_key(text.trim()).ok_or("TERMIUS_LOCAL_KEY is not 32 bytes of base64".to_owned());
    }
    let stored = keyring().ok_or("the Termius local key was not found in the system keyring: start Termius once, or set TERMIUS_LOCAL_KEY")?;
    unbase64_key(&String::from_utf8_lossy(&stored)).ok_or("the Termius keyring entry is not a 32-byte base64 key".to_owned())
}

fn unbase64_key(text: &str) -> Option<Vec<u8>> {
    crate::importers::unbase64(text).filter(|key| key.len() == 32)
}

#[cfg(windows)]
fn keyring() -> Option<Vec<u8>> {
    use std::ffi::c_void;
    #[repr(C)]
    struct Credential {
        flags: u32,
        kind: u32,
        target: *const u16,
        comment: *const u16,
        written: u64,
        blob_size: u32,
        blob: *mut c_void,
        persist: u32,
        attribute_count: u32,
        attributes: *mut c_void,
        alias: *const u16,
        user: *const u16,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn CredReadW(target: *const u16, kind: u32, flags: u32, credential: *mut *mut Credential) -> i32;
        fn CredFree(pointer: *mut c_void);
    }
    // keytar writes a generic credential named service/account: Termius/localKey.
    let target: Vec<u16> = "Termius/localKey".encode_utf16().chain(std::iter::once(0)).collect();
    let mut credential: *mut Credential = std::ptr::null_mut();
    // SAFETY: the name is null-terminated and lives for the call; a missing entry returns null.
    let found = unsafe { CredReadW(target.as_ptr(), 1, 0, &mut credential) };
    if found == 0 || credential.is_null() {
        return None;
    }
    // SAFETY: CredReadW filled a live credential whose blob stays valid until CredFree.
    let stored = unsafe { std::slice::from_raw_parts((*credential).blob as *const u8, (*credential).blob_size as usize).to_vec() };
    // SAFETY: the pointer came from CredReadW and is freed once.
    unsafe { CredFree(credential as *mut c_void) };
    Some(stored)
}

#[cfg(target_os = "macos")]
fn keyring() -> Option<Vec<u8>> {
    run("security", &["find-generic-password", "-s", "Termius", "-a", "localKey", "-w"])
}

#[cfg(all(unix, not(target_os = "macos")))]
fn keyring() -> Option<Vec<u8>> {
    ["termius-app", "Termius"].into_iter().find_map(|service| run("secret-tool", &["lookup", "service", service, "account", "localKey"]))
}

#[cfg(not(windows))]
fn run(program: &str, arguments: &[&str]) -> Option<Vec<u8>> {
    let output = std::process::Command::new(program).args(arguments).output().ok()?;
    output.status.success().then(|| output.stdout.into_iter().filter(|byte| !byte.is_ascii_whitespace()).collect())
}

/// The records a scan reads: every host of the profile, decrypted field by field.
struct Profile {
    hosts: Vec<Value>,
    configs: Vec<Value>,
    identities: Vec<Value>,
    keys: Vec<Value>,
    groups: Vec<Value>,
    skipped: usize,
}

impl Profile {
    fn read(dir: &Path, cipher: &XSalsa20Poly1305) -> Result<Self, String> {
        let records = leveldb::read(dir)?;
        let mut profile = Self { hosts: Vec::new(), configs: Vec::new(), identities: Vec::new(), keys: Vec::new(), groups: Vec::new(), skipped: 0 };
        for (key, value) in &records {
            let Some((database, store, index)) = idb_key(key) else { continue };
            if index != 1 || store != 1 {
                continue;
            }
            let store = match database {
                HOSTS => &mut profile.hosts,
                CONFIGS => &mut profile.configs,
                IDENTITIES => &mut profile.identities,
                KEYS => &mut profile.keys,
                GROUPS => &mut profile.groups,
                _ => continue,
            };
            match idb_value(value).map(|record| decrypt_record(record, cipher)) {
                Some(record) => store.push(record),
                None => profile.skipped += 1,
            }
        }
        Ok(profile)
    }
}

/// The database id, store id and index id a leveldb key names. Only the record index carries the
/// value; the others describe stores and the secondary indexes over their keys.
fn idb_key(key: &[u8]) -> Option<(u16, u8, u8)> {
    let header = *key.first()?;
    let widths = [usize::from((header >> 5) & 0x07) + 1, usize::from((header >> 2) & 0x03) + 1, usize::from(header & 0x03) + 1];
    let mut at = 1;
    let mut ids = [0u32; 3];
    for (id, width) in ids.iter_mut().zip(widths) {
        let bytes = key.get(at..at + width)?;
        *id = bytes.iter().rev().fold(0u32, |value, byte| (value << 8) | u32::from(*byte));
        at += width;
    }
    Some((u16::try_from(ids[0]).ok()?, u8::try_from(ids[1]).ok()?, u8::try_from(ids[2]).ok()?))
}

/// A record value: the value version, an optional Blink trailer, then the V8-serialised record.
fn idb_value(value: &[u8]) -> Option<Value> {
    let mut at = 0;
    while value.get(at)? & 0x80 != 0 {
        at += 1;
    }
    at += 1;
    // Blink puts a thirteen-byte trailer (tag, offset, length) before the serialised value.
    if value.get(at) == Some(&0xff) {
        at += 13;
    }
    Decoder::new(value.get(at..)?).read()
}

/// Every text field of a record, unsealed: Termius seals each one on its own, and the content
/// field holds a JSON document carrying the rest of the record.
fn decrypt_record(record: Value, cipher: &XSalsa20Poly1305) -> Value {
    let Value::Object(fields) = record else { return record };
    let mut opened: Vec<(String, Value)> = Vec::new();
    for (name, value) in fields {
        let value = match value {
            Value::Text(text) => Value::Text(decrypt_field(&text, cipher).unwrap_or(text)),
            other => other,
        };
        opened.push((name, value));
    }
    let document = opened.iter().find(|(name, _)| name == "content").and_then(|(_, value)| value.text()).and_then(|text| serde_json::from_str::<Json>(text).ok());
    if let Some(Json::Object(fields)) = document {
        for (name, value) in fields {
            if opened.iter().any(|(seen, _)| seen == &name) {
                continue;
            }
            opened.push((name, json_value(&value)));
        }
    }
    Value::Object(opened)
}

fn json_value(value: &Json) -> Value {
    match value {
        Json::String(text) => Value::Text(text.clone()),
        Json::Number(number) => Value::Number(number.as_f64().unwrap_or(0.0)),
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Array(items) => Value::List(items.iter().map(json_value).collect()),
        Json::Object(fields) => Value::Object(fields.iter().map(|(name, value)| (name.clone(), json_value(value))).collect()),
        Json::Null => Value::Null,
    }
}

/// A sealed field: base64 of a two-byte version tag, a 24-byte nonce and a secretbox ciphertext.
fn decrypt_field(text: &str, cipher: &XSalsa20Poly1305) -> Option<String> {
    let sealed = crate::importers::unbase64(text)?;
    if sealed.len() < 26 || sealed[0] != 4 || sealed[1] != 1 {
        return None;
    }
    let plain = cipher.decrypt(Nonce::from_slice(&sealed[2..26]), &sealed[26..]).ok()?;
    String::from_utf8(plain).ok()
}

fn text(record: &Value, name: &str) -> Option<String> {
    record.get(name).and_then(Value::text).filter(|text| !text.is_empty()).map(str::to_owned)
}

/// What a reference points at: Termius keeps a relation as {"id": n}.
fn reference(record: &Value, name: &str) -> Option<i64> {
    let inner = record.get(name)?;
    inner.get("id").and_then(Value::number).map(|id| id as i64)
}

fn find(records: &[Value], id: i64) -> Option<&Value> {
    records.iter().find(|record| record.get("id").and_then(Value::number).is_some_and(|own| own as i64 == id))
}

/// The folder a host sits in, its parents first: what the importer calls a group.
fn group_path(groups: &[Value], record: &Value) -> Option<String> {
    let mut path: Vec<String> = Vec::new();
    let mut current = reference(record, "group");
    let mut depth = 0;
    while let Some(id) = current {
        if depth > 16 {
            break;
        }
        depth += 1;
        let Some(group) = find(groups, id) else { break };
        if let Some(name) = text(group, "name") {
            path.push(name);
        }
        current = reference(group, "parent");
    }
    path.reverse();
    (!path.is_empty()).then(|| path.join("/"))
}

/// The hosts of the Termius profile on this machine, passwords and private keys included: the
/// core keeps them until the vault saves them, so the UI never sees one.
pub fn scan() -> Result<Scan, String> {
    let dir = data_dir().ok_or("Termius' local data was not found: is Termius installed and started once for this user?")?;
    let key = local_key()?;
    let cipher = XSalsa20Poly1305::new_from_slice(&key).map_err(|_| "the Termius local key is not 32 bytes".to_owned())?;
    let profile = Profile::read(&dir, &cipher)?;
    let mut scan = Scan { source: "Termius", skipped: profile.skipped, ..Scan::default() };
    for record in &profile.hosts {
        let Some(address) = text(record, "address") else {
            scan.skipped += 1;
            continue;
        };
        let config = reference(record, "ssh_config").and_then(|id| find(&profile.configs, id));
        let identity = config.and_then(|config| reference(config, "identity")).and_then(|id| find(&profile.identities, id));
        let ring = identity.and_then(|identity| reference(identity, "ssh_key")).and_then(|id| find(&profile.keys, id));
        // Termius leaves the port empty when it is 22, which is what ssh does anyway.
        let port = config.and_then(|config| config.get("port").and_then(Value::number)).and_then(|port| u16::try_from(port as u64).ok()).filter(|port| *port != 22);
        scan.hosts.push(Host {
            name: text(record, "label").unwrap_or_else(|| address.clone()),
            address,
            user: identity.and_then(|identity| text(identity, "username")),
            port,
            identity_file: None,
            jump: None,
            group: group_path(&profile.groups, record),
            password: identity.and_then(|identity| text(identity, "password")),
            private_key: ring.and_then(|ring| text(ring, "private_key")),
            passphrase: ring.and_then(|ring| text(ring, "passphrase")),
            key_name: ring.and_then(|ring| text(ring, "label")),
        });
    }
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xsalsa20poly1305::aead::Aead;

    /// The base64 a sealed field is written in, so the test can seal one and read it back.
    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let triple = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
            for index in 0..4 {
                out.push(if index > chunk.len() { '=' } else { char::from(ALPHABET[(triple >> (18 - index * 6) & 0x3f) as usize]) });
            }
        }
        out
    }

    #[test]
    fn a_leveldb_key_names_its_database_store_and_index() {
        assert_eq!(idb_key(&[0x00, 21, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f]), Some((21, 1, 1)));
        assert_eq!(idb_key(&[0x00, 6, 1, 2]), Some((6, 1, 2)));
    }

    #[test]
    fn a_sealed_field_carries_a_version_tag_a_nonce_and_a_ciphertext() {
        let cipher = XSalsa20Poly1305::new_from_slice(&[7u8; 32]).unwrap();
        let nonce = [9u8; 24];
        let mut field = vec![4, 1];
        field.extend_from_slice(&nonce);
        field.extend_from_slice(&cipher.encrypt(Nonce::from_slice(&nonce), b"hunter2".as_slice()).unwrap());
        assert_eq!(decrypt_field(&base64(&field), &cipher).as_deref(), Some("hunter2"));
        // Plain text is not a sealed field, and neither is a sealed one under another key.
        assert_eq!(decrypt_field("hunter2", &cipher), None);
        assert_eq!(decrypt_field(&base64(&[4, 1, 9, 9]), &cipher), None);
    }
}
