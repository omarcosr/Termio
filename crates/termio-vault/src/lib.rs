//! The vault: hosts, identities, keys, snippets and settings in one encrypted file.
//!
//! A random 32-byte data key encrypts everything. The key itself is stored wrapped by a key
//! derived from the master password (Argon2id), so changing the password rewrites one small
//! envelope and sync can share the same envelope with other devices.
//!
//! File layout: `TERMIOV1`, a big-endian u32 header length, the header (JSON: KDF parameters
//! and the wrapped key), then a 24-byte nonce and the XChaCha20-Poly1305 ciphertext of the
//! records. The header is the AAD of the body, so neither can be swapped or edited alone.
//!
//! Every record carries a hybrid logical clock stamp; merging keeps the newest stamp per record
//! and keeps the version it replaced in a bounded history, so concurrent edits on two devices
//! can be recovered.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"TERMIOV1";
const WRAP_AAD: &[u8] = b"termio vault data key v1";
const HISTORY_LIMIT: usize = 200;

#[derive(Debug)]
pub enum VaultError {
    WrongPassword,
    /// The file is not a vault, is truncated, or was modified.
    Corrupt(String),
    Io(std::io::Error),
    NotFound(String),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::WrongPassword => f.write_str("wrong password"),
            VaultError::Corrupt(why) => write!(f, "the vault file is damaged: {why}"),
            VaultError::Io(error) => write!(f, "{error}"),
            VaultError::NotFound(id) => write!(f, "no record {id}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(error: std::io::Error) -> Self {
        VaultError::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    bytes
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0)
}

/// Argon2id cost. The default takes a few hundred milliseconds on a desktop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 }
    }
}

/// The data key wrapped by the password: all another device needs, with the password, to read
/// what this vault encrypts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub kdf: KdfParams,
    #[serde(with = "hex::serde")]
    pub salt: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub wrapped: Vec<u8>,
}

fn derive(password: &str, salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|error| VaultError::Corrupt(format!("KDF parameters: {error}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| VaultError::Corrupt(format!("KDF: {error}")))?;
    Ok(key)
}

impl KeyEnvelope {
    fn seal(data_key: &[u8; 32], password: &str, kdf: KdfParams) -> Result<Self> {
        let salt = random::<16>().to_vec();
        let nonce = random::<24>();
        let wrapping = derive(password, &salt, kdf)?;
        let wrapped = XChaCha20Poly1305::new(wrapping.as_ref().into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: data_key, aad: WRAP_AAD })
            .map_err(|_| VaultError::Corrupt("could not wrap the key".into()))?;
        Ok(Self { kdf, salt, nonce: nonce.to_vec(), wrapped })
    }

    /// The data key, or `WrongPassword`.
    pub fn open(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        if self.nonce.len() != 24 {
            return Err(VaultError::Corrupt("bad key nonce".into()));
        }
        let wrapping = derive(password, &self.salt, self.kdf)?;
        let key = XChaCha20Poly1305::new(wrapping.as_ref().into())
            .decrypt(XNonce::from_slice(&self.nonce), Payload { msg: &self.wrapped, aad: WRAP_AAD })
            .map_err(|_| VaultError::WrongPassword)?;
        let key = Zeroizing::new(key);
        let mut out = Zeroizing::new([0u8; 32]);
        if key.len() != 32 {
            return Err(VaultError::Corrupt("bad key length".into()));
        }
        out.copy_from_slice(&key);
        Ok(out)
    }
}

/// A hybrid logical clock stamp: wall time, a counter for events in the same millisecond, and
/// the device, so two stamps never compare equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Stamp {
    pub ms: u64,
    pub counter: u32,
    pub node: String,
}

impl Ord for Stamp {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.ms, self.counter, &self.node).cmp(&(other.ms, other.counter, &other.node))
    }
}

impl PartialOrd for Stamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    /// `host`, `identity`, `key`, `snippet`, `known_host`, `forward`, `settings`…
    pub kind: String,
    pub data: Value,
    pub stamp: Stamp,
    /// A deletion: kept so the deletion reaches other devices.
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Merge {
    /// The remote version was newer and replaced ours (or was new).
    Applied,
    /// Ours is newer or the same.
    Kept,
}

#[derive(Default, Serialize, Deserialize)]
struct Body {
    records: BTreeMap<String, Record>,
    #[serde(default)]
    history: Vec<Record>,
    #[serde(default)]
    last: Option<Stamp>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    node: String,
    envelope: KeyEnvelope,
}

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    header: Header,
    body: Body,
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// A new, empty vault at `path` (which must not exist yet).
    pub fn create(path: &Path, password: &str) -> Result<Self> {
        Self::create_with(path, password, KdfParams::default())
    }

    pub fn create_with(path: &Path, password: &str, kdf: KdfParams) -> Result<Self> {
        let key = Zeroizing::new(random::<32>());
        let envelope = KeyEnvelope::seal(&key, password, kdf)?;
        Self::start(path, key, envelope)
    }

    /// A new local vault that shares another device's key: joining a synced vault.
    pub fn join(path: &Path, envelope: KeyEnvelope, password: &str) -> Result<Self> {
        let key = envelope.open(password)?;
        Self::start(path, key, envelope)
    }

    fn start(path: &Path, key: Zeroizing<[u8; 32]>, envelope: KeyEnvelope) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::Io(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "a vault already exists there")));
        }
        let header = Header { node: hex::encode(random::<6>()), envelope };
        let vault = Self { path: path.to_owned(), key, header, body: Body::default() };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let file = fs::read(path)?;
        let corrupt = |why: &str| VaultError::Corrupt(why.to_owned());
        if file.len() < 12 || &file[..8] != MAGIC {
            return Err(corrupt("not a Termio vault"));
        }
        let header_len = u32::from_be_bytes(file[8..12].try_into().unwrap()) as usize;
        let body_start = 12 + header_len;
        if file.len() < body_start + 24 + 16 {
            return Err(corrupt("truncated"));
        }
        let header_bytes = &file[12..body_start];
        let header: Header = serde_json::from_slice(header_bytes).map_err(|_| corrupt("unreadable header"))?;
        let key = header.envelope.open(password)?;
        let plain = XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(XNonce::from_slice(&file[body_start..body_start + 24]), Payload { msg: &file[body_start + 24..], aad: &file[..body_start] })
            .map_err(|_| corrupt("the contents do not match their checksum"))?;
        let plain = Zeroizing::new(plain);
        let body: Body = serde_json::from_slice(&plain).map_err(|_| corrupt("unreadable records"))?;
        Ok(Self { path: path.to_owned(), key, header, body })
    }

    /// Writes the vault atomically: a crash leaves the old file or the new one.
    pub fn save(&self) -> Result<()> {
        let header = serde_json::to_vec(&self.header).expect("the header serializes");
        let mut file = Vec::with_capacity(header.len() + 1024);
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&(header.len() as u32).to_be_bytes());
        file.extend_from_slice(&header);
        let plain = Zeroizing::new(serde_json::to_vec(&self.body).expect("records serialize"));
        let nonce = random::<24>();
        let sealed = XChaCha20Poly1305::new(self.key.as_ref().into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &file })
            .map_err(|_| VaultError::Corrupt("could not encrypt".into()))?;
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&sealed);
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("tmp");
        {
            let mut out = fs::File::create(&temporary)?;
            out.write_all(&file)?;
            out.sync_all()?;
        }
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This device's name in stamps.
    pub fn node(&self) -> &str {
        &self.header.node
    }

    pub fn envelope(&self) -> &KeyEnvelope {
        &self.header.envelope
    }

    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        self.change_password_with(new_password, KdfParams::default())
    }

    pub fn change_password_with(&mut self, new_password: &str, kdf: KdfParams) -> Result<()> {
        self.header.envelope = KeyEnvelope::seal(&self.key, new_password, kdf)?;
        self.save()
    }

    /// Adopts an envelope another device published (after it changed the password). It must
    /// wrap this vault's key: checked with `password`.
    pub fn adopt_envelope(&mut self, envelope: KeyEnvelope, password: &str) -> Result<()> {
        if *envelope.open(password)? != *self.key {
            return Err(VaultError::Corrupt("the envelope wraps another vault's key".into()));
        }
        self.header.envelope = envelope;
        self.save()
    }

    fn tick(&mut self) -> Stamp {
        let now = now_ms();
        let stamp = match &self.body.last {
            Some(last) if last.ms >= now => Stamp { ms: last.ms, counter: last.counter + 1, node: self.header.node.clone() },
            _ => Stamp { ms: now, counter: 0, node: self.header.node.clone() },
        };
        self.body.last = Some(stamp.clone());
        stamp
    }

    fn observe(&mut self, remote: &Stamp) {
        if self.body.last.as_ref().is_none_or(|last| remote > last) {
            self.body.last = Some(Stamp { node: self.header.node.clone(), ..remote.clone() });
        }
    }

    fn remember(&mut self, replaced: Record) {
        self.body.history.push(replaced);
        let excess = self.body.history.len().saturating_sub(HISTORY_LIMIT);
        self.body.history.drain(..excess);
    }

    /// Creates or replaces a record. Without `id` a new one is made. Saves.
    pub fn put(&mut self, kind: &str, id: Option<&str>, data: Value) -> Result<Record> {
        let id = id.map(str::to_owned).unwrap_or_else(|| hex::encode(random::<12>()));
        let stamp = self.tick();
        let record = Record { id: id.clone(), kind: kind.to_owned(), data, stamp, deleted: false };
        if let Some(old) = self.body.records.insert(id, record.clone()) {
            self.remember(old);
        }
        self.save()?;
        Ok(record)
    }

    /// Marks a record deleted. Saves.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let stamp = self.tick();
        let record = self.body.records.get_mut(id).filter(|record| !record.deleted).ok_or_else(|| VaultError::NotFound(id.to_owned()))?;
        let old = record.clone();
        record.deleted = true;
        record.data = Value::Null;
        record.stamp = stamp;
        self.remember(old);
        self.save()
    }

    pub fn get(&self, id: &str) -> Option<&Record> {
        self.body.records.get(id).filter(|record| !record.deleted)
    }

    /// Live records of `kind`, oldest first.
    pub fn list(&self, kind: &str) -> Vec<&Record> {
        let mut records: Vec<&Record> = self.body.records.values().filter(|record| record.kind == kind && !record.deleted).collect();
        records.sort_by(|a, b| a.stamp.cmp(&b.stamp));
        records
    }

    /// Every record, deletions included: what sync compares.
    pub fn all(&self) -> impl Iterator<Item = &Record> {
        self.body.records.values()
    }

    /// Earlier versions of a record, newest first.
    pub fn history(&self, id: &str) -> Vec<&Record> {
        self.body.history.iter().rev().filter(|record| record.id == id).collect()
    }

    /// Takes a record from another device if its stamp is newer. Does not save: call `save`
    /// after a batch.
    pub fn merge(&mut self, remote: Record) -> Merge {
        self.observe(&remote.stamp);
        match self.body.records.get(&remote.id) {
            Some(local) if local.stamp >= remote.stamp => {
                if local.stamp != remote.stamp {
                    self.remember(remote);
                }
                Merge::Kept
            }
            _ => {
                if let Some(old) = self.body.records.insert(remote.id.clone(), remote) {
                    self.remember(old);
                }
                Merge::Applied
            }
        }
    }

    /// Encrypts bytes with the data key (sync blobs). `aad` binds them to their name.
    pub fn seal(&self, plain: &[u8], aad: &[u8]) -> Vec<u8> {
        seal_with(&self.key, plain, aad)
    }

    pub fn unseal(&self, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        unseal_with(&self.key, sealed, aad)
    }
}

/// Nonce then ciphertext, with a data key.
pub fn seal_with(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = random::<24>();
    let mut out = nonce.to_vec();
    out.extend(XChaCha20Poly1305::new(key.into()).encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad }).expect("encryption"));
    out
}

pub fn unseal_with(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 24 + 16 {
        return Err(VaultError::Corrupt("sealed data is truncated".into()));
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(&sealed[..24]), Payload { msg: &sealed[24..], aad })
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Corrupt("sealed data does not match its checksum".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Cheap Argon2 so tests stay fast; the format is the same.
    const FAST: KdfParams = KdfParams { memory_kib: 64, iterations: 1, parallelism: 1 };

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("termio-vault-{name}-{}", hex::encode(random::<4>())));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn records_survive_a_reopen_and_stay_encrypted_on_disk() {
        let dir = Dir::new("roundtrip");
        let path = dir.file("vault.termio");
        let mut vault = Vault::create_with(&path, "correct horse", FAST).unwrap();
        let host = vault.put("host", None, json!({ "name": "prod", "address": "10.0.0.5", "password": "hunter2-secret" })).unwrap();
        vault.put("snippet", Some("s1"), json!({ "command": "uptime" })).unwrap();
        drop(vault);

        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(14).any(|w| w == b"hunter2-secret"), "secrets never reach the disk in clear");
        assert!(!raw.windows(4).any(|w| w == b"prod"));

        let vault = Vault::open(&path, "correct horse").unwrap();
        assert_eq!(vault.get(&host.id).unwrap().data["address"], "10.0.0.5");
        assert_eq!(vault.list("snippet").len(), 1);
        assert_eq!(vault.list("host").len(), 1);
    }

    #[test]
    fn a_wrong_password_and_a_tampered_file_are_told_apart() {
        let dir = Dir::new("tamper");
        let path = dir.file("vault.termio");
        let mut vault = Vault::create_with(&path, "pw", FAST).unwrap();
        vault.put("host", None, json!({ "name": "a" })).unwrap();
        assert!(matches!(Vault::open(&path, "nope"), Err(VaultError::WrongPassword)));

        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(&path, &raw).unwrap();
        assert!(matches!(Vault::open(&path, "pw"), Err(VaultError::Corrupt(_))));

        fs::write(&path, &raw[..20]).unwrap();
        assert!(matches!(Vault::open(&path, "pw"), Err(VaultError::Corrupt(_))));
        fs::write(&path, b"hello").unwrap();
        assert!(matches!(Vault::open(&path, "pw"), Err(VaultError::Corrupt(_))));
    }

    #[test]
    fn changing_the_password_keeps_the_data_key() {
        let dir = Dir::new("password");
        let path = dir.file("vault.termio");
        let mut vault = Vault::create_with(&path, "old", FAST).unwrap();
        vault.put("host", Some("h"), json!({ "name": "a" })).unwrap();
        let sealed = vault.seal(b"blob", b"name");
        vault.change_password_with("new", FAST).unwrap();
        drop(vault);
        assert!(matches!(Vault::open(&path, "old"), Err(VaultError::WrongPassword)));
        let vault = Vault::open(&path, "new").unwrap();
        assert_eq!(&**vault.unseal(&sealed, b"name").unwrap(), b"blob", "blobs sealed before the change still open");
        assert!(vault.unseal(&sealed, b"other").is_err(), "a blob only opens under its own name");
    }

    #[test]
    fn deletions_and_edits_keep_history() {
        let dir = Dir::new("history");
        let mut vault = Vault::create_with(&dir.file("v"), "pw", FAST).unwrap();
        vault.put("host", Some("h"), json!({ "v": 1 })).unwrap();
        vault.put("host", Some("h"), json!({ "v": 2 })).unwrap();
        vault.remove("h").unwrap();
        assert!(vault.get("h").is_none());
        assert!(vault.list("host").is_empty());
        assert!(vault.all().any(|record| record.id == "h" && record.deleted), "the deletion is kept for sync");
        let history: Vec<_> = vault.history("h").iter().map(|record| record.data["v"].as_i64()).collect();
        assert_eq!(history, vec![Some(2), Some(1)]);
        assert!(matches!(vault.remove("h"), Err(VaultError::NotFound(_))));
    }

    #[test]
    fn merging_keeps_the_newest_stamp_on_both_devices() {
        let dir = Dir::new("merge");
        let mut a = Vault::create_with(&dir.file("a"), "pw", FAST).unwrap();
        let mut b = Vault::join(&dir.file("b"), a.envelope().clone(), "pw").unwrap();
        assert_ne!(a.node(), b.node());

        let first = a.put("host", Some("h"), json!({ "name": "from a" })).unwrap();
        assert_eq!(b.merge(first.clone()), Merge::Applied);
        // b edits after seeing a's version: its stamp is later even if b's clock is behind.
        let second = b.put("host", Some("h"), json!({ "name": "from b" })).unwrap();
        assert!(second.stamp > first.stamp);
        assert_eq!(a.merge(second.clone()), Merge::Applied);
        assert_eq!(a.get("h").unwrap().data["name"], "from b");
        assert_eq!(b.merge(first.clone()), Merge::Kept, "an older version does not win");
        assert_eq!(b.history("h")[0].data["name"], "from a");

        // A deletion is a record too and wins by stamp.
        a.remove("h").unwrap();
        let deletion = a.all().find(|record| record.id == "h").unwrap().clone();
        assert_eq!(b.merge(deletion), Merge::Applied);
        assert!(b.get("h").is_none());
    }

    #[test]
    fn joining_needs_the_right_password_and_shares_sealed_blobs() {
        let dir = Dir::new("join");
        let a = Vault::create_with(&dir.file("a"), "pw", FAST).unwrap();
        assert!(matches!(Vault::join(&dir.file("b"), a.envelope().clone(), "wrong"), Err(VaultError::WrongPassword)));
        let b = Vault::join(&dir.file("b"), a.envelope().clone(), "pw").unwrap();
        let sealed = a.seal(b"shared", b"records/1");
        assert_eq!(&**b.unseal(&sealed, b"records/1").unwrap(), b"shared");
        assert!(Vault::create_with(&dir.file("a"), "pw", FAST).is_err(), "an existing vault is never overwritten");
    }
}
