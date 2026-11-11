//! Vault sync through an S3-compatible bucket (Cloudflare R2), with no server of our own.
//!
//! Layout under `termio/v1/`:
//! - `header`: the key envelope (the data key wrapped by the password) and a key check.
//!   Created once with `If-None-Match: *`, so two devices can never race two keys into it.
//! - `manifest`: sealed map of record id → stamp and blob name. Replaced with `If-Match` on its
//!   ETag, which R2 evaluates atomically: a concurrent writer gets 412, pulls, merges and retries.
//! - `records/<random>`: one sealed record version each, never rewritten.
//!
//! Everything but the header is encrypted with the vault's data key, and blob names are random,
//! so the bucket learns nothing about hosts or their number beyond blob counts. A change to one
//! host uploads about a kilobyte plus the manifest, which matters on a slow link.

pub mod cloudflare;
mod r2;

pub use r2::{R2Config, R2Store};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;
use termio_vault::{KeyEnvelope, Record, Stamp, Vault, VaultError};

const HEADER: &str = "termio/v1/header";
const MANIFEST: &str = "termio/v1/manifest";
const RECORDS: &str = "termio/v1/records/";
const KEY_CHECK: &[u8] = b"termio key check v1";
const RETRIES: usize = 6;

#[derive(Debug)]
pub enum SyncError {
    /// The bucket already holds another vault (a different key).
    OtherVault,
    /// No vault in the bucket yet (joining needs one).
    Empty,
    Vault(VaultError),
    Store(String),
    /// Kept losing the race for the manifest.
    Contended,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::OtherVault => f.write_str("this bucket holds a different vault"),
            SyncError::Empty => f.write_str("there is no vault in this bucket yet"),
            SyncError::Vault(error) => write!(f, "{error}"),
            SyncError::Store(error) => write!(f, "storage: {error}"),
            SyncError::Contended => f.write_str("other devices kept changing the vault; try again"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<VaultError> for SyncError {
    fn from(error: VaultError) -> Self {
        SyncError::Vault(error)
    }
}

/// A write precondition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    None,
    /// Only if the object does not exist.
    Absent,
    /// Only if the object still has this ETag.
    Matches(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    PreconditionFailed,
    Other(String),
}

/// The object storage sync needs: whole-object reads and conditional writes.
pub trait Store: Send + Sync {
    /// The object and its ETag, or `None` when it does not exist.
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError>;
    /// Writes the object and returns its new ETag.
    fn put(&self, key: &str, body: &[u8], condition: Condition) -> Result<String, StoreError>;
}

fn store(error: StoreError) -> SyncError {
    match error {
        StoreError::PreconditionFailed => SyncError::Store("unexpected precondition failure".into()),
        StoreError::Other(message) => SyncError::Store(message),
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    envelope: KeyEnvelope,
    #[serde(with = "hex::serde")]
    check: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct Entry {
    stamp: Stamp,
    blob: String,
}

type Manifest = BTreeMap<String, Entry>;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Records taken from the bucket.
    pub pulled: usize,
    /// Records uploaded.
    pub pushed: usize,
}

fn blob_name() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    format!("{RECORDS}{}", hex::encode(bytes))
}

/// The envelope of the vault in the bucket: what a new device opens with the password.
pub fn fetch_envelope(store: &dyn Store) -> Result<KeyEnvelope, SyncError> {
    let (body, _) = store.get(HEADER).map_err(self::store)?.ok_or(SyncError::Empty)?;
    let header: Header = serde_json::from_slice(&body).map_err(|_| SyncError::Store("unreadable header".into()))?;
    Ok(header.envelope)
}

/// Makes sure the bucket holds this vault's header, creating it on first sync.
fn claim(vault: &Vault, store: &dyn Store) -> Result<(), SyncError> {
    for _ in 0..2 {
        match store.get(HEADER).map_err(self::store)? {
            Some((body, _)) => {
                let header: Header = serde_json::from_slice(&body).map_err(|_| SyncError::Store("unreadable header".into()))?;
                return match vault.unseal(&header.check, KEY_CHECK) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(SyncError::OtherVault),
                };
            }
            None => {
                let header = Header { envelope: vault.envelope().clone(), check: vault.seal(KEY_CHECK, KEY_CHECK) };
                match store.put(HEADER, &serde_json::to_vec(&header).expect("header serializes"), Condition::Absent) {
                    Ok(_) => return Ok(()),
                    // Another device created it first: check it is ours.
                    Err(StoreError::PreconditionFailed) => continue,
                    Err(error) => return Err(self::store(error)),
                }
            }
        }
    }
    Err(SyncError::Contended)
}

/// Publishes this vault's envelope after a password change, so other devices take it.
pub fn publish_envelope(vault: &Vault, store: &dyn Store) -> Result<(), SyncError> {
    claim(vault, store)?;
    let header = Header { envelope: vault.envelope().clone(), check: vault.seal(KEY_CHECK, KEY_CHECK) };
    store.put(HEADER, &serde_json::to_vec(&header).expect("header serializes"), Condition::None).map_err(self::store)?;
    Ok(())
}

fn read_manifest(vault: &Vault, store: &dyn Store) -> Result<(Manifest, Option<String>), SyncError> {
    match store.get(MANIFEST).map_err(self::store)? {
        None => Ok((Manifest::new(), None)),
        Some((body, etag)) => {
            let plain = vault.unseal(&body, MANIFEST.as_bytes())?;
            let manifest = serde_json::from_slice(&plain).map_err(|_| SyncError::Store("unreadable manifest".into()))?;
            Ok((manifest, Some(etag)))
        }
    }
}

/// Two-way sync: takes newer records from the bucket, uploads newer local ones, and saves the
/// vault. Safe to run from several devices at once.
pub fn sync(vault: &mut Vault, store: &dyn Store) -> Result<Report, SyncError> {
    claim(vault, store)?;
    let mut report = Report::default();
    for _ in 0..RETRIES {
        let (mut manifest, etag) = read_manifest(vault, store)?;

        // Pull what is newer there.
        for (id, entry) in &manifest {
            if vault.all().any(|record| &record.id == id && record.stamp >= entry.stamp) {
                continue;
            }
            let Some((sealed, _)) = store.get(&entry.blob).map_err(self::store)? else {
                return Err(SyncError::Store(format!("missing record blob {}", entry.blob)));
            };
            let plain = vault.unseal(&sealed, entry.blob.as_bytes())?;
            let record: Record = serde_json::from_slice(&plain).map_err(|_| SyncError::Store("unreadable record".into()))?;
            vault.merge(record);
            report.pulled += 1;
        }

        // Push what is newer here.
        let outgoing: Vec<Record> = vault
            .all()
            .filter(|record| manifest.get(&record.id).is_none_or(|entry| record.stamp > entry.stamp))
            .cloned()
            .collect();
        if outgoing.is_empty() {
            vault.save()?;
            return Ok(report);
        }
        for record in &outgoing {
            let blob = blob_name();
            let sealed = vault.seal(&serde_json::to_vec(record).expect("records serialize"), blob.as_bytes());
            store.put(&blob, &sealed, Condition::Absent).map_err(self::store)?;
            manifest.insert(record.id.clone(), Entry { stamp: record.stamp.clone(), blob });
        }
        let sealed = vault.seal(&serde_json::to_vec(&manifest).expect("manifest serializes"), MANIFEST.as_bytes());
        let condition = etag.map_or(Condition::Absent, Condition::Matches);
        match store.put(MANIFEST, &sealed, condition) {
            Ok(_) => {
                report.pushed += outgoing.len();
                vault.save()?;
                return Ok(report);
            }
            // Someone else moved the manifest: start over from theirs. The blobs uploaded
            // above are orphans and cost a few bytes.
            Err(StoreError::PreconditionFailed) => {}
            Err(error) => return Err(self::store(error)),
        }
    }
    Err(SyncError::Contended)
}

/// An in-memory bucket with S3's conditional-write semantics, for tests and offline use.
#[derive(Default)]
pub struct MemoryStore {
    objects: Mutex<BTreeMap<String, (Vec<u8>, u64)>>,
    version: Mutex<u64>,
}

impl MemoryStore {
    pub fn keys(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }

    pub fn raw(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).map(|(body, _)| body.clone())
    }
}

impl Store for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
        Ok(self.objects.lock().unwrap().get(key).map(|(body, version)| (body.clone(), format!("\"{version}\""))))
    }

    fn put(&self, key: &str, body: &[u8], condition: Condition) -> Result<String, StoreError> {
        let mut objects = self.objects.lock().unwrap();
        let current = objects.get(key).map(|(_, version)| format!("\"{version}\""));
        let allowed = match &condition {
            Condition::None => true,
            Condition::Absent => current.is_none(),
            Condition::Matches(etag) => current.as_ref() == Some(etag),
        };
        if !allowed {
            return Err(StoreError::PreconditionFailed);
        }
        let mut version = self.version.lock().unwrap();
        *version += 1;
        objects.insert(key.to_owned(), (body.to_vec(), *version));
        Ok(format!("\"{version}\""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use termio_vault::KdfParams;

    const FAST: KdfParams = KdfParams { memory_kib: 64, iterations: 1, parallelism: 1 };

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let mut tag = [0u8; 4];
            getrandom::fill(&mut tag).unwrap();
            let dir = std::env::temp_dir().join(format!("termio-sync-{name}-{}", hex::encode(tag)));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pair(dir: &Dir, bucket: &MemoryStore) -> (Vault, Vault) {
        let mut a = Vault::create_with(&dir.file("a"), "pw", FAST).unwrap();
        sync(&mut a, bucket).unwrap();
        let b = Vault::join(&dir.file("b"), fetch_envelope(bucket).unwrap(), "pw").unwrap();
        (a, b)
    }

    fn names(vault: &Vault) -> Vec<String> {
        let mut names: Vec<String> = vault.list("host").iter().map(|record| record.data["name"].as_str().unwrap().to_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn a_new_device_joins_with_the_password_and_gets_everything() {
        let dir = Dir::new("join");
        let bucket = MemoryStore::default();
        let (mut a, mut b) = pair(&dir, &bucket);
        a.put("host", None, json!({ "name": "prod", "password": "hunter2-secret" })).unwrap();
        a.put("host", None, json!({ "name": "db" })).unwrap();
        assert_eq!(sync(&mut a, &bucket).unwrap(), Report { pulled: 0, pushed: 2 });
        assert_eq!(sync(&mut b, &bucket).unwrap(), Report { pulled: 2, pushed: 0 });
        assert_eq!(names(&b), ["db", "prod"]);
        assert!(Vault::join(&dir.file("c"), fetch_envelope(&bucket).unwrap(), "wrong").is_err());
        assert_eq!(sync(&mut a, &bucket).unwrap(), Report::default(), "nothing to do twice");
    }

    #[test]
    fn the_bucket_never_sees_names_or_secrets() {
        let dir = Dir::new("opaque");
        let bucket = MemoryStore::default();
        let (mut a, _) = pair(&dir, &bucket);
        a.put("host", Some("prod-db"), json!({ "name": "prod-db.internal", "password": "hunter2-secret" })).unwrap();
        sync(&mut a, &bucket).unwrap();
        for key in bucket.keys() {
            assert!(!key.contains("prod"), "object names are opaque: {key}");
            let raw = String::from_utf8_lossy(&bucket.raw(&key).unwrap()).into_owned();
            assert!(!raw.contains("hunter2") && !raw.contains("prod-db"), "{key} leaks content");
        }
    }

    #[test]
    fn offline_edits_on_both_devices_merge_by_record() {
        let dir = Dir::new("offline");
        let bucket = MemoryStore::default();
        let (mut a, mut b) = pair(&dir, &bucket);
        a.put("host", Some("shared"), json!({ "name": "v1" })).unwrap();
        sync(&mut a, &bucket).unwrap();
        sync(&mut b, &bucket).unwrap();

        // Offline: a adds a host, b adds another and edits the shared one later.
        a.put("host", None, json!({ "name": "only-a" })).unwrap();
        b.put("host", None, json!({ "name": "only-b" })).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        b.put("host", Some("shared"), json!({ "name": "v2" })).unwrap();

        sync(&mut a, &bucket).unwrap();
        sync(&mut b, &bucket).unwrap();
        sync(&mut a, &bucket).unwrap();
        assert_eq!(names(&a), ["only-a", "only-b", "v2"]);
        assert_eq!(names(&a), names(&b));
    }

    #[test]
    fn a_deletion_reaches_the_other_device() {
        let dir = Dir::new("delete");
        let bucket = MemoryStore::default();
        let (mut a, mut b) = pair(&dir, &bucket);
        a.put("host", Some("h"), json!({ "name": "gone" })).unwrap();
        sync(&mut a, &bucket).unwrap();
        sync(&mut b, &bucket).unwrap();
        assert_eq!(names(&b), ["gone"]);
        b.remove("h").unwrap();
        sync(&mut b, &bucket).unwrap();
        sync(&mut a, &bucket).unwrap();
        assert!(names(&a).is_empty());
    }

    /// A store where another device writes the manifest between our read and our write, once.
    struct Racing<'a> {
        inner: &'a MemoryStore,
        rival: Mutex<Option<Vault>>,
    }

    impl Store for Racing<'_> {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
            self.inner.get(key)
        }
        fn put(&self, key: &str, body: &[u8], condition: Condition) -> Result<String, StoreError> {
            if key == MANIFEST && let Some(mut rival) = self.rival.lock().unwrap().take() {
                sync(&mut rival, self.inner).unwrap();
            }
            self.inner.put(key, body, condition)
        }
    }

    #[test]
    fn a_lost_race_for_the_manifest_retries_and_keeps_both_changes() {
        let dir = Dir::new("race");
        let bucket = MemoryStore::default();
        let (mut a, mut b) = pair(&dir, &bucket);
        b.put("host", None, json!({ "name": "from-b" })).unwrap();
        a.put("host", None, json!({ "name": "from-a" })).unwrap();
        let racing = Racing { inner: &bucket, rival: Mutex::new(Some(b)) };
        let report = sync(&mut a, &racing).unwrap();
        assert_eq!(report, Report { pulled: 1, pushed: 1 });
        assert_eq!(names(&a), ["from-a", "from-b"]);
    }

    #[test]
    fn a_bucket_holding_another_vault_is_refused() {
        let dir = Dir::new("other");
        let bucket = MemoryStore::default();
        let mut a = Vault::create_with(&dir.file("a"), "pw", FAST).unwrap();
        sync(&mut a, &bucket).unwrap();
        let mut stranger = Vault::create_with(&dir.file("s"), "pw", FAST).unwrap();
        assert!(matches!(sync(&mut stranger, &bucket), Err(SyncError::OtherVault)));
        assert!(matches!(fetch_envelope(&MemoryStore::default()), Err(SyncError::Empty)));
    }

    #[test]
    fn a_password_change_published_by_one_device_opens_on_a_new_one() {
        let dir = Dir::new("rekey");
        let bucket = MemoryStore::default();
        let (mut a, _) = pair(&dir, &bucket);
        a.put("host", None, json!({ "name": "kept" })).unwrap();
        a.change_password_with("new", FAST).unwrap();
        publish_envelope(&a, &bucket).unwrap();
        sync(&mut a, &bucket).unwrap();
        let mut c = Vault::join(&dir.file("c"), fetch_envelope(&bucket).unwrap(), "new").unwrap();
        sync(&mut c, &bucket).unwrap();
        assert_eq!(names(&c), ["kept"]);
    }
}
