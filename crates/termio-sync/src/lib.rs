//! Vault sync through an S3-compatible bucket (Cloudflare R2), with no server of our own.
//!
//! The bucket holds a single object, `termio.vault`: the key envelope (the data key wrapped by
//! the password), a key check, and every record sealed together with the data key. A sync reads
//! it, merges record by record (newest stamp wins, deletions travel as tombstones), and writes it
//! back with `If-Match` on its ETag, which R2 evaluates atomically: a device that lost a race gets
//! 412, reads the newer copy, merges again and retries. The first write uses `If-None-Match: *`,
//! so two devices can never race two different vaults into one bucket.
//!
//! Only the envelope is outside the seal, and it opens only with the password.

pub mod cloudflare;
mod r2;

pub use r2::{R2Config, R2Store};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;
use termio_vault::{KeyEnvelope, Record, Vault, VaultError};

/// The object sync keeps in the bucket when no name is given.
pub const VAULT: &str = "termio.vault";

/// The bucket key of a named vault: `<name>.vault`.
pub fn vault_key(name: &str) -> String {
    format!("{}.vault", name.trim().trim_end_matches(".vault"))
}
const KEY_CHECK: &[u8] = b"termio key check v1";
const RECORDS_AAD: &[u8] = b"termio records v1";
const RETRIES: usize = 6;

#[derive(Debug)]
pub enum SyncError {
    /// The bucket already holds another vault (a different key).
    OtherVault,
    /// No vault in the bucket yet (joining needs one).
    Empty,
    Vault(VaultError),
    Store(String),
    /// Kept losing the race for the object.
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
    /// The key of the vault object this store syncs.
    fn vault_key(&self) -> String {
        VAULT.to_owned()
    }
    /// Every `.vault` object at the top of the bucket.
    fn list_vaults(&self) -> Result<Vec<String>, StoreError>;
}

fn store(error: StoreError) -> SyncError {
    match error {
        StoreError::PreconditionFailed => SyncError::Store("unexpected precondition failure".into()),
        StoreError::Other(message) => SyncError::Store(message),
    }
}

/// The bucket's `termio.vault`.
#[derive(Serialize, Deserialize)]
struct Remote {
    version: u32,
    envelope: KeyEnvelope,
    #[serde(with = "hex::serde")]
    check: Vec<u8>,
    /// Every record, as one sealed JSON array.
    #[serde(with = "hex::serde")]
    records: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Records taken from the bucket.
    pub pulled: usize,
    /// Records uploaded.
    pub pushed: usize,
}

fn read_remote(store: &dyn Store) -> Result<Option<(Remote, String)>, SyncError> {
    let key = store.vault_key();
    let Some((body, etag)) = store.get(&key).map_err(self::store)? else { return Ok(None) };
    let remote = serde_json::from_slice(&body).map_err(|_| SyncError::Store(format!("unreadable {key}")))?;
    Ok(Some((remote, etag)))
}

fn remote_records(vault: &Vault, remote: &Remote) -> Result<Vec<Record>, SyncError> {
    if vault.unseal(&remote.check, KEY_CHECK).is_err() {
        return Err(SyncError::OtherVault);
    }
    let plain = vault.unseal(&remote.records, RECORDS_AAD)?;
    serde_json::from_slice(&plain).map_err(|_| SyncError::Store("unreadable records".into()))
}

fn encode(vault: &Vault) -> Vec<u8> {
    let records: Vec<&Record> = vault.all().collect();
    let remote = Remote {
        version: 1,
        envelope: vault.envelope().clone(),
        check: vault.seal(KEY_CHECK, KEY_CHECK),
        records: vault.seal(&serde_json::to_vec(&records).expect("records serialize"), RECORDS_AAD),
    };
    serde_json::to_vec(&remote).expect("the vault object serializes")
}

/// The envelope of the vault in the bucket: what a new device opens with the password.
pub fn fetch_envelope(store: &dyn Store) -> Result<KeyEnvelope, SyncError> {
    Ok(read_remote(store)?.ok_or(SyncError::Empty)?.0.envelope)
}

/// Publishes this vault's envelope after a password change, so other devices take it.
pub fn publish_envelope(vault: &mut Vault, store: &dyn Store) -> Result<(), SyncError> {
    sync_with(vault, store, true).map(|_| ())
}

/// Two-way sync: takes newer records from the bucket, uploads newer local ones, and saves the
/// vault. Safe to run from several devices at once.
pub fn sync(vault: &mut Vault, store: &dyn Store) -> Result<Report, SyncError> {
    sync_with(vault, store, false)
}

fn sync_with(vault: &mut Vault, store: &dyn Store, rewrite: bool) -> Result<Report, SyncError> {
    for _ in 0..RETRIES {
        let mut report = Report::default();
        let (condition, outgoing) = match read_remote(store)? {
            None => (Condition::Absent, vault.all().count()),
            Some((remote, etag)) => {
                let theirs = remote_records(vault, &remote)?;
                // Pull what is newer there.
                for record in &theirs {
                    if !vault.all().any(|mine| mine.id == record.id && mine.stamp >= record.stamp) {
                        vault.merge(record.clone());
                        report.pulled += 1;
                    }
                }
                // Push what is newer here.
                let outgoing = vault.all().filter(|mine| !theirs.iter().any(|record| record.id == mine.id && record.stamp >= mine.stamp)).count();
                (Condition::Matches(etag), outgoing)
            }
        };
        if outgoing == 0 && !rewrite && condition != Condition::Absent {
            vault.save()?;
            return Ok(report);
        }
        match store.put(&store.vault_key(), &encode(vault), condition) {
            Ok(_) => {
                report.pushed = outgoing;
                vault.save()?;
                return Ok(report);
            }
            // Another device wrote first: merge its copy and try again.
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
    fn list_vaults(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.keys().into_iter().filter(|key| key.ends_with(".vault") && !key.contains('/')).collect())
    }

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
    fn the_bucket_holds_one_object() {
        let dir = Dir::new("single");
        let bucket = MemoryStore::default();
        let (mut a, _) = pair(&dir, &bucket);
        for name in ["a", "b", "c"] {
            a.put("host", None, json!({ "name": name })).unwrap();
        }
        sync(&mut a, &bucket).unwrap();
        assert_eq!(bucket.keys(), [VAULT]);
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

    /// A store where another device writes the vault between our read and our write, once.
    struct Racing<'a> {
        inner: &'a MemoryStore,
        rival: Mutex<Option<Vault>>,
    }

    impl Store for Racing<'_> {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
            self.inner.get(key)
        }
        fn list_vaults(&self) -> Result<Vec<String>, StoreError> {
            self.inner.list_vaults()
        }
        fn put(&self, key: &str, body: &[u8], condition: Condition) -> Result<String, StoreError> {
            if key == VAULT && let Some(mut rival) = self.rival.lock().unwrap().take() {
                sync(&mut rival, self.inner).unwrap();
            }
            self.inner.put(key, body, condition)
        }
    }

    #[test]
    fn a_lost_race_for_the_vault_retries_and_keeps_both_changes() {
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
        publish_envelope(&mut a, &bucket).unwrap();
        sync(&mut a, &bucket).unwrap();
        let mut c = Vault::join(&dir.file("c"), fetch_envelope(&bucket).unwrap(), "new").unwrap();
        sync(&mut c, &bucket).unwrap();
        assert_eq!(names(&c), ["kept"]);
    }
}
