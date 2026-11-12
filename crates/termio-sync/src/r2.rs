//! Cloudflare R2, AWS S3 (any S3-compatible endpoint) through presigned SigV4 URLs. Conditional
//! headers are signed too, so a proxy cannot strip them and turn a guarded write into a blind one.
//! S3 has evaluated `If-None-Match` and `If-Match` on PutObject since late 2024, as R2 does.

use crate::{Condition, Store, StoreError};
use rusty_s3::actions::ListObjectsV2;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2Config {
    /// The Cloudflare account id (the `<account>.r2.cloudflarestorage.com` host).
    pub account: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    /// Another S3 endpoint instead of R2's (MinIO, S3 itself).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// AWS S3: the bucket's region. Set, the endpoint is `s3.<region>.amazonaws.com` and `account` is unused.
    #[serde(default)]
    pub region: Option<String>,
    /// The vault's name in the bucket: stored as `<name>.vault`.
    #[serde(default = "default_name")]
    pub name: String,
}

fn default_name() -> String {
    "termio".into()
}

pub struct R2Store {
    bucket: Bucket,
    credentials: Credentials,
    agent: ureq::Agent,
    key: String,
}

const SIGNATURE_LIFETIME: Duration = Duration::from_secs(300);

impl R2Config {
    /// Whether this is an AWS S3 bucket rather than Cloudflare R2.
    pub fn is_aws(&self) -> bool {
        self.region.is_some()
    }

    /// The provider, as the UI names it.
    pub fn provider(&self) -> &'static str {
        if self.is_aws() { "AWS S3" } else { "Cloudflare R2" }
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        // Generous: a slow link still finishes a small object; a dead one does not hang sync.
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into()
}

/// The region of an AWS S3 bucket: S3 names it in `x-amz-bucket-region` on any answer about the
/// bucket, even an unsigned one it refuses.
pub fn detect_region(bucket: &str) -> Result<String, String> {
    let bucket = bucket.trim();
    if bucket.is_empty() {
        return Err("missing bucket".into());
    }
    let url = format!("https://s3.amazonaws.com/{bucket}");
    // A bucket elsewhere answers 301 with no Location: that answer is the one to read.
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(Duration::from_secs(20))).build().into();
    let response = agent.head(&url).call().map_err(|error| format!("region of {bucket}: {error}"))?;
    if response.status().as_u16() == 404 {
        return Err(format!("there is no S3 bucket named {bucket}"));
    }
    response
        .headers()
        .get("x-amz-bucket-region")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| format!("S3 did not say where {bucket} is: enter its region"))
}

impl R2Store {
    pub fn new(config: &R2Config) -> Result<Self, String> {
        let region = config.region.as_deref().map(str::trim).filter(|region| !region.is_empty());
        let bucket_name = config.bucket.trim().to_owned();
        let (endpoint, style) = match (&config.endpoint, region) {
            (Some(endpoint), _) => (endpoint.clone(), UrlStyle::Path),
            // A dotted bucket name breaks the TLS wildcard of a virtual host: it goes in the path.
            (None, Some(region)) => (format!("https://s3.{region}.amazonaws.com"), if bucket_name.contains('.') { UrlStyle::Path } else { UrlStyle::VirtualHost }),
            (None, None) => (format!("https://{}.r2.cloudflarestorage.com", config.account.trim()), UrlStyle::Path),
        };
        let endpoint: url::Url = endpoint.parse().map_err(|error| format!("endpoint: {error}"))?;
        let bucket = Bucket::new(endpoint, style, bucket_name, region.unwrap_or("auto").to_owned()).map_err(|error| format!("bucket: {error}"))?;
        let agent = agent();
        Ok(Self { bucket, credentials: Credentials::new(config.access_key.trim(), config.secret_key.trim()), agent, key: crate::vault_key(&config.name) })
    }
}

fn etag(response: &ureq::http::Response<ureq::Body>) -> String {
    response.headers().get("etag").and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned()
}

fn failure(action: &str, key: &str, response: &mut ureq::http::Response<ureq::Body>) -> StoreError {
    let status = response.status();
    let body = response.body_mut().read_to_string().unwrap_or_default();
    // S3 error bodies are XML with a <Code>: enough to tell bad credentials from a missing bucket.
    let code = body.split("<Code>").nth(1).and_then(|rest| rest.split("</Code>").next()).unwrap_or("");
    StoreError::Other(format!("{action} {key}: HTTP {status} {code}").trim().to_owned())
}

impl Store for R2Store {
    fn vault_key(&self) -> String {
        self.key.clone()
    }

    fn list_vaults(&self) -> Result<Vec<String>, StoreError> {
        let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
        action.with_delimiter("/");
        let url = action.sign(SIGNATURE_LIFETIME);
        let mut response = self.agent.get(url.as_str()).call().map_err(|error| StoreError::Other(error.to_string()))?;
        if response.status().as_u16() != 200 {
            return Err(failure("list", "", &mut response));
        }
        let body = response.body_mut().read_to_string().map_err(|error| StoreError::Other(error.to_string()))?;
        let list = ListObjectsV2::parse_response(&body).map_err(|error| StoreError::Other(error.to_string()))?;
        Ok(list.contents.into_iter().map(|object| object.key).filter(|key| key.ends_with(".vault")).collect())
    }

    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
        let url = self.bucket.get_object(Some(&self.credentials), key).sign(SIGNATURE_LIFETIME);
        let mut response = self.agent.get(url.as_str()).call().map_err(|error| StoreError::Other(error.to_string()))?;
        match response.status().as_u16() {
            200 => {
                let tag = etag(&response);
                let body = response.body_mut().with_config().limit(64 * 1024 * 1024).read_to_vec().map_err(|error| StoreError::Other(error.to_string()))?;
                Ok(Some((body, tag)))
            }
            404 => Ok(None),
            _ => Err(failure("read", key, &mut response)),
        }
    }

    fn put(&self, key: &str, body: &[u8], condition: Condition) -> Result<String, StoreError> {
        let mut action = self.bucket.put_object(Some(&self.credentials), key);
        let header = match &condition {
            Condition::None => None,
            Condition::Absent => Some(("if-none-match", "*".to_owned())),
            Condition::Matches(tag) => Some(("if-match", tag.clone())),
        };
        if let Some((name, value)) = &header {
            action.headers_mut().insert(*name, value.clone());
        }
        let url = action.sign(SIGNATURE_LIFETIME);
        let mut request = self.agent.put(url.as_str()).header("content-type", "application/octet-stream");
        if let Some((name, value)) = &header {
            request = request.header(*name, value.as_str());
        }
        let mut response = request.send(body).map_err(|error| StoreError::Other(error.to_string()))?;
        match response.status().as_u16() {
            200 => Ok(etag(&response)),
            412 => Err(StoreError::PreconditionFailed),
            _ => Err(failure("write", key, &mut response)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against AWS, only with TERMIO_NET_TESTS set: public buckets in two regions, and one that does not exist.
    #[test]
    fn the_region_of_an_s3_bucket_is_detected() {
        if std::env::var("TERMIO_NET_TESTS").is_err() {
            eprintln!("skipped: TERMIO_NET_TESTS is unset");
            return;
        }
        assert_eq!(detect_region("commoncrawl").unwrap(), "us-east-1");
        assert_eq!(detect_region("ookla-open-data").unwrap(), "us-west-2");
        assert!(detect_region("termio-nonexistent-bucket-xyz123").unwrap_err().contains("no S3 bucket"));
    }

    fn conditional_writes(config: R2Config) {
        let store = R2Store::new(&config).unwrap();
        let mut tag = [0u8; 8];
        getrandom::fill(&mut tag).unwrap();
        let key = format!("termio-test/{}", hex::encode(tag));
        assert_eq!(store.get(&key).unwrap(), None);
        let first = store.put(&key, b"one", Condition::Absent).unwrap();
        assert_eq!(store.put(&key, b"two", Condition::Absent), Err(StoreError::PreconditionFailed));
        assert_eq!(store.put(&key, b"two", Condition::Matches("\"stale\"".into())), Err(StoreError::PreconditionFailed));
        store.put(&key, b"two", Condition::Matches(first)).unwrap();
        assert_eq!(store.get(&key).unwrap().unwrap().0, b"two");
    }

    /// Against a real bucket, only when credentials are in the environment:
    /// `TERMIO_R2_ACCOUNT`, `TERMIO_R2_BUCKET`, `TERMIO_R2_ACCESS_KEY`, `TERMIO_R2_SECRET_KEY`.
    #[test]
    fn conditional_writes_against_a_real_bucket() {
        let var = |name: &str| std::env::var(name).ok();
        let (Some(account), Some(bucket), Some(access_key), Some(secret_key)) =
            (var("TERMIO_R2_ACCOUNT"), var("TERMIO_R2_BUCKET"), var("TERMIO_R2_ACCESS_KEY"), var("TERMIO_R2_SECRET_KEY"))
        else {
            eprintln!("skipped: no TERMIO_R2_* credentials");
            return;
        };
        conditional_writes(R2Config { account, bucket, access_key, secret_key, endpoint: None, region: None, name: "termio".into() });
    }

    /// The same against AWS S3: `TERMIO_S3_BUCKET`, `TERMIO_S3_ACCESS_KEY`, `TERMIO_S3_SECRET_KEY`,
    /// and `TERMIO_S3_REGION` (detected when unset).
    #[test]
    fn conditional_writes_against_a_real_s3_bucket() {
        let var = |name: &str| std::env::var(name).ok();
        let (Some(bucket), Some(access_key), Some(secret_key)) = (var("TERMIO_S3_BUCKET"), var("TERMIO_S3_ACCESS_KEY"), var("TERMIO_S3_SECRET_KEY")) else {
            eprintln!("skipped: no TERMIO_S3_* credentials");
            return;
        };
        let region = var("TERMIO_S3_REGION").unwrap_or_else(|| detect_region(&bucket).unwrap());
        conditional_writes(R2Config { account: String::new(), bucket, access_key, secret_key, endpoint: None, region: Some(region), name: "termio".into() });
    }
}
