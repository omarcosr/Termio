//! Cloudflare R2 (any S3-compatible endpoint) through presigned SigV4 URLs. Conditional headers
//! are signed too, so a proxy cannot strip them and turn a guarded write into a blind one.

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

impl R2Store {
    pub fn new(config: &R2Config) -> Result<Self, String> {
        let endpoint = match &config.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => format!("https://{}.r2.cloudflarestorage.com", config.account.trim()),
        };
        let endpoint: url::Url = endpoint.parse().map_err(|error| format!("endpoint: {error}"))?;
        let bucket = Bucket::new(endpoint, UrlStyle::Path, config.bucket.trim().to_owned(), "auto").map_err(|error| format!("bucket: {error}"))?;
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // Generous: a slow link still finishes a small object; a dead one does not hang sync.
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .into();
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
        let store = R2Store::new(&R2Config { account, bucket, access_key, secret_key, endpoint: None, name: "termio".into() }).unwrap();
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
}
