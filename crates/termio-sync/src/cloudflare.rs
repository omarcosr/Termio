//! Setting sync up from one Cloudflare API token: list the accounts and R2 buckets it reaches,
//! create a bucket, and derive the S3 credentials R2 accepts for the same token
//! (access key = token id, secret = SHA-256 of the token value, as Cloudflare documents).

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

const API: &str = "https://api.cloudflare.com/client/v4";

/// The dashboard page that creates a token with exactly what sync needs, already filled in.
pub const TOKEN_URL: &str = "https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_r2%22%2C%22type%22%3A%22edit%22%7D%5D&name=Termio%20Sync&accountId=*&zoneId=all";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Account {
    pub id: String,
    pub name: String,
}

pub struct Cloudflare {
    token: String,
    agent: ureq::Agent,
}

impl Cloudflare {
    pub fn new(token: &str) -> Self {
        let agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
        Self { token: token.trim().to_owned(), agent }
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let url = format!("{API}{path}");
        let auth = format!("Bearer {}", self.token);
        let response = match (method, body) {
            ("POST", Some(body)) => self.agent.post(&url).header("Authorization", &auth).header("Content-Type", "application/json").send(body.to_string()),
            _ => self.agent.get(&url).header("Authorization", &auth).call(),
        };
        let mut response = response.map_err(|error| format!("Cloudflare: {error}"))?;
        let text = response.body_mut().read_to_string().map_err(|error| format!("Cloudflare: {error}"))?;
        let value: Value = serde_json::from_str(&text).map_err(|error| format!("Cloudflare: {error}"))?;
        if value["success"].as_bool() != Some(true) {
            let message = value["errors"][0]["message"].as_str().unwrap_or("request failed");
            return Err(format!("Cloudflare: {message}"));
        }
        Ok(value["result"].clone())
    }

    /// Checks the token is active; returns its id (the S3 access key).
    pub fn verify(&self) -> Result<String, String> {
        let result = self.call("GET", "/user/tokens/verify", None)?;
        if result["status"].as_str() != Some("active") {
            return Err("this token is not active".into());
        }
        result["id"].as_str().map(str::to_owned).ok_or_else(|| "Cloudflare: no token id".into())
    }

    pub fn accounts(&self) -> Result<Vec<Account>, String> {
        let result = self.call("GET", "/accounts?per_page=50", None)?;
        Ok(result.as_array().into_iter().flatten().filter_map(|account| Some(Account { id: account["id"].as_str()?.to_owned(), name: account["name"].as_str().unwrap_or("").to_owned() })).collect())
    }

    pub fn buckets(&self, account: &str) -> Result<Vec<String>, String> {
        let result = self.call("GET", &format!("/accounts/{account}/r2/buckets?per_page=1000"), None)?;
        Ok(result["buckets"].as_array().into_iter().flatten().filter_map(|bucket| bucket["name"].as_str().map(str::to_owned)).collect())
    }

    pub fn create_bucket(&self, account: &str, name: &str) -> Result<(), String> {
        self.call("POST", &format!("/accounts/{account}/r2/buckets"), Some(serde_json::json!({ "name": name }))).map(|_| ())
    }
}

/// The S3 secret key R2 pairs with a token: the hex SHA-256 of its value.
pub fn secret_key(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_secret_is_the_hex_sha256_of_the_token() {
        assert_eq!(super::secret_key(" abc\n"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
