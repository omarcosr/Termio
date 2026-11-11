//! SSH key pairs: generation and import. Private keys are OpenSSH text; callers keep them in the
//! vault and only ever hand the public half and the fingerprint to the UI.

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// `ssh-ed25519`, `rsa-sha2-512`…
    pub algorithm: String,
    /// The `authorized_keys` line.
    pub public: String,
    /// `SHA256:…`
    pub fingerprint: String,
    /// The private key needs a passphrase to be used.
    pub encrypted: bool,
}

fn info(key: &PrivateKey) -> Result<KeyInfo, String> {
    let public = key.public_key();
    Ok(KeyInfo {
        algorithm: public.algorithm().to_string(),
        public: public.to_openssh().map_err(|error| error.to_string())?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        encrypted: key.is_encrypted(),
    })
}

/// A new Ed25519 key: its OpenSSH private text and what to show about it.
pub fn generate_ed25519(comment: &str) -> Result<(Zeroizing<String>, KeyInfo), String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|error| error.to_string())?;
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment(comment);
    let text = key.to_openssh(LineEnding::LF).map_err(|error| error.to_string())?;
    Ok((Zeroizing::new(text.to_string()), info(&key)?))
}

/// Reads a private key someone pasted or picked (OpenSSH or PEM/PKCS#8). With a passphrase
/// the key is also checked to decrypt.
pub fn inspect(private: &str, passphrase: Option<&str>) -> Result<KeyInfo, String> {
    let key = russh::keys::decode_secret_key(private, None).or_else(|error| match passphrase {
        Some(_) => russh::keys::decode_secret_key(private, passphrase),
        None => Err(error),
    });
    match key {
        Ok(key) => info(&key),
        // An encrypted OpenSSH key still shows its public half without the passphrase.
        Err(error) => match PrivateKey::from_openssh(private) {
            Ok(key) if key.is_encrypted() && passphrase.is_none() => info(&key),
            _ => Err(error.to_string()),
        },
    }
}

/// The key ready for authentication.
pub fn load(private: &str, passphrase: Option<&str>) -> Result<PrivateKey, String> {
    russh::keys::decode_secret_key(private, passphrase).map_err(|error| match error {
        russh::keys::Error::KeyIsEncrypted => "the key needs its passphrase".to_owned(),
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_reads_back_with_the_same_fingerprint() {
        let (private, generated) = generate_ed25519("termio test").unwrap();
        assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(generated.public.starts_with("ssh-ed25519 "));
        assert!(generated.fingerprint.starts_with("SHA256:"));
        assert!(!generated.encrypted);
        let read = inspect(&private, None).unwrap();
        assert_eq!(read, generated);
        assert_eq!(load(&private, None).unwrap().public_key().fingerprint(HashAlg::Sha256).to_string(), generated.fingerprint);
        assert!(inspect("not a key", None).is_err());
    }
}
