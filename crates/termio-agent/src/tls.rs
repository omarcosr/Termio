//! QUIC's TLS without a certificate authority: the agent makes a fresh self-signed certificate
//! each time it starts and prints its SHA-256 over the already-authenticated SSH channel; the
//! client accepts that certificate and no other.

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

pub const ALPN: &[u8] = b"termio/1";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Shared by both ends: BBR for long, lossy paths and keepalives that hold NAT bindings open.
fn transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // A link is declared lost after this much silence. Tests shorten it to exercise drops.
    let idle = std::env::var("TERMIO_QUIC_IDLE_MS").ok().and_then(|ms| ms.parse().ok()).map_or(Duration::from_secs(30), Duration::from_millis);
    transport.keep_alive_interval(Some((idle / 6).max(Duration::from_millis(100))));
    transport.max_idle_timeout(Some(idle.try_into().expect("the idle timeout fits")));
    Arc::new(transport)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

/// A server config with a new certificate, and that certificate's SHA-256.
pub fn server_config() -> std::io::Result<(quinn::ServerConfig, Vec<u8>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["termio-agent".to_owned()]).map_err(invalid)?;
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()));
    let hash = Sha256::digest(&cert).to_vec();
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(invalid)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(invalid)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).map_err(invalid)?));
    config.transport_config(transport());
    Ok((config, hash))
}

#[derive(Debug)]
struct Pinned {
    hash: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity).as_slice() == self.hash.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("the agent's certificate is not the one it announced".into()))
        }
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, signed: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signed, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config that trusts only the certificate with this SHA-256.
pub fn client_config(cert_hash: &[u8]) -> std::io::Result<quinn::ClientConfig> {
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(invalid)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { hash: cert_hash.to_vec(), provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).map_err(invalid)?));
    config.transport_config(transport());
    Ok(config)
}
