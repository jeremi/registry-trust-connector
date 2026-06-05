use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Once;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::config::{dns_identity_map, trust_domain_map, ConnectorConfig, IdentityFiles};
use crate::errors::ConnectorError;
use crate::identity::{
    extract_peer_identity_from_der, load_certs, load_private_key, load_single_ca_cert, PeerIdentity,
};

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

#[derive(Debug, Clone)]
pub struct PeerCertificateChain(pub Vec<CertificateDer<'static>>);

#[derive(Debug, Clone)]
pub struct ServerTrustPolicy {
    anchors_by_domain: BTreeMap<String, Arc<RootCertStore>>,
    anchors_by_dns_identity: BTreeMap<String, Arc<RootCertStore>>,
    allow_dns_san_identity: bool,
}

impl ServerTrustPolicy {
    pub fn from_config(config: &ConnectorConfig) -> Result<Self, ConnectorError> {
        let mut anchors_by_domain = BTreeMap::new();
        for (domain, paths) in trust_domain_map(config) {
            anchors_by_domain.insert(domain, Arc::new(root_store_from_paths(&paths)?));
        }
        let mut anchors_by_dns_identity = BTreeMap::new();
        for (identity, paths) in dns_identity_map(config) {
            anchors_by_dns_identity.insert(identity, Arc::new(root_store_from_paths(&paths)?));
        }
        Ok(Self {
            anchors_by_domain,
            anchors_by_dns_identity,
            allow_dns_san_identity: config.allow_dns_san_identity,
        })
    }

    pub fn verify_peer(&self, chain: &PeerCertificateChain) -> Result<PeerIdentity, String> {
        let leaf = chain
            .0
            .first()
            .ok_or_else(|| "peer did not present a certificate".to_string())?;
        let identity = extract_peer_identity_from_der(leaf.as_ref(), self.allow_dns_san_identity)?;
        if let Some(domain) = spiffe_trust_domain(&identity.value) {
            let roots = self
                .anchors_by_domain
                .get(domain)
                .ok_or_else(|| format!("no trust anchor for trust domain '{domain}'"))?;
            verify_chain_against_roots(roots, &chain.0)?;
        } else if !self.allow_dns_san_identity {
            return Err("DNS SAN identity fallback is disabled".to_string());
        } else {
            let roots = self
                .anchors_by_dns_identity
                .get(&identity.value)
                .ok_or_else(|| {
                    format!(
                        "no trust anchor is bound to DNS SAN identity '{}'",
                        identity.value
                    )
                })?;
            verify_chain_against_roots(roots, &chain.0)?;
        }
        Ok(identity)
    }
}

pub fn server_config(config: &ConnectorConfig) -> Result<ServerConfig, ConnectorError> {
    ensure_crypto_provider();
    let identity = config.server_identity.as_ref().ok_or_else(|| {
        ConnectorError::InvalidConfig("server mode requires server_identity".to_string())
    })?;
    let certs = load_certs(&identity.cert).map_err(ConnectorError::Tls)?;
    let key = load_private_key(&identity.key).map_err(ConnectorError::Tls)?;
    let trust_paths: Vec<PathBuf> = config
        .client_trust
        .as_ref()
        .ok_or_else(|| {
            ConnectorError::InvalidConfig("server mode requires client_trust".to_string())
        })?
        .trust_anchors
        .iter()
        .map(|anchor| anchor.ca.clone())
        .collect();
    let roots = Arc::new(root_store_from_paths(&trust_paths)?);
    let verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|err| ConnectorError::Tls(format!("client verifier setup failed: {err}")))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| ConnectorError::Tls(format!("server identity setup failed: {err}")))
}

pub fn reqwest_mtls_client(
    identity: &IdentityFiles,
    trust_bundle: &Path,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, ConnectorError> {
    let pem = crate::identity::read_identity_pem(&identity.cert, &identity.key)
        .map_err(ConnectorError::Tls)?;
    let identity = reqwest::Identity::from_pem(&pem).map_err(|err| {
        ConnectorError::Tls(format!("failed to load client identity for reqwest: {err}"))
    })?;
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .identity(identity)
        .tls_built_in_root_certs(false);
    for cert in crate::identity::read_ca_pem(trust_bundle).map_err(ConnectorError::Tls)? {
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|err| ConnectorError::Tls(format!("failed to build mTLS client: {err}")))
}

pub fn root_store_from_paths(paths: &[PathBuf]) -> Result<RootCertStore, ConnectorError> {
    let mut roots = RootCertStore::empty();
    for path in paths {
        let cert = load_single_ca_cert(path).map_err(ConnectorError::Tls)?;
        roots.add(cert).map_err(|err| {
            ConnectorError::Tls(format!("invalid trust anchor '{}': {err}", path.display()))
        })?;
    }
    Ok(roots)
}

fn verify_chain_against_roots(
    roots: &Arc<RootCertStore>,
    chain: &[CertificateDer<'static>],
) -> Result<(), String> {
    ensure_crypto_provider();
    let verifier = WebPkiClientVerifier::builder(Arc::clone(roots))
        .build()
        .map_err(|err| err.to_string())?;
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or_else(|| "peer did not present a certificate".to_string())?;
    verifier
        .verify_client_cert(leaf, intermediates, UnixTime::now())
        .map(|_| ())
        .map_err(|err| {
            format!("peer certificate does not chain to bound trust domain anchor: {err}")
        })
}

fn ensure_crypto_provider() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn spiffe_trust_domain(identity: &str) -> Option<&str> {
    identity
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split('/').next())
        .filter(|value| !value.is_empty())
}
