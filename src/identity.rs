use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Once;
use std::time::{Duration, SystemTime};

use ::time::format_description::well_known::Rfc3339;
use ::time::OffsetDateTime;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use x509_parser::extensions::{ExtendedKeyUsage, GeneralName};
use x509_parser::prelude::*;

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EkUsage {
    ClientAuth,
    ServerAuth,
}

impl fmt::Display for EkUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientAuth => f.write_str("clientAuth"),
            Self::ServerAuth => f.write_str("serverAuth"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub value: String,
    pub kind: IdentityKind,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    UriSan,
    DnsSan,
}

#[derive(Debug, Clone)]
pub struct CertificateSummary {
    pub not_after: String,
    not_after_system: SystemTime,
}

impl CertificateSummary {
    pub fn expires_within(&self, duration: Duration) -> bool {
        match self.not_after_system.duration_since(SystemTime::now()) {
            Ok(remaining) => remaining <= duration,
            Err(_) => true,
        }
    }
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = BufReader::new(File::open(path).map_err(|err| err.to_string())?);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed to parse certificate PEM: {err}"))
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = BufReader::new(File::open(path).map_err(|err| err.to_string())?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|err| format!("failed to parse private key PEM: {err}"))?
        .ok_or_else(|| "private key PEM did not contain a supported private key".to_string())
}

pub fn read_identity_pem(cert: &Path, key: &Path) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    File::open(cert)
        .map_err(|err| err.to_string())?
        .read_to_end(&mut out)
        .map_err(|err| err.to_string())?;
    out.push(b'\n');
    File::open(key)
        .map_err(|err| err.to_string())?
        .read_to_end(&mut out)
        .map_err(|err| err.to_string())?;
    Ok(out)
}

pub fn read_ca_pem(path: &Path) -> Result<Vec<reqwest::Certificate>, String> {
    let bytes = std::fs::read(path).map_err(|err| err.to_string())?;
    reqwest::Certificate::from_pem_bundle(&bytes).map_err(|err| err.to_string())
}

pub fn validate_leaf_certificate(
    cert_path: &Path,
    key_path: &Path,
    usage: EkUsage,
) -> Result<(), String> {
    ensure_crypto_provider();
    let certs = load_certs(cert_path)?;
    if certs.is_empty() {
        return Err("certificate file contains no certificates".to_string());
    }
    let key = load_private_key(key_path)?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .map_err(|err| format!("private key does not match certificate: {err}"))?;
    let cert = parse_cert_der(certs[0].as_ref())?;
    validate_time(&cert)?;
    if !leaf_has_eku(&cert, usage)? {
        return Err(format!(
            "leaf certificate must assert Extended Key Usage {usage}"
        ));
    }
    Ok(())
}

fn ensure_crypto_provider() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub fn validate_ca_certificate(cert_path: &Path) -> Result<(), String> {
    let certs = load_certs(cert_path)?;
    match certs.len() {
        0 => return Err("CA file contains no certificates".to_string()),
        1 => {}
        _ => {
            return Err(
                "trust anchor PEM must contain exactly one CA certificate; use separate trust_anchors entries"
                    .to_string(),
            );
        }
    }
    let cert = parse_cert_der(certs[0].as_ref())?;
    validate_time(&cert)?;
    match cert.basic_constraints().map_err(|err| err.to_string())? {
        Some(ext) if ext.value.ca => {}
        Some(_) => return Err("trust anchor is not a CA certificate".to_string()),
        None => return Err("trust anchor missing basic constraints".to_string()),
    }
    if let Some(ext) = cert.key_usage().map_err(|err| err.to_string())? {
        if !ext.value.key_cert_sign() {
            return Err("trust anchor key usage does not allow certificate signing".to_string());
        }
    }
    Ok(())
}

pub fn load_single_ca_cert(path: &Path) -> Result<CertificateDer<'static>, String> {
    let certs = load_certs(path)?;
    match certs.len() {
        1 => Ok(certs.into_iter().next().expect("one cert")),
        0 => Err("CA file contains no certificates".to_string()),
        _ => Err(
            "trust anchor PEM must contain exactly one CA certificate; use separate trust_anchors entries"
                .to_string(),
        ),
    }
}

pub fn certificate_summary(cert_path: &Path) -> Result<CertificateSummary, String> {
    let certs = load_certs(cert_path)?;
    let first = certs
        .first()
        .ok_or_else(|| "certificate file contains no certificates".to_string())?;
    let cert = parse_cert_der(first.as_ref())?;
    let not_after_system = as_system_time(cert.validity().not_after)?;
    let not_after = OffsetDateTime::from(not_after_system)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());
    Ok(CertificateSummary {
        not_after,
        not_after_system,
    })
}

pub fn extract_peer_identity_from_der(
    cert_der: &[u8],
    allow_dns_fallback: bool,
) -> Result<PeerIdentity, String> {
    let cert = parse_cert_der(cert_der)?;
    validate_time(&cert)?;
    if !leaf_has_eku(&cert, EkUsage::ClientAuth)? {
        return Err("client certificate missing clientAuth EKU".to_string());
    }
    let fingerprint_sha256 = sha256_hex(cert_der);
    let san = cert
        .subject_alternative_name()
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "certificate has no subject alternative name".to_string())?;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            return Ok(PeerIdentity {
                value: uri.to_string(),
                kind: IdentityKind::UriSan,
                fingerprint_sha256,
            });
        }
    }
    if allow_dns_fallback {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                return Ok(PeerIdentity {
                    value: dns.to_string(),
                    kind: IdentityKind::DnsSan,
                    fingerprint_sha256,
                });
            }
        }
    }
    Err("certificate has no acceptable URI SAN identity".to_string())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_cert_der(bytes: &[u8]) -> Result<X509Certificate<'_>, String> {
    X509Certificate::from_der(bytes)
        .map(|(_, cert)| cert)
        .map_err(|err| format!("failed to parse certificate DER: {err}"))
}

fn validate_time(cert: &X509Certificate<'_>) -> Result<(), String> {
    let now = SystemTime::now();
    let not_before = as_system_time(cert.validity().not_before)?;
    let not_after = as_system_time(cert.validity().not_after)?;
    if now < not_before {
        return Err("certificate is not valid yet".to_string());
    }
    if now > not_after {
        return Err("certificate is expired".to_string());
    }
    Ok(())
}

fn leaf_has_eku(cert: &X509Certificate<'_>, usage: EkUsage) -> Result<bool, String> {
    let Some(ext) = cert.extended_key_usage().map_err(|err| err.to_string())? else {
        return Ok(false);
    };
    Ok(eku_matches(ext.value, usage))
}

fn eku_matches(eku: &ExtendedKeyUsage<'_>, usage: EkUsage) -> bool {
    match usage {
        EkUsage::ClientAuth => eku.client_auth,
        EkUsage::ServerAuth => eku.server_auth,
    }
}

fn as_system_time(time: ASN1Time) -> Result<SystemTime, String> {
    let offset = time.to_datetime();
    let unix = offset.unix_timestamp();
    if unix >= 0 {
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(unix as u64))
    } else {
        Ok(SystemTime::UNIX_EPOCH - Duration::from_secs((-unix) as u64))
    }
}
