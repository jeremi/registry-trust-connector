use http::HeaderMap;
use registry_platform_audit::AuditKeyHasher;

use crate::config::ConnectorConfig;
use crate::errors::ConnectorError;

pub fn audit_key_hasher(config: &ConnectorConfig) -> Result<AuditKeyHasher, ConnectorError> {
    if let Some(env_var) = config.audit.hash_secret_env.as_deref() {
        return AuditKeyHasher::from_env(env_var).map_err(|err| {
            ConnectorError::InvalidConfig(format!("audit hash secret is invalid: {err}"))
        });
    }
    if config.audit.allow_unkeyed_hashing {
        Ok(AuditKeyHasher::unkeyed_dev_only())
    } else {
        Err(ConnectorError::InvalidConfig(
            "audit.hash_secret_env is required unless audit.allow_unkeyed_hashing is true"
                .to_string(),
        ))
    }
}

pub fn identity_hash_for_log(hasher: &AuditKeyHasher, value: &str) -> String {
    hasher
        .audit_reference_hash("registry-trust-connector-client-identity-v1", "", value)
        .expect("identity log hash class and canonical input are non-empty")
}

pub fn certificate_hash_for_log(hasher: &AuditKeyHasher, fingerprint_sha256: &str) -> String {
    hasher
        .audit_reference_hash(
            "registry-trust-connector-client-cert-v1",
            "",
            fingerprint_sha256,
        )
        .expect("certificate log hash class and canonical input are non-empty")
}

pub fn sanitized_path(path: &str) -> &str {
    path
}

pub fn has_sensitive_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(http::header::AUTHORIZATION) || headers.contains_key(http::header::COOKIE)
}
