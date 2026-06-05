use http::HeaderMap;
use sha2::{Digest, Sha256};

pub fn hash_for_log(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().take(12).map(|b| format!("{b:02x}")).collect()
}

pub fn sanitized_path(path: &str) -> &str {
    path
}

pub fn has_sensitive_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(http::header::AUTHORIZATION) || headers.contains_key(http::header::COOKIE)
}
