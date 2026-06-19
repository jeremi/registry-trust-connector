use http::Method;
use percent_encoding::percent_decode_str;

use crate::config::RouteConfig;

#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    pub route: &'a RouteConfig,
    pub upstream_path: String,
}

pub fn find_client_route<'a>(
    routes: &'a [RouteConfig],
    method: &Method,
    path: &str,
) -> Result<RouteMatch<'a>, String> {
    let path = canonical_request_path(path)?;
    let mut best: Option<(usize, RouteMatch<'a>)> = None;
    for route in routes {
        if !route.methods.iter().any(|candidate| candidate == method) {
            continue;
        }
        let Some(local_prefix) = route.local_prefix.as_deref() else {
            continue;
        };
        let local_prefix = canonical_request_path(local_prefix)?;
        if !prefix_matches(&path, &local_prefix) {
            continue;
        }
        let upstream_prefix = route
            .upstream_prefix
            .as_deref()
            .unwrap_or(local_prefix.as_str());
        let upstream_prefix = canonical_request_path(upstream_prefix)?;
        let route_match = RouteMatch {
            route,
            upstream_path: rewrite_prefix(&path, &local_prefix, &upstream_prefix),
        };
        let prefix_len = local_prefix.len();
        if best
            .as_ref()
            .map(|(best_len, _)| prefix_len > *best_len)
            .unwrap_or(true)
        {
            best = Some((prefix_len, route_match));
        }
    }
    best.map(|(_, route_match)| route_match)
        .ok_or_else(|| "no client route matched".to_string())
}

pub fn find_server_route<'a>(
    routes: &'a [RouteConfig],
    method: &Method,
    path: &str,
    client_identity: &str,
) -> Result<RouteMatch<'a>, String> {
    let path = canonical_request_path(path)?;
    let mut best: Option<(usize, RouteMatch<'a>)> = None;
    for route in routes {
        if !route.methods.iter().any(|candidate| candidate == method) {
            continue;
        }
        if !route_matches_client_identity(route, client_identity) {
            continue;
        }
        let Some(prefix) = route.upstream_prefix.as_deref() else {
            continue;
        };
        let prefix = canonical_request_path(prefix)?;
        if prefix_matches(&path, &prefix) {
            let route_match = RouteMatch {
                route,
                upstream_path: path.clone(),
            };
            let prefix_len = prefix.len();
            if best
                .as_ref()
                .map(|(best_len, _)| prefix_len > *best_len)
                .unwrap_or(true)
            {
                best = Some((prefix_len, route_match));
            }
        }
    }
    best.map(|(_, route_match)| route_match)
        .ok_or_else(|| "no server route matched".to_string())
}

fn route_matches_client_identity(route: &RouteConfig, client_identity: &str) -> bool {
    route.client_identity.as_deref().map(str::trim) == Some(client_identity)
        || route
            .client_identities
            .iter()
            .any(|allowed| allowed.trim() == client_identity)
}

pub fn validate_route_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty() {
        return Err("prefix must not be empty".to_string());
    }
    if !prefix.starts_with('/') {
        return Err("prefix must start with '/'".to_string());
    }
    validate_request_path(prefix)
}

pub fn validate_request_path(path: &str) -> Result<(), String> {
    let _ = canonical_request_path(path)?;
    Ok(())
}

fn canonical_request_path(path: &str) -> Result<String, String> {
    if !path.starts_with('/') {
        return Err("path must start with '/'".to_string());
    }
    reject_invalid_percent_encoding(path)?;
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| "path contains invalid percent-encoding".to_string())?;
    reject_encoded_delimiters(path, &decoded)?;
    for segment in decoded.split('/') {
        if matches!(segment, "." | "..") {
            return Err("path contains dot segment".to_string());
        }
    }
    Ok(decoded.into_owned())
}

fn reject_encoded_delimiters(raw: &str, decoded: &str) -> Result<(), String> {
    if raw.as_bytes().contains(&b'%') && decoded.contains('\\') {
        return Err("path contains encoded delimiter".to_string());
    }
    let raw_slashes = raw.as_bytes().iter().filter(|byte| **byte == b'/').count();
    let decoded_slashes = decoded
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b'/')
        .count();
    if decoded_slashes > raw_slashes {
        return Err("path contains encoded delimiter".to_string());
    }
    Ok(())
}

fn reject_invalid_percent_encoding(path: &str) -> Result<(), String> {
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("path contains invalid percent-encoding".to_string());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

pub fn prefix_matches(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    prefix.ends_with('/') || rest.starts_with('/')
}

fn rewrite_prefix(path: &str, local_prefix: &str, upstream_prefix: &str) -> String {
    let suffix = path.strip_prefix(local_prefix).unwrap_or("");
    if suffix.is_empty() {
        upstream_prefix.to_string()
    } else if upstream_prefix.ends_with('/') || suffix.starts_with('/') {
        format!("{upstream_prefix}{suffix}")
    } else {
        format!("{upstream_prefix}/{suffix}")
    }
}
