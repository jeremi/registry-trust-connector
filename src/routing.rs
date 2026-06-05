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
    validate_request_path(path)?;
    for route in routes {
        if !route.methods.iter().any(|candidate| candidate == method) {
            continue;
        }
        let Some(local_prefix) = route.local_prefix.as_deref() else {
            continue;
        };
        if !prefix_matches(path, local_prefix) {
            continue;
        }
        let upstream_prefix = route.upstream_prefix.as_deref().unwrap_or(local_prefix);
        return Ok(RouteMatch {
            route,
            upstream_path: rewrite_prefix(path, local_prefix, upstream_prefix),
        });
    }
    Err("no client route matched".to_string())
}

pub fn find_server_route<'a>(
    routes: &'a [RouteConfig],
    method: &Method,
    path: &str,
    client_identity: &str,
) -> Result<RouteMatch<'a>, String> {
    validate_request_path(path)?;
    for route in routes {
        if !route.methods.iter().any(|candidate| candidate == method) {
            continue;
        }
        if route.client_identity.as_deref() != Some(client_identity) {
            continue;
        }
        let Some(prefix) = route.upstream_prefix.as_deref() else {
            continue;
        };
        if prefix_matches(path, prefix) {
            return Ok(RouteMatch {
                route,
                upstream_path: path.to_string(),
            });
        }
    }
    Err("no server route matched".to_string())
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
    if !path.starts_with('/') {
        return Err("path must start with '/'".to_string());
    }
    reject_invalid_percent_encoding(path)?;
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| "path contains invalid percent-encoding".to_string())?;
    for segment in decoded.split('/') {
        if matches!(segment, "." | "..") {
            return Err("path contains dot segment".to_string());
        }
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
