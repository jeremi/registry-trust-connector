use axum::http::StatusCode;
use registry_platform_httpsec::Problem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorProblem {
    ConfigInvalid,
    ClientIdentityMissing,
    ClientIdentityDenied,
    RouteDenied,
    PurposeRequired,
    PurposeDenied,
    UpstreamAuthMissing,
    UpstreamUnavailable,
    BodyTooLarge,
    RequestTimeout,
    RateLimited,
}

impl ConnectorProblem {
    pub fn code(self) -> &'static str {
        match self {
            Self::ConfigInvalid => "connector.config_invalid",
            Self::ClientIdentityMissing => "connector.client_identity_missing",
            Self::ClientIdentityDenied => "connector.client_identity_denied",
            Self::RouteDenied => "connector.route_denied",
            Self::PurposeRequired => "connector.purpose_required",
            Self::PurposeDenied => "connector.purpose_denied",
            Self::UpstreamAuthMissing => "connector.upstream_auth_missing",
            Self::UpstreamUnavailable => "connector.upstream_unavailable",
            Self::BodyTooLarge => "connector.body_too_large",
            Self::RequestTimeout => "connector.request_timeout",
            Self::RateLimited => "connector.rate_limited",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            Self::ConfigInvalid => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ClientIdentityMissing => StatusCode::UNAUTHORIZED,
            Self::ClientIdentityDenied => StatusCode::FORBIDDEN,
            Self::RouteDenied => StatusCode::FORBIDDEN,
            Self::PurposeRequired => StatusCode::BAD_REQUEST,
            Self::PurposeDenied => StatusCode::FORBIDDEN,
            Self::UpstreamAuthMissing => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UpstreamUnavailable => StatusCode::BAD_GATEWAY,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::ConfigInvalid => "Connector configuration is invalid",
            Self::ClientIdentityMissing => "Client identity is missing",
            Self::ClientIdentityDenied => "Client identity is denied",
            Self::RouteDenied => "Route is denied",
            Self::PurposeRequired => "Data purpose is required",
            Self::PurposeDenied => "Data purpose is denied",
            Self::UpstreamAuthMissing => "Upstream authentication is unavailable",
            Self::UpstreamUnavailable => "Upstream is unavailable",
            Self::BodyTooLarge => "Request body is too large",
            Self::RequestTimeout => "Request timed out",
            Self::RateLimited => "Request rate limit exceeded",
        }
    }

    pub fn response(self) -> axum::response::Response {
        Problem::new(
            &format!("urn:registry:problem:{}", self.code()),
            self.title(),
            self.status(),
        )
        .detail("request denied by registry trust connector")
        .with_extra("code", serde_json::json!(self.code()))
        .into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("{0}")]
    InvalidConfig(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_saphyr::Error),
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("http error: {0}")]
    Http(#[from] http::Error),
    #[error("upstream error: {0}")]
    Upstream(#[from] reqwest::Error),
}
