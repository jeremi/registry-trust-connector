use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Text,
    Json,
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match log_format() {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_writer(std::io::stderr)
                .init();
        }
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
    }
}

fn log_format() -> LogFormat {
    match std::env::var("REGISTRY_TRUST_CONNECTOR_LOG_FORMAT")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" | "jsonl" => LogFormat::Json,
        _ => LogFormat::Text,
    }
}
