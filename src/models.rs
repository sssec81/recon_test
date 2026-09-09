use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub subdomain: String,
    pub ip_address: Option<String>,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub rtt_ms: Option<u64>,
}

impl Target {
    pub fn new(
        subdomain: String,
        ip_address: Option<String>,
        status_code: Option<u16>,
        title: Option<String>,
        server: Option<String>,
        rtt_ms: Option<u64>,
    ) -> Self {
        Self {
            subdomain,
            ip_address,
            status_code,
            title,
            server,
            rtt_ms,
        }
    }
}
