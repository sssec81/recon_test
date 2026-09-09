use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoverySource {
    Seed,
    CertificateTransparency,
    DnsBruteforce,
    TlsSan,
    HttpRedirect,
    HtmlLink,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seed => write!(f, "Seed"),
            Self::CertificateTransparency => write!(f, "CertificateTransparency"),
            Self::DnsBruteforce => write!(f, "DnsBruteforce"),
            Self::TlsSan => write!(f, "TlsSan"),
            Self::HttpRedirect => write!(f, "HttpRedirect"),
            Self::HtmlLink => write!(f, "HtmlLink"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub root_scope: Vec<String>,
    pub config_hash: String,
}

impl ScanRun {
    pub fn new(root_scope: Vec<String>, config_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: None,
            root_scope,
            config_hash,
        }
    }

    pub fn complete(&mut self) {
        self.finished_at = Some(Utc::now());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hostname {
    pub id: String,
    pub name: String,
    pub source: DiscoverySource,
    pub discovered_from: Option<String>,
}

impl Hostname {
    pub fn new(name: String, source: DiscoverySource, discovered_from: Option<String>) -> Self {
        Self {
            id: name.to_lowercase(),
            name,
            source,
            discovered_from,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub hostname_id: String,
    pub record_type: String, // A, AAAA, CNAME
    pub value: String,
    pub ttl: Option<u32>,
    pub observed_at: DateTime<Utc>,
}

impl DnsRecord {
    pub fn new(hostname_id: String, record_type: String, value: String, ttl: Option<u32>) -> Self {
        let id = format!("{}:{}:{}", hostname_id, record_type, value);
        Self {
            id,
            hostname_id,
            record_type,
            value,
            ttl,
            observed_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpObservation {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub hostname: String,
    pub url: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub server_header: Option<String>,
    pub rtt_ms: Option<u64>,
    pub content_length: Option<usize>,
    pub observed_at: DateTime<Utc>,
}

impl HttpObservation {
    pub fn new(
        scan_id: Uuid,
        hostname: String,
        url: String,
        status_code: Option<u16>,
        title: Option<String>,
        server_header: Option<String>,
        rtt_ms: Option<u64>,
        content_length: Option<usize>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            scan_id,
            hostname,
            url,
            status_code,
            title,
            server_header,
            rtt_ms,
            content_length,
            observed_at: Utc::now(),
        }
    }
}
