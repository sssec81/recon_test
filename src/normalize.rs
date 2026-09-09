use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedHostname(pub String);

impl NormalizedHostname {
    pub fn new(input: &str) -> Option<Self> {
        let mut clean = input.trim().to_lowercase();

        // Strip http:// or https:// prefix if present
        if clean.starts_with("https://") {
            clean = clean["https://".len()..].to_string();
        } else if clean.starts_with("http://") {
            clean = clean["http://".len()..].to_string();
        }

        // Strip trailing path/slash/query
        if let Some(slash_idx) = clean.find('/') {
            clean = clean[..slash_idx].to_string();
        }

        // Strip port if present (e.g. example.com:8080)
        if let Some(colon_idx) = clean.find(':') {
            clean = clean[..colon_idx].to_string();
        }

        // Strip trailing dots
        clean = clean.trim_end_matches('.').to_string();

        if clean.is_empty() {
            None
        } else {
            Some(Self(clean))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NormalizedHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedUrl(pub String);

impl NormalizedUrl {
    pub fn new(hostname: &NormalizedHostname, scheme: &str) -> Self {
        let s = scheme.to_lowercase();
        let clean_scheme = if s.starts_with("http") { s } else { "https".to_string() };
        Self(format!("{}://{}", clean_scheme, hostname.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
