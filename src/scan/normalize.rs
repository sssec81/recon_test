use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedHostname(pub String);

impl NormalizedHostname {
    pub fn new(input: &str) -> Option<Self> {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }
        if let Ok(ip) = input.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Some(Self(ip.to_string()));
        }
        let url = if input.contains("://") {
            reqwest::Url::parse(input).ok()?
        } else {
            reqwest::Url::parse(&format!("http://{input}")).ok()?
        };
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return None;
        }
        let host = url
            .host_str()?
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(Self(ip.to_string()));
        }
        if host.is_empty()
            || host.len() > 253
            || !host.is_ascii()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return None;
        }
        Some(Self(host))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_url_host(&self) -> String {
        if self.0.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.0)
        } else {
            self.0.clone()
        }
    }
    pub fn is_ip(&self) -> bool {
        self.0.parse::<IpAddr>().is_ok()
    }
}

impl std::fmt::Display for NormalizedHostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_domains_and_ips() {
        assert_eq!(
            NormalizedHostname::new("https://Sub.Example.com/path?x=1")
                .unwrap()
                .as_str(),
            "sub.example.com"
        );
        assert_eq!(
            NormalizedHostname::new("http://EXAMPLE.COM:8080/")
                .unwrap()
                .as_str(),
            "example.com"
        );
        assert_eq!(
            NormalizedHostname::new("[2001:db8::1]").unwrap().as_str(),
            "2001:db8::1"
        );
        assert_eq!(
            NormalizedHostname::new("2001:db8::1")
                .unwrap()
                .as_url_host(),
            "[2001:db8::1]"
        );
        for invalid in [
            "",
            "bad..example.com",
            "-bad.example",
            "http://user@example.com",
            "*.example.com",
        ] {
            assert!(NormalizedHostname::new(invalid).is_none(), "{invalid}");
        }
    }
}
