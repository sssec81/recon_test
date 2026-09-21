use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub canonical_url: String,
}

pub fn normalize_endpoint(input: &str, base: Option<&reqwest::Url>) -> Option<CanonicalEndpoint> {
    let mut url = match base {
        Some(base) => base.join(input).ok()?,
        None => reqwest::Url::parse(input).ok()?,
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_fragment(None);
    let host = NormalizedHostname::new(url.host_str()?)?
        .as_str()
        .to_string();
    let scheme = url.scheme().to_ascii_lowercase();
    let port = url
        .port()
        .filter(|port| !((scheme == "http" && *port == 80) || (scheme == "https" && *port == 443)));
    let path = if url.path().is_empty() {
        "/".into()
    } else {
        url.path().to_string()
    };
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let canonical_url = match port {
        Some(port) => format!("{scheme}://{authority}:{port}{path}"),
        None => format!("{scheme}://{authority}{path}"),
    };
    Some(CanonicalEndpoint {
        scheme,
        host,
        port,
        path,
        canonical_url,
    })
}

pub fn endpoint_id(endpoint: &CanonicalEndpoint) -> String {
    format!("{:x}", Sha256::digest(endpoint.canonical_url.as_bytes()))
}

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

    #[test]
    fn canonical_endpoint_preserves_raw_query_outside_identity() {
        let first =
            normalize_endpoint("HTTPS://API.Example.com:443/api/users?id=123#top", None).unwrap();
        let second = normalize_endpoint("https://api.example.com/api/users?id=456", None).unwrap();
        assert_eq!(first.canonical_url, "https://api.example.com/api/users");
        assert_eq!(first.canonical_url, second.canonical_url);
        assert!(normalize_endpoint("mailto:test@example.com", None).is_none());
    }
}
