use reqwest::Client;
use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone)]
pub struct ScanResult {
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub rtt_ms: Option<u64>,
}

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start_tag = "<title";
    let end_tag = "</title>";

    if let Some(start_offset) = lower.find(start_tag) {
        let tag_suffix = &html[start_offset..];
        if let Some(tag_close) = tag_suffix.find('>') {
            let content_start = start_offset + tag_close + 1;
            let remaining_lower = &lower[content_start..];
            if let Some(end_offset) = remaining_lower.find(end_tag) {
                let raw_title = &html[content_start..content_start + end_offset];
                let clean_title = raw_title.trim().replace('\n', " ").replace('\r', "");
                if !clean_title.is_empty() {
                    return Some(clean_title);
                }
            }
        }
    }
    None
}

pub async fn probe_subdomain(subdomain: &str) -> ScanResult {
    let client = match Client::builder()
        .timeout(Duration::from_secs(4))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return ScanResult::default(),
    };

    let urls_to_try = if subdomain.starts_with("http://") || subdomain.starts_with("https://") {
        vec![subdomain.to_string()]
    } else {
        vec![
            format!("https://{}", subdomain),
            format!("http://{}", subdomain),
        ]
    };

    for url in urls_to_try {
        let start = Instant::now();
        if let Ok(response) = client.get(&url).send().await {
            let rtt_ms = start.elapsed().as_millis() as u64;
            let status_code = Some(response.status().as_u16());
            let server = response
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let mut title = None;
            if let Ok(text) = response.text().await {
                title = extract_title(&text);
            }

            return ScanResult {
                status_code,
                title,
                server,
                rtt_ms: Some(rtt_ms),
            };
        }
    }

    ScanResult::default()
}

pub async fn resolve_ip(subdomain: &str) -> Option<String> {
    let clean_host = subdomain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?;

    let addr_str = format!("{}:80", clean_host);
    if let Ok(mut addrs) = tokio::net::lookup_host(&addr_str).await {
        if let Some(addr) = addrs.next() {
            return Some(addr.ip().to_string());
        }
    }

    None
}
