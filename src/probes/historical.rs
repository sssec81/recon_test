//! Passive historical URL providers.  These clients only contact provider APIs;
//! callers are responsible for scope validation and inventory persistence.  In
//! particular, a URL returned here is never an instruction to request a target.

use crate::probes::crtsh::{DiscoveryProvider, DiscoveryResult, ProviderStatus};
use crate::scan::scope::ScopePolicy;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

const WAYBACK_CDX: &str = "https://web.archive.org/cdx/search/cdx";
const COMMON_CRAWL_INDEXES: &str = "https://index.commoncrawl.org/collinfo.json";
const MAX_ATTEMPTS: u8 = 3;

pub struct WaybackProvider {
    endpoint: String,
}

impl Default for WaybackProvider {
    fn default() -> Self {
        Self::at(WAYBACK_CDX)
    }
}

impl WaybackProvider {
    pub fn at(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl DiscoveryProvider for WaybackProvider {
    fn name(&self) -> &'static str {
        "wayback"
    }

    fn discover<'a>(
        &'a self,
        client: &'a Client,
        domain: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DiscoveryResult> + Send + 'a>> {
        Box::pin(query_wayback_at(client, &self.endpoint, domain))
    }
}

pub struct CommonCrawlProvider {
    catalog_endpoint: String,
}

impl Default for CommonCrawlProvider {
    fn default() -> Self {
        Self::at(COMMON_CRAWL_INDEXES)
    }
}

impl CommonCrawlProvider {
    pub fn at(catalog_endpoint: impl Into<String>) -> Self {
        Self {
            catalog_endpoint: catalog_endpoint.into(),
        }
    }
}

impl DiscoveryProvider for CommonCrawlProvider {
    fn name(&self) -> &'static str {
        "common_crawl"
    }

    fn discover<'a>(
        &'a self,
        client: &'a Client,
        domain: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DiscoveryResult> + Send + 'a>> {
        Box::pin(query_common_crawl_at(
            client,
            &self.catalog_endpoint,
            domain,
        ))
    }
}

pub async fn query_wayback_at(client: &Client, endpoint: &str, domain: &str) -> DiscoveryResult {
    let mut category = "network_error";
    for attempt in 1..=MAX_ATTEMPTS {
        let response = client
            .get(endpoint)
            .query(&[
                ("url", format!("*.{domain}/*")),
                ("output", "json".to_string()),
                ("fl", "original".to_string()),
                ("filter", "statuscode:200".to_string()),
                ("collapse", "urlkey".to_string()),
            ])
            .timeout(Duration::from_secs(12))
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(body) => match parse_wayback_urls(&body) {
                    Ok(urls) => return success("wayback", attempt, urls),
                    Err(()) => category = "invalid_response",
                },
                Err(_) => category = "network_error",
            },
            Ok(_) => category = "http_error",
            Err(_) => category = "network_error",
        }
        backoff(attempt).await;
    }
    failed("wayback", category)
}

pub async fn query_common_crawl_at(
    client: &Client,
    catalog_endpoint: &str,
    domain: &str,
) -> DiscoveryResult {
    let mut category = "network_error";
    for attempt in 1..=MAX_ATTEMPTS {
        let catalog = client
            .get(catalog_endpoint)
            .timeout(Duration::from_secs(12))
            .send()
            .await;
        let index_endpoint = match catalog {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(body) => match latest_index_endpoint(&body) {
                    Some(endpoint) => endpoint,
                    None => {
                        category = "invalid_response";
                        backoff(attempt).await;
                        continue;
                    }
                },
                Err(_) => {
                    category = "network_error";
                    backoff(attempt).await;
                    continue;
                }
            },
            Ok(_) => {
                category = "http_error";
                backoff(attempt).await;
                continue;
            }
            Err(_) => {
                category = "network_error";
                backoff(attempt).await;
                continue;
            }
        };
        let response = client
            .get(index_endpoint)
            .query(&[
                ("url", format!("*.{domain}/*")),
                ("output", "json".to_string()),
                ("fl", "url".to_string()),
                ("filter", "status:200".to_string()),
                ("collapse", "urlkey".to_string()),
            ])
            .timeout(Duration::from_secs(12))
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => match response.text().await {
                Ok(body) => match parse_common_crawl_urls(&body) {
                    Ok(urls) => return success("common_crawl", attempt, urls),
                    Err(()) => category = "invalid_response",
                },
                Err(_) => category = "network_error",
            },
            Ok(_) => category = "http_error",
            Err(_) => category = "network_error",
        }
        backoff(attempt).await;
    }
    failed("common_crawl", category)
}

async fn backoff(attempt: u8) {
    if attempt < MAX_ATTEMPTS {
        tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
    }
}

fn success(provider: &'static str, attempts: u8, urls: Vec<String>) -> DiscoveryResult {
    DiscoveryResult {
        names: Vec::new(),
        status: ProviderStatus {
            provider,
            ok: true,
            attempts,
            discovered_count: urls.len(),
            error_category: None,
        },
        urls,
    }
}

fn failed(provider: &'static str, error_category: &'static str) -> DiscoveryResult {
    DiscoveryResult {
        names: Vec::new(),
        urls: Vec::new(),
        status: ProviderStatus {
            provider,
            ok: false,
            attempts: MAX_ATTEMPTS,
            discovered_count: 0,
            error_category: Some(error_category),
        },
    }
}

fn unique_sorted(urls: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut urls: Vec<_> = urls
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    urls.sort();
    urls
}

fn parse_wayback_urls(body: &str) -> Result<Vec<String>, ()> {
    let rows: Vec<Vec<String>> = serde_json::from_str(body).map_err(|_| ())?;
    Ok(unique_sorted(rows.into_iter().filter_map(|row| {
        row.first()
            .filter(|value| value.as_str() != "original")
            .cloned()
    })))
}

#[derive(Deserialize)]
struct CommonCrawlIndex {
    #[serde(rename = "cdx-api")]
    cdx_api: String,
}

#[derive(Deserialize)]
struct CommonCrawlUrl {
    url: String,
}

fn latest_index_endpoint(body: &str) -> Option<String> {
    serde_json::from_str::<Vec<CommonCrawlIndex>>(body)
        .ok()?
        .into_iter()
        .next()
        .map(|index| index.cdx_api)
}

fn parse_common_crawl_urls(body: &str) -> Result<Vec<String>, ()> {
    let mut urls = Vec::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        urls.push(
            serde_json::from_str::<CommonCrawlUrl>(line)
                .map_err(|_| ())?
                .url,
        );
    }
    Ok(unique_sorted(urls))
}

/// Filters provider output before it reaches inventory persistence. This is a
/// pure local operation: it neither owns nor can invoke a target HTTP client.
pub fn in_scope_historical_urls(scope: &ScopePolicy, urls: Vec<String>) -> Vec<String> {
    urls.into_iter()
        .filter(|raw_url| {
            let Ok(url) = reqwest::Url::parse(raw_url) else {
                return false;
            };
            scope.allows_redirect_url(&url)
                && crate::scan::normalize::normalize_endpoint(raw_url, None).is_some()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parsers_dedupe_provider_output() {
        assert_eq!(
            parse_wayback_urls(
                r#"[["original"],["https://example.com/a"],["https://example.com/a"]]"#
            )
            .unwrap(),
            ["https://example.com/a"]
        );
        assert_eq!(
            parse_common_crawl_urls(
                "{\"url\":\"https://example.com/a\"}\n{\"url\":\"https://example.com/b\"}\n"
            )
            .unwrap(),
            ["https://example.com/a", "https://example.com/b"]
        );
    }

    #[tokio::test]
    async fn local_wayback_response_is_passive_and_deterministic() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[[\"original\"],[\"https://example.com/a?x=1\"],[\"https://example.com/a?x=2\"]]")
                .await
                .unwrap();
        });
        let result = query_wayback_at(&Client::new(), &endpoint, "example.com").await;
        assert!(result.status.ok);
        assert_eq!(result.status.discovered_count, 2);
        assert_eq!(result.urls.len(), 2);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn common_crawl_catalog_and_index_are_local_provider_traffic() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let catalog = format!("{base}/catalog");
        let server = tokio::spawn(async move {
            for body in [
                format!("[{{\"cdx-api\":\"{base}/index\"}}]"),
                "{\"url\":\"https://example.com/archive\"}\n".to_string(),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                let _ = socket.read(&mut request).await;
                socket
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let result = query_common_crawl_at(&Client::new(), &catalog, "example.com").await;
        assert!(result.status.ok);
        assert_eq!(result.status.attempts, 1);
        assert_eq!(result.urls, ["https://example.com/archive"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn historical_provider_retry_exhaustion_is_non_fatal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..MAX_ATTEMPTS {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                let _ = socket.read(&mut request).await;
                socket
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let result = query_wayback_at(&Client::new(), &endpoint, "example.com").await;
        assert!(!result.status.ok);
        assert_eq!(result.status.attempts, MAX_ATTEMPTS);
        assert_eq!(result.status.error_category, Some("http_error"));
        assert!(result.urls.is_empty());
        server.await.unwrap();
    }

    #[test]
    fn only_in_scope_http_urls_reach_inventory() {
        let scope = ScopePolicy::new(vec!["example.com".to_string()]);
        assert_eq!(
            in_scope_historical_urls(
                &scope,
                vec![
                    "https://api.example.com/v1?x=1".to_string(),
                    "https://example.com.evil.test/".to_string(),
                    "mailto:security@example.com".to_string(),
                    "not a url".to_string(),
                ],
            ),
            ["https://api.example.com/v1?x=1"]
        );
    }
}
