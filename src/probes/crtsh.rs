use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

#[derive(Debug, Clone)]
pub struct ProviderStatus {
    pub provider: &'static str,
    pub ok: bool,
    pub attempts: u8,
    pub discovered_count: usize,
    pub error_category: Option<&'static str>,
}

pub struct DiscoveryResult {
    pub names: Vec<String>,
    pub status: ProviderStatus,
}

pub trait DiscoveryProvider {
    fn name(&self) -> &'static str;
    fn discover<'a>(
        &'a self,
        client: &'a Client,
        domain: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DiscoveryResult> + Send + 'a>>;
}

pub struct CrtShProvider;
impl DiscoveryProvider for CrtShProvider {
    fn name(&self) -> &'static str {
        "crt.sh"
    }
    fn discover<'a>(
        &'a self,
        client: &'a Client,
        domain: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DiscoveryResult> + Send + 'a>> {
        Box::pin(query_crtsh(client, domain))
    }
}

pub async fn query_crtsh(client: &Client, domain: &str) -> DiscoveryResult {
    query_crtsh_at(client, "https://crt.sh/", domain).await
}

pub async fn query_crtsh_at(client: &Client, endpoint: &str, domain: &str) -> DiscoveryResult {
    let query_val = format!("%.{domain}");
    let mut last_error = String::new();
    for attempt in 1..=3 {
        let result = client
            .get(endpoint)
            .query(&[("q", &query_val), ("output", &"json".to_string())])
            .timeout(Duration::from_secs(12))
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {
                match response.json::<Vec<CrtShEntry>>().await {
                    Ok(entries) => {
                        let mut names = HashSet::new();
                        for entry in entries {
                            for line in entry.name_value.lines() {
                                let name =
                                    line.trim().trim_start_matches("*.").to_ascii_lowercase();
                                if !name.is_empty() {
                                    names.insert(name);
                                }
                            }
                        }
                        let mut names: Vec<String> = names.into_iter().collect();
                        names.sort();
                        let count = names.len();
                        return DiscoveryResult {
                            names,
                            status: ProviderStatus {
                                provider: "crt.sh",
                                ok: true,
                                attempts: attempt,
                                discovered_count: count,
                                error_category: None,
                            },
                        };
                    }
                    Err(error) => last_error = format!("invalid crt.sh JSON: {error}"),
                }
            }
            Ok(response) => last_error = format!("crt.sh HTTP {}", response.status()),
            Err(error) => last_error = format!("crt.sh request failed: {error}"),
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
        }
    }
    let category = if last_error.contains("JSON") {
        "invalid_response"
    } else if last_error.contains("HTTP") {
        "http_error"
    } else {
        "network_error"
    };
    DiscoveryResult {
        names: Vec::new(),
        status: ProviderStatus {
            provider: "crt.sh",
            ok: false,
            attempts: 3,
            discovered_count: 0,
            error_category: Some(category),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn local_provider_response_reports_discoveries_without_target_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut b = [0; 512];
            let _ = socket.read(&mut b).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[{\"name_value\":\"api.example.com\\n*.www.example.com\"}]").await.unwrap();
        });
        let result = query_crtsh_at(&Client::new(), &endpoint, "example.com").await;
        assert!(result.status.ok);
        assert_eq!(result.status.attempts, 1);
        assert_eq!(result.status.discovered_count, 2);
        assert_eq!(result.names, vec!["api.example.com", "www.example.com"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn provider_retries_then_succeeds_and_exhausts_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for response in [b"HTTP/1.1 500 Bad\r\nContent-Length: 0\r\n\r\n".as_slice(), b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n[{\"name_value\":\"api.example.com\"}]".as_slice()] { let (mut socket, _) = listener.accept().await.unwrap(); let mut b=[0;512]; let _=socket.read(&mut b).await; socket.write_all(response).await.unwrap(); }
        });
        let ok = query_crtsh_at(&Client::new(), &endpoint, "example.com").await;
        assert!(ok.status.ok);
        assert_eq!(ok.status.attempts, 2);
        assert_eq!(ok.names, vec!["api.example.com"]);
        server.await.unwrap();
        let failed = query_crtsh_at(&Client::new(), "http://127.0.0.1:1", "example.com").await;
        assert!(!failed.status.ok);
        assert_eq!(failed.status.attempts, 3);
        assert_eq!(failed.status.error_category, Some("network_error"));
    }
}
