use crate::scan::network::RequestScheduler;
use std::time::Instant;

#[derive(Debug, Default, Clone)]
pub struct ScanResult {
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub rtt_ms: Option<u64>,
    pub headers: reqwest::header::HeaderMap,
    pub body_snippet: String,
}

const MAX_RESPONSE_BYTES: usize = 128 * 1024; // 128 KB limit

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SchemeStrategy {
    HttpsFirst,
    HttpsOnly,
    BothParallel,
}

fn extract_title(html: &str) -> Option<String> {
    let document = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse("title").ok()?;
    document.select(&selector).next().and_then(|node| {
        let title = node
            .text()
            .collect::<String>()
            .trim()
            .replace(['\n', '\r'], " ");
        (!title.is_empty()).then_some(title)
    })
}

pub async fn probe_single_url(client: &RequestScheduler, url: &str) -> Option<ScanResult> {
    use futures_util::StreamExt;

    let start = Instant::now();
    let response = client.get(&url.parse().ok()?).await.ok()?;
    let rtt_ms = start.elapsed().as_millis() as u64;

    let status_code = Some(response.status().as_u16());
    let headers = response.headers().clone();
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Stream response body up to MAX_RESPONSE_BYTES
    let mut body_bytes = Vec::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk_res) = stream.next().await {
        if let Ok(chunk) = chunk_res {
            let space_left = MAX_RESPONSE_BYTES.saturating_sub(body_bytes.len());
            if space_left == 0 {
                break;
            }
            let to_take = chunk.len().min(space_left);
            body_bytes.extend_from_slice(&chunk[..to_take]);
        } else {
            break;
        }
    }

    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let title = extract_title(&body_str);

    Some(ScanResult {
        status_code,
        title,
        server,
        rtt_ms: Some(rtt_ms),
        headers,
        body_snippet: body_str,
    })
}

pub async fn probe_subdomain(
    client: &RequestScheduler,
    subdomain: &str,
    strategy: SchemeStrategy,
) -> Vec<(String, ScanResult)> {
    if subdomain.starts_with("http://") || subdomain.starts_with("https://") {
        return vec![(
            subdomain.to_string(),
            probe_single_url(client, subdomain)
                .await
                .unwrap_or_default(),
        )];
    }

    match strategy {
        SchemeStrategy::HttpsOnly => {
            let url = format!("https://{}", subdomain);
            let result = probe_single_url(client, &url).await.unwrap_or_default();
            vec![(url, result)]
        }
        SchemeStrategy::HttpsFirst => {
            let https_url = format!("https://{}", subdomain);
            if let Some(res) = probe_single_url(client, &https_url).await {
                return vec![(https_url, res)];
            }
            let http_url = format!("http://{}", subdomain);
            let result = probe_single_url(client, &http_url)
                .await
                .unwrap_or_default();
            vec![(http_url, result)]
        }
        SchemeStrategy::BothParallel => {
            let https_url = format!("https://{}", subdomain);
            let http_url = format!("http://{}", subdomain);
            let (https, http) = tokio::join!(
                probe_single_url(client, &https_url),
                probe_single_url(client, &http_url)
            );
            vec![
                (https_url, https.unwrap_or_default()),
                (http_url, http.unwrap_or_default()),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_extract_title() {
        let html = "<html><head><title> Example Title </title></head><body></body></html>";
        assert_eq!(extract_title(html), Some("Example Title".to_string()));

        let html_multiline = "<html><head><title>\n  Multi \n Line \n</title></head></html>";
        assert_eq!(
            extract_title(html_multiline),
            Some("Multi   Line".to_string())
        );

        let no_title = "<html><body>No Title</body></html>";
        assert_eq!(extract_title(no_title), None);
        assert_eq!(
            extract_title("<html><body>İ</body><title>Unicode ✓</title></html>"),
            Some("Unicode ✓".to_string())
        );
    }

    #[tokio::test]
    async fn both_parallel_keeps_http_when_https_fails() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1];
                socket.read_exact(&mut request).await.unwrap();
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let client = crate::scan::network::RequestScheduler::new(
            Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .unwrap(),
            crate::scan::scope::ScopePolicy::new(vec![host.clone()]),
            2,
            10,
            0,
            0,
            None,
        );
        let results = probe_subdomain(&client, &host, SchemeStrategy::BothParallel).await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, format!("https://{host}"));
        assert_eq!(results[1].0, format!("http://{host}"));
        assert_eq!(results[1].1.status_code, Some(200));
        server.await.unwrap();
    }
}
