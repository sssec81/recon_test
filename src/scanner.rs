use reqwest::Client;
use std::time::Instant;

#[derive(Debug, Default, Clone)]
pub struct ScanResult {
    pub final_url: Option<String>,
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

pub async fn probe_single_url(client: &Client, url: &str) -> Option<ScanResult> {
    use futures_util::StreamExt;

    let start = Instant::now();
    let response = client.get(url).send().await.ok()?;
    let rtt_ms = start.elapsed().as_millis() as u64;

    let final_url = Some(response.url().as_str().to_string());
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
        final_url,
        status_code,
        title,
        server,
        rtt_ms: Some(rtt_ms),
        headers,
        body_snippet: body_str,
    })
}

pub async fn probe_subdomain(
    client: &Client,
    subdomain: &str,
    strategy: SchemeStrategy,
) -> ScanResult {
    if subdomain.starts_with("http://") || subdomain.starts_with("https://") {
        return probe_single_url(client, subdomain)
            .await
            .unwrap_or_default();
    }

    match strategy {
        SchemeStrategy::HttpsOnly => {
            let url = format!("https://{}", subdomain);
            probe_single_url(client, &url).await.unwrap_or_default()
        }
        SchemeStrategy::HttpsFirst => {
            let https_url = format!("https://{}", subdomain);
            if let Some(res) = probe_single_url(client, &https_url).await {
                return res;
            }
            let http_url = format!("http://{}", subdomain);
            probe_single_url(client, &http_url).await.unwrap_or_default()
        }
        SchemeStrategy::BothParallel => {
            let https_url = format!("https://{}", subdomain);
            let http_url = format!("http://{}", subdomain);

            let c1 = client.clone();
            let c2 = client.clone();

            let https_fut = tokio::spawn(async move { probe_single_url(&c1, &https_url).await });
            let http_fut = tokio::spawn(async move { probe_single_url(&c2, &http_url).await });

            let (res_https, res_http) = tokio::join!(https_fut, http_fut);

            if let Ok(Some(res)) = res_https {
                return res;
            }
            if let Ok(Some(res)) = res_http {
                return res;
            }

            ScanResult::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_title() {
        let html = "<html><head><title> Example Title </title></head><body></body></html>";
        assert_eq!(extract_title(html), Some("Example Title".to_string()));

        let html_multiline = "<html><head><title>\n  Multi \n Line \n</title></head></html>";
        assert_eq!(extract_title(html_multiline), Some("Multi   Line".to_string()));

        let no_title = "<html><body>No Title</body></html>";
        assert_eq!(extract_title(no_title), None);
    }
}
