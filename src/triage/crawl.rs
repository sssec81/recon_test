use crate::scan::scope::ScopePolicy;
use crate::triage::model::{HttpEvidence, Page};
use futures_util::StreamExt;
use regex::Regex;
use reqwest::{Client, Url};
use scraper::{Html, Selector};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const MAX_BODY_BYTES: usize = 256 * 1024;
const EXCERPT_CHARS: usize = 1024;
static API_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'](/(?:api|v[0-9]+)/[^"'\s<>]{1,180})["']"#)
        .expect("constant API path regex must compile")
});

pub struct FetchBudget<'a> {
    client: &'a Client,
    scope: &'a ScopePolicy,
    deadline: Instant,
    max_requests: usize,
    delay: Duration,
    pub requests: usize,
}

impl<'a> FetchBudget<'a> {
    pub fn new(
        client: &'a Client,
        scope: &'a ScopePolicy,
        max_requests: usize,
        max_minutes: u64,
        delay_ms: u64,
    ) -> Self {
        Self {
            client,
            scope,
            deadline: Instant::now() + Duration::from_secs(max_minutes.saturating_mul(60)),
            max_requests,
            delay: Duration::from_millis(delay_ms),
            requests: 0,
        }
    }

    pub fn exhausted(&self) -> bool {
        self.requests >= self.max_requests || Instant::now() >= self.deadline
    }

    pub async fn fetch(&mut self, url: &Url) -> Option<Page> {
        if self.exhausted() || !is_safe_url(url, self.scope) {
            return None;
        }
        let started = Instant::now();
        let mut current = url.clone();
        let mut redirects = 0;
        let response = loop {
            if self.requests > 0 && !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.exhausted() {
                return None;
            }
            self.requests += 1;
            let response = match self.client.get(current.clone()).send().await {
                Ok(response) => response,
                Err(error) => {
                    return Some(Page {
                        evidence: HttpEvidence {
                            requested_url: url.to_string(),
                            final_url: Some(current.to_string()),
                            status: None,
                            content_type: None,
                            bytes: 0,
                            body_sha256: None,
                            title: None,
                            body_excerpt: None,
                            elapsed_ms: started.elapsed().as_millis() as u64,
                            error: Some(error.to_string()),
                        },
                        body: String::new(),
                    });
                }
            };
            let redirect_url = if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308)
            {
                response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| current.join(value).ok())
            } else {
                None
            };
            if let Some(next) = redirect_url
                && redirects < 5
                && !self.exhausted()
                && is_safe_url(&next, self.scope)
            {
                current = next;
                redirects += 1;
                continue;
            }
            break response;
        };
        let final_url = response.url().clone();
        if !self.scope.allows_redirect_url(&final_url) {
            return None;
        }
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        let mut stream_error = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    let remaining = MAX_BODY_BYTES.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if bytes.len() == MAX_BODY_BYTES {
                        break;
                    }
                }
                Err(error) => {
                    stream_error = Some(error.to_string());
                    break;
                }
            }
        }
        let body = String::from_utf8_lossy(&bytes).to_string();
        let title = if is_html(&content_type) {
            let document = Html::parse_document(&body);
            Selector::parse("title")
                .ok()
                .and_then(|selector| {
                    document
                        .select(&selector)
                        .next()
                        .map(|node| node.text().collect::<String>().trim().to_string())
                })
                .filter(|title| !title.is_empty())
        } else {
            None
        };
        let body_excerpt = if is_textual(&content_type) {
            Some(body.chars().take(EXCERPT_CHARS).collect())
        } else {
            None
        };
        Some(Page {
            evidence: HttpEvidence {
                requested_url: url.to_string(),
                final_url: Some(final_url.to_string()),
                status: Some(status),
                content_type,
                bytes: bytes.len(),
                body_sha256: Some(format!("{:x}", Sha256::digest(&bytes))),
                title,
                body_excerpt,
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: stream_error,
            },
            body,
        })
    }
}

pub fn is_html(content_type: &Option<String>) -> bool {
    content_type
        .as_deref()
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
}

fn is_textual(content_type: &Option<String>) -> bool {
    content_type.as_deref().is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.starts_with("text/") || value.contains("json") || value.contains("javascript")
    })
}

pub fn is_safe_url(url: &Url, scope: &ScopePolicy) -> bool {
    if !scope.allows_redirect_url(url) || !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let path = url.path().to_ascii_lowercase();
    if path.split('/').any(|part| {
        matches!(
            part,
            "logout"
                | "signout"
                | "delete"
                | "remove"
                | "destroy"
                | "revoke"
                | "terminate"
                | "shutdown"
                | "purchase"
                | "checkout"
                | "pay"
        )
    }) {
        return false;
    }
    if [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".zip", ".pdf",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
    {
        return false;
    }
    !url.query_pairs().any(|(key, _)| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "token" | "access_token" | "auth" | "apikey" | "api_key" | "session" | "csrf"
        )
    })
}

pub fn extract_links(page: &Page, base: &Url, scope: &ScopePolicy) -> Vec<Url> {
    let mut links = Vec::new();
    if is_html(&page.evidence.content_type) {
        let document = Html::parse_document(&page.body);
        if let Ok(selector) = Selector::parse("a[href], script[src], form[method=get][action]") {
            for node in document.select(&selector) {
                let value = node
                    .value()
                    .attr("href")
                    .or_else(|| node.value().attr("src"))
                    .or_else(|| node.value().attr("action"));
                if let Some(value) = value
                    && let Ok(mut url) = base.join(value)
                {
                    url.set_fragment(None);
                    if is_safe_url(&url, scope) {
                        links.push(url);
                    }
                }
            }
        }
    }
    if is_html(&page.evidence.content_type)
        || page
            .evidence
            .content_type
            .as_deref()
            .is_some_and(|t| t.contains("javascript"))
    {
        for captures in API_PATH.captures_iter(&page.body) {
            if let Some(path) = captures.get(1)
                && let Ok(url) = base.join(path.as_str())
                && is_safe_url(&url, scope)
            {
                links.push(url);
            }
        }
    }
    links.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    links.dedup();
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_in_scope_links_and_skips_state_actions() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let base = Url::parse("https://example.com/").unwrap();
        let page = Page {
            evidence: HttpEvidence { requested_url: base.to_string(), final_url: None, status: Some(200),
                content_type: Some("text/html".into()), bytes: 0, body_sha256: None, title: None,
                body_excerpt: None, elapsed_ms: 0, error: None },
            body: r#"<a href="/api/user?id=42">user</a><a href="https://outside.test/">out</a><a href="/logout">logout</a>"#.into(),
        };
        let links = extract_links(&page, &base, &scope);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].as_str(), "https://example.com/api/user?id=42");
    }
}
