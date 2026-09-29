use crate::scan::network::RequestScheduler;
use crate::scan::scope::ScopePolicy;
use crate::triage::model::{HttpEvidence, Page};
use futures_util::StreamExt;
use regex::Regex;
use reqwest::Url;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_SCRIPT_BODY_BYTES: usize = 2 * 1024 * 1024;
const EXCERPT_CHARS: usize = 1024;
static API_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'](/(?:api|v[0-9]+)/[^"'\s<>]{1,180})["']"#)
        .expect("constant API path regex must compile")
});
pub struct FetchBudget<'a> {
    client: &'a RequestScheduler,
    scope: &'a ScopePolicy,
    deadline: Instant,
    max_requests: usize,
    delay: Duration,
    pub requests: usize,
}

impl<'a> FetchBudget<'a> {
    pub fn new(
        client: &'a RequestScheduler,
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
        if self.requests > 0 && !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let remaining = self.max_requests.saturating_sub(self.requests);
        let contacts_before = self.client.contacts();
        let scheduled = match self.client.get_with_trace_limited(url, remaining).await {
            Ok(response) => response,
            Err(error) => {
                self.requests += self.client.contacts().saturating_sub(contacts_before);
                return Some(Page {
                    evidence: HttpEvidence {
                        requested_url: url.to_string(),
                        final_url: None,
                        status: None,
                        content_type: None,
                        bytes: 0,
                        body_sha256: None,
                        title: None,
                        body_excerpt: None,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                        error: Some(error.to_string()),
                        fingerprint: None,
                        redirect_hops: Vec::new(),
                    },
                    body: String::new(),
                });
            }
        };
        self.requests += scheduled.requests_used;
        if scheduled.termination != crate::scan::network::RedirectTermination::FinalResponse {
            let redirect_detail = scheduled
                .blocked_destination
                .as_deref()
                .map(|destination| format!(" blocked={destination}"))
                .unwrap_or_default();
            let safe_initial =
                crate::scan::normalize::normalize_endpoint(scheduled.initial_url.as_str(), None)
                    .map(|endpoint| endpoint.canonical_url)
                    .unwrap_or_else(|| "invalid-endpoint".into());
            return Some(Page {
                evidence: HttpEvidence {
                    requested_url: url.to_string(),
                    final_url: None,
                    status: scheduled.last_status,
                    content_type: None,
                    bytes: 0,
                    body_sha256: None,
                    title: None,
                    body_excerpt: None,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    error: Some(
                        format!(
                            "redirect_{:?} initial={} hops={}{}",
                            scheduled.termination,
                            safe_initial,
                            scheduled.redirect_hops,
                            redirect_detail
                        )
                        .to_ascii_lowercase(),
                    ),
                    fingerprint: None,
                    redirect_hops: scheduled.hops,
                },
                body: String::new(),
            });
        }
        let response = scheduled.response.expect("final scheduler response");
        let final_url = response.url().clone();
        if !self.scope.allows_redirect_url(&final_url) {
            return None;
        }
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let declared_length = response.content_length().map(|value| value as usize);
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let capture_limit = if content_type
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains("javascript"))
            || final_url.path().ends_with(".js")
        {
            MAX_SCRIPT_BODY_BYTES
        } else {
            MAX_BODY_BYTES
        };
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        let mut stream_error = None;
        let mut truncated = false;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    let remaining = capture_limit.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if chunk.len() > remaining {
                        truncated = true;
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
        let body_complete = stream_error.is_none()
            && !truncated
            && declared_length.is_none_or(|length| length <= bytes.len());
        let mut response_fingerprint = crate::scan::fingerprint::fingerprint(
            status,
            &bytes,
            declared_length.unwrap_or(bytes.len()),
            body_complete,
            content_type.as_deref(),
            &headers,
            Some(started.elapsed().as_millis() as u64),
        );
        response_fingerprint.redirect_target = response_fingerprint
            .redirect_target
            .as_deref()
            .and_then(|value| final_url.join(value).ok())
            .and_then(|url| crate::scan::normalize::normalize_endpoint(url.as_str(), None))
            .map(|endpoint| endpoint.canonical_url);
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
                body_sha256: Some(response_fingerprint.raw_hash.clone()),
                title,
                body_excerpt,
                elapsed_ms: started.elapsed().as_millis() as u64,
                error: stream_error,
                fingerprint: Some(response_fingerprint),
                redirect_hops: scheduled.hops,
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
    if let Some(script_text) = script_text(page, base) {
        let calls = extract_js_calls(&script_text, base, base, scope);
        let non_get: HashSet<String> = calls
            .iter()
            .filter(|(_, method)| method != "GET")
            .map(|(url, _)| url.to_string())
            .collect();
        links.extend(
            calls
                .into_iter()
                .filter(|(url, method)| method == "GET" && !non_get.contains(url.as_str()))
                .map(|(url, _)| url),
        );
        for captures in API_PATH.captures_iter(&script_text) {
            if let Some(path) = captures.get(1)
                && let Ok(url) = base.join(path.as_str())
                && is_safe_url(&url, scope)
                && !non_get.contains(url.as_str())
            {
                links.push(url);
            }
        }
    }
    links.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    links.dedup();
    links.truncate(200);
    links
}

pub fn script_text(page: &Page, resource_url: &Url) -> Option<String> {
    if is_html(&page.evidence.content_type) {
        let document = Html::parse_document(&page.body);
        Selector::parse("script").ok().map(|selector| {
            document
                .select(&selector)
                .flat_map(|node| node.text())
                .collect::<Vec<_>>()
                .join("\n")
        })
    } else if is_javascript_resource(page.evidence.content_type.as_deref(), resource_url) {
        Some(page.body.clone())
    } else {
        None
    }
}

pub fn extract_js_calls(
    script: &str,
    source_url: &Url,
    resolution_base: &Url,
    scope: &ScopePolicy,
) -> Vec<(Url, String)> {
    crate::scan::javascript::extract(script, source_url, resolution_base, scope)
        .into_iter()
        .filter(|candidate| matches!(candidate.kind, "http_call" | "url_literal"))
        .filter_map(|candidate| {
            let url = Url::parse(candidate.resolved_url.as_deref()?).ok()?;
            if candidate.kind == "url_literal" && !actionable_url_literal(&url) {
                return None;
            }
            Some((url, candidate.method.unwrap_or_else(|| "GET".into())))
        })
        .collect()
}

fn actionable_url_literal(url: &Url) -> bool {
    let structural_path = url
        .path_segments()
        .and_then(|mut segments| segments.next())
        .is_some_and(|segment| matches!(segment, "api" | "rest" | "redirect" | "ftp"));
    let security_parameter = url.query_pairs().any(|(name, _)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "q" | "query"
                | "search"
                | "url"
                | "uri"
                | "to"
                | "next"
                | "redirect"
                | "return"
                | "continue"
                | "dest"
                | "destination"
                | "file"
                | "path"
                | "page"
                | "template"
        )
    });
    structural_path || security_parameter
}

pub fn is_javascript_resource(content_type: Option<&str>, resource_url: &Url) -> bool {
    content_type.is_some_and(|value| value.to_ascii_lowercase().contains("javascript"))
        || resource_url.path().to_ascii_lowercase().ends_with(".js")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javascript_path_is_analyzed_despite_generic_content_type() {
        let url = Url::parse("https://example.com/assets/app.js").unwrap();
        let page = Page {
            evidence: HttpEvidence {
                requested_url: url.to_string(),
                final_url: None,
                status: Some(200),
                content_type: Some("text/plain".into()),
                bytes: 18,
                body_sha256: None,
                title: None,
                body_excerpt: None,
                elapsed_ms: 0,
                error: None,
                fingerprint: None,
                redirect_hops: Vec::new(),
            },
            body: "fetch('/api/users')".into(),
        };
        assert!(script_text(&page, &url).is_some());
        assert!(is_javascript_resource(
            Some("application/octet-stream"),
            &url
        ));
    }

    #[test]
    fn weak_url_literals_remain_passive_but_structural_literals_can_crawl() {
        let base = Url::parse("https://example.com/main.js").unwrap();
        assert!(!actionable_url_literal(
            &Url::parse("https://example.com/1G").unwrap()
        ));
        assert!(actionable_url_literal(
            &base.join("./redirect?to=https://allowed.example").unwrap()
        ));
        assert!(actionable_url_literal(
            &base.join("/rest/products/search?q=juice").unwrap()
        ));
    }
    #[test]
    fn extracts_in_scope_links_and_skips_state_actions() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let base = Url::parse("https://example.com/").unwrap();
        let page = Page {
            evidence: HttpEvidence { requested_url: base.to_string(), final_url: None, status: Some(200),
                content_type: Some("text/html".into()), bytes: 0, body_sha256: None, title: None,
                body_excerpt: None, elapsed_ms: 0, error: None, fingerprint: None, redirect_hops: Vec::new() },
            body: r#"<a href="/api/user?id=42">user</a><a href="https://outside.test/">out</a><a href="/logout">logout</a>"#.into(),
        };
        let links = extract_links(&page, &base, &scope);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].as_str(), "https://example.com/api/user?id=42");
    }

    #[test]
    fn js_post_endpoint_is_recordable_but_not_crawled_as_get() {
        let scope = ScopePolicy::new(vec!["example.com".into()]);
        let base = Url::parse("https://example.com/app.js").unwrap();
        let body = "axios.post('/api/order', {id: 1}); fetch('/api/items?id=2');";
        let page = Page {
            evidence: HttpEvidence {
                requested_url: base.to_string(),
                final_url: None,
                status: Some(200),
                content_type: Some("application/javascript".into()),
                bytes: body.len(),
                body_sha256: None,
                title: None,
                body_excerpt: None,
                elapsed_ms: 0,
                error: None,
                fingerprint: None,
                redirect_hops: Vec::new(),
            },
            body: body.into(),
        };
        let links = extract_links(&page, &base, &scope);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].path(), "/api/items");
        let calls = extract_js_calls(body, &base, &base, &scope);
        assert!(
            calls
                .iter()
                .any(|(url, method)| url.path() == "/api/order" && method == "POST")
        );
    }
}
