mod crawl;
mod detect;
mod model;
mod report;

use crate::cli::Args;
use crate::scan::scope::ScopePolicy;
use crate::storage::models::HttpObservation;
pub(crate) use crawl::is_safe_url;
use crawl::{FetchBudget, extract_links};
use model::{Confidence, Finding, ReviewQueue};
use reqwest::{Client, Url};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use uuid::Uuid;

pub struct TriageConfig {
    pub max_pages: usize,
    pub max_depth: usize,
    pub max_requests: usize,
    pub max_minutes: u64,
    pub max_findings: usize,
    pub delay_ms: u64,
    pub output_dir: PathBuf,
}

impl From<&Args> for TriageConfig {
    fn from(args: &Args) -> Self {
        Self {
            max_pages: args.triage_max_pages,
            max_depth: args.triage_max_depth,
            max_requests: args.triage_max_requests,
            max_minutes: args.triage_max_minutes,
            max_findings: args.triage_max_findings,
            delay_ms: args.triage_delay_ms,
            output_dir: PathBuf::from(&args.triage_dir),
        }
    }
}

pub async fn run(
    client: &Client,
    scope: &ScopePolicy,
    observations: &[HttpObservation],
    config: TriageConfig,
    scan_id: Uuid,
) -> Result<ReviewQueue, Box<dyn std::error::Error>> {
    let mut budget = FetchBudget::new(
        client,
        scope,
        config.max_requests,
        config.max_minutes,
        config.delay_ms,
    );
    let mut queue: VecDeque<(Url, usize)> = VecDeque::new();
    let mut seen_urls = HashSet::new();
    for observation in observations {
        if observation
            .status_code
            .is_some_and(|status| (200..400).contains(&status))
            && let Ok(mut url) = Url::parse(&observation.url)
        {
            url.set_fragment(None);
            if is_safe_url(&url, scope) && seen_urls.insert(url.to_string()) {
                queue.push_back((url, 0));
            }
        }
    }
    let mut pages_crawled = 0;
    let mut candidates: Vec<Finding> = Vec::new();
    let mut seen_candidates = HashSet::new();
    let crawl_request_limit = config.max_requests.saturating_mul(3).div_ceil(4);
    while let Some((url, depth)) = queue.pop_front() {
        if pages_crawled >= config.max_pages
            || budget.requests >= crawl_request_limit
            || budget.exhausted()
        {
            queue.push_front((url, depth));
            break;
        }
        let Some(page) = budget.fetch(&url).await else {
            continue;
        };
        pages_crawled += 1;
        let response_url = page
            .evidence
            .final_url
            .as_deref()
            .and_then(|value| Url::parse(value).ok())
            .unwrap_or_else(|| url.clone());
        for finding in detect::detect(&page, &response_url) {
            if seen_candidates.insert(finding.id.clone())
                && candidates.len() < config.max_findings.saturating_mul(20).max(50)
            {
                candidates.push(finding);
            }
        }
        if depth < config.max_depth
            && page
                .evidence
                .status
                .is_some_and(|status| (200..400).contains(&status))
        {
            let base = page
                .evidence
                .final_url
                .as_deref()
                .and_then(|value| Url::parse(value).ok())
                .unwrap_or(url);
            for link in extract_links(&page, &base, scope) {
                if seen_urls.insert(link.to_string()) {
                    queue.push_back((link, depth + 1));
                }
            }
        }
        if pages_crawled % 25 == 0 {
            println!(
                "  [triage] crawled {pages_crawled} page(s), {} request(s), {} candidate(s)",
                budget.requests,
                seen_candidates.len()
            );
        }
    }
    // Verification uses the same request and time budget as crawling.
    for finding in &mut candidates {
        if budget.exhausted() {
            break;
        }
        detect::verify(finding, &mut budget).await;
    }
    let candidates_found = seen_candidates.len();
    candidates.retain(|finding| finding.confidence >= Confidence::Candidate);
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.endpoint.cmp(&b.endpoint))
    });
    candidates.truncate(config.max_findings);
    let mut review = ReviewQueue {
        scan_id,
        pages_crawled,
        requests_sent: budget.requests,
        budget_exhausted: !queue.is_empty() || budget.exhausted(),
        candidates_found,
        findings_suppressed: candidates_found.saturating_sub(candidates.len()),
        findings: candidates,
    };
    let path = report::write_review(&mut review, &config.output_dir)?;
    println!(
        "📋 Triage review queue: {} finding(s), {} suppressed; saved to '{}'",
        review.findings.len(),
        review.findings_suppressed,
        path.display()
    );
    Ok(review)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn local_crawl_verifies_and_writes_review_queue() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    let Ok(length) = stream.read(&mut buffer).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..length]);
                    let path = request.split_whitespace().nth(1).unwrap_or("/");
                    let (status, content_type, body) = match path {
                        "/" => (
                            "200 OK",
                            "text/html",
                            "<a href=\"/files/\">files</a><a href=\"/go-user\">user</a>",
                        ),
                        "/go-user" => ("302 Found", "text/plain", ""),
                        "/files/" => (
                            "200 OK",
                            "text/html",
                            "<title>Index of /files/</title>Parent Directory",
                        ),
                        "/api/user?id=1847" => ("200 OK", "application/json", "{\"id\":1847}"),
                        _ => ("404 Not Found", "text/plain", "not found"),
                    };
                    let location = if path == "/go-user" {
                        "Location: /api/user?id=1847\r\n"
                    } else {
                        ""
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\n{location}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let scan_id = Uuid::new_v4();
        let seed = format!("http://127.0.0.1:{}/", address.port());
        let observations = vec![
            HttpObservation::new(scan_id, "127.0.0.1".into(), seed).with_response(
                Some(200),
                None,
                None,
                None,
                None,
            ),
        ];
        let output_dir = std::env::temp_dir().join(format!("recon_triage_test_{}", scan_id));
        let config = TriageConfig {
            max_pages: 10,
            max_depth: 1,
            max_requests: 20,
            max_minutes: 1,
            max_findings: 5,
            delay_ms: 0,
            output_dir: output_dir.clone(),
        };
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let review = run(
            &client,
            &ScopePolicy::new(vec!["127.0.0.1".into()]),
            &observations,
            config,
            scan_id,
        )
        .await
        .unwrap();
        assert_eq!(review.pages_crawled, 3);
        assert_eq!(review.findings.len(), 2);
        assert_eq!(review.requests_sent, 7);
        assert!(
            review
                .findings
                .iter()
                .any(|finding| finding.category == "directory_listing"
                    && finding.confidence == Confidence::Reproduced
                    && finding.control.is_some())
        );
        assert!(
            review
                .findings
                .iter()
                .any(|finding| finding.category == "object_identifier"
                    && finding.confidence == Confidence::Candidate)
        );
        assert!(
            output_dir
                .join(scan_id.to_string())
                .join("review.json")
                .exists()
        );
        assert!(
            output_dir
                .join(scan_id.to_string())
                .join("evidence/finding-001/control.json")
                .exists()
        );
        std::fs::remove_dir_all(output_dir).unwrap();
        server.abort();
    }
}
