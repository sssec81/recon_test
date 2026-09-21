use crate::triage::crawl::FetchBudget;
use crate::triage::model::{Confidence, Finding, HttpEvidence, Page, ResponseAnomaly};
use reqwest::Url;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn finding_id(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))[..12].to_string()
}

#[allow(clippy::too_many_arguments)]
fn base_finding(
    category: &str,
    key: &str,
    title: &str,
    endpoint: &str,
    page: &Page,
    reason: &str,
    manual_validation: &str,
    false_positive_notes: &str,
    confidence: Confidence,
) -> Finding {
    Finding {
        id: finding_id(key),
        category: category.into(),
        title: title.into(),
        endpoint: endpoint.into(),
        confidence,
        reason: reason.into(),
        manual_validation: manual_validation.into(),
        false_positive_notes: false_positive_notes.into(),
        baseline: page.evidence.clone(),
        repeats: Vec::new(),
        control: None,
        control_repeats: Vec::new(),
        evidence_dir: None,
    }
}

pub fn detect(page: &Page, url: &Url) -> Vec<Finding> {
    let mut findings = Vec::new();
    if page.evidence.status == Some(200) && directory_listing(page) {
        findings.push(base_finding(
            "directory_listing", &format!("directory_listing|{}|{}", url.origin().ascii_serialization(), url.path()),
            "Directory index is visible", url.as_str(), page,
            "The response has a directory-index title and listing structure.",
            "Check whether this directory is intended to be public and whether listed files disclose sensitive data.",
            "Directory indexes can be intentional; the listing alone is not proof of a vulnerability.", Confidence::Interesting,
        ));
    }
    if page.evidence.status.is_some_and(|status| status >= 500) && stack_trace(page) {
        findings.push(base_finding(
            "stack_trace", &format!("stack_trace|{}|{}", url.origin().ascii_serialization(), url.path()),
            "Detailed server error is visible", url.as_str(), page,
            "The server returned an error page containing a recognizable stack-trace marker.",
            "Inspect the response locally for sensitive details, then reproduce with a safe request before reporting.",
            "Generic error templates or transient failures can resemble stack traces.", Confidence::Interesting,
        ));
    }
    if page
        .evidence
        .status
        .is_some_and(|status| (200..300).contains(&status))
    {
        let names: Vec<String> = url
            .query_pairs()
            .filter_map(|(key, value)| {
                let key = key.to_ascii_lowercase();
                let id_name = key == "id"
                    || key.ends_with("_id")
                    || matches!(
                        key.as_str(),
                        "user" | "account" | "order" | "invoice" | "project"
                    );
                let id_value = value.parse::<u64>().is_ok() || Uuid::parse_str(&value).is_ok();
                (id_name && id_value).then_some(key)
            })
            .collect();
        for name in names {
            findings.push(base_finding(
                "object_identifier", &format!("object_identifier|{}|{}|{name}", url.origin().ascii_serialization(), url.path()),
                "Object identifier in a reachable endpoint", url.as_str(), page,
                &format!("A user-controlled `{name}` parameter has an object-like identifier and the endpoint responded successfully."),
                "Use two authorized test accounts. Confirm which account owns the object, then check whether the other account can access it. Do not infer an authorization flaw from the identifier alone.",
                "Identifiers in URLs are common and usually protected by server-side authorization. Automated authorization verification was not attempted.", Confidence::Candidate,
            ));
        }
    }
    findings
}

fn directory_listing(page: &Page) -> bool {
    page.evidence
        .title
        .as_deref()
        .is_some_and(|title| title.to_ascii_lowercase().starts_with("index of /"))
        && (page.body.to_ascii_lowercase().contains("parent directory")
            || page.body.to_ascii_lowercase().contains("last modified"))
}

fn stack_trace(page: &Page) -> bool {
    [
        "Traceback (most recent call last)",
        "System.NullReferenceException",
        "java.lang.NullPointerException",
        " at org.springframework.",
    ]
    .iter()
    .any(|marker| page.body.contains(marker))
}

pub enum Verification {
    Kept,
    Rejected(&'static str),
    Incomplete(&'static str),
}

fn stable_response(reference: &HttpEvidence, repeated: &HttpEvidence) -> bool {
    stable_profile(reference, repeated) && reference.final_url == repeated.final_url
}

fn stable_profile(reference: &HttpEvidence, repeated: &HttpEvidence) -> bool {
    let mime = |evidence: &HttpEvidence| {
        evidence
            .content_type
            .as_deref()
            .and_then(|value| value.split(';').next())
            .map(|value| value.trim().to_ascii_lowercase())
    };
    let tolerance = reference.bytes / 5 + 64;
    reference.status.is_some()
        && reference.status == repeated.status
        && mime(reference) == mime(repeated)
        && reference.bytes.abs_diff(repeated.bytes) <= tolerance
        && reference.error.is_none()
        && repeated.error.is_none()
}

pub async fn verify(finding: &mut Finding, budget: &mut FetchBudget<'_>) -> Verification {
    let Ok(url) = Url::parse(&finding.endpoint) else {
        return Verification::Rejected("invalid endpoint URL");
    };
    for _ in 0..2 {
        let Some(page) = budget.fetch(&url).await else {
            return Verification::Incomplete("request or time budget ended before repeat checks");
        };
        let stable = stable_response(&finding.baseline, &page.evidence);
        let signal = match finding.category.as_str() {
            "directory_listing" | "stack_trace" => signal_matches(&finding.category, &page),
            "object_identifier" => page
                .evidence
                .status
                .is_some_and(|status| (200..300).contains(&status)),
            _ => false,
        };
        finding.repeats.push(page.evidence);
        if !stable || !signal {
            return Verification::Rejected(
                "baseline response or detector signal changed on repeat",
            );
        }
    }
    if finding.category == "object_identifier" {
        return Verification::Kept;
    }
    for _ in 0..2 {
        let mut control_url = url.clone();
        if finding.category == "directory_listing" {
            let path = format!(
                "{}/__recon_control_{}",
                url.path().trim_end_matches('/'),
                Uuid::new_v4().simple()
            );
            control_url.set_path(&path);
            control_url.set_query(None);
        } else {
            control_url
                .query_pairs_mut()
                .append_pair("__recon_control", &Uuid::new_v4().simple().to_string());
        }
        let Some(control_page) = budget.fetch(&control_url).await else {
            return Verification::Incomplete("request or time budget ended before control checks");
        };
        let valid_control = if finding.category == "directory_listing" {
            matches!(control_page.evidence.status, Some(403 | 404))
                && !signal_matches(&finding.category, &control_page)
        } else {
            control_page.evidence.status.is_some()
                && !signal_matches(&finding.category, &control_page)
        };
        let stable_control = finding
            .control
            .as_ref()
            .is_none_or(|first| stable_profile(first, &control_page.evidence));
        if finding.control.is_none() {
            finding.control = Some(control_page.evidence);
        } else {
            finding.control_repeats.push(control_page.evidence);
        }
        if !valid_control || !stable_control {
            return Verification::Rejected(
                "control response was unstable or did not distinguish the signal from ordinary behavior",
            );
        }
    }
    finding.confidence = if finding.category == "directory_listing" {
        Confidence::Reproduced
    } else {
        Confidence::StrongCandidate
    };
    Verification::Kept
}

pub async fn verify_response_anomaly(
    anomaly: &ResponseAnomaly,
    budget: &mut FetchBudget<'_>,
) -> Result<Finding, &'static str> {
    let failure_url = Url::parse(&anomaly.baseline_url).map_err(|_| "invalid baseline URL")?;
    let control_url = Url::parse(&anomaly.control_url).map_err(|_| "invalid control URL")?;
    let baseline = budget
        .fetch(&failure_url)
        .await
        .ok_or("request or time budget ended before baseline check")?;
    if !stable_response(&anomaly.baseline_evidence, &baseline.evidence) {
        return Err("error response changed before verification");
    }
    let mut finding = base_finding(
        "response_anomaly",
        &format!(
            "response_anomaly|{}|{}",
            anomaly.url_template, anomaly.parameter
        ),
        "Repeatable server error for one parameter variant",
        failure_url.as_str(),
        &baseline,
        &format!(
            "The same route and parameter set returned HTTP {} for one observed value and HTTP {} for another. Repeated baseline and control requests kept that distinction.",
            anomaly.baseline_status, anomaly.control_status
        ),
        "Inspect the error and compare the two authorized input values. Determine whether this exposes sensitive details or impacts a real user workflow before reporting.",
        "Different values can validly produce different responses. A stable server error alone does not establish a security vulnerability.",
        Confidence::Candidate,
    );
    for _ in 0..2 {
        let control = budget
            .fetch(&control_url)
            .await
            .ok_or("request or time budget ended before control checks")?;
        if !stable_response(&anomaly.control_evidence, &control.evidence) {
            return Err("successful control changed before verification");
        }
        if finding.control.is_none() {
            finding.control = Some(control.evidence);
        } else {
            finding.control_repeats.push(control.evidence);
        }
        let repeat = budget
            .fetch(&failure_url)
            .await
            .ok_or("request or time budget ended before error repeats")?;
        if !stable_response(&baseline.evidence, &repeat.evidence) {
            return Err("error baseline was unstable across repeats");
        }
        finding.repeats.push(repeat.evidence);
    }
    Ok(finding)
}

fn signal_matches(category: &str, page: &Page) -> bool {
    match category {
        "directory_listing" => page.evidence.status == Some(200) && directory_listing(page),
        "stack_trace" => {
            page.evidence.status.is_some_and(|status| status >= 500) && stack_trace(page)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::network::RequestScheduler;
    use crate::scan::scope::ScopePolicy;
    use crate::triage::model::HttpEvidence;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    fn page(url: &str, status: u16, title: Option<&str>, body: &str) -> Page {
        Page {
            evidence: HttpEvidence {
                requested_url: url.into(),
                final_url: Some(url.into()),
                status: Some(status),
                content_type: Some("text/html".into()),
                bytes: body.len(),
                body_sha256: None,
                title: title.map(str::to_string),
                body_excerpt: None,
                elapsed_ms: 1,
                error: None,
            },
            body: body.into(),
        }
    }
    #[test]
    fn id_parameter_is_candidate_not_vulnerability() {
        let url = Url::parse("https://example.com/api/user?id=1847").unwrap();
        let findings = detect(&page(url.as_str(), 200, None, "{}"), &url);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Candidate);
        assert!(
            findings[0]
                .manual_validation
                .contains("two authorized test accounts")
        );
    }
    #[test]
    fn directory_listing_needs_verification() {
        let url = Url::parse("https://example.com/files/").unwrap();
        let findings = detect(
            &page(
                url.as_str(),
                200,
                Some("Index of /files/"),
                "Parent Directory",
            ),
            &url,
        );
        assert_eq!(findings[0].confidence, Confidence::Interesting);
    }

    #[tokio::test]
    async fn changed_error_is_rejected_before_becoming_a_candidate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await;
            let body = "{\"ok\":true}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let baseline_url = format!("http://127.0.0.1:{}/api/items?id=2", address.port());
        let control_url = format!("http://127.0.0.1:{}/api/items?id=1", address.port());
        let baseline = HttpEvidence {
            requested_url: baseline_url.clone(),
            final_url: Some(baseline_url.clone()),
            status: Some(500),
            content_type: Some("application/json".into()),
            bytes: 14,
            body_sha256: None,
            title: None,
            body_excerpt: None,
            elapsed_ms: 1,
            error: None,
        };
        let control = HttpEvidence {
            requested_url: control_url.clone(),
            final_url: Some(control_url.clone()),
            status: Some(200),
            ..baseline.clone()
        };
        let anomaly = ResponseAnomaly {
            url_template: format!("http://127.0.0.1:{}/api/items", address.port()),
            parameter: "id".into(),
            baseline_url,
            control_url,
            baseline_status: 500,
            control_status: 200,
            baseline_content_type: Some("application/json".into()),
            control_content_type: Some("application/json".into()),
            baseline_evidence: baseline,
            control_evidence: control,
        };
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let client = RequestScheduler::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            scope.clone(),
            2,
            20,
            0,
            0,
            None,
        );
        let mut budget = FetchBudget::new(&client, &scope, 10, 1, 0);
        let outcome = verify_response_anomaly(&anomaly, &mut budget).await;
        assert!(matches!(
            outcome,
            Err("error response changed before verification")
        ));
        assert_eq!(budget.requests, 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn inconsistent_controls_do_not_promote_directory_listing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut controls = 0;
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0_u8; 1024];
                let length = stream.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..length]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = if path == "/files/" {
                    ("200 OK", "<title>Index of /files/</title>Parent Directory")
                } else {
                    controls += 1;
                    if controls == 1 {
                        ("404 Not Found", "missing")
                    } else {
                        ("200 OK", "missing")
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let url = Url::parse(&format!("http://127.0.0.1:{}/files/", address.port())).unwrap();
        let mut finding = detect(
            &page(
                url.as_str(),
                200,
                Some("Index of /files/"),
                "<title>Index of /files/</title>Parent Directory",
            ),
            &url,
        )
        .remove(0);
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let client = RequestScheduler::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            scope.clone(),
            2,
            20,
            0,
            0,
            None,
        );
        let mut budget = FetchBudget::new(&client, &scope, 10, 1, 0);
        let outcome = verify(&mut finding, &mut budget).await;
        assert!(matches!(outcome, Verification::Rejected(_)));
        assert_eq!(finding.confidence, Confidence::Interesting);
        assert_eq!(finding.control_repeats.len(), 1);
        server.await.unwrap();
    }
}
