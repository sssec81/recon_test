use crate::triage::crawl::FetchBudget;
use crate::triage::model::{Confidence, Finding, Page};
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
        evidence_dir: None,
    }
}

pub fn detect(page: &Page, url: &Url) -> Vec<Finding> {
    let mut findings = Vec::new();
    if page.evidence.status == Some(200) && directory_listing(page) {
        findings.push(base_finding(
            "directory_listing", &format!("directory_listing|{}", url.as_str()),
            "Directory index is visible", url.as_str(), page,
            "The response has a directory-index title and listing structure.",
            "Check whether this directory is intended to be public and whether listed files disclose sensitive data.",
            "Directory indexes can be intentional; the listing alone is not proof of a vulnerability.", Confidence::Interesting,
        ));
    }
    if page.evidence.status.is_some_and(|status| status >= 500) && stack_trace(page) {
        findings.push(base_finding(
            "stack_trace", &format!("stack_trace|{}", url.path()),
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
                "object_identifier", &format!("object_identifier|{}|{}|{name}", url.host_str().unwrap_or_default(), url.path()),
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

pub async fn verify(finding: &mut Finding, budget: &mut FetchBudget<'_>) {
    if !matches!(
        finding.category.as_str(),
        "directory_listing" | "stack_trace"
    ) {
        return;
    }
    let Ok(url) = Url::parse(&finding.endpoint) else {
        return;
    };
    let mut repeats_match = true;
    for _ in 0..2 {
        let Some(page) = budget.fetch(&url).await else {
            return;
        };
        repeats_match &= signal_matches(&finding.category, &page)
            && page.evidence.status == finding.baseline.status;
        finding.repeats.push(page.evidence);
    }
    if !repeats_match {
        return;
    }
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
        return;
    };
    let control_has_signal = signal_matches(&finding.category, &control_page);
    finding.control = Some(control_page.evidence);
    if !control_has_signal {
        finding.confidence = if finding.category == "directory_listing" {
            Confidence::Reproduced
        } else {
            Confidence::StrongCandidate
        };
    }
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
    use crate::triage::model::HttpEvidence;
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
}
