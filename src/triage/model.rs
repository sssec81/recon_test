use serde::Serialize;
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
// Noise is the suppression floor; Confirmed is reserved for later manual validation.
#[allow(dead_code)]
pub enum Confidence {
    Noise = 0,
    Interesting = 1,
    Candidate = 2,
    StrongCandidate = 3,
    Reproduced = 4,
    Confirmed = 5,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpEvidence {
    pub requested_url: String,
    pub final_url: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub bytes: usize,
    pub body_sha256: Option<String>,
    pub title: Option<String>,
    pub body_excerpt: Option<String>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
    pub fingerprint: Option<crate::scan::fingerprint::ResponseFingerprint>,
    pub redirect_hops: Vec<crate::scan::network::RedirectHop>,
}

pub struct Page {
    pub evidence: HttpEvidence,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub title: String,
    pub endpoint: String,
    pub confidence: Confidence,
    pub reason: String,
    pub manual_validation: String,
    pub false_positive_notes: String,
    pub baseline: HttpEvidence,
    pub repeats: Vec<HttpEvidence>,
    pub control: Option<HttpEvidence>,
    pub control_repeats: Vec<HttpEvidence>,
    pub evidence_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuppressedCandidate {
    pub category: String,
    pub endpoint: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct ReviewQueue {
    pub scan_id: Uuid,
    pub pages_crawled: usize,
    pub requests_sent: usize,
    pub budget_exhausted: bool,
    pub candidates_found: usize,
    pub findings_suppressed: usize,
    pub findings: Vec<Finding>,
    pub endpoints_discovered: usize,
    pub response_anomalies: usize,
    pub suppressed_candidates: Vec<SuppressedCandidate>,
    pub duplicates_removed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointRecord {
    pub method: String,
    pub url_template: String,
    pub parameters: BTreeSet<String>,
    pub sources: BTreeSet<String>,
    pub status_codes: BTreeSet<u16>,
    pub content_types: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseAnomaly {
    pub url_template: String,
    pub parameter: String,
    pub baseline_url: String,
    pub control_url: String,
    pub baseline_status: u16,
    pub control_status: u16,
    pub baseline_content_type: Option<String>,
    pub control_content_type: Option<String>,
    pub baseline_evidence: HttpEvidence,
    pub control_evidence: HttpEvidence,
}
