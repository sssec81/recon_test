use serde::Serialize;
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
    pub evidence_dir: Option<String>,
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
}
