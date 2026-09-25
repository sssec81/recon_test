//! Phase 5 deterministic human review packages.
//!
//! This module consumes persisted Phase 1–4 evidence. It intentionally has no
//! scheduler, network client, discovery provider, probe policy, or AI backend.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const OUTPUT_VERSION: i64 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct ReviewPackage {
    pub output_version: i64,
    pub scan: ScanReview,
    pub summary: ReviewSummary,
    pub candidates: Vec<CandidateReview>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReview {
    pub scan_id: Uuid,
    pub root_scope: Vec<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewSummary {
    pub canonical_endpoints: usize,
    pub live_endpoints: usize,
    pub historical_only_endpoints: usize,
    pub javascript_derived_endpoints: usize,
    pub source_map_derived_endpoints: usize,
    pub investigation_opportunities: usize,
    pub verification_attempts: usize,
    pub correlated_candidates: usize,
    pub suppressed_candidates: usize,
    pub ranked_candidates: usize,
    pub ranked_evidence_states: BTreeMap<String, usize>,
    pub historical_comparison_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateReview {
    pub rank: usize,
    pub candidate_id: String,
    pub endpoint: String,
    pub score: u16,
    pub evidence_state: String,
    pub categories: Vec<String>,
    pub endpoint_classes: Vec<String>,
    pub parameters: Vec<ReviewParameter>,
    pub provenance: Vec<ProvenanceReview>,
    pub score_reasons: Vec<ReviewScoreReason>,
    pub historical_signals: Vec<ReviewHistoricalSignal>,
    pub linked_opportunities: Vec<OpportunityReview>,
    pub verification: VerificationReview,
    pub established_by_scanner: Vec<String>,
    pub not_established: Vec<String>,
    pub limitations: Vec<String>,
    pub manual_validation: Vec<String>,
    pub manual_validation_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReviewParameter {
    pub name: String,
    pub semantic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceReview {
    pub source: String,
    pub explanation: String,
    pub confirms_live: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewScoreReason {
    pub code: String,
    pub points: u16,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewHistoricalSignal {
    pub code: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpportunityReview {
    pub opportunity_id: String,
    pub category: String,
    pub evidence_state: String,
    pub suppression: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationReview {
    pub performed: bool,
    pub evidence_state: String,
    pub narrative: Vec<String>,
    pub attempts: Vec<AttemptReview>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttemptReview {
    pub opportunity_id: String,
    pub sequence: usize,
    pub request_type: String,
    pub comparison: String,
    pub outcome: String,
    pub baseline_status: Option<u16>,
    pub response_status: Option<u16>,
    pub response_complete: Option<bool>,
    pub material_response_difference: bool,
}

#[derive(Default)]
struct CandidateParts {
    score_reasons: Vec<ReviewScoreReason>,
    history: Vec<ReviewHistoricalSignal>,
    opportunities: Vec<OpportunityReview>,
    attempts: Vec<AttemptReview>,
}

pub fn generate(
    conn: &Connection,
    scan_id: Uuid,
    output_dir: &Path,
) -> Result<ReviewPackage, Box<dyn std::error::Error>> {
    let package = assemble(conn, scan_id)?;
    let markdown = markdown(&package);
    let json = serde_json::to_vec_pretty(&package)?;
    std::fs::create_dir_all(output_dir)?;
    let markdown_path = output_dir.join("review_report.md");
    let json_path = output_dir.join("review_report.json");
    atomic_write(&markdown_path, markdown.as_bytes())?;
    atomic_write(&json_path, &json)?;
    conn.execute(
        "INSERT INTO review_packages (scan_id,candidate_count,output_version) VALUES (?1,?2,?3) ON CONFLICT(scan_id) DO UPDATE SET candidate_count=excluded.candidate_count,output_version=excluded.output_version",
        params![scan_id.to_string(), package.candidates.len() as i64, OUTPUT_VERSION],
    )?;
    print_summary(&package, &markdown_path, &json_path);
    Ok(package)
}

pub fn assemble(conn: &Connection, scan_id: Uuid) -> rusqlite::Result<ReviewPackage> {
    let scan = load_scan(conn, scan_id)?;
    let summary = load_summary(conn, scan_id, &scan)?;
    let mut candidates = load_ranked_candidates(conn, scan_id)?;
    let ids: BTreeSet<String> = candidates
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect();
    let mut parts: BTreeMap<String, CandidateParts> = ids
        .iter()
        .map(|id| (id.clone(), CandidateParts::default()))
        .collect();
    load_score_reasons(conn, scan_id, &mut parts)?;
    load_history(conn, scan_id, &mut parts)?;
    load_opportunities(conn, scan_id, &mut parts)?;
    load_attempts(conn, scan_id, &mut parts)?;

    for candidate in &mut candidates {
        let candidate_parts = parts.remove(&candidate.candidate_id).unwrap_or_default();
        candidate.score_reasons = candidate_parts.score_reasons;
        candidate.historical_signals = candidate_parts.history;
        candidate.linked_opportunities = candidate_parts.opportunities;
        candidate.verification = verification_review(
            &candidate.evidence_state,
            &candidate.categories,
            &candidate.linked_opportunities,
            candidate_parts.attempts,
        );
        candidate.established_by_scanner = established(candidate);
        candidate.not_established = not_established(&candidate.categories);
        candidate.limitations = limitations(candidate, summary.historical_comparison_available);
        candidate.manual_validation = manual_guidance(&candidate.categories);
    }

    Ok(ReviewPackage {
        output_version: OUTPUT_VERSION,
        scan,
        summary,
        candidates,
    })
}

fn load_scan(conn: &Connection, scan_id: Uuid) -> rusqlite::Result<ScanReview> {
    conn.query_row(
        "SELECT root_scope,started_at,finished_at FROM scan_runs WHERE id=?1",
        params![scan_id.to_string()],
        |row| {
            let scope: String = row.get(0)?;
            Ok(ScanReview {
                scan_id,
                root_scope: serde_json::from_str(&scope).unwrap_or_else(|_| vec![scope]),
                started_at: row.get(1)?,
                finished_at: row.get(2)?,
            })
        },
    )
}

fn load_summary(
    conn: &Connection,
    scan_id: Uuid,
    scan: &ScanReview,
) -> rusqlite::Result<ReviewSummary> {
    let id = scan_id.to_string();
    let count = |sql: &str| -> rusqlite::Result<usize> {
        conn.query_row(sql, params![id], |row| row.get::<_, i64>(0))
            .map(|value| value as usize)
    };
    let mut states = BTreeMap::new();
    let mut statement = conn.prepare("SELECT evidence_state,count(*) FROM correlated_candidates WHERE scan_id=?1 AND rank IS NOT NULL GROUP BY evidence_state ORDER BY evidence_state")?;
    for row in statement.query_map(params![id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })? {
        let (state, total) = row?;
        states.insert(state, total as usize);
    }
    let scope = serde_json::to_string(&scan.root_scope).unwrap_or_default();
    let previous = conn
        .query_row(
            "SELECT 1 FROM scan_runs WHERE id<>?1 AND root_scope=?2 AND config_hash=(SELECT config_hash FROM scan_runs WHERE id=?1) AND finished_at IS NOT NULL AND started_at<?3 LIMIT 1",
            params![id, scope, scan.started_at],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    Ok(ReviewSummary {
        canonical_endpoints: count(
            "SELECT count(DISTINCT endpoint_id) FROM endpoint_observations WHERE scan_id=?1",
        )?,
        live_endpoints: count(
            "SELECT count(DISTINCT endpoint_id) FROM endpoint_observations WHERE scan_id=?1 AND source IN ('http_probe','triage_fetch','verification')",
        )?,
        historical_only_endpoints: count(
            "SELECT count(DISTINCT o.endpoint_id) FROM endpoint_observations o WHERE o.scan_id=?1 AND lower(o.source) IN ('historical','wayback','common_crawl','commoncrawl') AND NOT EXISTS (SELECT 1 FROM endpoint_observations live WHERE live.scan_id=o.scan_id AND live.endpoint_id=o.endpoint_id AND live.source IN ('http_probe','triage_fetch','verification'))",
        )?,
        javascript_derived_endpoints: count(
            "SELECT count(DISTINCT endpoint_id) FROM endpoint_observations WHERE scan_id=?1 AND source='javascript'",
        )?,
        source_map_derived_endpoints: count(
            "SELECT count(DISTINCT endpoint_id) FROM endpoint_observations WHERE scan_id=?1 AND source='source_map'",
        )?,
        investigation_opportunities: count(
            "SELECT count(*) FROM investigation_opportunities WHERE scan_id=?1",
        )?,
        verification_attempts: count(
            "SELECT count(*) FROM verification_attempts WHERE scan_id=?1",
        )?,
        correlated_candidates: count(
            "SELECT count(*) FROM correlated_candidates WHERE scan_id=?1",
        )?,
        suppressed_candidates: count(
            "SELECT count(*) FROM correlated_candidates WHERE scan_id=?1 AND suppression_reason IS NOT NULL",
        )?,
        ranked_candidates: count(
            "SELECT count(*) FROM correlated_candidates WHERE scan_id=?1 AND rank IS NOT NULL",
        )?,
        ranked_evidence_states: states,
        historical_comparison_available: previous,
    })
}

fn load_ranked_candidates(
    conn: &Connection,
    scan_id: Uuid,
) -> rusqlite::Result<Vec<CandidateReview>> {
    let mut statement = conn.prepare("SELECT id,canonical_url,score,evidence_state,categories,endpoint_classes,parameters,provenance,rank FROM correlated_candidates WHERE scan_id=?1 AND rank IS NOT NULL ORDER BY rank,id")?;
    statement
        .query_map(params![scan_id.to_string()], |row| {
            let raw_url: String = row.get(1)?;
            let categories = sorted_strings(row.get::<_, String>(4)?);
            Ok(CandidateReview {
                rank: row.get::<_, i64>(8)? as usize,
                candidate_id: row.get(0)?,
                endpoint: safe_endpoint(&raw_url),
                score: row.get(2)?,
                evidence_state: safe_state(&row.get::<_, String>(3)?),
                categories: categories.clone(),
                endpoint_classes: sorted_strings(row.get(5)?),
                parameters: sorted_parameters(row.get(6)?),
                provenance: sorted_strings(row.get::<_, String>(7)?)
                    .into_iter()
                    .map(provenance_review)
                    .collect(),
                score_reasons: Vec::new(),
                historical_signals: Vec::new(),
                linked_opportunities: Vec::new(),
                verification: VerificationReview {
                    performed: false,
                    evidence_state: "Unverified".into(),
                    narrative: Vec::new(),
                    attempts: Vec::new(),
                },
                established_by_scanner: Vec::new(),
                not_established: Vec::new(),
                limitations: Vec::new(),
                manual_validation: manual_guidance(&categories),
                manual_validation_required: true,
            })
        })?
        .collect()
}

fn load_score_reasons(
    conn: &Connection,
    scan_id: Uuid,
    parts: &mut BTreeMap<String, CandidateParts>,
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("SELECT r.candidate_id,r.reason_code,r.points,r.explanation FROM candidate_score_reasons r JOIN correlated_candidates c ON c.id=r.candidate_id WHERE c.scan_id=?1 AND c.rank IS NOT NULL ORDER BY r.candidate_id,r.reason_code")?;
    for row in statement.query_map(params![scan_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ReviewScoreReason {
                code: row.get(1)?,
                points: row.get(2)?,
                explanation: row.get(3)?,
            },
        ))
    })? {
        let (candidate, reason) = row?;
        if let Some(part) = parts.get_mut(&candidate) {
            part.score_reasons.push(reason);
        }
    }
    Ok(())
}

fn load_history(
    conn: &Connection,
    scan_id: Uuid,
    parts: &mut BTreeMap<String, CandidateParts>,
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("SELECT h.candidate_id,h.signal_code,h.explanation FROM candidate_history_signals h JOIN correlated_candidates c ON c.id=h.candidate_id WHERE c.scan_id=?1 AND c.rank IS NOT NULL ORDER BY h.candidate_id,h.signal_code,h.explanation")?;
    for row in statement.query_map(params![scan_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            ReviewHistoricalSignal {
                code: row.get(1)?,
                explanation: row.get(2)?,
            },
        ))
    })? {
        let (candidate, signal) = row?;
        if let Some(part) = parts.get_mut(&candidate) {
            part.history.push(signal);
        }
    }
    Ok(())
}

fn load_opportunities(
    conn: &Connection,
    scan_id: Uuid,
    parts: &mut BTreeMap<String, CandidateParts>,
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("SELECT co.candidate_id,o.id,o.category,o.evidence_state,o.suppression_reason FROM candidate_opportunities co JOIN correlated_candidates c ON c.id=co.candidate_id JOIN investigation_opportunities o ON o.id=co.opportunity_id WHERE c.scan_id=?1 AND c.rank IS NOT NULL ORDER BY co.candidate_id,o.category,o.id")?;
    for row in statement.query_map(params![scan_id.to_string()], |row| {
        let suppression: Option<String> = row.get(4)?;
        Ok((
            row.get::<_, String>(0)?,
            OpportunityReview {
                opportunity_id: row.get(1)?,
                category: safe_category(&row.get::<_, String>(2)?),
                evidence_state: safe_state(&row.get::<_, String>(3)?),
                suppression: suppression.as_deref().map(safe_suppression),
            },
        ))
    })? {
        let (candidate, opportunity) = row?;
        if let Some(part) = parts.get_mut(&candidate) {
            part.opportunities.push(opportunity);
        }
    }
    Ok(())
}

fn load_attempts(
    conn: &Connection,
    scan_id: Uuid,
    parts: &mut BTreeMap<String, CandidateParts>,
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("SELECT co.candidate_id,a.opportunity_id,a.sequence,a.request_type,a.comparison,a.failure_reason,a.fingerprint,b.status FROM candidate_opportunities co JOIN correlated_candidates c ON c.id=co.candidate_id JOIN verification_attempts a ON a.opportunity_id=co.opportunity_id LEFT JOIN response_fingerprints b ON b.http_observation_id=a.baseline_observation_id AND b.scan_id=a.scan_id WHERE c.scan_id=?1 AND c.rank IS NOT NULL ORDER BY co.candidate_id,a.opportunity_id,a.sequence,a.id")?;
    for row in statement.query_map(params![scan_id.to_string()], |row| {
        let fingerprint: Option<String> = row.get(6)?;
        let (response_status, complete) = fingerprint_summary(fingerprint.as_deref());
        let comparison: String = row.get(4)?;
        let failure: Option<String> = row.get(5)?;
        Ok((
            row.get::<_, String>(0)?,
            AttemptReview {
                opportunity_id: row.get(1)?,
                sequence: row.get::<_, i64>(2)? as usize,
                request_type: safe_attempt_type(&row.get::<_, String>(3)?),
                comparison: safe_comparison(&comparison),
                outcome: failure
                    .as_deref()
                    .map(safe_failure)
                    .unwrap_or_else(|| "request completed".into()),
                baseline_status: row.get(7)?,
                response_status,
                response_complete: complete,
                material_response_difference: comparison == "meaningfully_different",
            },
        ))
    })? {
        let (candidate, attempt) = row?;
        if let Some(part) = parts.get_mut(&candidate) {
            part.attempts.push(attempt);
        }
    }
    Ok(())
}

fn verification_review(
    state: &str,
    categories: &[String],
    opportunities: &[OpportunityReview],
    attempts: Vec<AttemptReview>,
) -> VerificationReview {
    let performed = !attempts.is_empty();
    let mut narrative = Vec::new();
    if !performed {
        narrative.push("Controlled verification was not performed.".into());
    } else {
        if attempts
            .iter()
            .any(|attempt| attempt.baseline_status.is_some())
        {
            narrative.push("A persisted baseline observation was available.".into());
        }
        for attempt in &attempts {
            match (attempt.request_type.as_str(), attempt.comparison.as_str()) {
                ("repeat", "stable") => narrative.push(
                    "An equivalent repeat request completed and remained materially stable."
                        .into(),
                ),
                ("repeat", "meaningfully_different") => narrative
                    .push("The repeat response differed materially and was not treated as stable.".into()),
                ("control", "meaningfully_different") => narrative.push(
                    "A benign same-origin control produced a material response difference.".into(),
                ),
                ("control", "stable") => narrative.push(
                    "The benign control was materially indistinguishable from the repeated response."
                        .into(),
                ),
                (_, "inconclusive") => narrative.push(format!(
                    "The {} attempt was inconclusive: {}.",
                    attempt.request_type, attempt.outcome
                )),
                _ => {}
            }
        }
    }
    for opportunity in opportunities
        .iter()
        .filter(|value| value.suppression.is_some())
    {
        narrative.push(format!(
            "Opportunity {} was limited: {}.",
            opportunity.category,
            opportunity
                .suppression
                .as_deref()
                .unwrap_or("not completed")
        ));
    }
    if state == "Repeatable"
        && !attempts
            .iter()
            .any(|attempt| attempt.request_type == "control")
    {
        narrative.push("No benign control comparison was applicable or completed.".into());
    }
    if state == "ControlVerified" && categories.contains(&"RedirectBehavior".to_string()) {
        narrative.push(
            "The control established input influence on response behavior; destination safety was not tested."
                .into(),
        );
    }
    narrative.sort();
    narrative.dedup();
    VerificationReview {
        performed,
        evidence_state: safe_state(state),
        narrative,
        attempts,
    }
}

fn established(candidate: &CandidateReview) -> Vec<String> {
    let mut values = BTreeSet::new();
    if candidate.provenance.iter().any(|value| value.confirms_live) {
        values.insert("The endpoint was observed during live HTTP inventory.".to_string());
    }
    for parameter in &candidate.parameters {
        values.insert(format!(
            "Parameter `{}` was classified as {}.",
            parameter.name, parameter.semantic
        ));
    }
    match candidate.evidence_state.as_str() {
        "Repeatable" => {
            values.insert("Equivalent response behavior was repeatable.".into());
        }
        "ControlVerified" => {
            values.insert("Equivalent response behavior was repeatable.".into());
            values.insert("A benign control produced a material response difference.".into());
        }
        "Observed" => {
            values.insert("The candidate has persisted observed evidence.".into());
        }
        _ => {}
    }
    values.into_iter().collect()
}

fn not_established(categories: &[String]) -> Vec<String> {
    let mut values = BTreeSet::from([
        "Exploitability was not established.".to_string(),
        "Vulnerability severity was not established.".to_string(),
        "No vulnerability was confirmed by the scanner.".to_string(),
    ]);
    for category in categories {
        match category.as_str() {
            "IdentifierHandling" => {
                values.insert(
                    "Whether authorization or ownership checks are missing was not established."
                        .into(),
                );
            }
            "RedirectBehavior" => {
                values.insert(
                    "Whether arbitrary external destinations are accepted was not established."
                        .into(),
                );
                values.insert(
                    "Whether a security trust boundary can be bypassed was not established.".into(),
                );
            }
            "UrlHandling" => {
                values.insert("Whether URL-like input causes security-sensitive outbound behavior was not established.".into());
            }
            "SearchSurface" => {
                values.insert("No injection testing was performed.".into());
            }
            _ => {}
        }
    }
    values.into_iter().collect()
}

fn limitations(candidate: &CandidateReview, history_available: bool) -> Vec<String> {
    let mut values = BTreeSet::new();
    if !candidate.verification.performed {
        values.insert("No controlled verification was performed.".into());
    } else if candidate.evidence_state == "Repeatable"
        && !candidate
            .verification
            .attempts
            .iter()
            .any(|attempt| attempt.request_type == "control")
    {
        values.insert(
            "Only repeatability was established; no control comparison was applicable.".into(),
        );
    }
    if candidate
        .verification
        .attempts
        .iter()
        .any(|attempt| attempt.response_complete == Some(false))
    {
        values.insert("Response capture was incomplete.".into());
    }
    if candidate
        .verification
        .attempts
        .iter()
        .any(|attempt| attempt.outcome.contains("budget"))
    {
        values.insert("Verification was limited by the shared request budget.".into());
    }
    if !history_available {
        values.insert("Historical comparison was unavailable because no eligible previous same-scope scan existed.".into());
    } else if candidate.historical_signals.is_empty() {
        values.insert("No material historical signal was recorded.".into());
    }
    if candidate.provenance.iter().any(|value| {
        matches!(
            value.source.as_str(),
            "wayback" | "common_crawl" | "historical"
        )
    }) {
        values.insert("The candidate is based partly on passive historical evidence, which does not by itself confirm current availability.".into());
    }
    values.into_iter().collect()
}

fn manual_guidance(categories: &[String]) -> Vec<String> {
    let mut values = BTreeSet::new();
    for category in categories {
        let guidance = match category.as_str() {
            "IdentifierHandling" => {
                "Use authorized test accounts or resources to compare ownership and server-side authorization manually."
            }
            "RedirectBehavior" => {
                "Review destination validation manually within program scope and confirm the intended trust boundary."
            }
            "UrlHandling" => {
                "Determine manually what the URL-like input controls and whether it causes security-sensitive outbound or redirect behavior."
            }
            "FileOrPathHandling" => {
                "Review file/path constraints, authorization, and path boundaries manually."
            }
            "AuthenticationSurface" => {
                "Review authentication/session transitions, expected authorization, and error behavior manually."
            }
            "AdministrativeSurface" => {
                "Confirm whether the functionality is intentionally exposed and authorization is enforced."
            }
            "DebugOrInternalSurface" => {
                "Inspect whether exposed functionality or data is intended for the current user and context."
            }
            "WebhookSurface" => {
                "Review webhook destination restrictions, authentication, configuration ownership, and authorization manually."
            }
            "GraphQLSurface" => {
                "Review schema exposure and resolver-level authorization manually using program-permitted testing."
            }
            "UploadSurface" => {
                "Review accepted file types, authorization, storage behavior, and retrieval boundaries manually."
            }
            "DownloadSurface" => "Review authorization and object or file ownership manually.",
            "SearchSurface" => {
                "Review how input affects backend behavior manually; the scanner performed no injection testing."
            }
            _ => "Review the correlated behavior manually within program rules.",
        };
        values.insert(guidance.to_string());
    }
    values.into_iter().collect()
}

fn provenance_review(source: String) -> ProvenanceReview {
    let explanation = match source.as_str() {
        "http_probe" => "observed directly during live HTTP inventory",
        "javascript" => "referenced by fetched JavaScript",
        "source_map" => "recovered from source-map intelligence",
        "wayback" => "observed in Wayback historical data",
        "common_crawl" => "observed in Common Crawl historical data",
        "historical" => "observed in passive historical data",
        _ => "retained inventory provenance",
    };
    ProvenanceReview {
        confirms_live: crate::storage::db::provenance_is_live(&source),
        source: safe_identifier(&source),
        explanation: explanation.into(),
    }
}

fn sorted_strings(raw: String) -> Vec<String> {
    let values: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
    values
        .into_iter()
        .map(|value| safe_identifier(&value))
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_parameters(raw: String) -> Vec<ReviewParameter> {
    let values: Vec<ReviewParameter> = serde_json::from_str(&raw).unwrap_or_default();
    values
        .into_iter()
        .map(|parameter| ReviewParameter {
            name: safe_parameter_name(&parameter.name),
            semantic: safe_identifier(&parameter.semantic),
        })
        .filter(|parameter| !parameter.name.is_empty() && !parameter.semantic.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn safe_endpoint(value: &str) -> String {
    crate::scan::normalize::normalize_endpoint(value, None)
        .map(|endpoint| endpoint.canonical_url)
        .unwrap_or_else(|| "<invalid-canonical-endpoint>".into())
}

fn safe_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
        })
        .take(128)
        .collect()
}

fn safe_parameter_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '[' | ']')
        })
        .take(128)
        .collect()
}

fn safe_state(value: &str) -> String {
    match value {
        "ControlVerified" | "Repeatable" | "Observed" | "Unverified" => value.into(),
        _ => "Unverified".into(),
    }
}

fn safe_category(value: &str) -> String {
    safe_identifier(value)
}

fn safe_attempt_type(value: &str) -> String {
    match value {
        "repeat" | "control" => value.into(),
        _ => "verification".into(),
    }
}

fn safe_comparison(value: &str) -> String {
    match value {
        "stable" | "meaningfully_different" | "inconclusive" => value.into(),
        _ => "inconclusive".into(),
    }
}

fn safe_failure(value: &str) -> String {
    let value = value.to_ascii_lowercase();
    if value.contains("budget") {
        "shared request budget exhausted".into()
    } else if value.contains("deadline") {
        "verification deadline expired".into()
    } else if value.contains("scope") || value.contains("redirect") {
        "redirect or scope policy prevented completion".into()
    } else if value.contains("incomplete") || value.contains("truncat") {
        "response evidence was incomplete".into()
    } else {
        "verification request failed".into()
    }
}

fn safe_suppression(value: &str) -> String {
    let value = value.to_ascii_lowercase();
    if value.contains("unstable") {
        "repeat response was unstable".into()
    } else if value.contains("indistinguishable") {
        "benign control was indistinguishable".into()
    } else if value.contains("budget") || value.contains("cap") {
        "verification request budget or opportunity cap was reached".into()
    } else if value.contains("deadline") {
        "verification deadline expired".into()
    } else if value.contains("incomplete") || value.contains("inconclusive") {
        "verification evidence was incomplete or inconclusive".into()
    } else if value.contains("policy") || value.contains("eligible") {
        "verification policy did not permit an active check".into()
    } else {
        "verification was not completed".into()
    }
}

fn fingerprint_summary(raw: Option<&str>) -> (Option<u16>, Option<bool>) {
    let Some(raw) = raw else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return (None, None);
    };
    (
        value
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .map(|status| status as u16),
        value
            .get("body_complete")
            .and_then(serde_json::Value::as_bool),
    )
}

fn markdown(package: &ReviewPackage) -> String {
    let mut output = String::new();
    output.push_str("# Recon Test — Human Review Report\n\n");
    output.push_str("## Scan Summary\n\n");
    output.push_str(&format!("- Scan ID: `{}`\n", package.scan.scan_id));
    output.push_str(&format!(
        "- Scope: {}\n",
        package.scan.root_scope.join(", ")
    ));
    output.push_str(&format!("- Started: {}\n", package.scan.started_at));
    output.push_str(&format!(
        "- Finished: {}\n",
        package
            .scan
            .finished_at
            .as_deref()
            .unwrap_or("not recorded")
    ));
    output.push_str(&format!("- Canonical endpoints: {}\n- Live endpoints: {}\n- Historical-only endpoints: {}\n- JavaScript-derived endpoints: {}\n- Source-map-derived endpoints: {}\n", package.summary.canonical_endpoints, package.summary.live_endpoints, package.summary.historical_only_endpoints, package.summary.javascript_derived_endpoints, package.summary.source_map_derived_endpoints));
    output.push_str(&format!("- Investigation opportunities: {}\n- Verification attempts: {}\n- Correlated candidates: {}\n- Suppressed candidates: {}\n- Ranked candidates: {}\n", package.summary.investigation_opportunities, package.summary.verification_attempts, package.summary.correlated_candidates, package.summary.suppressed_candidates, package.summary.ranked_candidates));
    output.push_str("\nRanked evidence states:\n");
    if package.summary.ranked_evidence_states.is_empty() {
        output.push_str("- None\n");
    }
    for (state, count) in &package.summary.ranked_evidence_states {
        output.push_str(&format!("- {state}: {count}\n"));
    }
    output.push_str("\n## Ranked Investigation Candidates\n\n");
    if package.candidates.is_empty() {
        output.push_str("No candidates met the Phase 4 review threshold.\n");
    }
    for candidate in &package.candidates {
        output.push_str(&format!(
            "### #{} — {}\n\n",
            candidate.rank, candidate.endpoint
        ));
        output.push_str(&format!(
            "Investigation priority: {} / 100\n\nEvidence state: {}\n\n",
            candidate.score, candidate.evidence_state
        ));
        output.push_str("This is an investigation-priority score, not vulnerability severity.\n\n");
        markdown_list(&mut output, "Categories", &candidate.categories);
        markdown_list(&mut output, "Endpoint context", &candidate.endpoint_classes);
        let parameters: Vec<String> = candidate
            .parameters
            .iter()
            .map(|parameter| format!("`{}` → {}", parameter.name, parameter.semantic))
            .collect();
        if parameters.is_empty() {
            output.push_str(
                "#### Parameters\n\nNo classified parameters contributed to this candidate.\n\n",
            );
        } else {
            markdown_list(&mut output, "Parameters", &parameters);
        }
        let provenance: Vec<String> = candidate
            .provenance
            .iter()
            .map(|value| format!("{} — {}", value.source, value.explanation))
            .collect();
        markdown_list(&mut output, "Provenance", &provenance);
        let reasons: Vec<String> = candidate
            .score_reasons
            .iter()
            .map(|reason| format!("+{} {}", reason.points, reason.explanation))
            .collect();
        markdown_list(&mut output, "Score explanation", &reasons);
        markdown_list(
            &mut output,
            "Verification",
            &candidate.verification.narrative,
        );
        let history: Vec<String> = candidate
            .historical_signals
            .iter()
            .map(|signal| signal.explanation.clone())
            .collect();
        if history.is_empty() {
            output.push_str(
                "#### Historical changes\n\nNo material historical signal was recorded.\n\n",
            );
        } else {
            markdown_list(&mut output, "Historical changes", &history);
        }
        markdown_list(
            &mut output,
            "Established by scanner",
            &candidate.established_by_scanner,
        );
        markdown_list(&mut output, "Not established", &candidate.not_established);
        markdown_list(&mut output, "Limitations", &candidate.limitations);
        markdown_list(
            &mut output,
            "Manual validation",
            &candidate.manual_validation,
        );
        output.push_str("Manual validation required: **YES**\n\nScanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**\n\n---\n\n");
    }
    output
}

fn markdown_list(output: &mut String, title: &str, values: &[String]) {
    output.push_str(&format!("#### {title}\n\n"));
    if values.is_empty() {
        output.push_str("- None recorded.\n");
    } else {
        for value in values {
            output.push_str(&format!("- {value}\n"));
        }
    }
    output.push('\n');
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = temporary_path(path);
    std::fs::write(&temporary, bytes)?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("review");
    path.with_file_name(format!(".{name}.tmp"))
}

fn print_summary(package: &ReviewPackage, markdown: &Path, json: &Path) {
    println!("\n📋 Human Review Package\n");
    println!("Ranked candidates: {}", package.summary.ranked_candidates);
    for state in ["ControlVerified", "Repeatable", "Observed", "Unverified"] {
        if let Some(count) = package.summary.ranked_evidence_states.get(state) {
            println!("{state}: {count}");
        }
    }
    println!(
        "\nMarkdown:\n{}\n\nJSON:\n{}",
        markdown.display(),
        json.display()
    );
    println!("\nManual validation is required before treating any candidate as a vulnerability.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db;
    use crate::storage::models::ScanRun;

    fn fixture() -> (Connection, ScanRun) {
        let conn = db::init_db(":memory:").unwrap();
        let mut scan = ScanRun::new(vec!["example.com".into()], "review".into());
        scan.finished_at = Some(chrono::Utc::now());
        db::save_scan_run(&conn, &scan).unwrap();
        db::finish_scan_run(&conn, &scan.id).unwrap();
        (conn, scan)
    }

    fn endpoint(conn: &Connection, scan: &ScanRun, url: &str, sources: &[&str]) -> String {
        for source in sources {
            db::save_endpoint_observation(conn, &scan.id, url, source, Some("fixture")).unwrap();
        }
        crate::scan::normalize::endpoint_id(
            &crate::scan::normalize::normalize_endpoint(url, None).unwrap(),
        )
    }

    #[test]
    fn ranked_review_preserves_phase4_authority_and_verification_order() {
        let (conn, scan) = fixture();
        let endpoint_id = endpoint(
            &conn,
            &scan,
            "https://example.com/api/users?user_id=SUPER_SECRET_QUERY_VALUE",
            &["http_probe", "javascript"],
        );
        conn.execute("INSERT INTO correlated_candidates VALUES ('candidate',?1,?2,'https://example.com/api/users','Repeatable',57,'[\"IdentifierHandling\"]','[\"Api\",\"Account\"]','[{\"name\":\"user_id\",\"semantic\":\"UserId\"}]','[\"http_probe\",\"javascript\"]','[]',NULL,1,1)", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute("INSERT INTO candidate_score_reasons VALUES ('candidate','persisted',57,'persisted Phase 4 reason')", []).unwrap();
        conn.execute("INSERT INTO candidate_history_signals VALUES ('candidate','history:fingerprint_changed','complete stable fingerprint changed')", []).unwrap();
        conn.execute("INSERT INTO investigation_opportunities VALUES ('opp',?1,?2,'https://example.com/api/users','IdentifierHandling','reason','[]',5,'Repeatable',NULL)", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute(
            "INSERT INTO candidate_opportunities VALUES ('candidate','opp')",
            [],
        )
        .unwrap();
        for (id, sequence, request_type) in
            [("attempt-2", 2, "control"), ("attempt-1", 1, "repeat")]
        {
            conn.execute("INSERT INTO verification_attempts VALUES (?1,?2,'opp',?3,?4,'https://example.com/api/users?token=<redacted>',NULL,NULL,'stable',NULL,'now')", params![id, scan.id.to_string(), sequence, request_type]).unwrap();
        }
        let package = assemble(&conn, scan.id).unwrap();
        assert_eq!(package.candidates.len(), 1);
        let review = &package.candidates[0];
        assert_eq!(
            (review.rank, review.score, review.evidence_state.as_str()),
            (1, 57, "Repeatable")
        );
        assert_eq!(
            review.score_reasons[0].explanation,
            "persisted Phase 4 reason"
        );
        assert_eq!(
            review
                .verification
                .attempts
                .iter()
                .map(|attempt| attempt.sequence)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(review.parameters[0].name, "user_id");
        assert!(
            review
                .provenance
                .iter()
                .any(|value| value.source == "javascript"
                    && value.explanation.contains("JavaScript"))
        );
        assert_eq!(review.linked_opportunities[0].opportunity_id, "opp");
        assert!(
            review.historical_signals[0]
                .explanation
                .contains("fingerprint")
        );
    }

    #[test]
    fn unranked_candidates_are_excluded_and_missing_evidence_is_graceful() {
        let (conn, scan) = fixture();
        let ranked = endpoint(&conn, &scan, "https://example.com/admin", &["http_probe"]);
        let unranked = endpoint(
            &conn,
            &scan,
            "https://example.com/passive/old",
            &["wayback"],
        );
        for (id, endpoint, url, rank, suppressed) in [
            ("ranked", ranked, "https://example.com/admin", Some(1), None),
            (
                "unranked",
                unranked,
                "https://example.com/passive/old",
                None,
                Some("passive only"),
            ),
        ] {
            conn.execute("INSERT INTO correlated_candidates VALUES (?1,?2,?3,?4,'Observed',20,'[\"AdministrativeSurface\"]','[\"Admin\"]','[]','[\"http_probe\"]','[]',?5,?6,?7)", params![id, scan.id.to_string(), endpoint, url, suppressed, rank.is_some(), rank]).unwrap();
        }
        let package = assemble(&conn, scan.id).unwrap();
        assert_eq!(package.candidates.len(), 1);
        assert_eq!(package.candidates[0].candidate_id, "ranked");
        assert!(!package.candidates[0].verification.performed);
        assert!(
            package.candidates[0]
                .limitations
                .iter()
                .any(|value| value.contains("No controlled verification"))
        );
        assert_eq!(package.summary.correlated_candidates, 2);
        assert_eq!(package.summary.suppressed_candidates, 1);
    }

    #[test]
    fn deterministic_language_does_not_overclaim() {
        let identifier = not_established(&["IdentifierHandling".into()]).join(" ");
        let redirect = not_established(&["RedirectBehavior".into()]).join(" ");
        assert!(!identifier.to_ascii_lowercase().contains("idor confirmed"));
        assert!(
            !identifier
                .to_ascii_lowercase()
                .contains("authorization bypass confirmed")
        );
        assert!(
            !redirect
                .to_ascii_lowercase()
                .contains("open redirect confirmed")
        );
        assert!(identifier.contains("No vulnerability was confirmed"));
        assert!(redirect.contains("external destinations"));
        for category in [
            "UrlHandling",
            "FileOrPathHandling",
            "AuthenticationSurface",
            "AdministrativeSurface",
            "DebugOrInternalSurface",
            "WebhookSurface",
            "GraphQLSurface",
            "UploadSurface",
            "DownloadSurface",
            "SearchSurface",
        ] {
            assert!(!manual_guidance(&[category.into()]).is_empty());
        }
    }

    #[test]
    fn summary_counts_distinct_sources_and_states_exactly() {
        let (conn, scan) = fixture();
        let live = endpoint(
            &conn,
            &scan,
            "https://example.com/api",
            &["http_probe", "javascript", "source_map", "wayback"],
        );
        endpoint(
            &conn,
            &scan,
            "https://example.com/old",
            &["wayback", "common_crawl"],
        );
        conn.execute("INSERT INTO investigation_opportunities VALUES ('opp',?1,?2,'https://example.com/api','Other','reason','[]',1,'Observed',NULL)", params![scan.id.to_string(), live]).unwrap();
        conn.execute("INSERT INTO verification_attempts VALUES ('attempt',?1,'opp',1,'repeat','https://example.com/api',NULL,NULL,'stable',NULL,'now')", params![scan.id.to_string()]).unwrap();
        conn.execute("INSERT INTO correlated_candidates VALUES ('one',?1,?2,'https://example.com/api','Observed',20,'[\"Other\"]','[]','[]','[\"http_probe\"]','[]',NULL,1,1)", params![scan.id.to_string(), live]).unwrap();
        conn.execute("INSERT INTO correlated_candidates VALUES ('two',?1,(SELECT endpoint_id FROM endpoint_observations WHERE scan_id=?1 AND source='wayback' AND endpoint_id<>?2 LIMIT 1),'https://example.com/old','Unverified',0,'[]','[]','[]','[\"wayback\"]','[]','passive',0,NULL)", params![scan.id.to_string(), live]).unwrap();
        let summary = load_summary(&conn, scan.id, &load_scan(&conn, scan.id).unwrap()).unwrap();
        assert_eq!(
            (
                summary.canonical_endpoints,
                summary.live_endpoints,
                summary.historical_only_endpoints,
                summary.javascript_derived_endpoints,
                summary.source_map_derived_endpoints
            ),
            (2, 1, 1, 1, 1)
        );
        assert_eq!(
            (
                summary.investigation_opportunities,
                summary.verification_attempts,
                summary.correlated_candidates,
                summary.suppressed_candidates,
                summary.ranked_candidates
            ),
            (1, 1, 2, 1, 1)
        );
        assert_eq!(summary.ranked_evidence_states.get("Observed"), Some(&1));
    }

    #[test]
    fn generation_is_idempotent_atomic_and_private() {
        let (conn, scan) = fixture();
        let endpoint_id = endpoint(
            &conn,
            &scan,
            "https://example.com/api/account/export?user_id=SUPER_SECRET_QUERY_VALUE",
            &["http_probe", "javascript", "source_map", "wayback"],
        );
        conn.execute("INSERT INTO correlated_candidates VALUES ('a',?1,?2,'https://user:SUPER_SECRET_AUTH@example.com/api/account/export?token=SUPER_SECRET_QUERY_VALUE','ControlVerified',88,'[\"DownloadSurface\",\"IdentifierHandling\"]','[\"Account\",\"Api\",\"Export\"]','[{\"name\":\"user_id\",\"semantic\":\"UserId\"}]','[\"http_probe\",\"javascript\",\"source_map\",\"wayback\"]','[]',NULL,1,1)", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute("INSERT INTO candidate_score_reasons VALUES ('a','state',30,'ControlVerified evidence')", []).unwrap();
        conn.execute("INSERT INTO investigation_opportunities VALUES ('secret-opp',?1,?2,'https://example.com/api/account/export','IdentifierHandling','Authorization: Bearer SUPER_SECRET_AUTH Cookie: session=SUPER_SECRET_COOKIE SUPER_SECRET_BODY','[]',5,'ControlVerified',NULL)", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute(
            "INSERT INTO candidate_opportunities VALUES ('a','secret-opp')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO verification_attempts VALUES ('secret-attempt',?1,'secret-opp',1,'control','https://example.com/?redirect=SUPER_SECRET_REDIRECT',NULL,'{\"status\":302,\"body_complete\":true,\"redirect_target\":\"SUPER_SECRET_REDIRECT\",\"body\":\"SUPER_SECRET_BODY\"}','meaningfully_different','SUPER_SECRET_COOKIE','now')", params![scan.id.to_string()]).unwrap();
        let debug_id = endpoint(
            &conn,
            &scan,
            "https://example.com/admin/debug",
            &["http_probe", "wayback"],
        );
        conn.execute("INSERT INTO correlated_candidates VALUES ('b',?1,?2,'https://example.com/admin/debug','Repeatable',54,'[\"DebugOrInternalSurface\"]','[\"Admin\",\"Debug\"]','[]','[\"http_probe\",\"wayback\"]','[]',NULL,1,2)", params![scan.id.to_string(), debug_id]).unwrap();
        let passive_id = endpoint(
            &conn,
            &scan,
            "https://example.com/passive/old",
            &["wayback"],
        );
        conn.execute("INSERT INTO correlated_candidates VALUES ('c',?1,?2,'https://example.com/passive/old','Unverified',8,'[]','[]','[]','[\"wayback\"]','[]','passive-only evidence',0,NULL)", params![scan.id.to_string(), passive_id]).unwrap();
        let dir = std::env::temp_dir().join(format!("recon_review_{}", scan.id));
        let first = generate(&conn, scan.id, &dir).unwrap();
        let first_json = std::fs::read_to_string(dir.join("review_report.json")).unwrap();
        let first_markdown = std::fs::read_to_string(dir.join("review_report.md")).unwrap();
        let phase4_before: i64 = conn
            .query_row("SELECT count(*) FROM correlated_candidates", [], |row| {
                row.get(0)
            })
            .unwrap();
        let attempts_before: i64 = conn
            .query_row("SELECT count(*) FROM verification_attempts", [], |row| {
                row.get(0)
            })
            .unwrap();
        let second = generate(&conn, scan.id, &dir).unwrap();
        assert_eq!(first.candidates.len(), 2);
        assert_eq!(first.candidates.len(), second.candidates.len());
        assert_eq!(first.candidates[0].candidate_id, "a");
        assert_eq!(first.candidates[1].candidate_id, "b");
        assert!(
            !first
                .candidates
                .iter()
                .any(|candidate| candidate.candidate_id == "c")
        );
        assert_eq!(first.summary.correlated_candidates, 3);
        assert_eq!(first.summary.suppressed_candidates, 1);
        assert!(first.candidates[0].verification.performed);
        assert!(first.candidates[0].manual_validation_required);
        assert!(
            first.candidates[0]
                .not_established
                .iter()
                .any(|value| value.contains("No vulnerability was confirmed"))
        );
        assert!(
            first.candidates[1]
                .provenance
                .iter()
                .any(|value| value.source == "wayback")
        );
        assert_eq!(
            first_json,
            std::fs::read_to_string(dir.join("review_report.json")).unwrap()
        );
        assert_eq!(
            first_markdown,
            std::fs::read_to_string(dir.join("review_report.md")).unwrap()
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM review_packages", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM correlated_candidates", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            phase4_before
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM verification_attempts", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            attempts_before
        );
        for secret in [
            "SUPER_SECRET_QUERY_VALUE",
            "SUPER_SECRET_REDIRECT",
            "SUPER_SECRET_AUTH",
            "SUPER_SECRET_COOKIE",
            "SUPER_SECRET_BODY",
        ] {
            assert!(!first_json.contains(secret), "JSON leaked {secret}");
            assert!(!first_markdown.contains(secret), "Markdown leaked {secret}");
        }
        for allowed in ["user_id", "UserId", "IdentifierHandling", "ControlVerified"] {
            assert!(first_json.contains(allowed));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn phase4_database_upgrades_to_phase5_and_preserves_all_evidence() {
        let path = std::env::temp_dir().join(format!("recon_phase5_{}.db", Uuid::new_v4()));
        let dir = std::env::temp_dir().join(format!("recon_phase5_output_{}", Uuid::new_v4()));
        let conn = db::init_db(path.to_str().unwrap()).unwrap();
        let mut scan = ScanRun::new(vec!["example.com".into()], "phase5-migration".into());
        scan.finished_at = Some(chrono::Utc::now());
        db::save_scan_run(&conn, &scan).unwrap();
        let endpoint_id = endpoint(
            &conn,
            &scan,
            "https://example.com/api/users?user_id=1",
            &["http_probe"],
        );
        conn.execute(
            "INSERT INTO endpoint_classifications VALUES (?1,?2,'Api')",
            params![scan.id.to_string(), endpoint_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO parameter_semantics VALUES (?1,?2,'user_id','UserId')",
            params![scan.id.to_string(), endpoint_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO hostnames VALUES ('example.com','example.com','Seed',NULL)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO http_observations VALUES ('observation',?1,'example.com','https://example.com/api/users',200,NULL,NULL,2,2,'now')", params![scan.id.to_string()]).unwrap();
        conn.execute("INSERT INTO response_fingerprints VALUES ('observation',?1,?2,200,2,2,1,'raw','normalized','application/json','headers',NULL,'shape','fast')", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute("INSERT INTO investigation_opportunities VALUES ('opp',?1,?2,'https://example.com/api/users','IdentifierHandling','fixture','[]',5,'Repeatable',NULL)", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute("INSERT INTO verification_attempts VALUES ('attempt',?1,'opp',1,'repeat','https://example.com/api/users','observation',NULL,'stable',NULL,'now')", params![scan.id.to_string()]).unwrap();
        conn.execute("INSERT INTO correlated_candidates VALUES ('candidate',?1,?2,'https://example.com/api/users','Repeatable',50,'[\"IdentifierHandling\"]','[\"Api\"]','[{\"name\":\"user_id\",\"semantic\":\"UserId\"}]','[\"http_probe\"]','[]',NULL,1,1)", params![scan.id.to_string(), endpoint_id]).unwrap();
        conn.execute("INSERT INTO candidate_score_reasons VALUES ('candidate','state',30,'repeatable evidence')", []).unwrap();
        conn.execute("INSERT INTO candidate_history_signals VALUES ('candidate','history:new','new endpoint')", []).unwrap();
        conn.execute(
            "INSERT INTO candidate_opportunities VALUES ('candidate','opp')",
            [],
        )
        .unwrap();
        conn.execute("DROP TABLE review_packages", []).unwrap();
        drop(conn);

        let conn = db::init_db(path.to_str().unwrap()).unwrap();
        for table in [
            "scan_runs",
            "endpoints",
            "endpoint_observations",
            "response_fingerprints",
            "endpoint_classifications",
            "parameter_semantics",
            "investigation_opportunities",
            "verification_attempts",
            "correlated_candidates",
            "candidate_score_reasons",
            "candidate_history_signals",
            "candidate_opportunities",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1,
                "{table} was not preserved"
            );
        }
        let package = generate(&conn, scan.id, &dir).unwrap();
        assert_eq!(package.candidates[0].candidate_id, "candidate");
        assert_eq!(
            conn.query_row("SELECT count(*) FROM review_packages", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(conn);
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
