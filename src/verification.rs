//! Phase 3 controlled verification. Opportunities are review intelligence, not
//! vulnerability findings. Every target request is delegated to RequestScheduler.

use crate::scan::fingerprint::ResponseFingerprint;
use crate::scan::network::RequestScheduler;
use crate::scan::scope::ScopePolicy;
use reqwest::Url;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct VerificationConfig {
    pub max_opportunities: usize,
    pub max_requests_per_opportunity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceState {
    Unverified,
    Observed,
    Repeatable,
    ControlVerified,
}

impl EvidenceState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "Unverified",
            Self::Observed => "Observed",
            Self::Repeatable => "Repeatable",
            Self::ControlVerified => "ControlVerified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OpportunityCategory {
    RedirectBehavior,
    UrlHandling,
    IdentifierHandling,
    FileOrPathHandling,
    AuthenticationSurface,
    AdministrativeSurface,
    WebhookSurface,
    GraphQLSurface,
    UploadSurface,
    DownloadSurface,
    SearchSurface,
    DebugOrInternalSurface,
    DifferentialResponse,
    Other,
}

impl OpportunityCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::RedirectBehavior => "RedirectBehavior",
            Self::UrlHandling => "UrlHandling",
            Self::IdentifierHandling => "IdentifierHandling",
            Self::FileOrPathHandling => "FileOrPathHandling",
            Self::AuthenticationSurface => "AuthenticationSurface",
            Self::AdministrativeSurface => "AdministrativeSurface",
            Self::WebhookSurface => "WebhookSurface",
            Self::GraphQLSurface => "GraphQLSurface",
            Self::UploadSurface => "UploadSurface",
            Self::DownloadSurface => "DownloadSurface",
            Self::SearchSurface => "SearchSurface",
            Self::DebugOrInternalSurface => "DebugOrInternalSurface",
            Self::DifferentialResponse => "DifferentialResponse",
            Self::Other => "Other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvestigationOpportunity {
    pub id: String,
    pub endpoint_id: String,
    pub canonical_url: String,
    pub category: OpportunityCategory,
    pub reason: String,
    pub supporting_evidence: Vec<String>,
    pub priority: u8,
    pub evidence_state: EvidenceState,
    live_url: Option<String>,
    baseline_observation_id: Option<String>,
    baseline: Option<ResponseFingerprint>,
    control_parameter: Option<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Stable,
    MeaningfullyDifferent,
    Inconclusive,
}

impl Comparison {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::MeaningfullyDifferent => "meaningfully_different",
            Self::Inconclusive => "inconclusive",
        }
    }
}

pub async fn run(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    config: VerificationConfig,
) -> Result<Vec<InvestigationOpportunity>, Box<dyn std::error::Error>> {
    let mut opportunities = generate(conn, scan_id)?;
    persist_opportunities(conn, scan_id, &opportunities)?;
    let request_limit = config.max_requests_per_opportunity.min(2);
    let mut selected = 0usize;

    for opportunity in &mut opportunities {
        if !eligible(opportunity, scope) {
            let reason = if opportunity.evidence_state == EvidenceState::Unverified {
                "no confirmed-live baseline"
            } else {
                "verification policy denied this endpoint"
            };
            suppress(conn, &opportunity.id, reason)?;
            continue;
        }
        if selected >= config.max_opportunities {
            suppress(
                conn,
                &opportunity.id,
                "global verification opportunity cap reached",
            )?;
            continue;
        }
        selected += 1;
        if request_limit == 0 {
            suppress(conn, &opportunity.id, "per-opportunity request cap reached")?;
            continue;
        }
        let url = Url::parse(opportunity.live_url.as_deref().expect("eligible live URL"))?;
        let Some(repeat) = fetch_fingerprint(scheduler, &url).await else {
            save_attempt(
                conn,
                scan_id,
                opportunity,
                1,
                "repeat",
                &url,
                None,
                Comparison::Inconclusive,
                Some("request failed, deadline expired, or shared budget exhausted"),
            )?;
            suppress(
                conn,
                &opportunity.id,
                "repeat request failed or was not schedulable",
            )?;
            continue;
        };
        let comparison = compare(
            opportunity.baseline.as_ref().expect("eligible baseline"),
            &repeat,
            false,
        );
        save_attempt(
            conn,
            scan_id,
            opportunity,
            1,
            "repeat",
            &url,
            Some(&repeat),
            comparison,
            None,
        )?;
        if comparison != Comparison::Stable {
            suppress(
                conn,
                &opportunity.id,
                if comparison == Comparison::Inconclusive {
                    "baseline/repeat comparison was incomplete"
                } else {
                    "repeat response was unstable"
                },
            )?;
            continue;
        }
        opportunity.evidence_state = EvidenceState::Repeatable;
        update_state(conn, opportunity)?;

        if request_limit == 2
            && let Some((name, semantic)) = &opportunity.control_parameter
            && let Some(control_url) = benign_control(&url, name, semantic)
        {
            let Some(control) = fetch_fingerprint(scheduler, &control_url).await else {
                save_attempt(
                    conn,
                    scan_id,
                    opportunity,
                    2,
                    "control",
                    &control_url,
                    None,
                    Comparison::Inconclusive,
                    Some(
                        "control failed, deadline expired, redirect left scope, or shared budget exhausted",
                    ),
                )?;
                suppress(conn, &opportunity.id, "benign control was inconclusive")?;
                continue;
            };
            let comparison = compare(&repeat, &control, true);
            save_attempt(
                conn,
                scan_id,
                opportunity,
                2,
                "control",
                &control_url,
                Some(&control),
                comparison,
                None,
            )?;
            if comparison == Comparison::MeaningfullyDifferent {
                opportunity.evidence_state = EvidenceState::ControlVerified;
                update_state(conn, opportunity)?;
            } else {
                suppress(
                    conn,
                    &opportunity.id,
                    if comparison == Comparison::Stable {
                        "benign control was indistinguishable from baseline"
                    } else {
                        "benign control comparison was incomplete"
                    },
                )?;
            }
        }
    }
    print_review(conn, scan_id)?;
    Ok(opportunities)
}

pub fn generate(
    conn: &Connection,
    scan_id: Uuid,
) -> rusqlite::Result<Vec<InvestigationOpportunity>> {
    let scan = scan_id.to_string();
    let mut endpoint_stmt = conn.prepare(
        "SELECT e.id,e.canonical_url FROM endpoints e JOIN endpoint_observations o ON o.endpoint_id=e.id WHERE o.scan_id=?1 GROUP BY e.id,e.canonical_url ORDER BY e.canonical_url,e.id",
    )?;
    let endpoints = endpoint_stmt
        .query_map(params![scan], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for (endpoint_id, canonical_url) in endpoints {
        let classes = strings(
            conn,
            "SELECT class FROM endpoint_classifications WHERE scan_id=?1 AND endpoint_id=?2 ORDER BY class",
            &scan,
            &endpoint_id,
        )?;
        let parameters: Vec<(String, String)> = conn.prepare("SELECT parameter_name,semantic FROM parameter_semantics WHERE scan_id=?1 AND endpoint_id=?2 ORDER BY parameter_name,semantic")?
            .query_map(params![scan, endpoint_id], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
        let sources = strings(
            conn,
            "SELECT DISTINCT source FROM endpoint_observations WHERE scan_id=?1 AND endpoint_id=?2 ORDER BY source",
            &scan,
            &endpoint_id,
        )?;
        let functional_api_evidence = classes
            .iter()
            .any(|class| matches!(class.as_str(), "Api" | "GraphQL" | "Webhook" | "Upload"));
        if crate::scan::classify::is_content_route(&canonical_url) && !functional_api_evidence {
            continue;
        }
        let live: Option<(String, String, ResponseFingerprint)> = conn.query_row(
            "SELECT h.url,h.id,f.status,f.body_length,f.captured_length,f.body_complete,f.raw_hash,f.normalized_hash,f.content_type,f.header_hash,f.redirect_target,f.json_shape_hash,f.timing_bucket FROM http_observations h JOIN response_fingerprints f ON f.http_observation_id=h.id WHERE h.scan_id=?1 AND f.endpoint_id=?2 AND f.body_complete=1 AND EXISTS (SELECT 1 FROM endpoint_observations o WHERE o.scan_id=h.scan_id AND o.endpoint_id=f.endpoint_id AND o.source IN ('http_probe','triage_fetch','verification')) ORDER BY h.observed_at,h.id LIMIT 1",
            params![scan, endpoint_id], |row| Ok((row.get(0)?, row.get(1)?, fingerprint_row(row, 2)?))).optional()?;
        let mut categories: BTreeMap<OpportunityCategory, Vec<String>> = BTreeMap::new();
        for class in &classes {
            let category = match class.as_str() {
                "Authentication" => Some(OpportunityCategory::AuthenticationSurface),
                "Admin" => Some(OpportunityCategory::AdministrativeSurface),
                "Internal" | "Debug" => Some(OpportunityCategory::DebugOrInternalSurface),
                "Webhook" => Some(OpportunityCategory::WebhookSurface),
                "GraphQL" => Some(OpportunityCategory::GraphQLSurface),
                "Upload" => Some(OpportunityCategory::UploadSurface),
                "Download" => Some(OpportunityCategory::DownloadSurface),
                "Search" => Some(OpportunityCategory::SearchSurface),
                "Redirect" => Some(OpportunityCategory::RedirectBehavior),
                _ => None,
            };
            if let Some(category) = category {
                categories
                    .entry(category)
                    .or_default()
                    .push(format!("endpoint class `{class}`"));
            }
        }
        for (name, semantic) in &parameters {
            let category = match semantic.as_str() {
                "Redirect" => OpportunityCategory::RedirectBehavior,
                "Url" => OpportunityCategory::UrlHandling,
                "ObjectId" | "UserId" | "AccountId" => OpportunityCategory::IdentifierHandling,
                "File" | "Path" => OpportunityCategory::FileOrPathHandling,
                "Webhook" => OpportunityCategory::WebhookSurface,
                "Search" | "Query" => OpportunityCategory::SearchSurface,
                _ => continue,
            };
            categories
                .entry(category)
                .or_default()
                .push(format!("parameter `{name}` classified {semantic}"));
        }
        for (category, reasons) in categories {
            let evidence_state = if live.is_some() {
                EvidenceState::Observed
            } else {
                EvidenceState::Unverified
            };
            let priority = priority(category, sources.len(), live.is_some());
            let id = stable_id(&format!("{scan}:{endpoint_id}:{}", category.as_str()));
            let control_parameter = parameters
                .iter()
                .find(|(_, semantic)| matches!(semantic.as_str(), "Redirect" | "Search" | "Query"))
                .cloned();
            result.push(InvestigationOpportunity {
                id,
                endpoint_id: endpoint_id.clone(),
                canonical_url: canonical_url.clone(),
                category,
                reason: reasons.join("; "),
                supporting_evidence: sources
                    .iter()
                    .map(|source| format!("provenance:{source}"))
                    .collect(),
                priority,
                evidence_state,
                live_url: live.as_ref().map(|v| v.0.clone()),
                baseline_observation_id: live.as_ref().map(|v| v.1.clone()),
                baseline: live.as_ref().map(|v| v.2.clone()),
                control_parameter,
            });
        }
    }
    result.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| b.evidence_state.cmp(&a.evidence_state))
            .then_with(|| a.canonical_url.cmp(&b.canonical_url))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(result)
}

fn priority(category: OpportunityCategory, source_count: usize, live: bool) -> u8 {
    let base = match category {
        OpportunityCategory::AdministrativeSurface
        | OpportunityCategory::AuthenticationSurface
        | OpportunityCategory::DebugOrInternalSurface => 6,
        OpportunityCategory::RedirectBehavior
        | OpportunityCategory::UrlHandling
        | OpportunityCategory::IdentifierHandling
        | OpportunityCategory::FileOrPathHandling
        | OpportunityCategory::WebhookSurface => 5,
        _ => 3,
    };
    base + u8::from(live) * 2 + source_count.min(3) as u8
}

fn eligible(opportunity: &InvestigationOpportunity, scope: &ScopePolicy) -> bool {
    let Some(url) = opportunity
        .live_url
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
    else {
        return false;
    };
    opportunity
        .baseline
        .as_ref()
        .is_some_and(|fingerprint| fingerprint.body_complete)
        && crate::triage::is_safe_url(&url, scope)
        && matches!(url.scheme(), "http" | "https")
}

fn benign_control(url: &Url, parameter: &str, semantic: &str) -> Option<Url> {
    let replacement = match semantic {
        "Redirect" => "/",
        "Search" | "Query" => "__recon_control",
        _ => return None,
    };
    let mut control = url.clone();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            let is_controlled = k == parameter;
            (
                k.into_owned(),
                if is_controlled {
                    replacement.into()
                } else {
                    v.into_owned()
                },
            )
        })
        .collect();
    if !pairs.iter().any(|(name, _)| name == parameter) {
        return None;
    }
    control.query_pairs_mut().clear().extend_pairs(pairs);
    Some(control)
}

async fn fetch_fingerprint(scheduler: &RequestScheduler, url: &Url) -> Option<ResponseFingerprint> {
    crate::probes::scanner::probe_single_url(scheduler, url.as_str())
        .await?
        .fingerprint
}

fn compare(a: &ResponseFingerprint, b: &ResponseFingerprint, control: bool) -> Comparison {
    if !a.body_complete || !b.body_complete {
        return Comparison::Inconclusive;
    }
    let meaningful = a.status != b.status
        || a.normalized_hash != b.normalized_hash
        || a.json_shape_hash != b.json_shape_hash
        || a.redirect_target != b.redirect_target;
    if meaningful {
        Comparison::MeaningfullyDifferent
    } else if control || a.header_hash == b.header_hash {
        Comparison::Stable
    } else {
        Comparison::MeaningfullyDifferent
    }
}

fn persist_opportunities(
    conn: &Connection,
    scan_id: Uuid,
    opportunities: &[InvestigationOpportunity],
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM verification_attempts WHERE scan_id=?1",
        params![scan_id.to_string()],
    )?;
    conn.execute(
        "DELETE FROM investigation_opportunities WHERE scan_id=?1",
        params![scan_id.to_string()],
    )?;
    for item in opportunities {
        conn.execute("INSERT INTO investigation_opportunities (id,scan_id,endpoint_id,canonical_url,category,reason,supporting_evidence,priority,evidence_state,suppression_reason) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL)", params![item.id, scan_id.to_string(), item.endpoint_id, item.canonical_url, item.category.as_str(), item.reason, serde_json::to_string(&item.supporting_evidence).unwrap_or_default(), item.priority, item.evidence_state.as_str()])?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn save_attempt(
    conn: &Connection,
    scan_id: Uuid,
    item: &InvestigationOpportunity,
    sequence: usize,
    request_type: &str,
    url: &Url,
    fingerprint: Option<&ResponseFingerprint>,
    comparison: Comparison,
    failure: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute("INSERT OR REPLACE INTO verification_attempts (id,scan_id,opportunity_id,sequence,request_type,request_url,baseline_observation_id,fingerprint,comparison,failure_reason,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![stable_id(&format!("{}:{sequence}", item.id)), scan_id.to_string(), item.id, sequence as i64, request_type, sanitized_url(url), item.baseline_observation_id, fingerprint.and_then(sanitized_fingerprint), comparison.as_str(), failure, chrono::Utc::now().to_rfc3339()])?;
    Ok(())
}

fn sanitized_url(url: &Url) -> String {
    let mut safe = url.clone();
    if safe.query().is_some() {
        let names: BTreeSet<String> = safe
            .query_pairs()
            .map(|(name, _)| name.into_owned())
            .collect();
        safe.set_query(None);
        if !names.is_empty() {
            safe.set_query(Some(
                &names
                    .into_iter()
                    .map(|name| format!("{name}=<redacted>"))
                    .collect::<Vec<_>>()
                    .join("&"),
            ));
        }
    }
    safe.to_string()
}

fn sanitized_fingerprint(fingerprint: &ResponseFingerprint) -> Option<String> {
    let mut sanitized = fingerprint.clone();
    // Location can contain signed URLs, state values, or session material. The
    // hashes/comparison retain the useful relationship without persisting it.
    if sanitized.redirect_target.is_some() {
        sanitized.redirect_target = Some("<redacted>".into());
    }
    serde_json::to_string(&sanitized).ok()
}

fn update_state(conn: &Connection, item: &InvestigationOpportunity) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE investigation_opportunities SET evidence_state=?2 WHERE id=?1",
        params![item.id, item.evidence_state.as_str()],
    )?;
    Ok(())
}

fn suppress(conn: &Connection, id: &str, reason: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE investigation_opportunities SET suppression_reason=?2 WHERE id=?1",
        params![id, reason],
    )?;
    Ok(())
}

fn print_review(conn: &Connection, scan_id: Uuid) -> rusqlite::Result<()> {
    println!("\n🔬 Phase 3 controlled-verification review (manual validation required)");
    let mut statement = conn.prepare("SELECT priority,category,canonical_url,evidence_state,reason FROM investigation_opportunities WHERE scan_id=?1 AND suppression_reason IS NULL AND evidence_state IN ('Repeatable','ControlVerified') ORDER BY priority DESC,canonical_url,category,id")?;
    let rows = statement.query_map(params![scan_id.to_string()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut count = 0usize;
    for row in rows {
        let (priority, category, url, state, reason) = row?;
        count += 1;
        println!("  [{priority}] {category} — {url} — {state}");
        println!("      Evidence: {reason}");
        println!(
            "      Interpretation: behavior is an investigation candidate; no vulnerability is claimed."
        );
    }
    if count == 0 {
        println!("  No Phase 3 candidates survived repeat/control suppression.");
    }
    let suppressed = conn.query_row("SELECT count(*) FROM investigation_opportunities WHERE scan_id=?1 AND suppression_reason IS NOT NULL", params![scan_id.to_string()], |row| row.get::<_, i64>(0))?;
    println!("  {suppressed} opportunity/opportunities retained with a suppression reason.");
    Ok(())
}

fn strings(
    conn: &Connection,
    sql: &str,
    scan: &str,
    endpoint: &str,
) -> rusqlite::Result<Vec<String>> {
    conn.prepare(sql)?
        .query_map(params![scan, endpoint], |row| row.get(0))?
        .collect()
}

fn stable_id(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn fingerprint_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<ResponseFingerprint> {
    let timing: String = row.get(offset + 10)?;
    Ok(ResponseFingerprint {
        status: row.get(offset)?,
        body_length: row.get::<_, i64>(offset + 1)? as usize,
        captured_length: row.get::<_, i64>(offset + 2)? as usize,
        body_complete: row.get(offset + 3)?,
        raw_hash: row.get(offset + 4)?,
        normalized_hash: row.get(offset + 5)?,
        content_type: row.get(offset + 6)?,
        header_hash: row.get(offset + 7)?,
        redirect_target: row.get(offset + 8)?,
        json_shape_hash: row.get(offset + 9)?,
        timing_bucket: serde_json::from_str(&timing)
            .unwrap_or(crate::scan::fingerprint::TimingBucket::Unknown),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db;
    use crate::storage::models::ScanRun;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn seed(conn: &Connection, scan: &ScanRun, url: &str, fingerprint: &ResponseFingerprint) {
        db::save_scan_run(conn, scan).unwrap();
        let endpoint = crate::scan::normalize::normalize_endpoint(url, None).unwrap();
        db::save_endpoint_observation(conn, &scan.id, url, "http_probe", None).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO hostnames VALUES (?1,?1,'Seed',NULL)",
            params![endpoint.host],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO http_observations VALUES ('base',?1,?2,?3,200,NULL,NULL,1,2,'now')",
            params![scan.id.to_string(), endpoint.host, url],
        )
        .unwrap();
        conn.execute("INSERT INTO response_fingerprints VALUES ('base',?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", params![scan.id.to_string(), crate::scan::normalize::endpoint_id(&endpoint), fingerprint.status, fingerprint.body_length as i64, fingerprint.captured_length as i64, fingerprint.body_complete, fingerprint.raw_hash, fingerprint.normalized_hash, fingerprint.content_type, fingerprint.header_hash, fingerprint.redirect_target, fingerprint.json_shape_hash, serde_json::to_string(&fingerprint.timing_bucket).unwrap()]).unwrap();
        db::classify_scan_inventory(conn, &scan.id).unwrap();
    }

    #[test]
    fn generation_is_deterministic_prioritized_and_scan_scoped() {
        let conn = db::init_db(":memory:").unwrap();
        let a = ScanRun::new(vec!["example.com".into()], "a".into());
        db::save_scan_run(&conn, &a).unwrap();
        db::save_endpoint_observation(
            &conn,
            &a.id,
            "https://example.com/admin/api/users?id=1&next=/",
            "historical",
            Some("wayback"),
        )
        .unwrap();
        db::save_endpoint_observation(
            &conn,
            &a.id,
            "https://example.com/admin/api/users?id=2&next=/",
            "javascript",
            Some("app.js"),
        )
        .unwrap();
        db::classify_scan_inventory(&conn, &a.id).unwrap();
        let first = generate(&conn, a.id).unwrap();
        let second = generate(&conn, a.id).unwrap();
        assert_eq!(
            first
                .iter()
                .map(|o| (&o.id, o.priority))
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|o| (&o.id, o.priority))
                .collect::<Vec<_>>()
        );
        assert!(
            first
                .iter()
                .any(|o| o.category == OpportunityCategory::AdministrativeSurface)
        );
        assert!(
            first
                .iter()
                .any(|o| o.category == OpportunityCategory::IdentifierHandling)
        );
        assert!(
            first
                .iter()
                .any(|o| o.category == OpportunityCategory::RedirectBehavior)
        );
        assert!(
            first.iter().all(|o| o.supporting_evidence.len() == 2
                && o.evidence_state == EvidenceState::Unverified)
        );
        assert!(generate(&conn, Uuid::new_v4()).unwrap().is_empty());
    }

    #[test]
    fn content_routes_do_not_become_security_opportunities_from_titles_or_ids() {
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["example.com".into()], "content".into());
        db::save_scan_run(&conn, &scan).unwrap();
        for url in [
            "https://example.com/hc/en-us/articles/123-how-to-use-mfa-sso-login",
            "https://example.com/hc/en-us/categories/43062167779859",
            "https://example.com/help/articles/456-zip-download",
        ] {
            db::save_endpoint_observation(&conn, &scan.id, url, "triage_link", None).unwrap();
        }
        let content_endpoint = crate::scan::normalize::endpoint_id(
            &crate::scan::normalize::normalize_endpoint(
                "https://example.com/hc/en-us/categories/43062167779859",
                None,
            )
            .unwrap(),
        );
        // Simulate a row left by the broader pre-hardening classifier. A
        // rebuild must remove derived path evidence, not accumulate it.
        conn.execute(
            "INSERT INTO endpoint_request_shapes VALUES (?1,?2,'GET','path_classifier','path','path_id')",
            params![scan.id.to_string(), content_endpoint],
        )
        .unwrap();
        db::classify_scan_inventory(&conn, &scan.id).unwrap();
        assert!(generate(&conn, scan.id).unwrap().is_empty());
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM parameter_semantics WHERE scan_id=?1 AND semantic='ObjectId'",
                params![scan.id.to_string()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn full_workflow_is_bounded_persisted_and_uses_safe_controls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                server_hits.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut request = [0_u8; 2048];
                    let length = socket.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..length]);
                    let body = if request.contains("q=__recon_control") {
                        "control"
                    } else {
                        "ok"
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        let url = format!("http://{address}/api/search?q=hello");
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let baseline = crate::scan::fingerprint::fingerprint(
            200,
            b"ok",
            2,
            true,
            Some("text/plain"),
            &headers,
            Some(1),
        );
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "phase3".into());
        seed(&conn, &scan, &url, &baseline);
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler = RequestScheduler::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            scope.clone(),
            1,
            2,
            0,
            0,
            None,
        );
        let opportunities = run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            VerificationConfig {
                max_opportunities: 1,
                max_requests_per_opportunity: 2,
            },
        )
        .await
        .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(
            opportunities
                .iter()
                .any(|o| o.evidence_state == EvidenceState::ControlVerified)
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM verification_attempts", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            2
        );
        let stored: String = conn
            .query_row(
                "SELECT request_url FROM verification_attempts WHERE request_type='control'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored.contains("q=%3Credacted%3E") && !stored.contains("hello"));
        assert!(scheduler.get(&Url::parse(&url).unwrap()).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn unstable_repeat_is_suppressed_without_evidence_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            server_hits.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nchanged").await.unwrap();
        });
        let url = format!("http://{address}/admin");
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let baseline = crate::scan::fingerprint::fingerprint(
            200,
            b"stable",
            6,
            true,
            Some("text/plain"),
            &headers,
            None,
        );
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "unstable".into());
        seed(&conn, &scan, &url, &baseline);
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler = RequestScheduler::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            scope.clone(),
            1,
            1,
            0,
            0,
            None,
        );
        let opportunities = run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            VerificationConfig {
                max_opportunities: 1,
                max_requests_per_opportunity: 2,
            },
        )
        .await
        .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(
            opportunities
                .iter()
                .all(|item| item.evidence_state == EvidenceState::Observed)
        );
        let reason: String = conn.query_row("SELECT suppression_reason FROM investigation_opportunities WHERE category='AdministrativeSurface'", [], |row| row.get(0)).unwrap();
        assert_eq!(reason, "repeat response was unstable");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn indistinguishable_control_stays_repeatable_and_is_explained() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let _ = socket.read(&mut request).await;
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            }
        });
        let url = format!("http://{address}/api/search?q=hello");
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let baseline = crate::scan::fingerprint::fingerprint(
            200,
            b"ok",
            2,
            true,
            Some("text/plain"),
            &headers,
            None,
        );
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "same-control".into());
        seed(&conn, &scan, &url, &baseline);
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler = RequestScheduler::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            scope.clone(),
            1,
            2,
            0,
            0,
            None,
        );
        let opportunities = run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            VerificationConfig {
                max_opportunities: 1,
                max_requests_per_opportunity: 2,
            },
        )
        .await
        .unwrap();
        assert!(
            opportunities
                .iter()
                .any(|item| item.evidence_state == EvidenceState::Repeatable)
        );
        assert_eq!(conn.query_row("SELECT suppression_reason FROM investigation_opportunities WHERE category='SearchSurface'", [], |row| row.get::<_, String>(0)).unwrap(), "benign control was indistinguishable from baseline");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn deadline_and_global_cap_prevent_unscheduled_requests() {
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "deadline".into());
        let headers = reqwest::header::HeaderMap::new();
        let baseline =
            crate::scan::fingerprint::fingerprint(200, b"ok", 2, true, None, &headers, None);
        seed(&conn, &scan, "http://127.0.0.1:9/admin/internal", &baseline);
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler = RequestScheduler::new(
            reqwest::Client::new(),
            scope.clone(),
            1,
            5,
            0,
            0,
            Some(std::time::Instant::now()),
        );
        run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            VerificationConfig {
                max_opportunities: 1,
                max_requests_per_opportunity: 2,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM verification_attempts WHERE failure_reason IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(conn.query_row("SELECT count(*) FROM investigation_opportunities WHERE suppression_reason='global verification opportunity cap reached'", [], |row| row.get::<_, i64>(0)).unwrap() >= 1);
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM investigation_opportunities WHERE evidence_state!='Observed'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn out_of_scope_redirect_is_not_followed_or_upgraded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let url = format!("http://{address}/redirect?next=/");
        let headers = reqwest::header::HeaderMap::new();
        let baseline =
            crate::scan::fingerprint::fingerprint(200, b"", 0, true, None, &headers, None);
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "redirect".into());
        seed(&conn, &scan, &url, &baseline);
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler = RequestScheduler::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            scope.clone(),
            1,
            2,
            0,
            0,
            None,
        );
        let opportunities = run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            VerificationConfig {
                max_opportunities: 1,
                max_requests_per_opportunity: 2,
            },
        )
        .await
        .unwrap();
        assert!(
            opportunities
                .iter()
                .all(|item| item.evidence_state == EvidenceState::Observed)
        );
        assert_eq!(
            conn.query_row("SELECT comparison FROM verification_attempts", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "inconclusive"
        );
        server.await.unwrap();
    }

    #[test]
    fn comparison_handles_stability_difference_and_truncation() {
        let headers = reqwest::header::HeaderMap::new();
        let a = crate::scan::fingerprint::fingerprint(
            200,
            b"a",
            1,
            true,
            Some("text/plain"),
            &headers,
            None,
        );
        let b = crate::scan::fingerprint::fingerprint(
            200,
            b"b",
            1,
            true,
            Some("text/plain"),
            &headers,
            None,
        );
        let mut truncated = a.clone();
        truncated.body_complete = false;
        assert_eq!(compare(&a, &a, false), Comparison::Stable);
        assert_eq!(compare(&a, &b, true), Comparison::MeaningfullyDifferent);
        assert_eq!(compare(&a, &truncated, false), Comparison::Inconclusive);
        let mut secret_location = a.clone();
        secret_location.redirect_target = Some("/next?token=super-secret".into());
        let persisted = sanitized_fingerprint(&secret_location).unwrap();
        assert!(!persisted.contains("super-secret"));
        assert!(persisted.contains("<redacted>"));
    }
}
