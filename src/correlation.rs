//! Phase 4 correlation and deterministic ranking.
//!
//! This module is intentionally database-only. It receives no scheduler,
//! network client, discovery provider, or AI service and cannot issue requests.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ReviewConfig {
    pub max_candidates: usize,
    pub min_score: u16,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum EvidenceState {
    Unverified,
    Observed,
    Repeatable,
    ControlVerified,
}

impl EvidenceState {
    fn parse(value: &str) -> Self {
        match value {
            "ControlVerified" => Self::ControlVerified,
            "Repeatable" => Self::Repeatable,
            "Observed" => Self::Observed,
            _ => Self::Unverified,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "Unverified",
            Self::Observed => "Observed",
            Self::Repeatable => "Repeatable",
            Self::ControlVerified => "ControlVerified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ParameterEvidence {
    pub name: String,
    pub semantic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoreReason {
    pub code: String,
    pub points: u16,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistorySignal {
    pub code: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedCandidate {
    pub id: String,
    pub scan_id: Uuid,
    pub endpoint_id: String,
    pub canonical_url: String,
    pub categories: Vec<String>,
    pub endpoint_classes: Vec<String>,
    pub parameters: Vec<ParameterEvidence>,
    pub provenance: Vec<String>,
    pub evidence_state: EvidenceState,
    pub score: u16,
    pub score_reasons: Vec<ScoreReason>,
    pub historical_signals: Vec<HistorySignal>,
    pub suppression_reason: Option<String>,
    pub opportunity_ids: Vec<String>,
    pub rank: Option<usize>,
    pub manual_validation_required: bool,
    pub review_guidance: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RankedExport<'a> {
    scan_id: Uuid,
    candidates: Vec<&'a CorrelatedCandidate>,
}

#[derive(Default)]
struct EndpointEvidence {
    canonical_url: String,
    classes: BTreeSet<String>,
    parameters: BTreeSet<ParameterEvidence>,
    provenance: BTreeSet<String>,
    live: bool,
    complete_fingerprint: bool,
    independent_functional_evidence: bool,
    fingerprint: Option<FingerprintSummary>,
    opportunities: Vec<OpportunityEvidence>,
}

#[derive(Clone, PartialEq, Eq)]
struct FingerprintSummary {
    status: u16,
    normalized_hash: String,
    json_shape_hash: Option<String>,
    header_hash: String,
    redirect_target: Option<String>,
    complete: bool,
}

struct OpportunityEvidence {
    id: String,
    category: String,
    state: EvidenceState,
    suppression: Option<String>,
}

#[derive(Default)]
struct PreviousEvidence {
    endpoints: BTreeSet<String>,
    classes: BTreeMap<String, BTreeSet<String>>,
    parameters: BTreeMap<String, BTreeSet<ParameterEvidence>>,
    provenance: BTreeMap<String, BTreeSet<String>>,
    fingerprints: BTreeMap<String, FingerprintSummary>,
    states: BTreeMap<String, EvidenceState>,
}

pub fn run(
    conn: &Connection,
    scan_id: Uuid,
    config: ReviewConfig,
) -> Result<Vec<CorrelatedCandidate>, Box<dyn std::error::Error>> {
    let mut candidates = correlate(conn, scan_id)?;
    assign_ranks(&mut candidates, config.min_score, config.max_candidates);
    persist(conn, scan_id, &candidates)?;
    report(&candidates);
    export(&config.output_dir, scan_id, &candidates)?;
    Ok(candidates)
}

pub fn correlate(conn: &Connection, scan_id: Uuid) -> rusqlite::Result<Vec<CorrelatedCandidate>> {
    let scan = scan_id.to_string();
    let mut evidence = load_current(conn, &scan)?;
    let previous = previous_scan(conn, &scan)?
        .map(|previous| load_previous(conn, &previous))
        .transpose()?;
    let mut candidates = Vec::new();

    for (endpoint_id, item) in &mut evidence {
        let mut categories: BTreeSet<String> = item
            .opportunities
            .iter()
            .map(|opportunity| opportunity.category.clone())
            .collect();
        categories.extend(derived_categories(&item.classes, &item.parameters));
        let strongest = item
            .opportunities
            .iter()
            .map(|opportunity| opportunity.state)
            .max()
            .unwrap_or(if item.live {
                EvidenceState::Observed
            } else {
                EvidenceState::Unverified
            });

        let mut reasons = BTreeMap::<String, ScoreReason>::new();
        let has_security_signal = !categories.is_empty();
        add_reason(
            &mut reasons,
            format!("evidence_state:{}", strongest.as_str()),
            evidence_points(strongest, has_security_signal),
            format!("strongest evidence state is {}", strongest.as_str()),
        );
        if item.live {
            add_reason(&mut reasons, "live_endpoint", 10, "confirmed-live endpoint");
        }
        if item.complete_fingerprint {
            add_reason(
                &mut reasons,
                "complete_fingerprint",
                5,
                "complete response fingerprint",
            );
        }
        score_provenance(&mut reasons, &item.provenance);
        score_parameters(&mut reasons, &item.parameters);
        score_classes(&mut reasons, &item.classes);

        let mut historical_signals = Vec::new();
        if let Some(previous) = &previous {
            correlate_history(
                endpoint_id,
                item,
                strongest,
                previous,
                &mut reasons,
                &mut historical_signals,
            );
        }

        let opportunity_ids: Vec<String> = item
            .opportunities
            .iter()
            .map(|opportunity| opportunity.id.clone())
            .collect();
        let suppression_reason = suppression(item, strongest, &categories);
        let score = reasons
            .values()
            .map(|reason| reason.points)
            .sum::<u16>()
            .min(100);
        let id = stable_id(&format!("{scan}:{endpoint_id}"));
        let category_list: Vec<String> = categories.into_iter().collect();
        candidates.push(CorrelatedCandidate {
            id,
            scan_id,
            endpoint_id: endpoint_id.clone(),
            canonical_url: item.canonical_url.clone(),
            categories: category_list.clone(),
            endpoint_classes: item.classes.iter().cloned().collect(),
            parameters: item.parameters.iter().cloned().collect(),
            provenance: item.provenance.iter().cloned().collect(),
            evidence_state: strongest,
            score,
            score_reasons: reasons.into_values().collect(),
            historical_signals,
            suppression_reason,
            opportunity_ids,
            rank: None,
            manual_validation_required: true,
            review_guidance: guidance(&category_list),
        });
    }
    candidates.sort_by(candidate_order);
    Ok(candidates)
}

fn load_current(
    conn: &Connection,
    scan: &str,
) -> rusqlite::Result<BTreeMap<String, EndpointEvidence>> {
    let mut map = BTreeMap::new();
    let mut statement = conn.prepare("SELECT e.id,e.canonical_url FROM endpoints e JOIN endpoint_observations o ON o.endpoint_id=e.id WHERE o.scan_id=?1 GROUP BY e.id,e.canonical_url ORDER BY e.id")?;
    for row in statement.query_map(params![scan], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (id, url) = row?;
        map.insert(
            id,
            EndpointEvidence {
                canonical_url: url,
                ..Default::default()
            },
        );
    }
    load_sets(conn, scan, &mut map)?;
    Ok(map)
}

fn load_sets(
    conn: &Connection,
    scan: &str,
    map: &mut BTreeMap<String, EndpointEvidence>,
) -> rusqlite::Result<()> {
    let mut classes = conn.prepare("SELECT endpoint_id,class FROM endpoint_classifications WHERE scan_id=?1 ORDER BY endpoint_id,class")?;
    for row in classes.query_map(params![scan], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (endpoint, class) = row?;
        if let Some(item) = map.get_mut(&endpoint) {
            item.classes.insert(class);
        }
    }
    let mut parameters = conn.prepare("SELECT endpoint_id,parameter_name,semantic FROM parameter_semantics WHERE scan_id=?1 ORDER BY endpoint_id,parameter_name,semantic")?;
    for row in parameters.query_map(params![scan], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (endpoint, name, semantic) = row?;
        if let Some(item) = map.get_mut(&endpoint) {
            item.parameters.insert(ParameterEvidence { name, semantic });
        }
    }
    let mut provenance = conn.prepare("SELECT DISTINCT endpoint_id,source FROM endpoint_observations WHERE scan_id=?1 ORDER BY endpoint_id,source")?;
    for row in provenance.query_map(params![scan], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (endpoint, source) = row?;
        if let Some(item) = map.get_mut(&endpoint) {
            item.live |= crate::storage::db::provenance_is_live(&source);
            item.provenance.insert(source);
        }
    }
    let mut fingerprints = conn.prepare("SELECT endpoint_id,status,normalized_hash,json_shape_hash,header_hash,redirect_target,body_complete FROM response_fingerprints WHERE scan_id=?1 ORDER BY endpoint_id,http_observation_id")?;
    for row in fingerprints.query_map(params![scan], fingerprint_row)? {
        let (endpoint, fingerprint) = row?;
        if let Some(item) = map.get_mut(&endpoint) {
            item.complete_fingerprint |= fingerprint.complete;
            if item.fingerprint.is_none() || fingerprint.complete {
                item.fingerprint = Some(fingerprint);
            }
        }
    }
    let mut functional = conn.prepare(
        "SELECT endpoint_id FROM endpoint_request_shapes WHERE scan_id=?1 AND upper(method) NOT IN ('GET','HEAD','OPTIONS') UNION SELECT f.endpoint_id FROM response_fingerprints f WHERE f.scan_id=?1 AND f.body_complete=1 AND (f.json_shape_hash IS NOT NULL OR lower(COALESCE(f.content_type,'')) LIKE '%json%') AND EXISTS (SELECT 1 FROM endpoint_observations o WHERE o.scan_id=f.scan_id AND o.endpoint_id=f.endpoint_id AND o.source IN ('http_probe','triage_fetch','verification')) ORDER BY endpoint_id",
    )?;
    for row in functional.query_map(params![scan], |row| row.get::<_, String>(0))? {
        if let Some(item) = map.get_mut(&row?) {
            item.independent_functional_evidence = true;
        }
    }
    let mut opportunities = conn.prepare("SELECT id,endpoint_id,category,evidence_state,suppression_reason FROM investigation_opportunities WHERE scan_id=?1 ORDER BY endpoint_id,category,id")?;
    for row in opportunities.query_map(params![scan], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            EvidenceState::parse(&row.get::<_, String>(3)?),
            row.get::<_, Option<String>>(4)?,
        ))
    })? {
        let (id, endpoint, category, state, suppression) = row?;
        if let Some(item) = map.get_mut(&endpoint) {
            item.opportunities.push(OpportunityEvidence {
                id,
                category,
                state,
                suppression,
            });
        }
    }
    Ok(())
}

fn previous_scan(conn: &Connection, current: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT prior.id FROM scan_runs current JOIN scan_runs prior ON prior.root_scope=current.root_scope AND prior.config_hash=current.config_hash WHERE current.id=?1 AND prior.id<>current.id AND prior.finished_at IS NOT NULL AND prior.started_at<current.started_at ORDER BY prior.finished_at DESC,prior.id DESC LIMIT 1",
        params![current],
        |row| row.get(0),
    ).optional()
}

fn load_previous(conn: &Connection, scan: &str) -> rusqlite::Result<PreviousEvidence> {
    let current = load_current(conn, scan)?;
    let mut result = PreviousEvidence::default();
    for (endpoint, item) in current {
        result.endpoints.insert(endpoint.clone());
        result.classes.insert(endpoint.clone(), item.classes);
        result.parameters.insert(endpoint.clone(), item.parameters);
        result.provenance.insert(endpoint.clone(), item.provenance);
        if let Some(fingerprint) = item.fingerprint {
            result.fingerprints.insert(endpoint.clone(), fingerprint);
        }
        let state = item
            .opportunities
            .iter()
            .map(|opportunity| opportunity.state)
            .max()
            .unwrap_or(if item.live {
                EvidenceState::Observed
            } else {
                EvidenceState::Unverified
            });
        result.states.insert(endpoint, state);
    }
    Ok(result)
}

fn derived_categories(
    classes: &BTreeSet<String>,
    parameters: &BTreeSet<ParameterEvidence>,
) -> BTreeSet<String> {
    let mut categories = BTreeSet::new();
    for class in classes {
        let category = match class.as_str() {
            "Authentication" => Some("AuthenticationSurface"),
            "Admin" => Some("AdministrativeSurface"),
            "Internal" | "Debug" => Some("DebugOrInternalSurface"),
            "Webhook" => Some("WebhookSurface"),
            "GraphQL" => Some("GraphQLSurface"),
            "Upload" => Some("UploadSurface"),
            "Download" | "Export" => Some("DownloadSurface"),
            "Search" => Some("SearchSurface"),
            "Redirect" => Some("RedirectBehavior"),
            _ => None,
        };
        if let Some(category) = category {
            categories.insert(category.into());
        }
    }
    for parameter in parameters {
        let category = match parameter.semantic.as_str() {
            "Redirect" => Some("RedirectBehavior"),
            "Url" => Some("UrlHandling"),
            "ObjectId" | "UserId" | "AccountId" => Some("IdentifierHandling"),
            "File" | "Path" => Some("FileOrPathHandling"),
            "Webhook" => Some("WebhookSurface"),
            "Search" | "Query" => Some("SearchSurface"),
            _ => None,
        };
        if let Some(category) = category {
            categories.insert(category.into());
        }
    }
    categories
}

fn score_provenance(reasons: &mut BTreeMap<String, ScoreReason>, sources: &BTreeSet<String>) {
    // Reward independent evidence families, not several observations produced
    // by the same crawl/live pipeline.
    let live = sources.iter().any(|source| {
        matches!(
            source.as_str(),
            "http_probe" | "triage_fetch" | "verification"
        )
    });
    if live {
        add_reason(reasons, "provenance:live", 5, "live HTTP evidence family");
    }
    let crawl = sources.iter().any(|source| {
        matches!(
            source.as_str(),
            "javascript" | "javascript_call" | "triage_link" | "triage_script"
        )
    });
    if sources.contains("source_map") {
        add_reason(
            reasons,
            "provenance:code",
            8,
            "source-map/code evidence family",
        );
    } else if crawl {
        add_reason(
            reasons,
            "provenance:code",
            6,
            "crawl-derived code evidence family",
        );
    }
    let awarded: u16 = reasons
        .values()
        .filter(|reason| reason.code.starts_with("provenance:"))
        .map(|reason| reason.points)
        .sum();
    if awarded < 15
        && sources
            .iter()
            .any(|source| is_historical_source(source.as_str()))
    {
        add_reason(
            reasons,
            "provenance:historical",
            3.min(15 - awarded),
            "historical evidence family",
        );
    }
}

fn is_historical_source(source: &str) -> bool {
    matches!(
        source.to_ascii_lowercase().as_str(),
        "historical" | "wayback" | "common_crawl" | "commoncrawl"
    )
}

fn score_parameters(
    reasons: &mut BTreeMap<String, ScoreReason>,
    parameters: &BTreeSet<ParameterEvidence>,
) {
    let semantics: BTreeSet<&str> = parameters
        .iter()
        .map(|parameter| parameter.semantic.as_str())
        .collect();
    let dimensions = [
        (
            "identifier",
            ["UserId", "AccountId", "ObjectId"].as_slice(),
            8,
            "identifier parameter semantic",
        ),
        (
            "url_redirect",
            ["Url", "Redirect"].as_slice(),
            8,
            "URL or redirect parameter semantic",
        ),
        (
            "file_path",
            ["File", "Path"].as_slice(),
            7,
            "file or path parameter semantic",
        ),
        (
            "webhook",
            ["Webhook"].as_slice(),
            6,
            "webhook parameter semantic",
        ),
        (
            "search",
            ["Search", "Query"].as_slice(),
            3,
            "search or query parameter semantic",
        ),
    ];
    let mut awarded = 0u16;
    for (code, aliases, points, explanation) in dimensions {
        if aliases.iter().any(|semantic| semantics.contains(semantic)) && awarded < 16 {
            let actual = points.min(16 - awarded);
            add_reason(reasons, format!("parameter:{code}"), actual, explanation);
            awarded += actual;
        }
    }
}

fn score_classes(reasons: &mut BTreeMap<String, ScoreReason>, classes: &BTreeSet<String>) {
    let mut awarded = 0u16;
    for (class, points) in [
        ("Admin", 4),
        ("Internal", 4),
        ("Debug", 4),
        ("Authentication", 3),
        ("Account", 3),
        ("Payment", 3),
        ("Upload", 3),
        ("Download", 3),
        ("Export", 3),
        ("Webhook", 3),
        ("GraphQL", 3),
    ] {
        if classes.contains(class) && awarded < 12 {
            let actual = points.min(12 - awarded);
            add_reason(
                reasons,
                format!("endpoint_class:{}", class.to_ascii_lowercase()),
                actual,
                format!("{class} endpoint context"),
            );
            awarded += actual;
        }
    }
}

fn correlate_history(
    endpoint: &str,
    current: &EndpointEvidence,
    current_state: EvidenceState,
    previous: &PreviousEvidence,
    reasons: &mut BTreeMap<String, ScoreReason>,
    signals: &mut Vec<HistorySignal>,
) {
    if !previous.endpoints.contains(endpoint) {
        history(
            reasons,
            signals,
            "history:new_endpoint",
            6,
            "endpoint is new since the previous same-scope scan",
        );
        return;
    }
    let empty_parameters = BTreeSet::new();
    let previous_parameters = previous
        .parameters
        .get(endpoint)
        .unwrap_or(&empty_parameters);
    let previous_names: BTreeSet<&str> = previous_parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect();
    let current_names: BTreeSet<&str> = current
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect();
    let new_names: Vec<_> = current_names.difference(&previous_names).copied().collect();
    if !new_names.is_empty() {
        history(
            reasons,
            signals,
            "history:new_parameters",
            (new_names.len() as u16 * 4).min(8),
            format!("new parameter name: {}", new_names.join(", ")),
        );
    }
    let previous_semantics: BTreeSet<&str> = previous_parameters
        .iter()
        .map(|parameter| parameter.semantic.as_str())
        .collect();
    let current_semantics: BTreeSet<&str> = current
        .parameters
        .iter()
        .map(|parameter| parameter.semantic.as_str())
        .collect();
    let new_semantics: Vec<_> = current_semantics
        .difference(&previous_semantics)
        .copied()
        .collect();
    if !new_semantics.is_empty() {
        history(
            reasons,
            signals,
            "history:new_semantics",
            (new_semantics.len() as u16 * 4).min(8),
            format!("new parameter semantic: {}", new_semantics.join(", ")),
        );
    }
    let empty_classes = BTreeSet::new();
    let previous_classes = previous.classes.get(endpoint).unwrap_or(&empty_classes);
    let new_classes: Vec<_> = current.classes.difference(previous_classes).collect();
    if !new_classes.is_empty() {
        history(
            reasons,
            signals,
            "history:new_classes",
            (new_classes.len() as u16 * 3).min(6),
            format!(
                "new endpoint class: {}",
                new_classes
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    let empty_provenance = BTreeSet::new();
    let previous_provenance = previous
        .provenance
        .get(endpoint)
        .unwrap_or(&empty_provenance);
    let new_provenance: Vec<_> = current.provenance.difference(previous_provenance).collect();
    if !new_provenance.is_empty() {
        history(
            reasons,
            signals,
            "history:new_provenance",
            (new_provenance.len() as u16 * 3).min(6),
            format!(
                "new provenance source: {}",
                new_provenance
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    let previous_state = previous
        .states
        .get(endpoint)
        .copied()
        .unwrap_or(EvidenceState::Unverified);
    if let (Some(old), Some(new)) = (previous.fingerprints.get(endpoint), &current.fingerprint)
        && old.complete
        && new.complete
        && previous_state >= EvidenceState::Repeatable
        && current_state >= EvidenceState::Repeatable
        && old != new
    {
        history(
            reasons,
            signals,
            "history:fingerprint_changed",
            6,
            "complete stable response fingerprint changed; timing was ignored",
        );
    }
    if current_state > previous_state {
        history(
            reasons,
            signals,
            "history:evidence_improved",
            5,
            "verification evidence state improved",
        );
    }
}

fn history(
    reasons: &mut BTreeMap<String, ScoreReason>,
    signals: &mut Vec<HistorySignal>,
    code: &str,
    points: u16,
    explanation: impl Into<String>,
) {
    let explanation = explanation.into();
    add_reason(reasons, code, points, explanation.clone());
    signals.push(HistorySignal {
        code: code.into(),
        explanation,
    });
}

fn suppression(
    item: &EndpointEvidence,
    state: EvidenceState,
    categories: &BTreeSet<String>,
) -> Option<String> {
    if crate::scan::classify::is_content_route(&item.canonical_url)
        && !item.independent_functional_evidence
    {
        return Some(
            "documentation/content route without independent functional API evidence".into(),
        );
    }
    if !item.live && state == EvidenceState::Unverified {
        return Some("passive-only endpoint without confirmed-live evidence".into());
    }
    if categories.is_empty() {
        return Some(
            "no useful classification, parameter semantic, or verification category".into(),
        );
    }
    if !item.opportunities.is_empty()
        && item
            .opportunities
            .iter()
            .all(|opportunity| opportunity.suppression.is_some())
    {
        let reasons: BTreeSet<String> = item
            .opportunities
            .iter()
            .filter_map(|opportunity| opportunity.suppression.clone())
            .collect();
        let severe = reasons.iter().any(|reason| {
            let reason = reason.to_ascii_lowercase();
            reason.contains("unstable")
                || reason.contains("incomplete")
                || reason.contains("indistinguishable")
        });
        let independent_dimensions = usize::from(item.live)
            + usize::from(item.provenance.contains("javascript"))
            + usize::from(item.provenance.contains("source_map"))
            + usize::from(
                item.provenance
                    .iter()
                    .any(|source| is_historical_source(source)),
            );
        if severe || independent_dimensions < 2 {
            return Some(format!(
                "Phase 3 suppressed all endpoint opportunities: {}",
                reasons.into_iter().collect::<Vec<_>>().join("; ")
            ));
        }
    }
    if item.live && !item.complete_fingerprint && state <= EvidenceState::Observed {
        return Some("live response evidence is incomplete".into());
    }
    None
}

fn add_reason(
    reasons: &mut BTreeMap<String, ScoreReason>,
    code: impl Into<String>,
    points: u16,
    explanation: impl Into<String>,
) {
    if points == 0 {
        return;
    }
    let code = code.into();
    reasons.entry(code.clone()).or_insert(ScoreReason {
        code,
        points,
        explanation: explanation.into(),
    });
}

fn evidence_points(state: EvidenceState, has_security_signal: bool) -> u16 {
    if !has_security_signal {
        return 0;
    }
    match state {
        EvidenceState::ControlVerified => 30,
        EvidenceState::Repeatable => 20,
        EvidenceState::Observed => 8,
        EvidenceState::Unverified => 0,
    }
}

fn guidance(categories: &[String]) -> Vec<String> {
    let mut result = BTreeSet::new();
    for category in categories {
        let guidance = match category.as_str() {
            "IdentifierHandling" => {
                "Review authorization behavior manually with authorized test accounts."
            }
            "RedirectBehavior" => "Inspect destination validation manually within program rules.",
            "DebugOrInternalSurface" => "Review exposed functionality and data manually.",
            "AuthenticationSurface" => "Review authentication and session behavior manually.",
            "FileOrPathHandling" => "Review file and path handling manually within program rules.",
            _ => "Review the correlated behavior manually within program rules.",
        };
        result.insert(guidance.to_string());
    }
    result.into_iter().collect()
}

fn assign_ranks(candidates: &mut [CorrelatedCandidate], min_score: u16, max: usize) {
    candidates.sort_by(candidate_order);
    let mut rank = 0usize;
    for candidate in candidates {
        if candidate.suppression_reason.is_none() && candidate.score >= min_score && rank < max {
            rank += 1;
            candidate.rank = Some(rank);
        }
    }
}

fn candidate_order(a: &CorrelatedCandidate, b: &CorrelatedCandidate) -> std::cmp::Ordering {
    b.score
        .cmp(&a.score)
        .then_with(|| b.evidence_state.cmp(&a.evidence_state))
        .then_with(|| a.canonical_url.cmp(&b.canonical_url))
        .then_with(|| a.id.cmp(&b.id))
}

fn persist(
    conn: &Connection,
    scan_id: Uuid,
    candidates: &[CorrelatedCandidate],
) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    delete_derived(&tx, scan_id)?;
    for candidate in candidates {
        tx.execute("INSERT INTO correlated_candidates (id,scan_id,endpoint_id,canonical_url,evidence_state,score,categories,endpoint_classes,parameters,provenance,review_guidance,suppression_reason,ranked,rank) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)", params![candidate.id, scan_id.to_string(), candidate.endpoint_id, candidate.canonical_url, candidate.evidence_state.as_str(), candidate.score, json(&candidate.categories), json(&candidate.endpoint_classes), json(&candidate.parameters), json(&candidate.provenance), json(&candidate.review_guidance), candidate.suppression_reason, candidate.rank.is_some(), candidate.rank.map(|rank| rank as i64)])?;
        for reason in &candidate.score_reasons {
            tx.execute(
                "INSERT INTO candidate_score_reasons VALUES (?1,?2,?3,?4)",
                params![candidate.id, reason.code, reason.points, reason.explanation],
            )?;
        }
        for signal in &candidate.historical_signals {
            tx.execute(
                "INSERT INTO candidate_history_signals VALUES (?1,?2,?3)",
                params![candidate.id, signal.code, signal.explanation],
            )?;
        }
        for opportunity in &candidate.opportunity_ids {
            tx.execute(
                "INSERT INTO candidate_opportunities VALUES (?1,?2)",
                params![candidate.id, opportunity],
            )?;
        }
    }
    tx.commit()
}

fn delete_derived(tx: &Transaction<'_>, scan_id: Uuid) -> rusqlite::Result<()> {
    let scan = scan_id.to_string();
    for table in [
        "candidate_opportunities",
        "candidate_history_signals",
        "candidate_score_reasons",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE candidate_id IN (SELECT id FROM correlated_candidates WHERE scan_id=?1)"), params![scan])?;
    }
    tx.execute(
        "DELETE FROM correlated_candidates WHERE scan_id=?1",
        params![scan],
    )?;
    Ok(())
}

fn report(candidates: &[CorrelatedCandidate]) {
    println!("\n==================================================");
    println!("TOP INVESTIGATION CANDIDATES");
    println!("==================================================");
    let ranked: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.rank.is_some())
        .collect();
    if ranked.is_empty() {
        println!("No candidates met the deterministic review threshold.");
    }
    for candidate in ranked {
        println!(
            "\n#{}\nEndpoint: {}\nInvestigation score: {} / 100\nEvidence state: {}",
            candidate.rank.unwrap_or_default(),
            candidate.canonical_url,
            candidate.score,
            candidate.evidence_state.as_str()
        );
        println!("Categories: {}", candidate.categories.join(", "));
        println!(
            "Endpoint context: {}",
            candidate.endpoint_classes.join(", ")
        );
        println!(
            "Parameters: {}",
            candidate
                .parameters
                .iter()
                .map(|parameter| format!("{} → {}", parameter.name, parameter.semantic))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("Evidence: {}", candidate.provenance.join(", "));
        println!("Why ranked:");
        for reason in &candidate.score_reasons {
            println!("  +{} {}", reason.points, reason.explanation);
        }
        for signal in &candidate.historical_signals {
            println!("Historical signal: {}", signal.explanation);
        }
        for guidance in &candidate.review_guidance {
            println!("Review guidance: {guidance}");
        }
        println!("Manual validation: REQUIRED");
        println!(
            "Scanner conclusion: Investigation candidate only. No vulnerability is confirmed."
        );
    }
}

fn export(
    output_dir: &Path,
    scan_id: Uuid,
    candidates: &[CorrelatedCandidate],
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(output_dir)?;
    let path = output_dir.join("investigation_candidates.json");
    let ranked = candidates
        .iter()
        .filter(|candidate| candidate.rank.is_some())
        .collect();
    let bytes = serde_json::to_vec_pretty(&RankedExport {
        scan_id,
        candidates: ranked,
    })?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn fingerprint_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, FingerprintSummary)> {
    Ok((
        row.get(0)?,
        FingerprintSummary {
            status: row.get(1)?,
            normalized_hash: row.get(2)?,
            json_shape_hash: row.get(3)?,
            header_hash: row.get(4)?,
            redirect_target: row.get(5)?,
            complete: row.get(6)?,
        },
    ))
}

fn stable_id(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db;
    use crate::storage::models::ScanRun;

    fn save_run(conn: &Connection, run: &mut ScanRun, finished: &str) {
        db::save_scan_run(conn, run).unwrap();
        conn.execute(
            "UPDATE scan_runs SET started_at=?2,finished_at=?2 WHERE id=?1",
            params![run.id.to_string(), finished],
        )
        .unwrap();
    }

    fn endpoint(conn: &Connection, run: &ScanRun, url: &str, sources: &[&str]) -> String {
        for source in sources {
            db::save_endpoint_observation(conn, &run.id, url, source, Some("fixture")).unwrap();
        }
        crate::scan::normalize::endpoint_id(
            &crate::scan::normalize::normalize_endpoint(url, None).unwrap(),
        )
    }

    fn opportunity(
        conn: &Connection,
        run: &ScanRun,
        endpoint: &str,
        url: &str,
        category: &str,
        state: &str,
        suppression: Option<&str>,
    ) -> String {
        let id = stable_id(&format!("{}:{endpoint}:{category}", run.id));
        conn.execute("INSERT INTO investigation_opportunities VALUES (?1,?2,?3,?4,?5,'fixture','[]',5,?6,?7)", params![id, run.id.to_string(), endpoint, crate::scan::normalize::normalize_endpoint(url, None).unwrap().canonical_url, category, state, suppression]).unwrap();
        id
    }

    fn fingerprint(
        conn: &Connection,
        run: &ScanRun,
        endpoint: &str,
        hash: &str,
        complete: bool,
        timing: &str,
    ) {
        let observation = stable_id(&format!("{}:{endpoint}:{hash}", run.id));
        conn.execute(
            "INSERT OR IGNORE INTO hostnames VALUES ('example.com','example.com','Seed',NULL)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO http_observations VALUES (?1,?2,'example.com','https://example.com/',200,NULL,NULL,1,2,'now')", params![observation, run.id.to_string()]).unwrap();
        conn.execute("INSERT INTO response_fingerprints VALUES (?1,?2,?3,200,2,2,?4,?5,?5,NULL,'headers',NULL,NULL,?6)", params![observation, run.id.to_string(), endpoint, complete, hash, timing]).unwrap();
    }

    #[test]
    fn scoring_states_caps_and_deduplicates_dimensions() {
        let mut reasons = BTreeMap::new();
        let sources = [
            "http_probe",
            "javascript",
            "source_map",
            "wayback",
            "common_crawl",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        score_provenance(&mut reasons, &sources);
        assert_eq!(
            reasons.values().map(|reason| reason.points).sum::<u16>(),
            15
        );
        let crawl_aliases = ["javascript", "triage_link", "triage_script"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut crawl_reasons = BTreeMap::new();
        score_provenance(&mut crawl_reasons, &crawl_aliases);
        assert_eq!(crawl_reasons.len(), 1);
        assert_eq!(crawl_reasons["provenance:code"].points, 6);
        let parameters = [
            ParameterEvidence {
                name: "user_id".into(),
                semantic: "UserId".into(),
            },
            ParameterEvidence {
                name: "uid".into(),
                semantic: "UserId".into(),
            },
        ]
        .into_iter()
        .collect();
        score_parameters(&mut reasons, &parameters);
        assert_eq!(reasons.get("parameter:identifier").unwrap().points, 8);
        let uncapped = 30 + 10 + 5 + 15 + 16 + 12 + 20;
        assert!(uncapped > 100);
        assert_eq!(uncapped.min(100), 100);
        assert!(
            evidence_points(EvidenceState::ControlVerified, true)
                > evidence_points(EvidenceState::Repeatable, true)
        );
        assert!(
            evidence_points(EvidenceState::Repeatable, true)
                > evidence_points(EvidenceState::Observed, true)
        );
        let mut class_reasons = BTreeMap::new();
        score_classes(
            &mut class_reasons,
            &["Admin".to_string()].into_iter().collect(),
        );
        assert!(
            evidence_points(EvidenceState::ControlVerified, true)
                - evidence_points(EvidenceState::Observed, true)
                > class_reasons.values().map(|reason| reason.points).sum()
        );
        assert_eq!(evidence_points(EvidenceState::Repeatable, false), 0);
    }

    #[test]
    fn endpoint_correlation_is_stable_and_suppresses_passive_only() {
        let conn = db::init_db(":memory:").unwrap();
        let mut run = ScanRun::new(vec!["example.com".into()], "current".into());
        save_run(&conn, &mut run, "2026-01-02T00:00:00Z");
        let url = "https://example.com/api/account/export?user_id=secret-value";
        let id = endpoint(
            &conn,
            &run,
            url,
            &["wayback", "javascript", "source_map", "http_probe"],
        );
        db::classify_scan_inventory(&conn, &run.id).unwrap();
        fingerprint(&conn, &run, &id, "same", true, "\"very_fast\"");
        let first = opportunity(
            &conn,
            &run,
            &id,
            url,
            "IdentifierHandling",
            "ControlVerified",
            None,
        );
        let second = opportunity(&conn, &run, &id, url, "DownloadSurface", "Repeatable", None);
        let passive = endpoint(
            &conn,
            &run,
            "https://example.com/old/passive/path",
            &["wayback"],
        );
        db::classify_scan_inventory(&conn, &run.id).unwrap();
        let a = correlate(&conn, run.id).unwrap();
        let b = correlate(&conn, run.id).unwrap();
        assert_eq!(
            a.iter()
                .map(|candidate| (&candidate.id, candidate.score))
                .collect::<Vec<_>>(),
            b.iter()
                .map(|candidate| (&candidate.id, candidate.score))
                .collect::<Vec<_>>()
        );
        let correlated = a
            .iter()
            .find(|candidate| candidate.endpoint_id == id)
            .unwrap();
        let mut expected_opportunities = vec![first, second];
        expected_opportunities.sort();
        let mut actual_opportunities = correlated.opportunity_ids.clone();
        actual_opportunities.sort();
        assert_eq!(actual_opportunities, expected_opportunities);
        assert!(
            correlated.categories.contains(&"IdentifierHandling".into())
                && correlated.categories.contains(&"DownloadSurface".into())
        );
        assert!(!correlated.canonical_url.contains("secret-value"));
        assert!(
            a.iter()
                .find(|candidate| candidate.endpoint_id == passive)
                .unwrap()
                .suppression_reason
                .is_some()
        );
    }

    #[test]
    fn history_uses_same_scope_ignores_timing_and_detects_safe_changes() {
        let conn = db::init_db(":memory:").unwrap();
        let mut old = ScanRun::new(vec!["example.com".into()], "same".into());
        save_run(&conn, &mut old, "2026-01-01T00:00:00Z");
        let old_id = endpoint(
            &conn,
            &old,
            "https://example.com/api/users?id=1",
            &["http_probe"],
        );
        db::classify_scan_inventory(&conn, &old.id).unwrap();
        fingerprint(&conn, &old, &old_id, "same", true, "\"slow\"");
        opportunity(
            &conn,
            &old,
            &old_id,
            "https://example.com/api/users?id=1",
            "IdentifierHandling",
            "Observed",
            None,
        );
        let mut unrelated = ScanRun::new(vec!["other.com".into()], "other".into());
        save_run(&conn, &mut unrelated, "2026-01-02T00:00:00Z");
        let mut current = ScanRun::new(vec!["example.com".into()], "same".into());
        save_run(&conn, &mut current, "2026-01-03T00:00:00Z");
        let current_id = endpoint(
            &conn,
            &current,
            "https://example.com/api/users?id=2&cursor=x",
            &["http_probe", "javascript"],
        );
        db::classify_scan_inventory(&conn, &current.id).unwrap();
        fingerprint(&conn, &current, &current_id, "same", true, "\"very_fast\"");
        opportunity(
            &conn,
            &current,
            &current_id,
            "https://example.com/api/users?id=2&cursor=x",
            "IdentifierHandling",
            "Repeatable",
            None,
        );
        let candidate = correlate(&conn, current.id)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.endpoint_id == current_id)
            .unwrap();
        let codes: BTreeSet<_> = candidate
            .historical_signals
            .iter()
            .map(|signal| signal.code.as_str())
            .collect();
        assert!(
            codes.contains("history:new_parameters")
                && codes.contains("history:new_semantics")
                && codes.contains("history:new_provenance")
                && codes.contains("history:evidence_improved")
        );
        assert!(!codes.contains("history:fingerprint_changed"));
    }

    #[test]
    fn history_rejects_materially_different_collection_configuration() {
        let conn = db::init_db(":memory:").unwrap();
        let mut prior = ScanRun::new(vec!["example.com".into()], "triage-disabled".into());
        save_run(&conn, &mut prior, "2026-01-01T00:00:00Z");
        let mut current = ScanRun::new(vec!["example.com".into()], "triage-enabled".into());
        save_run(&conn, &mut current, "2026-01-02T00:00:00Z");
        assert_eq!(previous_scan(&conn, &current.id.to_string()).unwrap(), None);
    }

    #[test]
    fn historical_fingerprint_change_requires_complete_material_difference() {
        let old = FingerprintSummary {
            status: 200,
            normalized_hash: "old".into(),
            json_shape_hash: None,
            header_hash: "headers".into(),
            redirect_target: None,
            complete: true,
        };
        let mut previous = PreviousEvidence::default();
        previous.endpoints.insert("endpoint".into());
        previous.fingerprints.insert("endpoint".into(), old);
        previous
            .states
            .insert("endpoint".into(), EvidenceState::Repeatable);
        let mut current = EndpointEvidence {
            fingerprint: Some(FingerprintSummary {
                status: 200,
                normalized_hash: "new".into(),
                json_shape_hash: None,
                header_hash: "headers".into(),
                redirect_target: None,
                complete: true,
            }),
            ..Default::default()
        };
        let mut reasons = BTreeMap::new();
        let mut signals = Vec::new();
        correlate_history(
            "endpoint",
            &current,
            EvidenceState::Repeatable,
            &previous,
            &mut reasons,
            &mut signals,
        );
        assert!(reasons.contains_key("history:fingerprint_changed"));

        current.fingerprint.as_mut().unwrap().complete = false;
        reasons.clear();
        signals.clear();
        correlate_history(
            "endpoint",
            &current,
            EvidenceState::Repeatable,
            &previous,
            &mut reasons,
            &mut signals,
        );
        assert!(!reasons.contains_key("history:fingerprint_changed"));

        reasons.clear();
        signals.clear();
        correlate_history(
            "new-endpoint",
            &current,
            EvidenceState::Repeatable,
            &previous,
            &mut reasons,
            &mut signals,
        );
        assert!(reasons.contains_key("history:new_endpoint"));
    }

    #[test]
    fn database_only_workflow_persists_ranks_reasons_links_and_sanitized_export() {
        let conn = db::init_db(":memory:").unwrap();
        let mut scan = ScanRun::new(vec!["example.com".into()], "workflow".into());
        save_run(&conn, &mut scan, "2026-02-01T00:00:00Z");
        let a_url = "https://example.com/api/account/export?user_id=top-secret";
        let a = endpoint(
            &conn,
            &scan,
            a_url,
            &["http_probe", "javascript", "source_map", "wayback"],
        );
        let b_url = "https://example.com/admin/debug";
        let b = endpoint(&conn, &scan, b_url, &["http_probe", "wayback"]);
        endpoint(
            &conn,
            &scan,
            "https://example.com/old/passive/path",
            &["wayback"],
        );
        db::classify_scan_inventory(&conn, &scan.id).unwrap();
        fingerprint(&conn, &scan, &a, "a", true, "\"fast\"");
        fingerprint(&conn, &scan, &b, "b", true, "\"fast\"");
        let opportunity_id = opportunity(
            &conn,
            &scan,
            &a,
            a_url,
            "IdentifierHandling",
            "ControlVerified",
            None,
        );
        opportunity(
            &conn,
            &scan,
            &a,
            a_url,
            "DownloadSurface",
            "Repeatable",
            None,
        );
        opportunity(
            &conn,
            &scan,
            &b,
            b_url,
            "DebugOrInternalSurface",
            "Repeatable",
            None,
        );
        let dir = std::env::temp_dir().join(format!("recon_phase4_{}", scan.id));
        let first = run(
            &conn,
            scan.id,
            ReviewConfig {
                max_candidates: 10,
                min_score: 20,
                output_dir: dir.clone(),
            },
        )
        .unwrap();
        let first_json =
            std::fs::read_to_string(dir.join("investigation_candidates.json")).unwrap();
        let second = run(
            &conn,
            scan.id,
            ReviewConfig {
                max_candidates: 10,
                min_score: 20,
                output_dir: dir.clone(),
            },
        )
        .unwrap();
        let ranked: Vec<_> = second
            .iter()
            .filter(|candidate| candidate.rank.is_some())
            .collect();
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].endpoint_id, a);
        assert_eq!(ranked[1].endpoint_id, b);
        assert!(ranked[0].score > ranked[1].score);
        assert_eq!(
            first
                .iter()
                .map(|candidate| &candidate.id)
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|candidate| &candidate.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM candidate_opportunities WHERE opportunity_id=?1",
                params![opportunity_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(
            conn.query_row("SELECT count(*) FROM candidate_score_reasons", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
                > 0
        );
        let stored: String = conn
            .query_row(
                "SELECT canonical_url || categories || endpoint_classes || parameters || provenance || review_guidance FROM correlated_candidates WHERE endpoint_id=?1",
                params![a],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stored.contains("top-secret"));
        assert_eq!(
            conn.prepare("SELECT rank FROM correlated_candidates WHERE ranked=1 ORDER BY rank",)
                .unwrap()
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
            [1, 2]
        );
        let json = std::fs::read_to_string(dir.join("investigation_candidates.json")).unwrap();
        assert_eq!(json, first_json);
        assert!(!json.contains("top-secret") && !json.contains("redirect_target"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ordering_threshold_cap_and_unstable_suppression_are_deterministic() {
        let mut candidates = vec![
            fixture_candidate("b", 40, EvidenceState::Repeatable),
            fixture_candidate("a", 40, EvidenceState::ControlVerified),
            fixture_candidate("c", 10, EvidenceState::Observed),
        ];
        candidates[1].suppression_reason = Some("repeat response was unstable".into());
        assign_ranks(&mut candidates, 20, 1);
        assert_eq!(
            candidates
                .iter()
                .filter_map(|candidate| candidate
                    .rank
                    .map(|rank| (candidate.canonical_url.as_str(), rank)))
                .collect::<Vec<_>>(),
            [("https://example.com/b", 1)]
        );
    }

    #[test]
    fn persistence_rebuild_is_idempotent_and_scan_isolated() {
        let conn = db::init_db(":memory:").unwrap();
        let mut first = ScanRun::new(vec!["first.example".into()], "first".into());
        let mut second = ScanRun::new(vec!["second.example".into()], "second".into());
        save_run(&conn, &mut first, "2026-03-01T00:00:00Z");
        save_run(&conn, &mut second, "2026-03-02T00:00:00Z");
        endpoint(&conn, &first, "https://first.example/admin", &["wayback"]);
        endpoint(&conn, &second, "https://second.example/debug", &["wayback"]);
        db::classify_scan_inventory(&conn, &first.id).unwrap();
        db::classify_scan_inventory(&conn, &second.id).unwrap();
        let first_candidates = correlate(&conn, first.id).unwrap();
        persist(&conn, first.id, &first_candidates).unwrap();
        let second_candidates = correlate(&conn, second.id).unwrap();
        persist(&conn, second.id, &second_candidates).unwrap();
        persist(&conn, first.id, &first_candidates).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM correlated_candidates", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM correlated_candidates WHERE scan_id=?1",
                params![second.id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
    }

    fn fixture_candidate(path: &str, score: u16, state: EvidenceState) -> CorrelatedCandidate {
        CorrelatedCandidate {
            id: path.into(),
            scan_id: Uuid::nil(),
            endpoint_id: path.into(),
            canonical_url: format!("https://example.com/{path}"),
            categories: vec![],
            endpoint_classes: vec![],
            parameters: vec![],
            provenance: vec![],
            evidence_state: state,
            score,
            score_reasons: vec![],
            historical_signals: vec![],
            suppression_reason: None,
            opportunity_ids: vec![],
            rank: None,
            manual_validation_required: true,
            review_guidance: vec![],
        }
    }
}
