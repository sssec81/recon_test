//! Phase 9B-9F bounded web-behavior verifiers.
//!
//! These modules operate only on previously observed live GET requests, use the
//! shared scheduler, persist redacted evidence, and never claim a vulnerability.

use crate::scan::fingerprint::ResponseFingerprint;
use crate::scan::network::{RedirectTermination, RequestScheduler};
use crate::scan::scope::ScopePolicy;
use reqwest::{Url, header};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct WebVerificationConfig {
    pub xss: bool,
    pub redirect: bool,
    pub traversal: bool,
    pub cors: bool,
    pub ssrf: bool,
    pub max_candidates: usize,
}

#[derive(Clone)]
struct Candidate {
    endpoint_id: String,
    canonical_url: String,
    live_url: Url,
    observation_id: String,
    parameter: String,
    original_value: String,
    baseline: ResponseFingerprint,
}

struct Probe {
    fingerprint: ResponseFingerprint,
    body: String,
}

pub async fn run(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    config: WebVerificationConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidates = eligible_parameters(conn, scan_id)?;
    if config.xss {
        run_xss(
            scheduler,
            scope,
            conn,
            scan_id,
            &candidates,
            config.max_candidates,
        )
        .await?;
    }
    if config.redirect {
        let redirect_candidates = eligible_redirect_parameters(conn, scan_id, &candidates)?;
        run_redirect(
            scheduler,
            scope,
            conn,
            scan_id,
            &redirect_candidates,
            config.max_candidates,
        )
        .await?;
    }
    if config.traversal {
        run_traversal(
            scheduler,
            scope,
            conn,
            scan_id,
            &candidates,
            config.max_candidates,
        )
        .await?;
    }
    if config.cors {
        let endpoints = eligible_endpoints(conn, scan_id)?;
        run_cors(
            scheduler,
            scope,
            conn,
            scan_id,
            &endpoints,
            config.max_candidates,
        )
        .await?;
    }
    if config.ssrf {
        run_ssrf(
            scheduler,
            scope,
            conn,
            scan_id,
            &candidates,
            config.max_candidates,
        )
        .await?;
    }
    Ok(())
}

async fn run_xss(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    candidates: &[Candidate],
    max: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut checked = 0;
    let mut retained = 0;
    for candidate in candidates.iter().take(max) {
        if !crate::triage::is_safe_url(&candidate.live_url, scope) {
            continue;
        }
        checked += 1;
        let id = opportunity(conn, scan_id, candidate, "ReflectedXssBehavior", 8)?;
        let marker = format!("reconxss{}", &id[..10]);
        let values = [
            candidate.original_value.clone(),
            marker.clone(),
            format!(r#"<svg id="{marker}">"#),
        ];
        let mut probes = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let url = replace_query(&candidate.live_url, &candidate.parameter, value);
            let probe = fetch(scheduler, &url).await;
            save_attempt(
                conn,
                scan_id,
                &id,
                index + 1,
                ["xss_repeat", "xss_control", "xss_markup"][index],
                &url,
                candidate,
                probe.as_ref(),
            )?;
            probes.push(probe);
        }
        let stable = probes[0]
            .as_ref()
            .is_some_and(|probe| equal(&candidate.baseline, &probe.fingerprint));
        let raw_markup = format!(r#"<svg id="{marker}">"#);
        let reflected = probes[2].as_ref().is_some_and(|probe| {
            probe.body.contains(&raw_markup)
                && probe
                    .fingerprint
                    .content_type
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains("html"))
        });
        if stable && reflected {
            promote(conn, &id, "ControlVerified", &["xss_repeat", "xss_markup"])?;
            retained += 1;
        } else {
            suppress(
                conn,
                &id,
                "no stable unescaped markup reflection was reproduced",
            )?;
        }
    }
    println!("\n🧪 Phase 9B reflected-XSS investigation: {checked} checked, {retained} retained");
    Ok(())
}

async fn run_redirect(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    candidates: &[Candidate],
    max: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            name_matches(
                &candidate.parameter,
                &[
                    "url",
                    "uri",
                    "next",
                    "redirect",
                    "return",
                    "continue",
                    "dest",
                    "destination",
                    "to",
                ],
            )
        })
        .take(max)
        .collect();
    let mut retained = 0;
    for candidate in &eligible {
        if !crate::triage::is_safe_url(&candidate.live_url, scope) {
            continue;
        }
        let id = opportunity(conn, scan_id, candidate, "OpenRedirectBehavior", 9)?;
        let original_redirect = scheduler
            .get_with_trace_limited(&candidate.live_url, 1)
            .await
            .ok()
            .is_some_and(|result| result.termination == RedirectTermination::OutOfScope);
        save_observed_attempt(
            conn,
            scan_id,
            &id,
            1,
            "redirect_repeat",
            &candidate.live_url,
            candidate,
            original_redirect,
        )?;
        let original = Url::parse(&candidate.original_value).ok();
        let marker = if original
            .as_ref()
            .is_some_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
        {
            format!(
                "https://example.invalid/recon-{}?allowed={}",
                &id[..10],
                candidate.original_value
            )
        } else {
            format!("https://example.invalid/recon-{}", &id[..10])
        };
        let url = replace_query(&candidate.live_url, &candidate.parameter, &marker);
        let redirected = scheduler
            .get_with_trace_limited(&url, 1)
            .await
            .ok()
            .is_some_and(|result| {
                result.termination == RedirectTermination::OutOfScope
                    && result
                        .blocked_destination
                        .as_deref()
                        .is_some_and(|value| value.starts_with("https://example.invalid/"))
            });
        save_observed_attempt(
            conn,
            scan_id,
            &id,
            2,
            "redirect_external",
            &url,
            candidate,
            redirected,
        )?;
        if redirected {
            promote(
                conn,
                &id,
                "ControlVerified",
                &["redirect_repeat", "redirect_external"],
            )?;
            retained += 1;
        } else {
            suppress(
                conn,
                &id,
                "external destination was not returned in a blocked redirect",
            )?;
        }
    }
    println!(
        "\n🧪 Phase 9C open-redirect investigation: {} checked, {retained} retained",
        eligible.len()
    );
    Ok(())
}

async fn run_traversal(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    candidates: &[Candidate],
    max: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            name_matches(
                &candidate.parameter,
                &[
                    "file", "path", "page", "template", "include", "download", "filename",
                    "document",
                ],
            )
        })
        .take(max)
        .collect();
    let mut retained = 0;
    for candidate in &eligible {
        if !crate::triage::is_safe_url(&candidate.live_url, scope) {
            continue;
        }
        let id = opportunity(conn, scan_id, candidate, "PathTraversalBehavior", 9)?;
        let values = [
            candidate.original_value.clone(),
            "recon_missing_file_9d.txt".into(),
            "../../../../etc/passwd".into(),
            "../../../../etc/passwd".into(),
        ];
        let mut probes = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let url = replace_query(&candidate.live_url, &candidate.parameter, value);
            let probe = fetch(scheduler, &url).await;
            save_attempt(
                conn,
                scan_id,
                &id,
                index + 1,
                [
                    "traversal_repeat",
                    "traversal_control",
                    "traversal_probe",
                    "traversal_probe",
                ][index],
                &url,
                candidate,
                probe.as_ref(),
            )?;
            probes.push(probe);
        }
        let stable = probes[0]
            .as_ref()
            .is_some_and(|probe| equal(&candidate.baseline, &probe.fingerprint));
        let control_clean = probes[1]
            .as_ref()
            .is_some_and(|probe| !file_signature(&probe.body));
        let repeated = probes[2..].iter().all(|probe| {
            probe
                .as_ref()
                .is_some_and(|value| file_signature(&value.body))
        });
        if stable && control_clean && repeated {
            promote(
                conn,
                &id,
                "ControlVerified",
                &["traversal_repeat", "traversal_probe"],
            )?;
            retained += 1;
        } else {
            suppress(
                conn,
                &id,
                "paired traversal probes produced no repeatable file signature",
            )?;
        }
    }
    println!(
        "\n🧪 Phase 9D traversal investigation: {} checked, {retained} retained",
        eligible.len()
    );
    Ok(())
}

async fn run_cors(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    candidates: &[Candidate],
    max: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen = BTreeSet::new();
    let eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| seen.insert(candidate.endpoint_id.clone()))
        .take(max)
        .collect();
    let mut retained = 0;
    for candidate in &eligible {
        if !crate::triage::is_safe_url(&candidate.live_url, scope) {
            continue;
        }
        let id = opportunity(conn, scan_id, candidate, "CorsBehavior", 8)?;
        let mut evidence = Vec::new();
        for (index, origin) in ["https://recon.invalid", "null"].iter().enumerate() {
            let mut headers = header::HeaderMap::new();
            headers.insert(header::ORIGIN, header::HeaderValue::from_static(origin));
            let result = scheduler
                .get_with_headers(&candidate.live_url, headers)
                .await
                .ok();
            let reflected = result
                .as_ref()
                .and_then(|response| response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN))
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == *origin);
            let credentials = result
                .as_ref()
                .and_then(|response| {
                    response
                        .headers()
                        .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                })
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            save_observed_attempt(
                conn,
                scan_id,
                &id,
                index + 1,
                if index == 0 {
                    "cors_hostile_origin"
                } else {
                    "cors_null_origin"
                },
                &candidate.live_url,
                candidate,
                reflected && credentials,
            )?;
            evidence.push(reflected && credentials);
        }
        if evidence.first() == Some(&true) {
            promote(conn, &id, "ControlVerified", &["cors_hostile_origin"])?;
            retained += 1;
        } else {
            suppress(
                conn,
                &id,
                "hostile Origin was not reflected with credential permission",
            )?;
        }
    }
    println!(
        "\n🧪 Phase 9E CORS investigation: {} checked, {retained} retained",
        eligible.len()
    );
    Ok(())
}

async fn run_ssrf(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    candidates: &[Candidate],
    max: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            name_matches(
                &candidate.parameter,
                &[
                    "url", "uri", "host", "domain", "endpoint", "callback", "webhook", "feed",
                    "image", "proxy",
                ],
            )
        })
        .take(max)
        .collect();
    let mut retained = 0;
    for candidate in &eligible {
        if !crate::triage::is_safe_url(&candidate.live_url, scope) {
            continue;
        }
        let id = opportunity(conn, scan_id, candidate, "SsrfBehavior", 8)?;
        let values = [
            candidate.original_value.clone(),
            "http://192.0.2.1/recon-ssrf".into(),
            "http://127.0.0.1:1/recon-ssrf".into(),
        ];
        let mut probes = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let url = replace_query(&candidate.live_url, &candidate.parameter, value);
            let probe = fetch(scheduler, &url).await;
            save_attempt(
                conn,
                scan_id,
                &id,
                index + 1,
                ["ssrf_repeat", "ssrf_reserved", "ssrf_loopback"][index],
                &url,
                candidate,
                probe.as_ref(),
            )?;
            probes.push(probe);
        }
        let stable = probes[0]
            .as_ref()
            .is_some_and(|probe| equal(&candidate.baseline, &probe.fingerprint));
        let fetch_behavior =
            probes[1]
                .as_ref()
                .zip(probes[2].as_ref())
                .is_some_and(|(reserved, loopback)| {
                    network_error(&reserved.body)
                        && network_error(&loopback.body)
                        && !equal(&reserved.fingerprint, &loopback.fingerprint)
                });
        if stable && fetch_behavior {
            promote(
                conn,
                &id,
                "Repeatable",
                &["ssrf_repeat", "ssrf_reserved", "ssrf_loopback"],
            )?;
            retained += 1;
        } else {
            suppress(
                conn,
                &id,
                "reserved and loopback controls did not establish outbound fetch behavior",
            )?;
        }
    }
    println!(
        "\n🧪 Phase 9F SSRF investigation: {} checked, {retained} retained",
        eligible.len()
    );
    Ok(())
}

fn eligible_parameters(conn: &Connection, scan_id: Uuid) -> rusqlite::Result<Vec<Candidate>> {
    let mut statement = conn.prepare("SELECT f.endpoint_id,e.canonical_url,h.url,h.id,f.status,f.body_length,f.captured_length,f.body_complete,f.raw_hash,f.normalized_hash,f.content_type,f.header_hash,f.redirect_target,f.json_shape_hash,f.timing_bucket FROM response_fingerprints f JOIN http_observations h ON h.id=f.http_observation_id JOIN endpoints e ON e.id=f.endpoint_id WHERE f.scan_id=?1 AND f.body_complete=1 ORDER BY e.canonical_url,h.observed_at,h.id")?;
    let rows = statement
        .query_map(params![scan_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                fingerprint_row(row, 4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for (endpoint_id, canonical_url, raw_url, observation_id, baseline) in rows {
        let Ok(url) = Url::parse(&raw_url) else {
            continue;
        };
        for (name, value) in url.query_pairs() {
            let name = name.into_owned();
            if sensitive(&name) || !seen.insert((endpoint_id.clone(), name.clone())) {
                continue;
            }
            result.push(Candidate {
                endpoint_id: endpoint_id.clone(),
                canonical_url: canonical_url.clone(),
                live_url: url.clone(),
                observation_id: observation_id.clone(),
                parameter: name,
                original_value: value.into_owned(),
                baseline: baseline.clone(),
            });
        }
    }
    Ok(result)
}

fn eligible_endpoints(conn: &Connection, scan_id: Uuid) -> rusqlite::Result<Vec<Candidate>> {
    let mut statement = conn.prepare("SELECT f.endpoint_id,e.canonical_url,h.url,h.id,f.status,f.body_length,f.captured_length,f.body_complete,f.raw_hash,f.normalized_hash,f.content_type,f.header_hash,f.redirect_target,f.json_shape_hash,f.timing_bucket FROM response_fingerprints f JOIN http_observations h ON h.id=f.http_observation_id JOIN endpoints e ON e.id=f.endpoint_id WHERE f.scan_id=?1 AND f.body_complete=1 ORDER BY e.canonical_url,h.observed_at,h.id")?;
    let rows = statement
        .query_map(params![scan_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                fingerprint_row(row, 4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut seen = BTreeSet::new();
    Ok(rows
        .into_iter()
        .filter_map(
            |(endpoint_id, canonical_url, raw_url, observation_id, baseline)| {
                if !seen.insert(endpoint_id.clone()) {
                    return None;
                }
                Some(Candidate {
                    endpoint_id,
                    canonical_url,
                    live_url: Url::parse(&raw_url).ok()?,
                    observation_id,
                    parameter: String::new(),
                    original_value: String::new(),
                    baseline,
                })
            },
        )
        .collect())
}

fn eligible_redirect_parameters(
    conn: &Connection,
    scan_id: Uuid,
    existing: &[Candidate],
) -> rusqlite::Result<Vec<Candidate>> {
    let mut result = existing.to_vec();
    let mut seen: BTreeSet<(String, String)> = result
        .iter()
        .map(|candidate| (candidate.endpoint_id.clone(), candidate.parameter.clone()))
        .collect();
    let mut statement = conn.prepare(
        "SELECT e.id,e.canonical_url,o.raw_url FROM endpoint_observations o JOIN endpoints e ON e.id=o.endpoint_id WHERE o.scan_id=?1 ORDER BY e.canonical_url,o.raw_url",
    )?;
    let rows = statement
        .query_map(params![scan_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (endpoint_id, canonical_url, raw_url) in rows {
        let Ok(url) = Url::parse(&raw_url) else {
            continue;
        };
        for (name, value) in url.query_pairs() {
            let name = name.into_owned();
            if !name_matches(
                &name,
                &[
                    "url",
                    "uri",
                    "next",
                    "redirect",
                    "return",
                    "continue",
                    "dest",
                    "destination",
                    "to",
                ],
            ) || !seen.insert((endpoint_id.clone(), name.clone()))
            {
                continue;
            }
            result.push(Candidate {
                endpoint_id: endpoint_id.clone(),
                canonical_url: canonical_url.clone(),
                live_url: url.clone(),
                observation_id: stable_id(&format!("{scan_id}:redirect:{raw_url}")),
                parameter: name,
                original_value: value.into_owned(),
                baseline: placeholder_fingerprint(),
            });
        }
    }
    Ok(result)
}

fn placeholder_fingerprint() -> ResponseFingerprint {
    ResponseFingerprint {
        status: 0,
        body_length: 0,
        captured_length: 0,
        body_complete: false,
        raw_hash: String::new(),
        normalized_hash: String::new(),
        content_type: None,
        header_hash: String::new(),
        redirect_target: None,
        json_shape_hash: None,
        timing_bucket: crate::scan::fingerprint::TimingBucket::Unknown,
    }
}

async fn fetch(scheduler: &RequestScheduler, url: &Url) -> Option<Probe> {
    let result = crate::probes::scanner::probe_single_url(scheduler, url.as_str()).await?;
    Some(Probe {
        fingerprint: result.fingerprint?,
        body: result.body_snippet,
    })
}

fn opportunity(
    conn: &Connection,
    scan_id: Uuid,
    candidate: &Candidate,
    category: &str,
    priority: i64,
) -> rusqlite::Result<String> {
    let id = stable_id(&format!(
        "{scan_id}:{}:{category}:{}",
        candidate.endpoint_id, candidate.parameter
    ));
    conn.execute("INSERT OR REPLACE INTO investigation_opportunities (id,scan_id,endpoint_id,canonical_url,category,reason,supporting_evidence,priority,evidence_state,suppression_reason) VALUES (?1,?2,?3,?4,?5,?6,'[\"bounded_web_verifier\",\"live_request_binding\"]',?7,'Observed',NULL)", params![id, scan_id.to_string(), candidate.endpoint_id, candidate.canonical_url, category, format!("live GET parameter `{}` selected for bounded controls", candidate.parameter), priority])?;
    conn.execute(
        "INSERT OR REPLACE INTO opportunity_request_bindings VALUES (?1,?2,'GET',?3,?4,?5)",
        params![
            id,
            scan_id.to_string(),
            if candidate.parameter.is_empty() {
                "path"
            } else {
                "query"
            },
            candidate.parameter,
            candidate.observation_id,
        ],
    )?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn save_attempt(
    conn: &Connection,
    scan_id: Uuid,
    id: &str,
    sequence: usize,
    kind: &str,
    url: &Url,
    candidate: &Candidate,
    result: Option<&Probe>,
) -> rusqlite::Result<()> {
    conn.execute("INSERT OR REPLACE INTO verification_attempts (id,scan_id,opportunity_id,sequence,request_type,request_url,baseline_observation_id,fingerprint,comparison,failure_reason,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'observed',?9,?10)", params![stable_id(&format!("{id}:{sequence}")), scan_id.to_string(), id, sequence as i64, kind, sanitized_url(url), candidate.observation_id, result.and_then(|value| serde_json::to_string(&value.fingerprint).ok()), result.is_none().then_some("request failed or shared budget exhausted"), chrono::Utc::now().to_rfc3339()])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn save_observed_attempt(
    conn: &Connection,
    scan_id: Uuid,
    id: &str,
    sequence: usize,
    kind: &str,
    url: &Url,
    candidate: &Candidate,
    matched: bool,
) -> rusqlite::Result<()> {
    conn.execute("INSERT OR REPLACE INTO verification_attempts (id,scan_id,opportunity_id,sequence,request_type,request_url,baseline_observation_id,fingerprint,comparison,failure_reason,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,?8,NULL,?9)", params![stable_id(&format!("{id}:{sequence}")), scan_id.to_string(), id, sequence as i64, kind, sanitized_url(url), candidate.observation_id, if matched { "meaningfully_different" } else { "observed" }, chrono::Utc::now().to_rfc3339()])?;
    Ok(())
}

fn promote(conn: &Connection, id: &str, state: &str, meaningful: &[&str]) -> rusqlite::Result<()> {
    conn.execute("UPDATE investigation_opportunities SET evidence_state=?2,suppression_reason=NULL WHERE id=?1", params![id, state])?;
    for kind in meaningful {
        conn.execute("UPDATE verification_attempts SET comparison=CASE WHEN request_type=?2 THEN 'meaningfully_different' ELSE comparison END WHERE opportunity_id=?1", params![id, kind])?;
    }
    Ok(())
}

fn suppress(conn: &Connection, id: &str, reason: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE investigation_opportunities SET suppression_reason=?2 WHERE id=?1",
        params![id, reason],
    )?;
    Ok(())
}

fn replace_query(url: &Url, parameter: &str, replacement: &str) -> Url {
    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(name, value)| {
            let matches = name == parameter;
            (
                name.into_owned(),
                if matches {
                    replacement.into()
                } else {
                    value.into_owned()
                },
            )
        })
        .collect();
    let mut result = url.clone();
    result.query_pairs_mut().clear().extend_pairs(pairs);
    result
}

fn sanitized_url(url: &Url) -> String {
    let names: BTreeSet<_> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    let mut result = url.clone();
    result.set_query(None);
    if !names.is_empty() {
        result.set_query(Some(
            &names
                .into_iter()
                .map(|name| format!("{name}=<redacted>"))
                .collect::<Vec<_>>()
                .join("&"),
        ));
    }
    result.to_string()
}

fn equal(a: &ResponseFingerprint, b: &ResponseFingerprint) -> bool {
    a.body_complete
        && b.body_complete
        && a.status == b.status
        && a.normalized_hash == b.normalized_hash
        && a.json_shape_hash == b.json_shape_hash
        && a.redirect_target == b.redirect_target
}
fn file_signature(body: &str) -> bool {
    body.contains("root:x:0:0:") || body.to_ascii_lowercase().contains("[extensions]")
}
fn network_error(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    [
        "econnrefused",
        "connection refused",
        "connect timeout",
        "timed out",
        "unable to connect",
        "socket hang up",
    ]
    .iter()
    .any(|value| body.contains(value))
}
fn name_matches(name: &str, aliases: &[&str]) -> bool {
    let name = name.to_ascii_lowercase();
    aliases.iter().any(|alias| {
        name == *alias
            || name.ends_with(&format!("_{alias}"))
            || name.ends_with(&format!("-{alias}"))
    })
}
fn sensitive(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "token"
            | "access_token"
            | "auth"
            | "authorization"
            | "apikey"
            | "api_key"
            | "session"
            | "csrf"
            | "password"
            | "passwd"
    )
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
    use crate::storage::{db, models::ScanRun};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    type TestResponse = (String, Vec<(&'static str, String)>, String);

    async fn spawn_server(
        expected: usize,
        responder: fn(&str) -> TestResponse,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            for _ in 0..expected {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 8192];
                let length = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                let (status, headers, body) = responder(&request);
                server_hits.fetch_add(1, Ordering::SeqCst);
                let headers = headers
                    .into_iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>();
                socket
                    .write_all(
                        format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        (address, hits, server)
    }

    fn fixture(url: &str, body: &str, content_type: &str) -> (Connection, ScanRun) {
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "web-verifier-test".into());
        db::save_scan_run(&conn, &scan).unwrap();
        let baseline = crate::scan::fingerprint::fingerprint(
            200,
            body.as_bytes(),
            body.len(),
            true,
            Some(content_type),
            &header::HeaderMap::new(),
            None,
        );
        db::save_active_http_observation(&conn, &scan.id, url, "triage_fetch", 200, 1, &baseline)
            .unwrap();
        (conn, scan)
    }

    fn config(module: &str) -> WebVerificationConfig {
        WebVerificationConfig {
            xss: module == "xss",
            redirect: module == "redirect",
            traversal: module == "traversal",
            cors: module == "cors",
            ssrf: module == "ssrf",
            max_candidates: 1,
        }
    }
    #[test]
    fn helpers_are_conservative_and_redact_values() {
        assert!(file_signature("root:x:0:0:root:/root:/bin/bash"));
        assert!(!file_signature("500 server error"));
        assert!(network_error("connect ECONNREFUSED 127.0.0.1"));
        assert!(!network_error("ordinary application response"));
        let url = Url::parse("https://example.com/a?url=secret&q=value").unwrap();
        let safe = sanitized_url(&url);
        assert!(!safe.contains("secret"));
        assert!(!safe.contains("value"));
    }

    #[tokio::test]
    async fn xss_verifier_is_exactly_bounded_bound_and_redacted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let length = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                let target = request.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&format!("http://127.0.0.1{target}")).unwrap();
                let body = url
                    .query_pairs()
                    .find(|(name, _)| name == "q")
                    .unwrap()
                    .1
                    .into_owned();
                server_hits.fetch_add(1, Ordering::SeqCst);
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "web-verifier-test".into());
        db::save_scan_run(&conn, &scan).unwrap();
        let url = format!("http://{address}/search?q=juice");
        let baseline = crate::scan::fingerprint::fingerprint(
            200,
            b"juice",
            5,
            true,
            Some("text/html"),
            &header::HeaderMap::new(),
            None,
        );
        db::save_active_http_observation(&conn, &scan.id, &url, "triage_fetch", 200, 1, &baseline)
            .unwrap();
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler =
            RequestScheduler::new(reqwest::Client::new(), scope.clone(), 1, 3, 0, 0, None);
        run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            WebVerificationConfig {
                xss: true,
                redirect: false,
                traversal: false,
                cors: false,
                ssrf: false,
                max_candidates: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        assert_eq!(conn.query_row("SELECT evidence_state FROM investigation_opportunities WHERE category='ReflectedXssBehavior'", [], |row| row.get::<_, String>(0)).unwrap(), "ControlVerified");
        assert_eq!(conn.query_row("SELECT count(*) FROM verification_attempts WHERE baseline_observation_id IS NOT NULL AND request_url NOT LIKE '%juice%' AND request_url NOT LIKE '%reconxss%'", [], |row| row.get::<_, i64>(0)).unwrap(), 3);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_verifier_blocks_external_contact_and_uses_two_requests() {
        fn responder(request: &str) -> (String, Vec<(&'static str, String)>, String) {
            if request.contains("example.invalid") {
                (
                    "302 Found".into(),
                    vec![("Location", "https://example.invalid/recon-proof".into())],
                    String::new(),
                )
            } else {
                (
                    "200 OK".into(),
                    vec![("Content-Type", "text/plain".into())],
                    "baseline".into(),
                )
            }
        }
        let (address, hits, server) = spawn_server(2, responder).await;
        let url = format!("http://{address}/go?next=home");
        let (conn, scan) = fixture(&url, "baseline", "text/plain");
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
        run(&scheduler, &scope, &conn, scan.id, config("redirect"))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(conn.query_row("SELECT evidence_state FROM investigation_opportunities WHERE category='OpenRedirectBehavior'", [], |row| row.get::<_, String>(0)).unwrap(), "ControlVerified");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_verifier_detects_discovered_allowlist_substring_bypass() {
        fn responder(request: &str) -> TestResponse {
            let target = request.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&format!("http://127.0.0.1{target}")).unwrap();
            let destination = url
                .query_pairs()
                .find(|(name, _)| name == "to")
                .unwrap()
                .1
                .into_owned();
            if destination.contains("https://allowed.example/app") {
                (
                    "302 Found".into(),
                    vec![("Location", destination)],
                    String::new(),
                )
            } else {
                ("406 Not Acceptable".into(), vec![], "blocked".into())
            }
        }
        let (address, hits, server) = spawn_server(2, responder).await;
        let mut discovered = Url::parse(&format!("http://{address}/redirect")).unwrap();
        discovered
            .query_pairs_mut()
            .append_pair("to", "https://allowed.example/app");
        let raw_url = discovered.to_string();
        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "redirect-static-test".into());
        db::save_scan_run(&conn, &scan).unwrap();
        db::save_endpoint_observation(&conn, &scan.id, &raw_url, "javascript", None).unwrap();
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
        run(&scheduler, &scope, &conn, scan.id, config("redirect"))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            conn.query_row(
                "SELECT evidence_state FROM investigation_opportunities WHERE category='OpenRedirectBehavior'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "ControlVerified"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn traversal_verifier_requires_repeated_file_signature() {
        fn responder(request: &str) -> (String, Vec<(&'static str, String)>, String) {
            let target = request.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&format!("http://127.0.0.1{target}")).unwrap();
            let value = url
                .query_pairs()
                .find(|(name, _)| name == "file")
                .unwrap()
                .1;
            let body = if value.contains("etc/passwd") {
                "root:x:0:0:root:/root:/bin/bash"
            } else if value == "index" {
                "baseline"
            } else {
                "missing"
            };
            (
                "200 OK".into(),
                vec![("Content-Type", "text/plain".into())],
                body.into(),
            )
        }
        let (address, hits, server) = spawn_server(4, responder).await;
        let url = format!("http://{address}/view?file=index");
        let (conn, scan) = fixture(&url, "baseline", "text/plain");
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler =
            RequestScheduler::new(reqwest::Client::new(), scope.clone(), 1, 4, 0, 0, None);
        run(&scheduler, &scope, &conn, scan.id, config("traversal"))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 4);
        assert_eq!(conn.query_row("SELECT evidence_state FROM investigation_opportunities WHERE category='PathTraversalBehavior'", [], |row| row.get::<_, String>(0)).unwrap(), "ControlVerified");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cors_verifier_requires_exact_origin_and_credentials() {
        fn responder(request: &str) -> (String, Vec<(&'static str, String)>, String) {
            let origin = request
                .lines()
                .find_map(|line| {
                    line.strip_prefix("origin: ")
                        .or_else(|| line.strip_prefix("Origin: "))
                })
                .unwrap_or_default()
                .trim();
            (
                "200 OK".into(),
                vec![
                    ("Content-Type", "application/json".into()),
                    ("Access-Control-Allow-Origin", origin.into()),
                    ("Access-Control-Allow-Credentials", "true".into()),
                ],
                "{}".into(),
            )
        }
        let (address, hits, server) = spawn_server(2, responder).await;
        let url = format!("http://{address}/account");
        let (conn, scan) = fixture(&url, "{}", "application/json");
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler =
            RequestScheduler::new(reqwest::Client::new(), scope.clone(), 1, 2, 0, 0, None);
        run(&scheduler, &scope, &conn, scan.id, config("cors"))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(conn.query_row("SELECT evidence_state FROM investigation_opportunities WHERE category='CorsBehavior'", [], |row| row.get::<_, String>(0)).unwrap(), "ControlVerified");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ssrf_verifier_remains_repeatable_not_control_verified() {
        fn responder(request: &str) -> (String, Vec<(&'static str, String)>, String) {
            let target = request.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&format!("http://127.0.0.1{target}")).unwrap();
            let value = url.query_pairs().find(|(name, _)| name == "url").unwrap().1;
            let body = if value.contains("192.0.2.1") {
                "connect timeout to reserved address"
            } else if value.contains("127.0.0.1") {
                "connection refused for loopback"
            } else {
                "baseline"
            };
            (
                "200 OK".into(),
                vec![("Content-Type", "text/plain".into())],
                body.into(),
            )
        }
        let (address, hits, server) = spawn_server(3, responder).await;
        let url = format!("http://{address}/fetch?url=original");
        let (conn, scan) = fixture(&url, "baseline", "text/plain");
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler =
            RequestScheduler::new(reqwest::Client::new(), scope.clone(), 1, 3, 0, 0, None);
        run(&scheduler, &scope, &conn, scan.id, config("ssrf"))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        assert_eq!(conn.query_row("SELECT evidence_state FROM investigation_opportunities WHERE category='SsrfBehavior'", [], |row| row.get::<_, String>(0)).unwrap(), "Repeatable");
        server.await.unwrap();
    }
}
