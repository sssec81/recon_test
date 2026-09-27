//! Phase 9A: bounded, non-destructive SQL-injection investigation.
//!
//! Only complete, live GET query observations are eligible. All requests use
//! the shared scheduler. Results are investigation evidence, never findings.

use crate::scan::fingerprint::ResponseFingerprint;
use crate::scan::network::RequestScheduler;
use crate::scan::scope::ScopePolicy;
use reqwest::Url;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct SqlInjectionConfig {
    pub max_parameters: usize,
    pub max_requests_per_parameter: usize,
}

#[derive(Clone)]
struct EligibleParameter {
    endpoint_id: String,
    canonical_url: String,
    live_url: Url,
    observation_id: String,
    parameter: String,
    original_value: String,
    baseline: ResponseFingerprint,
}

struct ProbeResult {
    fingerprint: ResponseFingerprint,
    database_error: bool,
}

struct Attempt<'a> {
    scan_id: Uuid,
    opportunity_id: &'a str,
    sequence: usize,
    request_type: &'a str,
    url: &'a Url,
    baseline_observation_id: &'a str,
    result: Option<&'a ProbeResult>,
}

pub async fn run(
    scheduler: &RequestScheduler,
    scope: &ScopePolicy,
    conn: &Connection,
    scan_id: Uuid,
    config: SqlInjectionConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidates = eligible_parameters(conn, scan_id)?;
    let request_cap = config.max_requests_per_parameter.min(6);
    let mut checked = 0usize;
    let mut survived = 0usize;

    for candidate in candidates {
        if checked >= config.max_parameters {
            break;
        }
        checked += 1;
        let opportunity_id = stable_id(&format!(
            "{}:{}:SqlInjectionBehavior:{}",
            scan_id, candidate.endpoint_id, candidate.parameter
        ));
        insert_opportunity(conn, scan_id, &opportunity_id, &candidate)?;
        if request_cap < 4 || !crate::triage::is_safe_url(&candidate.live_url, scope) {
            suppress(
                conn,
                &opportunity_id,
                "SQL verifier request cap or scope policy prevented paired controls",
            )?;
            continue;
        }

        let probes = [
            ("sqli_repeat", candidate.original_value.clone()),
            ("sqli_control", "recon_control_value".into()),
            ("sqli_quote", format!("{}'", candidate.original_value)),
            ("sqli_quote", format!("{}'", candidate.original_value)),
            (
                "sqli_boolean_true",
                format!("{}' AND '1'='1", candidate.original_value),
            ),
            (
                "sqli_boolean_false",
                format!("{}' AND '1'='2", candidate.original_value),
            ),
        ];
        let mut results = Vec::new();
        for (sequence, (kind, value)) in probes.into_iter().take(request_cap).enumerate() {
            let url = replace_query_value(&candidate.live_url, &candidate.parameter, &value);
            let result = fetch(scheduler, &url).await;
            save_attempt(
                conn,
                Attempt {
                    scan_id,
                    opportunity_id: &opportunity_id,
                    sequence: sequence + 1,
                    request_type: kind,
                    url: &url,
                    baseline_observation_id: &candidate.observation_id,
                    result: result.as_ref(),
                },
            )?;
            results.push((kind, result));
        }

        let repeat_stable = results
            .first()
            .and_then(|(_, result)| result.as_ref())
            .is_some_and(|result| materially_equal(&candidate.baseline, &result.fingerprint));
        let control_clean = results
            .get(1)
            .and_then(|(_, result)| result.as_ref())
            .is_some_and(|result| !result.database_error && result.fingerprint.status < 500);
        let quotes: Vec<&ProbeResult> = results
            .iter()
            .filter(|(kind, _)| *kind == "sqli_quote")
            .filter_map(|(_, result)| result.as_ref())
            .collect();
        let repeatable_error = quotes.len() == 2
            && quotes.iter().all(|result| result.database_error)
            && quotes[0].fingerprint.status == quotes[1].fingerprint.status;
        let boolean_signal = results
            .get(4)
            .and_then(|(_, result)| result.as_ref())
            .zip(results.get(5).and_then(|(_, result)| result.as_ref()))
            .is_some_and(|(true_result, false_result)| {
                !true_result.database_error
                    && !false_result.database_error
                    && materially_equal(&candidate.baseline, &true_result.fingerprint)
                    && !materially_equal(&true_result.fingerprint, &false_result.fingerprint)
                    && true_result.fingerprint.status < 500
                    && false_result.fingerprint.status < 500
            });

        if repeat_stable && control_clean && (repeatable_error || boolean_signal) {
            conn.execute(
                "UPDATE investigation_opportunities SET evidence_state='ControlVerified',suppression_reason=NULL WHERE id=?1",
                params![opportunity_id],
            )?;
            conn.execute(
                "UPDATE verification_attempts SET comparison=CASE WHEN request_type='sqli_repeat' THEN 'stable' WHEN request_type='sqli_quote' THEN 'meaningfully_different' WHEN request_type='sqli_boolean_true' THEN 'stable' WHEN request_type='sqli_boolean_false' THEN 'meaningfully_different' ELSE comparison END WHERE opportunity_id=?1",
                params![opportunity_id],
            )?;
            survived += 1;
        } else {
            suppress(
                conn,
                &opportunity_id,
                "paired SQL controls produced no repeatable database-specific differential",
            )?;
        }
    }
    println!(
        "\n🧪 Phase 9A SQL-injection investigation: {checked} parameter(s) checked, {survived} candidate(s) retained"
    );
    Ok(())
}

fn eligible_parameters(
    conn: &Connection,
    scan_id: Uuid,
) -> rusqlite::Result<Vec<EligibleParameter>> {
    let mut statement = conn.prepare(
        "SELECT f.endpoint_id,e.canonical_url,h.url,h.id,f.status,f.body_length,f.captured_length,f.body_complete,f.raw_hash,f.normalized_hash,f.content_type,f.header_hash,f.redirect_target,f.json_shape_hash,f.timing_bucket FROM response_fingerprints f JOIN http_observations h ON h.id=f.http_observation_id JOIN endpoints e ON e.id=f.endpoint_id WHERE f.scan_id=?1 AND f.body_complete=1 ORDER BY e.canonical_url,h.observed_at,h.id",
    )?;
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
            if is_sensitive_parameter(&name) || !seen.insert((endpoint_id.clone(), name.clone())) {
                continue;
            }
            result.push(EligibleParameter {
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

fn is_sensitive_parameter(name: &str) -> bool {
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

async fn fetch(scheduler: &RequestScheduler, url: &Url) -> Option<ProbeResult> {
    let result = crate::probes::scanner::probe_single_url(scheduler, url.as_str()).await?;
    let database_error = contains_database_error(&result.body_snippet);
    Some(ProbeResult {
        fingerprint: result.fingerprint?,
        database_error,
    })
}

fn contains_database_error(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    [
        "sql syntax",
        "sqlite_error",
        "sqliteexception",
        "mysql_fetch",
        "postgresql error",
        "unterminated quoted string",
        "sequelize database error",
        "syntax error at or near",
    ]
    .iter()
    .any(|pattern| body.contains(pattern))
}

fn materially_equal(a: &ResponseFingerprint, b: &ResponseFingerprint) -> bool {
    a.body_complete
        && b.body_complete
        && a.status == b.status
        && a.normalized_hash == b.normalized_hash
        && a.json_shape_hash == b.json_shape_hash
        && a.redirect_target == b.redirect_target
}

fn replace_query_value(url: &Url, parameter: &str, replacement: &str) -> Url {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| {
            let value = if name == parameter {
                replacement.to_string()
            } else {
                value.into_owned()
            };
            (name.into_owned(), value)
        })
        .collect();
    let mut result = url.clone();
    result.query_pairs_mut().clear().extend_pairs(pairs);
    result
}

fn insert_opportunity(
    conn: &Connection,
    scan_id: Uuid,
    id: &str,
    candidate: &EligibleParameter,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO investigation_opportunities (id,scan_id,endpoint_id,canonical_url,category,reason,supporting_evidence,priority,evidence_state,suppression_reason) VALUES (?1,?2,?3,?4,'SqlInjectionBehavior',?5,'[\"sqli_verifier\",\"live_request_binding\"]',9,'Observed',NULL)",
        params![id, scan_id.to_string(), candidate.endpoint_id, candidate.canonical_url, format!("live GET query parameter `{}` selected for paired SQL controls", candidate.parameter)],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO opportunity_request_bindings VALUES (?1,?2,'GET','query',?3,?4)",
        params![
            id,
            scan_id.to_string(),
            candidate.parameter,
            candidate.observation_id
        ],
    )?;
    Ok(())
}

fn save_attempt(conn: &Connection, attempt: Attempt<'_>) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO verification_attempts (id,scan_id,opportunity_id,sequence,request_type,request_url,baseline_observation_id,fingerprint,comparison,failure_reason,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            stable_id(&format!("{}:{}", attempt.opportunity_id, attempt.sequence)),
            attempt.scan_id.to_string(),
            attempt.opportunity_id,
            attempt.sequence as i64,
            attempt.request_type,
            sanitized_url(attempt.url),
            attempt.baseline_observation_id,
            attempt.result.and_then(|value| serde_json::to_string(&value.fingerprint).ok()),
            if attempt.result.is_some() { "observed" } else { "inconclusive" },
            attempt.result.is_none().then_some("request failed, deadline expired, or shared budget exhausted"),
            chrono::Utc::now().to_rfc3339(),
        ],
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

fn sanitized_url(url: &Url) -> String {
    let names: BTreeSet<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    let mut safe = url.clone();
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
    safe.to_string()
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

fn stable_id(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{db, models::ScanRun};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn generic_server_errors_are_not_database_evidence() {
        assert!(!contains_database_error("500 Internal Server Error"));
        assert!(!contains_database_error("unexpected application failure"));
        assert!(contains_database_error(
            "SQLITE_ERROR: near quote: syntax error"
        ));
    }

    #[tokio::test]
    async fn paired_error_controls_are_bounded_persisted_and_cautious() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            for _ in 0..6 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let length = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                server_hits.fetch_add(1, Ordering::SeqCst);
                let injected = request.contains("%27") || request.contains("'");
                let (status, body) = if injected {
                    (
                        "500 Internal Server Error",
                        "SQL syntax error near quoted string",
                    )
                } else if request.contains("recon_control_value") {
                    ("200 OK", "control")
                } else {
                    ("200 OK", "baseline")
                };
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });

        let conn = db::init_db(":memory:").unwrap();
        let scan = ScanRun::new(vec!["127.0.0.1".into()], "sqli-test".into());
        db::save_scan_run(&conn, &scan).unwrap();
        let url = format!("http://{address}/search?q=juice");
        let headers = reqwest::header::HeaderMap::new();
        let baseline = crate::scan::fingerprint::fingerprint(
            200,
            b"baseline",
            8,
            true,
            Some("text/plain"),
            &headers,
            None,
        );
        db::save_active_http_observation(&conn, &scan.id, &url, "triage_fetch", 200, 1, &baseline)
            .unwrap();
        let scope = ScopePolicy::new(vec!["127.0.0.1".into()]);
        let scheduler =
            RequestScheduler::new(reqwest::Client::new(), scope.clone(), 1, 6, 0, 0, None);
        run(
            &scheduler,
            &scope,
            &conn,
            scan.id,
            SqlInjectionConfig {
                max_parameters: 1,
                max_requests_per_parameter: 6,
            },
        )
        .await
        .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 6);
        assert_eq!(
            conn.query_row(
                "SELECT evidence_state FROM investigation_opportunities WHERE category='SqlInjectionBehavior'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "ControlVerified"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM verification_attempts", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            6
        );
        server.await.unwrap();
    }
}
