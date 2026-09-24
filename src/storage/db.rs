use crate::storage::models::{
    DnsRecord, Hostname, HttpObservation, ScanRun, ServiceRecord, TechnologyObservation, TlsRecord,
};
use rusqlite::{Connection, Result, params};
use tokio::sync::mpsc;
use uuid::Uuid;

pub fn init_db(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    // Performance PRAGMAs for SQLite WAL mode
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;",
    )?;
    // 1. Scan Runs table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            root_scope TEXT NOT NULL,
            config_hash TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS provider_statuses (
            scan_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            discovered_count INTEGER NOT NULL,
            error_category TEXT,
            PRIMARY KEY(scan_id, provider),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        )",
        [],
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY, scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER,
            path TEXT NOT NULL, canonical_url TEXT NOT NULL UNIQUE,
            first_seen_scan TEXT NOT NULL, last_seen_scan TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS endpoint_observations (
            endpoint_id TEXT NOT NULL, scan_id TEXT NOT NULL, raw_url TEXT NOT NULL,
            source TEXT NOT NULL, source_reference TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(endpoint_id, scan_id, raw_url, source, source_reference),
            FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        );",
    )?;
    let observation_reference_is_key = conn
        .prepare("PRAGMA table_info(endpoint_observations)")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
        })?
        .collect::<Result<Vec<_>>>()?
        .iter()
        .any(|(name, key_order)| name == "source_reference" && *key_order > 0);
    if !observation_reference_is_key {
        conn.execute_batch(
            "ALTER TABLE endpoint_observations RENAME TO endpoint_observations_legacy;
             CREATE TABLE endpoint_observations (
                endpoint_id TEXT NOT NULL, scan_id TEXT NOT NULL, raw_url TEXT NOT NULL,
                source TEXT NOT NULL, source_reference TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(endpoint_id, scan_id, raw_url, source, source_reference),
                FOREIGN KEY(endpoint_id) REFERENCES endpoints(id), FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
             );
             INSERT OR IGNORE INTO endpoint_observations SELECT endpoint_id, scan_id, raw_url, source, COALESCE(source_reference, '') FROM endpoint_observations_legacy;
             DROP TABLE endpoint_observations_legacy;",
        )?;
    }

    // 2. Hostnames table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS hostnames (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            discovered_from TEXT
        )",
        [],
    )?;

    // 3. DNS Records table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dns_records (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            hostname_id TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INTEGER,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(hostname_id) REFERENCES hostnames(id),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        )",
        [],
    )?;

    // Migration for existing v1.0.0 databases missing scan_id in dns_records.
    let has_scan_id = {
        let mut stmt = conn.prepare("PRAGMA table_info(dns_records)")?;
        let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
        columns
            .collect::<Result<Vec<_>>>()?
            .iter()
            .any(|name| name == "scan_id")
    };
    if !has_scan_id {
        conn.execute(
            "ALTER TABLE dns_records ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }

    // 4. Services table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS services (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            is_open BOOLEAN NOT NULL,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(hostname) REFERENCES hostnames(name)
        )",
        [],
    )?;

    // 5. TLS Certificates table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tls_certificates (
            id TEXT PRIMARY KEY,
            service_id TEXT NOT NULL,
            issuer TEXT NOT NULL,
            subject_ans TEXT NOT NULL,
            expires_at TEXT,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(service_id) REFERENCES services(id)
        )",
        [],
    )?;

    // 6. Technology Observations table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS technology_observations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            endpoint_url TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            confidence REAL NOT NULL,
            evidence TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        )",
        [],
    )?;

    // 7. HTTP Observations table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS http_observations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            title TEXT,
            server_header TEXT,
            rtt_ms INTEGER,
            content_length INTEGER,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
            FOREIGN KEY(hostname) REFERENCES hostnames(name)
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS response_fingerprints (
        http_observation_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, endpoint_id TEXT,
        status INTEGER NOT NULL, body_length INTEGER NOT NULL, captured_length INTEGER NOT NULL,
        body_complete BOOLEAN NOT NULL, raw_hash TEXT NOT NULL, normalized_hash TEXT NOT NULL,
        content_type TEXT, header_hash TEXT NOT NULL, redirect_target TEXT, json_shape_hash TEXT,
        timing_bucket TEXT NOT NULL, FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
        FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
        FOREIGN KEY(http_observation_id) REFERENCES http_observations(id))",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS javascript_observations (
            scan_id TEXT NOT NULL, source_url TEXT NOT NULL, kind TEXT NOT NULL,
            raw_value TEXT NOT NULL, resolved_url TEXT, PRIMARY KEY(scan_id, source_url, kind, raw_value),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS source_map_observations (
            scan_id TEXT NOT NULL, script_url TEXT NOT NULL, map_url TEXT NOT NULL,
            source_file TEXT NOT NULL, PRIMARY KEY(scan_id, map_url, source_file),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        )",
        [],
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS endpoint_classifications (
            scan_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, class TEXT NOT NULL,
            PRIMARY KEY(scan_id, endpoint_id, class),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
        );
        CREATE TABLE IF NOT EXISTS parameter_semantics (
            scan_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, parameter_name TEXT NOT NULL,
            semantic TEXT NOT NULL, PRIMARY KEY(scan_id, endpoint_id, parameter_name),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
        );
        CREATE TABLE IF NOT EXISTS investigation_opportunities (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
            canonical_url TEXT NOT NULL, category TEXT NOT NULL, reason TEXT NOT NULL,
            supporting_evidence TEXT NOT NULL, priority INTEGER NOT NULL,
            evidence_state TEXT NOT NULL, suppression_reason TEXT,
            UNIQUE(scan_id, endpoint_id, category),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
        );
        CREATE TABLE IF NOT EXISTS verification_attempts (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, opportunity_id TEXT NOT NULL,
            sequence INTEGER NOT NULL, request_type TEXT NOT NULL,
            request_url TEXT NOT NULL, baseline_observation_id TEXT,
            fingerprint TEXT, comparison TEXT NOT NULL, failure_reason TEXT,
            created_at TEXT NOT NULL, UNIQUE(opportunity_id, sequence),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
            FOREIGN KEY(opportunity_id) REFERENCES investigation_opportunities(id)
        );
        CREATE TABLE IF NOT EXISTS correlated_candidates (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
            canonical_url TEXT NOT NULL, evidence_state TEXT NOT NULL, score INTEGER NOT NULL,
            categories TEXT NOT NULL, endpoint_classes TEXT NOT NULL, parameters TEXT NOT NULL,
            provenance TEXT NOT NULL, review_guidance TEXT NOT NULL,
            suppression_reason TEXT, ranked BOOLEAN NOT NULL, rank INTEGER,
            UNIQUE(scan_id, endpoint_id), FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
            FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
        );
        CREATE TABLE IF NOT EXISTS candidate_score_reasons (
            candidate_id TEXT NOT NULL, reason_code TEXT NOT NULL, points INTEGER NOT NULL,
            explanation TEXT NOT NULL, PRIMARY KEY(candidate_id, reason_code),
            FOREIGN KEY(candidate_id) REFERENCES correlated_candidates(id)
        );
        CREATE TABLE IF NOT EXISTS candidate_history_signals (
            candidate_id TEXT NOT NULL, signal_code TEXT NOT NULL, explanation TEXT NOT NULL,
            PRIMARY KEY(candidate_id, signal_code, explanation),
            FOREIGN KEY(candidate_id) REFERENCES correlated_candidates(id)
        );
        CREATE TABLE IF NOT EXISTS candidate_opportunities (
            candidate_id TEXT NOT NULL, opportunity_id TEXT NOT NULL,
            PRIMARY KEY(candidate_id, opportunity_id),
            FOREIGN KEY(candidate_id) REFERENCES correlated_candidates(id),
            FOREIGN KEY(opportunity_id) REFERENCES investigation_opportunities(id)
        );
        CREATE TABLE IF NOT EXISTS review_packages (
            scan_id TEXT PRIMARY KEY, candidate_count INTEGER NOT NULL,
            output_version INTEGER NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id)
        );",
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_endpoint_observations_scan_endpoint ON endpoint_observations(scan_id, endpoint_id);
         CREATE INDEX IF NOT EXISTS idx_fingerprints_scan_endpoint ON response_fingerprints(scan_id, endpoint_id);
         CREATE INDEX IF NOT EXISTS idx_opportunities_scan_endpoint ON investigation_opportunities(scan_id, endpoint_id);",
    )?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS hostname_discoveries (
            scan_id TEXT NOT NULL, hostname_id TEXT NOT NULL, source TEXT NOT NULL,
            discovered_from TEXT, observed_at TEXT NOT NULL,
            PRIMARY KEY(scan_id, hostname_id),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
            FOREIGN KEY(hostname_id) REFERENCES hostnames(id)
        );
        CREATE TABLE IF NOT EXISTS service_observations (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, hostname TEXT NOT NULL,
            port INTEGER NOT NULL, protocol TEXT NOT NULL, is_open BOOLEAN NOT NULL,
            observed_at TEXT NOT NULL,
            UNIQUE(scan_id, hostname, port, protocol),
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
            FOREIGN KEY(hostname) REFERENCES hostnames(name)
        );
        CREATE TABLE IF NOT EXISTS tls_observations (
            id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, service_id TEXT NOT NULL,
            issuer TEXT NOT NULL, subject_ans TEXT NOT NULL, expires_at TEXT,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scan_runs(id),
            FOREIGN KEY(service_id) REFERENCES service_observations(id)
        );",
    )?;

    Ok(conn)
}

pub fn save_provider_status(
    conn: &Connection,
    scan_id: &Uuid,
    provider: &str,
    ok: bool,
    attempts: u8,
    discovered_count: usize,
    error_category: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO provider_statuses (scan_id, provider, status, attempts, discovered_count, error_category) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![scan_id.to_string(), provider, if ok { "OK" } else { "FAILED" }, attempts, discovered_count as i64, error_category],
    )?;
    Ok(())
}

pub fn save_endpoint_observation(
    conn: &Connection,
    scan_id: &Uuid,
    raw_url: &str,
    source: &str,
    source_reference: Option<&str>,
) -> Result<()> {
    let Some(endpoint) = crate::scan::normalize::normalize_endpoint(raw_url, None) else {
        return Ok(());
    };
    let id = crate::scan::normalize::endpoint_id(&endpoint);
    conn.execute("INSERT INTO endpoints (id, scheme, host, port, path, canonical_url, first_seen_scan, last_seen_scan) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) ON CONFLICT(canonical_url) DO UPDATE SET last_seen_scan=excluded.last_seen_scan", params![id, endpoint.scheme, endpoint.host, endpoint.port, endpoint.path, endpoint.canonical_url, scan_id.to_string()])?;
    conn.execute("INSERT OR IGNORE INTO endpoint_observations (endpoint_id, scan_id, raw_url, source, source_reference) VALUES (?1, ?2, ?3, ?4, ?5)", params![crate::scan::normalize::endpoint_id(&endpoint), scan_id.to_string(), raw_url, source, source_reference.unwrap_or("")])?;
    Ok(())
}

pub fn save_javascript_observation(
    conn: &Connection,
    scan_id: &Uuid,
    source_url: &str,
    endpoint_source: &str,
    candidate: &crate::scan::javascript::JavaScriptCandidate,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO javascript_observations (scan_id, source_url, kind, raw_value, resolved_url) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![scan_id.to_string(), source_url, candidate.kind, candidate.raw_value, candidate.resolved_url],
    )?;
    if let Some(url) = &candidate.resolved_url
        && matches!(candidate.kind, "http_call" | "url_literal")
    {
        save_endpoint_observation(conn, scan_id, url, endpoint_source, Some(source_url))?;
    }
    Ok(())
}

pub fn save_source_map_observation(
    conn: &Connection,
    scan_id: &Uuid,
    script_url: &str,
    map_url: &str,
    source_file: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO source_map_observations (scan_id, script_url, map_url, source_file) VALUES (?1, ?2, ?3, ?4)",
        params![scan_id.to_string(), script_url, map_url, source_file],
    )?;
    Ok(())
}

/// Rebuilds scan-scoped, deterministic labels from all retained endpoint
/// observations. This operates solely on the local inventory database.
pub fn classify_scan_inventory(conn: &Connection, scan_id: &Uuid) -> Result<()> {
    let scan_id = scan_id.to_string();
    let tx = conn.unchecked_transaction()?;
    let rows = tx.prepare(
        "SELECT e.id, e.canonical_url FROM endpoints e JOIN endpoint_observations o ON o.endpoint_id=e.id WHERE o.scan_id=?1 GROUP BY e.id, e.canonical_url ORDER BY e.canonical_url, e.id",
    )?
        .query_map(params![scan_id.to_string()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>>>()?;
    // Derived semantics are rebuilt, not accumulated. This also removes stale
    // rows after a classifier upgrade while retaining every raw observation.
    tx.execute(
        "DELETE FROM endpoint_classifications WHERE scan_id=?1",
        params![scan_id],
    )?;
    tx.execute(
        "DELETE FROM parameter_semantics WHERE scan_id=?1",
        params![scan_id],
    )?;
    for (endpoint_id, canonical_url) in rows {
        let raw_urls = {
            let mut statement = tx.prepare(
                "SELECT raw_url FROM endpoint_observations WHERE scan_id=?1 AND endpoint_id=?2 ORDER BY raw_url, source, source_reference",
            )?;
            statement
                .query_map(params![scan_id, endpoint_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>>>()?
        };
        for class in crate::scan::classify::endpoint_classes(&canonical_url) {
            tx.execute(
                "INSERT OR IGNORE INTO endpoint_classifications (scan_id, endpoint_id, class) VALUES (?1, ?2, ?3)",
                params![scan_id, endpoint_id, class],
            )?;
        }
        let mut parameters = std::collections::BTreeSet::new();
        for raw_url in raw_urls {
            if let Ok(url) = reqwest::Url::parse(&raw_url) {
                parameters.extend(url.query_pairs().map(|(name, _)| name.into_owned()));
            }
        }
        for name in parameters {
            tx.execute(
                "INSERT INTO parameter_semantics (scan_id, endpoint_id, parameter_name, semantic) VALUES (?1, ?2, ?3, ?4)",
                params![scan_id, endpoint_id, name, crate::scan::classify::parameter_semantic(&name)],
            )?;
        }
    }
    tx.commit()
}

pub fn load_response_fingerprints(
    conn: &Connection,
    scan_id: &Uuid,
    endpoint_id: Option<&str>,
) -> Result<Vec<crate::scan::fingerprint::ResponseFingerprint>> {
    let sql = if endpoint_id.is_some() {
        "SELECT status, body_length, captured_length, body_complete, raw_hash, normalized_hash, content_type, header_hash, redirect_target, json_shape_hash, timing_bucket FROM response_fingerprints WHERE scan_id=?1 AND endpoint_id=?2"
    } else {
        "SELECT status, body_length, captured_length, body_complete, raw_hash, normalized_hash, content_type, header_hash, redirect_target, json_shape_hash, timing_bucket FROM response_fingerprints WHERE scan_id=?1"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = if let Some(endpoint_id) = endpoint_id {
        stmt.query_map(
            params![scan_id.to_string(), endpoint_id],
            fingerprint_from_row,
        )?
    } else {
        stmt.query_map(params![scan_id.to_string()], fingerprint_from_row)?
    };
    rows.collect()
}

fn fingerprint_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<crate::scan::fingerprint::ResponseFingerprint> {
    Ok(crate::scan::fingerprint::ResponseFingerprint {
        status: row.get::<_, i64>(0)? as u16,
        body_length: row.get::<_, i64>(1)? as usize,
        captured_length: row.get::<_, i64>(2)? as usize,
        body_complete: row.get(3)?,
        raw_hash: row.get(4)?,
        normalized_hash: row.get(5)?,
        content_type: row.get(6)?,
        header_hash: row.get(7)?,
        redirect_target: row.get(8)?,
        json_shape_hash: row.get(9)?,
        timing_bucket: serde_json::from_str(&row.get::<_, String>(10)?)
            .unwrap_or(crate::scan::fingerprint::TimingBucket::Unknown),
    })
}

pub fn save_scan_run(conn: &Connection, scan_run: &ScanRun) -> Result<()> {
    let root_scope_str = serde_json::to_string(&scan_run.root_scope).unwrap_or_default();
    conn.execute(
        "INSERT INTO scan_runs (id, started_at, finished_at, root_scope, config_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET finished_at = EXCLUDED.finished_at",
        params![
            scan_run.id.to_string(),
            scan_run.started_at.to_rfc3339(),
            scan_run.finished_at.map(|t| t.to_rfc3339()),
            root_scope_str,
            scan_run.config_hash
        ],
    )?;
    Ok(())
}

pub fn finish_scan_run(conn: &Connection, scan_run_id: &Uuid) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE scan_runs SET finished_at = ?1 WHERE id = ?2",
        params![now, scan_run_id.to_string()],
    )?;
    Ok(())
}

pub fn get_previous_compatible_scan(conn: &Connection, current: &ScanRun) -> Result<Option<Uuid>> {
    let scope = serde_json::to_string(&current.root_scope).unwrap_or_default();
    let result = conn.query_row(
        "SELECT id FROM scan_runs WHERE finished_at IS NOT NULL AND id != ?1
         AND root_scope = ?2 AND config_hash = ?3 ORDER BY finished_at DESC LIMIT 1",
        params![current.id.to_string(), scope, current.config_hash],
        |row| row.get::<_, String>(0),
    );
    match result {
        Ok(id) => Ok(Uuid::parse_str(&id).ok()),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub struct ObservationBundle {
    pub scan_id: Uuid,
    pub hostname: Hostname,
    pub dns_records: Vec<DnsRecord>,
    pub services: Vec<ServiceRecord>,
    pub tls_records: Vec<TlsRecord>,
    pub technologies: Vec<TechnologyObservation>,
    pub http_observations: Vec<HttpObservation>,
}

pub fn insert_bundle_batch(conn: &mut Connection, bundles: &[ObservationBundle]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt_host = tx.prepare(
            "INSERT INTO hostnames (id, name, source, discovered_from)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO NOTHING",
        )?;

        let mut stmt_discovery = tx.prepare(
            "INSERT INTO hostname_discoveries (scan_id, hostname_id, source, discovered_from, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(scan_id, hostname_id) DO NOTHING",
        )?;

        let mut stmt_dns = tx.prepare(
            "INSERT INTO dns_records (id, scan_id, hostname_id, record_type, value, ttl, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET observed_at = EXCLUDED.observed_at",
        )?;

        let mut stmt_svc = tx.prepare(
            "INSERT INTO service_observations (id, scan_id, hostname, port, protocol, is_open, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;

        let mut stmt_tls = tx.prepare(
            "INSERT INTO tls_observations (id, scan_id, service_id, issuer, subject_ans, expires_at, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;

        let mut stmt_tech = tx.prepare(
            "INSERT INTO technology_observations 
             (id, scan_id, endpoint_url, name, version, confidence, evidence, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET confidence = EXCLUDED.confidence",
        )?;

        let mut stmt_http = tx.prepare(
            "INSERT INTO http_observations 
             (id, scan_id, hostname, url, status_code, title, server_header, rtt_ms, content_length, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
               status_code = EXCLUDED.status_code,
               title = EXCLUDED.title,
               server_header = EXCLUDED.server_header,
               rtt_ms = EXCLUDED.rtt_ms,
               content_length = EXCLUDED.content_length,
               observed_at = EXCLUDED.observed_at",
        )?;
        let mut stmt_endpoint = tx.prepare("INSERT INTO endpoints (id, scheme, host, port, path, canonical_url, first_seen_scan, last_seen_scan) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) ON CONFLICT(canonical_url) DO UPDATE SET last_seen_scan=excluded.last_seen_scan")?;
        let mut stmt_endpoint_observation = tx.prepare("INSERT OR IGNORE INTO endpoint_observations (endpoint_id, scan_id, raw_url, source, source_reference) VALUES (?1, ?2, ?3, ?4, ?5)")?;
        let mut stmt_fingerprint = tx.prepare("INSERT OR REPLACE INTO response_fingerprints (http_observation_id, scan_id, endpoint_id, status, body_length, captured_length, body_complete, raw_hash, normalized_hash, content_type, header_hash, redirect_target, json_shape_hash, timing_bucket) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)")?;

        for bundle in bundles {
            // Save Hostname
            stmt_host.execute(params![
                bundle.hostname.id,
                bundle.hostname.name,
                bundle.hostname.source.to_string(),
                bundle.hostname.discovered_from,
            ])?;
            stmt_discovery.execute(params![
                bundle.scan_id.to_string(),
                bundle.hostname.id,
                bundle.hostname.source.to_string(),
                bundle.hostname.discovered_from,
                chrono::Utc::now().to_rfc3339(),
            ])?;

            // Save DNS Records
            for dns in &bundle.dns_records {
                stmt_dns.execute(params![
                    dns.id,
                    dns.scan_id.to_string(),
                    dns.hostname_id,
                    dns.record_type,
                    dns.value,
                    dns.ttl,
                    dns.observed_at.to_rfc3339(),
                ])?;
            }

            // Save Services
            for svc in &bundle.services {
                stmt_svc.execute(params![
                    svc.id,
                    svc.scan_id.to_string(),
                    svc.hostname,
                    svc.port as i32,
                    svc.protocol,
                    svc.is_open,
                    svc.observed_at.to_rfc3339(),
                ])?;
            }

            // Save TLS Certificate
            for tls in &bundle.tls_records {
                let ans_json = serde_json::to_string(&tls.subject_ans).unwrap_or_default();
                stmt_tls.execute(params![
                    tls.id,
                    tls.scan_id.to_string(),
                    tls.service_id,
                    tls.issuer,
                    ans_json,
                    tls.expires_at,
                    tls.observed_at.to_rfc3339(),
                ])?;
            }

            // Save Technology Observations
            for tech in &bundle.technologies {
                let ev_json = serde_json::to_string(&tech.evidence).unwrap_or_default();
                stmt_tech.execute(params![
                    tech.id.to_string(),
                    tech.scan_id.to_string(),
                    tech.endpoint_url,
                    tech.name,
                    tech.version,
                    tech.confidence,
                    ev_json,
                    tech.observed_at.to_rfc3339(),
                ])?;
            }

            // Save HTTP Observation
            for http in &bundle.http_observations {
                stmt_http.execute(params![
                    http.id.to_string(),
                    http.scan_id.to_string(),
                    http.hostname,
                    http.url,
                    http.status_code.map(|s| s as i32),
                    http.title,
                    http.server_header,
                    http.rtt_ms.map(|r| r as i64),
                    http.content_length.map(|c| c as i64),
                    http.observed_at.to_rfc3339(),
                ])?;
                if let Some(endpoint) = crate::scan::normalize::normalize_endpoint(&http.url, None)
                {
                    let endpoint_id = crate::scan::normalize::endpoint_id(&endpoint);
                    stmt_endpoint.execute(params![
                        endpoint_id,
                        endpoint.scheme,
                        endpoint.host,
                        endpoint.port,
                        endpoint.path,
                        endpoint.canonical_url,
                        bundle.scan_id.to_string()
                    ])?;
                    stmt_endpoint_observation.execute(params![
                        crate::scan::normalize::endpoint_id(&endpoint),
                        bundle.scan_id.to_string(),
                        http.url,
                        "http_probe",
                        ""
                    ])?;
                    if let Some(fingerprint) = &http.fingerprint {
                        stmt_fingerprint.execute(params![
                            http.id.to_string(),
                            http.scan_id.to_string(),
                            crate::scan::normalize::endpoint_id(&endpoint),
                            fingerprint.status,
                            fingerprint.body_length as i64,
                            fingerprint.captured_length as i64,
                            fingerprint.body_complete,
                            fingerprint.raw_hash,
                            fingerprint.normalized_hash,
                            fingerprint.content_type,
                            fingerprint.header_hash,
                            fingerprint.redirect_target,
                            fingerprint.json_shape_hash,
                            serde_json::to_string(&fingerprint.timing_bucket).unwrap_or_default()
                        ])?;
                    }
                }
            }
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn start_db_writer(
    db_path: String,
) -> (
    mpsc::Sender<ObservationBundle>,
    tokio::task::JoinHandle<Result<()>>,
) {
    let (tx, mut rx) = mpsc::channel::<ObservationBundle>(1000);

    let handle = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut conn = init_db(&db_path)?;

        let mut batch = Vec::with_capacity(100);

        while let Some(bundle) = rx.blocking_recv() {
            batch.push(bundle);

            if batch.len() >= 100 {
                insert_bundle_batch(&mut conn, &batch)?;
                batch.clear();
            }
        }

        if !batch.is_empty() {
            insert_bundle_batch(&mut conn, &batch)?;
        }
        Ok(())
    });

    (tx, handle)
}

pub fn get_scan_observations(conn: &Connection, scan_id: &Uuid) -> Result<Vec<HttpObservation>> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, hostname, url, status_code, title, server_header, rtt_ms, content_length, observed_at 
         FROM http_observations WHERE scan_id = ?1 ORDER BY observed_at ASC",
    )?;

    let scan_id_str = scan_id.to_string();
    let obs_iter = stmt.query_map(params![scan_id_str], |row| {
        let id_str: String = row.get(0)?;
        let scan_id_str: String = row.get(1)?;
        let status_code: Option<i32> = row.get(4)?;
        let rtt_ms: Option<i64> = row.get(7)?;
        let content_len: Option<i64> = row.get(8)?;
        let obs_at_str: String = row.get(9)?;

        Ok(HttpObservation {
            id: Uuid::parse_str(&id_str).unwrap_or_default(),
            scan_id: Uuid::parse_str(&scan_id_str).unwrap_or_default(),
            hostname: row.get(2)?,
            url: row.get(3)?,
            status_code: status_code.map(|s| s as u16),
            title: row.get(5)?,
            server_header: row.get(6)?,
            rtt_ms: rtt_ms.map(|r| r as u64),
            content_length: content_len.map(|c| c as usize),
            observed_at: chrono::DateTime::parse_from_rfc3339(&obs_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            fingerprint: None,
        })
    })?;

    let mut observations = Vec::new();
    for obs in obs_iter {
        observations.push(obs?);
    }
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::models::{
        DiscoverySource, Hostname, HttpObservation, ServiceRecord, TlsRecord,
    };

    #[test]
    fn test_rescan_foreign_key_safety() {
        let mut conn = init_db(":memory:").expect("Failed to init in-memory DB");
        let scan_run = ScanRun::new(vec!["example.com".to_string()], "test_hash".to_string());
        save_scan_run(&conn, &scan_run).expect("Failed to save scan run");

        let host = Hostname::new("sub.example.com".to_string(), DiscoverySource::Seed, None);
        let http_obs = HttpObservation::new(
            scan_run.id,
            "sub.example.com".to_string(),
            "https://sub.example.com".to_string(),
        )
        .with_response(Some(200), Some("Test".to_string()), None, Some(50), None);

        let bundle1 = ObservationBundle {
            scan_id: scan_run.id,
            hostname: host.clone(),
            dns_records: Vec::new(),
            services: Vec::new(),
            tls_records: Vec::new(),
            technologies: Vec::new(),
            http_observations: vec![http_obs.clone()],
        };

        // First scan insert
        insert_bundle_batch(&mut conn, &[bundle1]).expect("First scan batch insert failed");

        // Second scan insert (rescan of exact same host with foreign keys ON)
        let bundle2 = ObservationBundle {
            scan_id: scan_run.id,
            hostname: host,
            dns_records: Vec::new(),
            services: Vec::new(),
            tls_records: Vec::new(),
            technologies: Vec::new(),
            http_observations: vec![http_obs],
        };

        insert_bundle_batch(&mut conn, &[bundle2])
            .expect("Rescan batch insert failed due to foreign key failure!");
    }

    #[test]
    fn preserves_scan_scoped_history() {
        let mut conn = init_db(":memory:").unwrap();
        let mut first = ScanRun::new(vec!["example.com".into()], "same-config".into());
        let second = ScanRun::new(vec!["example.com".into()], "same-config".into());
        save_scan_run(&conn, &first).unwrap();
        save_scan_run(&conn, &second).unwrap();
        let name = "api.example.com".to_string();
        for (run, source) in [
            (first.id, DiscoverySource::Seed),
            (second.id, DiscoverySource::TlsSan),
        ] {
            let service = ServiceRecord::new(run, name.clone(), 443, "tcp".into(), true);
            let tls = TlsRecord::new(
                run,
                service.id.clone(),
                if run == first.id {
                    "issuer-a"
                } else {
                    "issuer-b"
                }
                .into(),
                vec![name.clone()],
                None,
            );
            let mut services = vec![service];
            let mut http_observations = vec![HttpObservation::new(
                run,
                name.clone(),
                format!("https://{name}"),
            )];
            if run == second.id {
                services.push(ServiceRecord::new(
                    run,
                    name.clone(),
                    8080,
                    "tcp".into(),
                    true,
                ));
                http_observations.push(HttpObservation::new(
                    run,
                    name.clone(),
                    format!("http://{name}:8080"),
                ));
            }
            let bundle = ObservationBundle {
                scan_id: run,
                hostname: Hostname::new(name.clone(), source, None),
                dns_records: Vec::new(),
                services,
                tls_records: vec![tls],
                technologies: Vec::new(),
                http_observations,
            };
            insert_bundle_batch(&mut conn, &[bundle]).unwrap();
        }
        for table in [
            "service_observations",
            "tls_observations",
            "hostname_discoveries",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                count,
                if table == "service_observations" {
                    3
                } else {
                    2
                },
                "{table}"
            );
        }
        let first_source: String = conn
            .query_row(
                "SELECT source FROM hostname_discoveries WHERE scan_id = ?1",
                params![first.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first_source, "Seed");
        let comparison =
            crate::report::diff::compare_scan_runs(&conn, &first.id, &second.id).unwrap();
        assert_eq!(comparison.changed_tls, vec!["api.example.com:443"]);
        assert_eq!(comparison.new_services, vec!["api.example.com:8080/tcp"]);
        assert_eq!(
            comparison.new_endpoints,
            vec!["http://api.example.com:8080"]
        );
        first.complete();
        save_scan_run(&conn, &first).unwrap();
        assert_eq!(
            get_previous_compatible_scan(&conn, &second).unwrap(),
            Some(first.id)
        );
        let other = ScanRun::new(vec!["other.com".into()], "same-config".into());
        assert_eq!(get_previous_compatible_scan(&conn, &other).unwrap(), None);
        let changed_config = ScanRun::new(vec!["example.com".into()], "different-config".into());
        assert_eq!(
            get_previous_compatible_scan(&conn, &changed_config).unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn writer_reports_failed_batches() {
        let (tx, handle) = start_db_writer(":memory:".into());
        let run = Uuid::new_v4();
        tx.send(ObservationBundle {
            scan_id: run,
            hostname: Hostname::new("example.com".into(), DiscoverySource::Seed, None),
            dns_records: Vec::new(),
            services: Vec::new(),
            tls_records: Vec::new(),
            technologies: Vec::new(),
            http_observations: vec![HttpObservation::new(
                run,
                "example.com".into(),
                "https://example.com".into(),
            )],
        })
        .await
        .unwrap();
        drop(tx);
        assert!(handle.await.unwrap().is_err());
    }

    #[test]
    fn provider_status_schema_and_scan_association_are_created_non_destructively() {
        let conn = init_db(":memory:").unwrap();
        let run = ScanRun::new(vec!["example.com".into()], "test".into());
        save_scan_run(&conn, &run).unwrap();
        save_provider_status(&conn, &run.id, "crt.sh", true, 2, 3, None).unwrap();
        let row: (String, String, i64, i64) = conn.query_row(
            "SELECT status, scan_id, attempts, discovered_count FROM provider_statuses WHERE provider='crt.sh'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(row.0, "OK");
        assert_eq!(row.1, run.id.to_string());
        assert_eq!((row.2, row.3), (2, 3));
    }

    #[test]
    fn existing_database_is_upgraded_without_losing_scan_rows() {
        let path = std::env::temp_dir().join(format!("recon_pre_phase1_{}.db", Uuid::new_v4()));
        let legacy = Connection::open(&path).unwrap();
        legacy.execute("CREATE TABLE scan_runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, root_scope TEXT NOT NULL, config_hash TEXT NOT NULL)", []).unwrap();
        legacy
            .execute(
                "INSERT INTO scan_runs VALUES ('legacy', 'now', NULL, 'example.com', 'hash')",
                [],
            )
            .unwrap();
        drop(legacy);
        let conn = init_db(path.to_str().unwrap()).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM scan_runs WHERE id='legacy'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        conn.query_row("SELECT count(*) FROM provider_statuses", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        conn.execute(
            "INSERT INTO provider_statuses VALUES ('legacy','crt.sh','OK',1,1,NULL)",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT scan_id FROM provider_statuses", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "legacy"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn endpoint_identity_dedupes_raw_observations_with_provenance() {
        let conn = init_db(":memory:").unwrap();
        let run = ScanRun::new(vec!["example.com".into()], "test".into());
        save_scan_run(&conn, &run).unwrap();
        save_endpoint_observation(
            &conn,
            &run.id,
            "https://API.example.com:443/api/users?id=1",
            "crawler",
            Some("page"),
        )
        .unwrap();
        save_endpoint_observation(
            &conn,
            &run.id,
            "https://api.example.com/api/users?id=2",
            "javascript",
            Some("admin.js"),
        )
        .unwrap();
        save_endpoint_observation(
            &conn,
            &run.id,
            "https://api.example.com/api/users?id=2",
            "javascript",
            Some("app.js"),
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM endpoints", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM endpoint_observations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn javascript_evidence_preserves_source_and_does_not_require_activation() {
        let conn = init_db(":memory:").unwrap();
        let run = ScanRun::new(vec!["example.com".into()], "javascript".into());
        save_scan_run(&conn, &run).unwrap();
        let candidate = crate::scan::javascript::JavaScriptCandidate {
            kind: "http_call",
            raw_value: "/api/users?id=1".into(),
            resolved_url: Some("https://example.com/api/users?id=1".into()),
        };
        save_javascript_observation(
            &conn,
            &run.id,
            "https://example.com/assets/app.js",
            "javascript",
            &candidate,
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM javascript_observations", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT source_reference FROM endpoint_observations WHERE source='javascript'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap(),
            "https://example.com/assets/app.js"
        );
    }

    #[test]
    fn inventory_classification_covers_provenance_deduplication_and_scan_isolation() {
        let conn = init_db(":memory:").unwrap();
        let run = ScanRun::new(vec!["example.com".into()], "classify".into());
        let other = ScanRun::new(vec!["example.com".into()], "other".into());
        save_scan_run(&conn, &run).unwrap();
        save_scan_run(&conn, &other).unwrap();
        // Two historical observations with different values share one canonical
        // endpoint and yield a deduplicated set of parameter names.
        save_endpoint_observation(
            &conn,
            &run.id,
            "https://example.com/admin/api/users/redirect?redirect=/home&account_id=7&page=1",
            "historical",
            Some("wayback"),
        )
        .unwrap();
        save_endpoint_observation(
            &conn,
            &run.id,
            "https://example.com/admin/api/users/redirect?redirect=/dashboard&account_id=8&page=2",
            "historical",
            Some("common_crawl"),
        )
        .unwrap();
        // URL-bearing JavaScript/source-map evidence is safely associated.
        for (source, url) in [
            (
                "javascript",
                "https://example.com/api/search?q=rust&query=viewer",
            ),
            (
                "source_map",
                "https://example.com/api/search?q=rust&cursor=end",
            ),
        ] {
            let candidate = crate::scan::javascript::JavaScriptCandidate {
                kind: "http_call",
                raw_value: url.into(),
                resolved_url: Some(url.into()),
            };
            save_javascript_observation(
                &conn,
                &run.id,
                "https://example.com/app.js",
                source,
                &candidate,
            )
            .unwrap();
        }
        // An unassociated JS name remains intelligence and is not invented as
        // an endpoint parameter.
        let loose = crate::scan::javascript::JavaScriptCandidate {
            kind: "parameter_name",
            raw_value: "userId".into(),
            resolved_url: None,
        };
        save_javascript_observation(
            &conn,
            &run.id,
            "https://example.com/app.js",
            "javascript",
            &loose,
        )
        .unwrap();
        save_endpoint_observation(
            &conn,
            &other.id,
            "https://example.com/debug?file=x",
            "http_probe",
            None,
        )
        .unwrap();

        classify_scan_inventory(&conn, &run.id).unwrap();
        let classes = conn
            .prepare("SELECT class FROM endpoint_classifications WHERE scan_id=?1 ORDER BY class")
            .unwrap()
            .query_map(params![run.id.to_string()], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(classes.contains(&"Api".into()));
        assert!(classes.contains(&"UserProfile".into()));
        assert!(classes.contains(&"Redirect".into()));
        assert!(classes.contains(&"Admin".into()));
        assert_eq!(
            conn.prepare("SELECT parameter_name || ':' || semantic FROM parameter_semantics WHERE scan_id=?1 ORDER BY parameter_name")
                .unwrap().query_map(params![run.id.to_string()], |row| row.get::<_, String>(0)).unwrap()
                .collect::<Result<Vec<_>>>().unwrap(),
            ["account_id:AccountId", "cursor:Pagination", "page:Pagination", "q:Search", "query:Query", "redirect:Redirect"]
        );
        assert_eq!(conn.query_row("SELECT count(*) FROM parameter_semantics WHERE scan_id=?1 AND parameter_name='userId'", params![run.id.to_string()], |row| row.get::<_, i64>(0)).unwrap(), 0);

        let before = conn
            .query_row(
                "SELECT count(*) FROM endpoint_classifications WHERE scan_id=?1",
                params![run.id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        classify_scan_inventory(&conn, &run.id).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM endpoint_classifications WHERE scan_id=?1",
                params![run.id.to_string()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            before
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM endpoint_classifications WHERE scan_id=?1",
                params![other.id.to_string()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        classify_scan_inventory(&conn, &other.id).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT class FROM endpoint_classifications WHERE scan_id=?1",
                params![other.id.to_string()],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "Debug"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM endpoint_classifications WHERE scan_id=?1",
                params![run.id.to_string()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            before
        );
    }

    #[test]
    fn fingerprint_history_is_scan_and_endpoint_scoped() {
        let conn = init_db(":memory:").unwrap();
        let a = ScanRun::new(vec!["example.com".into()], "a".into());
        let b = ScanRun::new(vec!["example.com".into()], "b".into());
        save_scan_run(&conn, &a).unwrap();
        save_scan_run(&conn, &b).unwrap();
        conn.execute(
            "INSERT INTO hostnames VALUES ('example.com','example.com','Seed',NULL)",
            [],
        )
        .unwrap();
        for (scan, observation, hash) in [(&a, "oa", "ha"), (&b, "ob", "hb")] {
            conn.execute("INSERT INTO endpoints VALUES ('ep','https','example.com',NULL,'/','https://example.com/',?1,?1) ON CONFLICT(id) DO NOTHING", params![scan.id.to_string()]).unwrap();
            conn.execute("INSERT INTO http_observations VALUES (?1,?2,'example.com','https://example.com/',200,NULL,NULL,NULL,NULL,'now')", params![observation, scan.id.to_string()]).unwrap();
            conn.execute("INSERT INTO response_fingerprints VALUES (?1,?2,'ep',200,1,1,1,?3,?3,NULL,'h',NULL,NULL,'\"very_fast\"')", params![observation, scan.id.to_string(), hash]).unwrap();
        }
        assert_eq!(
            load_response_fingerprints(&conn, &a.id, Some("ep")).unwrap()[0].raw_hash,
            "ha"
        );
        assert_eq!(
            load_response_fingerprints(&conn, &b.id, None).unwrap()[0].raw_hash,
            "hb"
        );
        assert!(
            load_response_fingerprints(&conn, &Uuid::new_v4(), None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn phase2a_database_upgrades_without_losing_provenance_or_provider_data() {
        let path = std::env::temp_dir().join(format!("recon_phase2a_{}.db", Uuid::new_v4()));
        let scan_id = Uuid::new_v4();
        let legacy = Connection::open(&path).unwrap();
        legacy.execute_batch("CREATE TABLE scan_runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, root_scope TEXT NOT NULL, config_hash TEXT NOT NULL);
            CREATE TABLE provider_statuses (scan_id TEXT NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, discovered_count INTEGER NOT NULL, error_category TEXT, PRIMARY KEY(scan_id,provider));
            CREATE TABLE endpoints (id TEXT PRIMARY KEY, scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER, path TEXT NOT NULL, canonical_url TEXT NOT NULL UNIQUE, first_seen_scan TEXT NOT NULL, last_seen_scan TEXT NOT NULL);
            CREATE TABLE endpoint_observations (endpoint_id TEXT NOT NULL, scan_id TEXT NOT NULL, raw_url TEXT NOT NULL, source TEXT NOT NULL, source_reference TEXT NOT NULL DEFAULT '', PRIMARY KEY(endpoint_id,scan_id,raw_url,source,source_reference));
            CREATE TABLE hostnames (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, source TEXT NOT NULL, discovered_from TEXT);
            CREATE TABLE http_observations (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, hostname TEXT NOT NULL, url TEXT NOT NULL, status_code INTEGER, title TEXT, server_header TEXT, rtt_ms INTEGER, content_length INTEGER, observed_at TEXT NOT NULL);")
            .unwrap();
        legacy
            .execute(
                "INSERT INTO scan_runs VALUES (?1, 'now', NULL, '[\"example.com\"]', 'phase2a')",
                params![scan_id.to_string()],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO provider_statuses VALUES (?1, 'crt.sh', 'OK', 2, 3, NULL)",
                params![scan_id.to_string()],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO endpoints VALUES ('ep', 'https', 'example.com', NULL, '/api', 'https://example.com/api', ?1, ?1)",
                params![scan_id.to_string()],
            )
            .unwrap();
        for source_reference in ["app.js", "admin.js"] {
            legacy
                .execute(
                    "INSERT INTO endpoint_observations VALUES ('ep', ?1, 'https://example.com/api?a=1', 'javascript', ?2)",
                    params![scan_id.to_string(), source_reference],
                )
                .unwrap();
        }
        legacy
            .execute(
                "INSERT INTO hostnames VALUES ('example.com', 'example.com', 'Seed', NULL)",
                [],
            )
            .unwrap();
        legacy
            .execute(
                "INSERT INTO http_observations VALUES ('obs', ?1, 'example.com', 'https://example.com/api', 200, NULL, NULL, 1, 0, 'now')",
                params![scan_id.to_string()],
            )
            .unwrap();
        drop(legacy);

        let conn = init_db(path.to_str().unwrap()).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT config_hash FROM scan_runs WHERE id=?1",
                params![scan_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .unwrap(),
            "phase2a"
        );
        assert_eq!(
            conn.query_row(
                "SELECT attempts || ':' || discovered_count FROM provider_statuses WHERE scan_id=?1 AND provider='crt.sh'",
                params![scan_id.to_string()],
                |r| r.get::<_, String>(0),
            )
            .unwrap(),
            "2:3"
        );
        let references = conn
            .prepare("SELECT source_reference FROM endpoint_observations WHERE endpoint_id='ep' ORDER BY source_reference")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(references, ["admin.js", "app.js"]);
        assert_eq!(
            conn.query_row(
                "SELECT canonical_url FROM endpoints WHERE id='ep'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap(),
            "https://example.com/api"
        );

        conn.execute(
            "INSERT INTO response_fingerprints VALUES ('obs', ?1, 'ep', 200, 7, 7, 1, 'raw', 'normal', NULL, 'headers', NULL, NULL, '\"unknown\"')",
            params![scan_id.to_string()],
        )
        .unwrap();
        let fingerprints = load_response_fingerprints(&conn, &scan_id, Some("ep")).unwrap();
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].raw_hash, "raw");
        assert_eq!(fingerprints[0].body_length, 7);

        // Phase 2F tables are added non-destructively and can classify the
        // endpoint observations retained by an older database.
        classify_scan_inventory(&conn, &scan_id).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT class FROM endpoint_classifications WHERE scan_id=?1",
                params![scan_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "Api"
        );
        assert_eq!(
            conn.query_row(
                "SELECT semantic FROM parameter_semantics WHERE scan_id=?1 AND parameter_name='a'",
                params![scan_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "Unknown"
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM investigation_opportunities",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM verification_attempts", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );

        drop(conn);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn phase3_database_upgrades_to_phase4_without_losing_evidence() {
        let path = std::env::temp_dir().join(format!("recon_phase3_{}.db", Uuid::new_v4()));
        let scan = ScanRun::new(vec!["example.com".into()], "phase3".into());
        let conn = init_db(path.to_str().unwrap()).unwrap();
        save_scan_run(&conn, &scan).unwrap();
        save_endpoint_observation(
            &conn,
            &scan.id,
            "https://example.com/api/users?id=1",
            "http_probe",
            None,
        )
        .unwrap();
        classify_scan_inventory(&conn, &scan.id).unwrap();
        let endpoint =
            crate::scan::normalize::normalize_endpoint("https://example.com/api/users?id=1", None)
                .unwrap();
        let endpoint_id = crate::scan::normalize::endpoint_id(&endpoint);
        conn.execute(
            "INSERT INTO hostnames VALUES ('example.com','example.com','Seed',NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO http_observations VALUES ('phase3-observation',?1,'example.com',?2,200,NULL,NULL,1,2,'now')",
            params![scan.id.to_string(), endpoint.canonical_url],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO response_fingerprints VALUES ('phase3-observation',?1,?2,200,2,2,1,'raw','normalized',NULL,'headers',NULL,NULL,'\"fast\"')",
            params![scan.id.to_string(), endpoint_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO investigation_opportunities VALUES ('opp',?1,?2,?3,'IdentifierHandling','fixture','[]',5,'Repeatable',NULL)",
            params![scan.id.to_string(), endpoint_id, endpoint.canonical_url],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO verification_attempts VALUES ('attempt',?1,'opp',1,'repeat',?2,NULL,NULL,'stable',NULL,'now')",
            params![scan.id.to_string(), endpoint.canonical_url],
        )
        .unwrap();
        conn.execute_batch(
            "DROP TABLE candidate_opportunities;
             DROP TABLE candidate_history_signals;
             DROP TABLE candidate_score_reasons;
             DROP TABLE correlated_candidates;",
        )
        .unwrap();
        drop(conn);

        let conn = init_db(path.to_str().unwrap()).unwrap();
        for table in [
            "scan_runs",
            "endpoints",
            "endpoint_observations",
            "response_fingerprints",
            "endpoint_classifications",
            "parameter_semantics",
            "investigation_opportunities",
            "verification_attempts",
        ] {
            assert!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap()
                    > 0,
                "{table} was not preserved"
            );
        }
        for table in [
            "correlated_candidates",
            "candidate_score_reasons",
            "candidate_history_signals",
            "candidate_opportunities",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        drop(conn);
        std::fs::remove_file(path).unwrap();
    }
}
