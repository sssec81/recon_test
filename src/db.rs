use crate::models::{
    DnsRecord, Hostname, HttpObservation, ScanRun, ServiceRecord, TechnologyObservation, TlsRecord,
};
use rusqlite::{params, Connection, Result};
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
            hostname_id TEXT NOT NULL,
            record_type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INTEGER,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(hostname_id) REFERENCES hostnames(id)
        )",
        [],
    )?;

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

    Ok(conn)
}

pub fn save_scan_run(conn: &Connection, scan_run: &ScanRun) -> Result<()> {
    let root_scope_str = serde_json::to_string(&scan_run.root_scope).unwrap_or_default();
    conn.execute(
        "INSERT OR REPLACE INTO scan_runs (id, started_at, finished_at, root_scope, config_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
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

pub fn get_last_two_scan_runs(conn: &Connection) -> Result<Option<(ScanRun, ScanRun)>> {
    let mut stmt = conn.prepare(
        "SELECT id, started_at, finished_at, root_scope, config_hash FROM scan_runs ORDER BY started_at DESC LIMIT 2",
    )?;

    let runs_iter = stmt.query_map([], |row| {
        let id_str: String = row.get(0)?;
        let start_str: String = row.get(1)?;
        let finish_str: Option<String> = row.get(2)?;
        let scope_json: String = row.get(3)?;
        let hash: String = row.get(4)?;

        let root_scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();

        Ok(ScanRun {
            id: Uuid::parse_str(&id_str).unwrap_or_default(),
            started_at: chrono::DateTime::parse_from_rfc3339(&start_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            finished_at: finish_str.and_then(|f| {
                chrono::DateTime::parse_from_rfc3339(&f)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .ok()
            }),
            root_scope,
            config_hash: hash,
        })
    })?;

    let mut runs = Vec::new();
    for r in runs_iter {
        runs.push(r?);
    }

    if runs.len() == 2 {
        Ok(Some((runs[1].clone(), runs[0].clone())))
    } else {
        Ok(None)
    }
}

pub struct ObservationBundle {
    pub hostname: Hostname,
    pub dns_records: Vec<DnsRecord>,
    pub services: Vec<ServiceRecord>,
    pub tls_record: Option<TlsRecord>,
    pub technologies: Vec<TechnologyObservation>,
    pub http_observation: HttpObservation,
}

pub fn insert_bundle_batch(conn: &mut Connection, bundles: &[ObservationBundle]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt_host = tx.prepare(
            "INSERT OR REPLACE INTO hostnames (id, name, source, discovered_from)
             VALUES (?1, ?2, ?3, ?4)",
        )?;

        let mut stmt_dns = tx.prepare(
            "INSERT OR REPLACE INTO dns_records (id, hostname_id, record_type, value, ttl, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;

        let mut stmt_svc = tx.prepare(
            "INSERT OR REPLACE INTO services (id, hostname, port, protocol, is_open, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;

        let mut stmt_tls = tx.prepare(
            "INSERT OR REPLACE INTO tls_certificates (id, service_id, issuer, subject_ans, expires_at, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;

        let mut stmt_tech = tx.prepare(
            "INSERT OR REPLACE INTO technology_observations 
             (id, scan_id, endpoint_url, name, version, confidence, evidence, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;

        let mut stmt_http = tx.prepare(
            "INSERT OR REPLACE INTO http_observations 
             (id, scan_id, hostname, url, status_code, title, server_header, rtt_ms, content_length, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?;

        for bundle in bundles {
            // Save Hostname
            stmt_host.execute(params![
                bundle.hostname.id,
                bundle.hostname.name,
                bundle.hostname.source.to_string(),
                bundle.hostname.discovered_from,
            ])?;

            // Save DNS Records
            for dns in &bundle.dns_records {
                stmt_dns.execute(params![
                    dns.id,
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
                    svc.hostname,
                    svc.port as i32,
                    svc.protocol,
                    svc.is_open,
                    svc.observed_at.to_rfc3339(),
                ])?;
            }

            // Save TLS Certificate
            if let Some(ref tls) = bundle.tls_record {
                let ans_json = serde_json::to_string(&tls.subject_ans).unwrap_or_default();
                stmt_tls.execute(params![
                    tls.id,
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
            let http = &bundle.http_observation;
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
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn start_db_writer(db_path: String) -> mpsc::Sender<ObservationBundle> {
    let (tx, mut rx) = mpsc::channel::<ObservationBundle>(1000);

    tokio::task::spawn_blocking(move || {
        let mut conn = match init_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("❌ Failed to initialize SQLite database at '{}': {}", db_path, e);
                return;
            }
        };

        let mut batch = Vec::with_capacity(100);

        while let Some(bundle) = rx.blocking_recv() {
            batch.push(bundle);

            if batch.len() >= 100 {
                if let Err(e) = insert_bundle_batch(&mut conn, &batch) {
                    eprintln!("❌ Error flushing SQLite observation batch: {}", e);
                }
                batch.clear();
            }
        }

        if !batch.is_empty() {
            if let Err(e) = insert_bundle_batch(&mut conn, &batch) {
                eprintln!("❌ Error flushing final SQLite observation batch: {}", e);
            }
        }
    });

    tx
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
        })
    })?;

    let mut observations = Vec::new();
    for obs in obs_iter {
        observations.push(obs?);
    }
    Ok(observations)
}
