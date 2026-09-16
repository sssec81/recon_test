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
}
