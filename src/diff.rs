use crate::models::HttpObservation;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusChange {
    pub hostname: String,
    pub old_status: Option<u16>,
    pub new_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpChange {
    pub hostname: String,
    pub old_ips: Vec<String>,
    pub new_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiffResult {
    pub scan_id_a: Uuid,
    pub scan_id_b: Uuid,
    pub new_subdomains: Vec<String>,
    pub removed_subdomains: Vec<String>,
    pub status_changes: Vec<StatusChange>,
    pub ip_changes: Vec<IpChange>,
    pub new_technologies: Vec<String>,
}

fn fetch_scan_http_obs(
    conn: &Connection,
    scan_id: &Uuid,
) -> Result<HashMap<String, HttpObservation>, Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare(
        "SELECT id, scan_id, hostname, url, status_code, title, server_header, rtt_ms, content_length, observed_at 
         FROM http_observations WHERE scan_id = ?1",
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

    let mut map = HashMap::new();
    for obs in obs_iter {
        let o = obs?;
        map.insert(o.hostname.clone(), o);
    }
    Ok(map)
}

fn fetch_scan_dns_records(
    conn: &Connection,
    scan_id: &Uuid,
    hostnames: &[String],
) -> Result<HashMap<String, Vec<String>>, Box<dyn std::error::Error>> {
    let mut map = HashMap::new();
    let scan_id_str = scan_id.to_string();

    for host in hostnames {
        let mut stmt = conn.prepare(
            "SELECT value FROM dns_records WHERE scan_id = ?1 AND hostname_id = ?2 AND (record_type = 'A' OR record_type = 'AAAA')",
        )?;
        let rows = stmt.query_map(params![scan_id_str, host.to_lowercase()], |row| {
            let val: String = row.get(0)?;
            Ok(val)
        })?;

        let mut ips = Vec::new();
        for r in rows {
            ips.push(r?);
        }
        ips.sort();
        map.insert(host.clone(), ips);
    }

    Ok(map)
}

fn fetch_scan_tech_obs(
    conn: &Connection,
    scan_id: &Uuid,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT name FROM technology_observations WHERE scan_id = ?1",
    )?;

    let scan_id_str = scan_id.to_string();
    let rows = stmt.query_map(params![scan_id_str], |row| {
        let name: String = row.get(0)?;
        Ok(name)
    })?;

    let mut tech = Vec::new();
    for r in rows {
        tech.push(r?);
    }
    Ok(tech)
}

pub fn compare_scan_runs(
    conn: &Connection,
    scan_id_a: &Uuid,
    scan_id_b: &Uuid,
) -> Result<ScanDiffResult, Box<dyn std::error::Error>> {
    let obs_a = fetch_scan_http_obs(conn, scan_id_a)?;
    let obs_b = fetch_scan_http_obs(conn, scan_id_b)?;

    let keys_a: HashSet<String> = obs_a.keys().cloned().collect();
    let keys_b: HashSet<String> = obs_b.keys().cloned().collect();

    // 1. Added & Removed Subdomains
    let mut new_subdomains: Vec<String> = keys_b.difference(&keys_a).cloned().collect();
    let mut removed_subdomains: Vec<String> = keys_a.difference(&keys_b).cloned().collect();
    new_subdomains.sort();
    removed_subdomains.sort();

    // 2. HTTP Status Code Changes
    let mut status_changes = Vec::new();
    for host in keys_a.intersection(&keys_b) {
        let item_a = obs_a.get(host).unwrap();
        let item_b = obs_b.get(host).unwrap();
        if item_a.status_code != item_b.status_code {
            status_changes.push(StatusChange {
                hostname: host.clone(),
                old_status: item_a.status_code,
                new_status: item_b.status_code,
            });
        }
    }

    // 3. DNS IP Changes (Scoped per ScanRun)
    let all_hosts: Vec<String> = keys_a.union(&keys_b).cloned().collect();
    let dns_a = fetch_scan_dns_records(conn, scan_id_a, &all_hosts)?;
    let dns_b = fetch_scan_dns_records(conn, scan_id_b, &all_hosts)?;

    let mut ip_changes = Vec::new();
    for host in keys_a.intersection(&keys_b) {
        let ips_a = dns_a.get(host).cloned().unwrap_or_default();
        let ips_b = dns_b.get(host).cloned().unwrap_or_default();
        if ips_a != ips_b {
            ip_changes.push(IpChange {
                hostname: host.clone(),
                old_ips: ips_a,
                new_ips: ips_b,
            });
        }
    }

    // 4. New Technology Detections
    let tech_a: HashSet<String> = fetch_scan_tech_obs(conn, scan_id_a)?.into_iter().collect();
    let tech_b: HashSet<String> = fetch_scan_tech_obs(conn, scan_id_b)?.into_iter().collect();

    let mut new_technologies: Vec<String> = tech_b.difference(&tech_a).cloned().collect();
    new_technologies.sort();

    Ok(ScanDiffResult {
        scan_id_a: *scan_id_a,
        scan_id_b: *scan_id_b,
        new_subdomains,
        removed_subdomains,
        status_changes,
        ip_changes,
        new_technologies,
    })
}
