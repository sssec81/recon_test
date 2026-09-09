use crate::models::Target;
use rusqlite::{params, Connection, Result};

pub fn init_db(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS active_targets (
            id INTEGER PRIMARY KEY,
            subdomain TEXT NOT NULL UNIQUE,
            ip_address TEXT,
            status_code INTEGER,
            title TEXT,
            server TEXT,
            rtt_ms INTEGER
        )",
        [],
    )?;

    // Safe column additions for schema migrations
    let _ = conn.execute("ALTER TABLE active_targets ADD COLUMN title TEXT", []);
    let _ = conn.execute("ALTER TABLE active_targets ADD COLUMN server TEXT", []);
    let _ = conn.execute("ALTER TABLE active_targets ADD COLUMN rtt_ms INTEGER", []);

    Ok(conn)
}

pub fn insert_target(conn: &Connection, target: &Target) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO active_targets 
         (subdomain, ip_address, status_code, title, server, rtt_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            target.subdomain,
            target.ip_address,
            target.status_code.map(|s| s as i32),
            target.title,
            target.server,
            target.rtt_ms.map(|r| r as i64),
        ],
    )?;
    Ok(())
}

pub fn get_all_targets(conn: &Connection) -> Result<Vec<Target>> {
    let mut stmt = conn.prepare(
        "SELECT subdomain, ip_address, status_code, title, server, rtt_ms FROM active_targets ORDER BY id ASC",
    )?;

    let target_iter = stmt.query_map([], |row| {
        let status_code: Option<i32> = row.get(2)?;
        let rtt_ms: Option<i64> = row.get(5)?;
        Ok(Target {
            subdomain: row.get(0)?,
            ip_address: row.get(1)?,
            status_code: status_code.map(|s| s as u16),
            title: row.get(3)?,
            server: row.get(4)?,
            rtt_ms: rtt_ms.map(|r| r as u64),
        })
    })?;

    let mut targets = Vec::new();
    for target in target_iter {
        targets.push(target?);
    }
    Ok(targets)
}
