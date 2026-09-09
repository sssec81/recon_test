use crate::models::Target;
use rusqlite::{params, Connection, Result};
use tokio::sync::mpsc;

pub fn init_db(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;

    // Performance PRAGMAs for high-throughput SQLite execution
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;",
    )?;

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

    let _ = conn.execute("ALTER TABLE active_targets ADD COLUMN title TEXT", []);
    let _ = conn.execute("ALTER TABLE active_targets ADD COLUMN server TEXT", []);
    let _ = conn.execute("ALTER TABLE active_targets ADD COLUMN rtt_ms INTEGER", []);

    Ok(conn)
}

pub fn insert_batch(conn: &mut Connection, targets: &[Target]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO active_targets 
             (subdomain, ip_address, status_code, title, server, rtt_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;

        for target in targets {
            stmt.execute(params![
                target.subdomain,
                target.ip_address,
                target.status_code.map(|s| s as i32),
                target.title,
                target.server,
                target.rtt_ms.map(|r| r as i64),
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn start_db_writer(db_path: String) -> mpsc::Sender<Target> {
    let (tx, mut rx) = mpsc::channel::<Target>(1000);

    tokio::task::spawn_blocking(move || {
        let mut conn = match init_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("❌ Failed to initialize SQLite database at '{}': {}", db_path, e);
                return;
            }
        };

        let mut batch = Vec::with_capacity(100);

        while let Some(target) = rx.blocking_recv() {
            batch.push(target);

            // Flush whenever batch reaches 100 items
            if batch.len() >= 100 {
                if let Err(e) = insert_batch(&mut conn, &batch) {
                    eprintln!("❌ Error flushing SQLite batch transaction: {}", e);
                }
                batch.clear();
            }
        }

        // Flush remaining items on channel closure
        if !batch.is_empty() {
            if let Err(e) = insert_batch(&mut conn, &batch) {
                eprintln!("❌ Error flushing final SQLite batch: {}", e);
            }
        }
    });

    tx
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
