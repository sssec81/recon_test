mod db;
mod exporter;
mod models;
mod scanner;

use clap::Parser;
use models::Target;
use scanner::SchemeStrategy;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Async Bug Bounty Subdomain Recon Tool v0.3.0
#[derive(Parser, Debug)]
#[command(author, version = "0.3.0", about = "Async Rust Recon Engine with Connection Pooling & SQLite WAL Queue")]
struct Args {
    /// Single target subdomain to probe
    #[arg(short, long)]
    target: Option<String>,

    /// Path to a text file containing target subdomains (one per line)
    #[arg(short, long)]
    file: Option<String>,

    /// Maximum concurrent scan tasks
    #[arg(short, long, default_value_t = 20)]
    concurrency: usize,

    /// Probing scheme strategy
    #[arg(long, value_enum, default_value_t = SchemeStrategy::HttpsFirst)]
    scheme_strategy: SchemeStrategy,

    /// Export scan results to JSON file
    #[arg(long)]
    export_json: Option<String>,

    /// Export scan results to CSV file
    #[arg(long)]
    export_csv: Option<String>,

    /// SQLite database storage file
    #[arg(long, default_value = "recon_data.db")]
    db: String,
}

fn load_targets_from_file(file_path: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut targets = Vec::new();
    for line in reader.lines() {
        let l = line?.trim().to_string();
        if !l.is_empty() && !l.starts_with('#') {
            targets.push(l);
        }
    }
    Ok(targets)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("🚀 Starting Async Recon Engine v0.3.0...");

    // 1. Start SQLite WAL mode database writer thread
    let db_tx = db::start_db_writer(args.db.clone());
    println!("✅ Database WAL writer connected to '{}'", args.db);

    // 2. Initialize shared HTTP Client with connection pooling
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .pool_max_idle_per_host(10)
        .user_agent("recon_test/0.3.0")
        .danger_accept_invalid_certs(true)
        .build()?;

    // 3. Determine targets to scan
    let targets = if let Some(single_target) = args.target {
        vec![single_target]
    } else if let Some(ref file_path) = args.file {
        match load_targets_from_file(file_path) {
            Ok(t) => {
                println!("📄 Loaded {} targets from file '{}'", t.len(), file_path);
                t
            }
            Err(e) => {
                eprintln!("❌ Failed to read target file '{}': {}", file_path, e);
                return Err(e.into());
            }
        }
    } else {
        println!("ℹ️  No target or file provided. Using sample target list.");
        vec![
            "example.com".to_string(),
            "httpbin.org".to_string(),
            "google.com".to_string(),
        ]
    };

    println!(
        "🔎 Scanning {} target(s) with concurrency limit of {} [Strategy: {:?}]...",
        targets.len(),
        args.concurrency,
        args.scheme_strategy
    );

    // 4. Rate-limited concurrent scanning with shared HTTP client
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut set = JoinSet::new();

    for target in targets {
        let sem = Arc::clone(&semaphore);
        let client = http_client.clone();
        let domain = target.clone();
        let strategy = args.scheme_strategy;
        let db_channel = db_tx.clone();

        set.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let scan = scanner::probe_subdomain(&client, &domain, strategy).await;
            let ip = scanner::resolve_ip(&domain).await;

            let target_obj = Target::new(
                domain,
                ip,
                scan.status_code,
                scan.title,
                scan.server,
                scan.rtt_ms,
            );

            // Send target observation to DB writer
            let _ = db_channel.send(target_obj.clone()).await;
            target_obj
        });
    }

    // 5. Collect scan execution results
    while let Some(res) = set.join_next().await {
        match res {
            Ok(target) => {
                let status_str = target
                    .status_code
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "ERR".to_string());
                let title_str = target
                    .title
                    .as_deref()
                    .unwrap_or("No Title");
                let server_str = target
                    .server
                    .as_deref()
                    .unwrap_or("Unknown Server");
                let rtt_str = target
                    .rtt_ms
                    .map(|r| format!("{}ms", r))
                    .unwrap_or_else(|| "N/A".to_string());
                let ip_str = target
                    .ip_address
                    .as_deref()
                    .unwrap_or("No IP");

                println!(
                    "  [{:<3}] {:<22} | RTT: {:<6} | Server: {:<12} | IP: {:<15} | Title: {}",
                    status_str, target.subdomain, rtt_str, server_str, ip_str, title_str
                );
            }
            Err(e) => eprintln!("❌ Task join error: {}", e),
        }
    }

    // Close channel sender so database writer flushes remaining records
    drop(db_tx);

    // Short yield to let DB blocking task finish flushing
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("🎉 Scan completed successfully!");

    // 6. Handle Data Export if requested
    if args.export_json.is_some() || args.export_csv.is_some() {
        let conn = db::init_db(&args.db)?;
        let all_targets = db::get_all_targets(&conn)?;

        if let Some(json_path) = args.export_json {
            exporter::export_json(&all_targets, &json_path)?;
            println!("💾 Exported {} target(s) to JSON: '{}'", all_targets.len(), json_path);
        }

        if let Some(csv_path) = args.export_csv {
            exporter::export_csv(&all_targets, &csv_path)?;
            println!("💾 Exported {} target(s) to CSV: '{}'", all_targets.len(), csv_path);
        }
    }

    Ok(())
}
