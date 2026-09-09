mod db;
mod exporter;
mod models;
mod scanner;

use clap::Parser;
use models::{DiscoverySource, DnsRecord, Hostname, HttpObservation, ScanRun};
use scanner::SchemeStrategy;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Async Bug Bounty Subdomain Recon Engine v0.4.0
#[derive(Parser, Debug)]
#[command(author, version = "0.4.0", about = "Async Rust Recon Engine with Relational Asset Graph & ScanRun Session Lineage")]
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

    /// Export scan observations to JSON file
    #[arg(long)]
    export_json: Option<String>,

    /// Export scan observations to CSV file
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

    println!("🚀 Starting Async Recon Engine v0.4.0...");

    // 1. Initialize SQLite Database & start WAL writer channel
    let conn = db::init_db(&args.db)?;
    let db_tx = db::start_db_writer(args.db.clone());
    println!("✅ Database WAL writer connected to '{}'", args.db);

    // 2. Determine target scope
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

    // 3. Create ScanRun session
    let mut scan_run = ScanRun::new(targets.clone(), "v0.4.0".to_string());
    db::save_scan_run(&conn, &scan_run)?;
    println!("🆔 Initialized ScanRun session: {}", scan_run.id);

    // 4. Initialize shared HTTP Client with connection pooling
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .pool_max_idle_per_host(10)
        .user_agent("recon_test/0.4.0")
        .danger_accept_invalid_certs(true)
        .build()?;

    println!(
        "🔎 Scanning {} target(s) with concurrency limit of {} [Strategy: {:?}]...",
        targets.len(),
        args.concurrency,
        args.scheme_strategy
    );

    // 5. Rate-limited concurrent scanning
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut set = JoinSet::new();

    for target in targets {
        let sem = Arc::clone(&semaphore);
        let client = http_client.clone();
        let domain = target.clone();
        let strategy = args.scheme_strategy;
        let db_channel = db_tx.clone();
        let scan_id = scan_run.id;

        set.spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            // 5a. Create Hostname entity with Seed lineage
            let hostname = Hostname::new(domain.clone(), DiscoverySource::Seed, None);

            // 5b. Resolve IP and create DnsRecord
            let ip_opt = scanner::resolve_ip(&domain).await;
            let mut dns_records = Vec::new();
            if let Some(ref ip) = ip_opt {
                let rec_type = if ip.contains(':') { "AAAA" } else { "A" };
                dns_records.push(DnsRecord::new(
                    hostname.id.clone(),
                    rec_type.to_string(),
                    ip.clone(),
                    Some(300),
                ));
            }

            // 5c. Perform HTTP Probe
            let scan = scanner::probe_subdomain(&client, &domain, strategy).await;

            let url = if domain.starts_with("http://") || domain.starts_with("https://") {
                domain.clone()
            } else {
                format!("https://{}", domain)
            };

            let http_obs = HttpObservation::new(
                scan_id,
                domain.clone(),
                url,
                scan.status_code,
                scan.title,
                scan.server,
                scan.rtt_ms,
                None,
            );

            let bundle = db::ObservationBundle {
                hostname,
                dns_records,
                http_observation: http_obs.clone(),
            };

            // Send relational observation bundle to DB writer queue
            let _ = db_channel.send(bundle).await;

            http_obs
        });
    }

    // 6. Collect scan execution observations
    while let Some(res) = set.join_next().await {
        match res {
            Ok(obs) => {
                let status_str = obs
                    .status_code
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "ERR".to_string());
                let title_str = obs
                    .title
                    .as_deref()
                    .unwrap_or("No Title");
                let server_str = obs
                    .server_header
                    .as_deref()
                    .unwrap_or("Unknown Server");
                let rtt_str = obs
                    .rtt_ms
                    .map(|r| format!("{}ms", r))
                    .unwrap_or_else(|| "N/A".to_string());

                println!(
                    "  [{:<3}] {:<22} | RTT: {:<6} | Server: {:<12} | Title: {}",
                    status_str, obs.hostname, rtt_str, server_str, title_str
                );
            }
            Err(e) => eprintln!("❌ Task join error: {}", e),
        }
    }

    // Close channel sender so database writer flushes remaining records
    drop(db_tx);

    // Yield to let DB blocking task finish writing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 7. Complete ScanRun session
    scan_run.complete();
    db::finish_scan_run(&conn, &scan_run.id)?;

    println!("🎉 ScanRun {} completed successfully!", scan_run.id);

    // 8. Handle Data Export if requested
    if args.export_json.is_some() || args.export_csv.is_some() {
        let scan_observations = db::get_scan_observations(&conn, &scan_run.id)?;

        if let Some(json_path) = args.export_json {
            exporter::export_json(&scan_observations, &json_path)?;
            println!(
                "💾 Exported {} observation(s) from ScanRun {} to JSON: '{}'",
                scan_observations.len(),
                scan_run.id,
                json_path
            );
        }

        if let Some(csv_path) = args.export_csv {
            exporter::export_csv(&scan_observations, &csv_path)?;
            println!(
                "💾 Exported {} observation(s) from ScanRun {} to CSV: '{}'",
                scan_observations.len(),
                scan_run.id,
                csv_path
            );
        }
    }

    Ok(())
}
