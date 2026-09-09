mod crtsh;
mod db;
mod dns;
mod exporter;
mod models;
mod normalize;
mod pipeline;
mod scanner;
mod scope;
mod services;
mod tls;

use clap::Parser;
use dns::AsyncDnsResolver;
use models::{DiscoverySource, Hostname, HttpObservation, ScanRun, ServiceRecord, TlsRecord};
use pipeline::{ReconEvent, Scheduler, WorkItem};
use scanner::SchemeStrategy;
use scope::ScopePolicy;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

/// Async Bug Bounty Subdomain Recon Engine v0.8.0
#[derive(Parser, Debug)]
#[command(author, version = "0.8.0", about = "Async Rust Recon Engine with TCP Service Port Scanner & TLS SAN Feedback Loop")]
struct Args {
    /// Single target subdomain to probe
    #[arg(short, long)]
    target: Option<String>,

    /// Authorized root scope domains (e.g. --scope example.com)
    #[arg(short, long)]
    scope: Vec<String>,

    /// Path to a text file containing target subdomains (one per line)
    #[arg(short, long)]
    file: Option<String>,

    /// Maximum concurrent scan tasks
    #[arg(short, long, default_value_t = 20)]
    concurrency: usize,

    /// Enable passive Certificate Transparency reconnaissance
    #[arg(long, default_value_t = true)]
    passive: bool,

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

    println!("🚀 Starting Async Recon Engine v0.8.0...");

    // 1. Initialize SQLite Database & start WAL writer channel
    let conn = db::init_db(&args.db)?;
    let db_tx = db::start_db_writer(args.db.clone());
    println!("✅ Database WAL writer connected to '{}'", args.db);

    // 2. Initialize Async DNS Resolver & Shared HTTP Client
    let dns_resolver = AsyncDnsResolver::new();
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .pool_max_idle_per_host(10)
        .user_agent("recon_test/0.8.0")
        .danger_accept_invalid_certs(true)
        .build()?;

    // 3. Determine raw target inputs
    let raw_targets = if let Some(single_target) = args.target {
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

    // 4. Initialize Scope Policy & Work Scheduler
    let root_scope = if !args.scope.is_empty() {
        args.scope.clone()
    } else {
        raw_targets.clone()
    };

    let scope_policy = ScopePolicy::new(root_scope.clone());
    let (work_tx, mut work_rx) = mpsc::channel::<WorkItem>(10000);
    let (event_tx, mut event_rx) = mpsc::channel::<ReconEvent>(10000);

    let scheduler = Scheduler::new(scope_policy, work_tx);

    // 5. Check Wildcard DNS on root scope domains
    for root_domain in &root_scope {
        if dns_resolver.is_wildcard_domain(root_domain).await {
            println!("⚠️  Wildcard DNS catch-all detected for domain: '{}'", root_domain);
        }
    }

    // 6. Create ScanRun session
    let mut scan_run = ScanRun::new(root_scope.clone(), "v0.8.0".to_string());
    db::save_scan_run(&conn, &scan_run)?;
    println!("🆔 Initialized ScanRun session: {}", scan_run.id);

    // 7. Submit raw target inputs to Scheduler (Seed Lineage)
    let mut queued_count = 0;
    for raw in &raw_targets {
        if scheduler.submit_raw_target(raw).await {
            queued_count += 1;
        }
    }

    // 8. Perform Passive Reconnaissance (crt.sh Ingestion Feedback Loop)
    if args.passive {
        println!("📜 Ingesting passive Certificate Transparency logs (crt.sh)...");
        for root_domain in &root_scope {
            let ct_subdomains = crtsh::query_crtsh(&http_client, root_domain).await;
            println!(
                "  [crt.sh] Discovered {} candidate subdomain(s) for domain '{}'",
                ct_subdomains.len(),
                root_domain
            );
            for ct_sub in ct_subdomains {
                if scheduler
                    .submit_target_with_source(&ct_sub, DiscoverySource::CertificateTransparency)
                    .await
                {
                    queued_count += 1;
                }
            }
        }
    }

    println!(
        "🔎 Scheduler queued {} total in-scope target(s) for scanning [Strategy: {:?}]...",
        queued_count, args.scheme_strategy
    );

    // 9. Event Bus Processor Task
    let db_channel = db_tx.clone();
    let scheduler_clone = scheduler.clone();

    let event_processor_handle = tokio::spawn(async move {
        let mut pending_bundles: std::collections::HashMap<String, db::ObservationBundle> =
            std::collections::HashMap::new();

        while let Some(event) = event_rx.recv().await {
            match event {
                ReconEvent::HostnameDiscovered { hostname, source } => {
                    let name = hostname.as_str().to_string();
                    let host_entity = Hostname::new(name.clone(), source, None);
                    let dummy_http = HttpObservation::new(
                        scan_run.id,
                        name.clone(),
                        format!("https://{}", name),
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                    pending_bundles.insert(
                        name,
                        db::ObservationBundle {
                            hostname: host_entity,
                            dns_records: Vec::new(),
                            services: Vec::new(),
                            tls_record: None,
                            http_observation: dummy_http,
                        },
                    );
                }
                ReconEvent::DnsResolved { hostname, records } => {
                    let name = hostname.as_str().to_string();
                    if let Some(bundle) = pending_bundles.get_mut(&name) {
                        bundle.dns_records.extend(records);
                    }
                }
                ReconEvent::ServiceObserved { hostname, services } => {
                    let name = hostname.as_str().to_string();
                    if let Some(bundle) = pending_bundles.get_mut(&name) {
                        bundle.services.extend(services);
                    }
                }
                ReconEvent::TlsObserved { hostname, tls_record } => {
                    let name = hostname.as_str().to_string();

                    // TLS SAN Feedback Loop: feed SAN subdomains back into Scheduler
                    for san_domain in &tls_record.subject_ans {
                        scheduler_clone
                            .submit_target_with_source(san_domain, DiscoverySource::TlsSan)
                            .await;
                    }

                    if let Some(bundle) = pending_bundles.get_mut(&name) {
                        bundle.tls_record = Some(tls_record);
                    }
                }
                ReconEvent::HttpObserved(obs) => {
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
                        "  [{:<3}] {:<32} | RTT: {:<6} | Server: {:<12} | Title: {}",
                        status_str, obs.hostname, rtt_str, server_str, title_str
                    );

                    let name = obs.hostname.clone();
                    if let Some(mut bundle) = pending_bundles.remove(&name) {
                        bundle.http_observation = obs;
                        let _ = db_channel.send(bundle).await;
                    } else {
                        let host_entity = Hostname::new(name.clone(), DiscoverySource::Seed, None);
                        let bundle = db::ObservationBundle {
                            hostname: host_entity,
                            dns_records: Vec::new(),
                            services: Vec::new(),
                            tls_record: None,
                            http_observation: obs,
                        };
                        let _ = db_channel.send(bundle).await;
                    }
                }
            }
        }
    });

    // 10. Work Scheduler Dispatcher Loop
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut set = JoinSet::new();

    while let Some(work) = work_rx.recv().await {
        match work {
            WorkItem::ProbeTarget { hostname, source } => {
                let sem = Arc::clone(&semaphore);
                let client = http_client.clone();
                let resolver = dns_resolver.clone();
                let strategy = args.scheme_strategy;
                let scan_id = scan_run.id;
                let bus = event_tx.clone();

                set.spawn(async move {
                    let _permit = sem.acquire().await.unwrap();

                    // Emit HostnameDiscovered event
                    let _ = bus
                        .send(ReconEvent::HostnameDiscovered {
                            hostname: hostname.clone(),
                            source,
                        })
                        .await;

                    // Resolve multi-record DNS asynchronously
                    let dns_records = resolver.resolve_all(hostname.as_str()).await;
                    let _ = bus
                        .send(ReconEvent::DnsResolved {
                            hostname: hostname.clone(),
                            records: dns_records,
                        })
                        .await;

                    // Perform TCP Port Scan on default web ports
                    let open_ports = services::probe_open_ports(hostname.as_str(), services::DEFAULT_PORTS).await;
                    let service_records: Vec<ServiceRecord> = open_ports
                        .iter()
                        .map(|&port| ServiceRecord::new(hostname.as_str().to_string(), port, "tcp".to_string(), true))
                        .collect();

                    let _ = bus
                        .send(ReconEvent::ServiceObserved {
                            hostname: hostname.clone(),
                            services: service_records,
                        })
                        .await;

                    // Fetch TLS Certificate & SANs if port 443 or 8443 is open
                    if open_ports.contains(&443) || open_ports.contains(&8443) {
                        let tls_port = if open_ports.contains(&443) { 443 } else { 8443 };
                        let host_str = hostname.as_str().to_string();
                        let tls_info_opt = tokio::task::spawn_blocking(move || {
                            tls::fetch_tls_info(&host_str, tls_port)
                        })
                        .await
                        .ok()
                        .flatten();

                        if let Some(tls_info) = tls_info_opt {
                            let service_id = format!("{}:{}:tcp", hostname.as_str(), tls_port);
                            let tls_rec = TlsRecord::new(
                                service_id,
                                tls_info.issuer,
                                tls_info.san_domains,
                                tls_info.expires_at,
                            );

                            let _ = bus
                                .send(ReconEvent::TlsObserved {
                                    hostname: hostname.clone(),
                                    tls_record: tls_rec,
                                })
                                .await;
                        }
                    }

                    // Perform HTTP Probe & emit HttpObserved event
                    let scan = scanner::probe_subdomain(&client, hostname.as_str(), strategy).await;

                    let url = format!("https://{}", hostname.as_str());
                    let http_obs = HttpObservation::new(
                        scan_id,
                        hostname.as_str().to_string(),
                        url,
                        scan.status_code,
                        scan.title,
                        scan.server,
                        scan.rtt_ms,
                        None,
                    );

                    let _ = bus.send(ReconEvent::HttpObserved(http_obs)).await;
                });
            }
        }

        if work_rx.is_empty() {
            break;
        }
    }

    // Wait for worker tasks to complete
    while let Some(_) = set.join_next().await {}

    // Drop event_tx & work_tx to close processor cleanly
    drop(event_tx);
    let _ = event_processor_handle.await;

    // Drop db_tx to flush remaining SQLite records
    drop(db_tx);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 11. Complete ScanRun session
    scan_run.complete();
    db::finish_scan_run(&conn, &scan_run.id)?;

    println!("🎉 ScanRun {} completed successfully!", scan_run.id);

    // 12. Handle Data Export if requested
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
