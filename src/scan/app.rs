use crate::cli::{self, Args};
use crate::probes::crtsh;
use crate::probes::dns::AsyncDnsResolver;
use crate::report::reporting;
use crate::scan::events;
use crate::scan::pipeline::{ReconEvent, Scheduler, WorkItem};
use crate::scan::scope::ScopePolicy;
use crate::scan::worker;
use crate::storage::db;
use crate::storage::models::{DiscoverySource, ScanRun};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

pub async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting Async Recon Engine v1.0.0...");

    // The shared client is used for crt.sh and optional LLM requests.
    let dns_resolver = AsyncDnsResolver::new();
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(5))
        .pool_max_idle_per_host(10)
        .user_agent("recon_test/1.0.0")
        .danger_accept_invalid_certs(true)
        .build()?;

    // Load targets before creating a scan run.
    let raw_targets = if let Some(ref single_target) = args.target {
        vec![single_target.clone()]
    } else if let Some(ref file_path) = args.file {
        match cli::load_targets_from_file(file_path) {
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
        return Err("Provide --target or --file to start a scan".into());
    };

    // Build one policy for scheduling and HTTP redirects.
    let root_scope = if !args.scope.is_empty() {
        args.scope.clone()
    } else {
        raw_targets.clone()
    };

    let scope_policy = ScopePolicy::new(root_scope.clone());
    if scope_policy.allowed_roots.is_empty() {
        return Err("No valid scope domains were provided".into());
    }

    // Active HTTP redirects must stay within the same scope as the seed targets.
    let redirect_scope = scope_policy.clone();
    let probe_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.stop();
            }
            if redirect_scope.allows_redirect_url(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .pool_max_idle_per_host(10)
        .user_agent("recon_test/1.0.0")
        .danger_accept_invalid_certs(true)
        .build()?;
    let conn = db::init_db(&args.db)?;
    let (db_tx, db_writer_handle) = db::start_db_writer(args.db.clone());
    println!("✅ Database WAL writer connected to '{}'", args.db);

    let (work_tx, mut work_rx) = mpsc::channel::<WorkItem>(10000);
    let (event_tx, event_rx) = mpsc::channel::<ReconEvent>(10000);

    let scheduler = Scheduler::new(scope_policy, work_tx);

    // Check wildcard DNS on root scope domains.
    for root_domain in &root_scope {
        if dns_resolver.is_wildcard_domain(root_domain).await {
            println!(
                "⚠️  Wildcard DNS catch-all detected for domain: '{}'",
                root_domain
            );
        }
    }

    // Create the scan run.
    let mut scan_run = ScanRun::new(root_scope.clone(), "v1.0.0".to_string());
    db::save_scan_run(&conn, &scan_run)?;
    println!("🆔 Initialized ScanRun session: {}", scan_run.id);

    // Submit seed targets.
    let mut queued_count = 0;
    for raw in &raw_targets {
        if scheduler.submit_raw_target(raw).await {
            queued_count += 1;
        }
    }

    // Add passive Certificate Transparency discoveries.
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

    let event_processor_handle =
        tokio::spawn(events::process_events(event_rx, db_tx.clone(), scan_run.id));

    // Dispatch work until workers stop adding new targets.
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut set = JoinSet::new();
    let mut inflight = 0usize;

    // Drop main scheduler instance so channel closes when all worker tasks finish
    let main_scheduler = scheduler;

    loop {
        if inflight == 0 && work_rx.is_empty() {
            break;
        }

        tokio::select! {
            Some(work) = work_rx.recv() => {
                inflight += 1;
                let sem = Arc::clone(&semaphore);
                let client = probe_client.clone();
                let resolver = dns_resolver.clone();
                let strategy = args.scheme_strategy;
                let scan_id = scan_run.id;
                let bus = event_tx.clone();
                let worker_scheduler = main_scheduler.clone();

                set.spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    worker::probe(work, client, resolver, strategy, scan_id, bus, worker_scheduler).await;
                });
            }
            Some(_) = set.join_next(), if inflight > 0 => {
                inflight -= 1;
            }
            else => break,
        }
    }

    drop(main_scheduler);

    // Drop event_tx & work_tx to close processor cleanly
    drop(event_tx);
    let _ = event_processor_handle.await;

    // Drop db_tx to flush remaining SQLite records and await writer completion
    drop(db_tx);
    let _ = db_writer_handle.await;

    // Mark the run complete after all observation bundles are written.
    scan_run.complete();
    db::finish_scan_run(&conn, &scan_run.id)?;

    println!("🎉 ScanRun {} completed successfully!", scan_run.id);

    reporting::report(args, &conn, scan_run.id, &http_client).await
}
