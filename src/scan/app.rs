use crate::cli::{self, Args, LlmBackend};
use crate::probes::crtsh;
use crate::probes::dns::AsyncDnsResolver;
use crate::report::{llm, reporting};
use crate::scan::events;
use crate::scan::pipeline::{ReconEvent, Scheduler, WorkItem};
use crate::scan::scope::ScopePolicy;
use crate::scan::worker;
use crate::storage::db;
use crate::storage::models::{DiscoverySource, ScanRun};
use crate::triage::{self, TriageConfig};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
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
    if raw_targets.is_empty() {
        return Err("Target file did not contain any targets".into());
    }

    // Build one policy for scheduling and HTTP redirects.
    let raw_scope = if !args.scope.is_empty() {
        args.scope.clone()
    } else {
        raw_targets.clone()
    };

    let scope_policy = ScopePolicy::new(raw_scope.clone());
    if scope_policy.allowed_roots.len() != raw_scope.len() || raw_scope.is_empty() {
        return Err("No valid scope domains were provided".into());
    }
    let mut root_scope: Vec<String> = scope_policy
        .allowed_roots
        .iter()
        .map(|root| root.as_str().to_string())
        .collect();
    root_scope.sort();
    root_scope.dedup();
    let mut seed_hosts: Vec<String> = raw_targets
        .iter()
        .map(|raw| {
            crate::scan::normalize::NormalizedHostname::new(raw)
                .map(|host| host.as_str().to_string())
                .ok_or_else(|| format!("Invalid target: {raw}"))
        })
        .collect::<Result<_, _>>()?;
    seed_hosts.sort();
    seed_hosts.dedup();
    let config = format!(
        "v2;passive={};scheme={:?};ports={:?};seeds={:?}",
        args.passive,
        args.scheme_strategy,
        crate::probes::services::DEFAULT_PORTS,
        seed_hosts
    );
    let config_hash = format!("{:x}", Sha256::digest(config.as_bytes()));

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

    let (work_tx, mut work_rx) = mpsc::unbounded_channel::<WorkItem>();
    let (event_tx, event_rx) = mpsc::channel::<ReconEvent>(10000);

    let scheduler = Scheduler::new(scope_policy, work_tx, args.max_targets);

    // Keep wildcard fingerprints for validating generated DNS candidates.
    let mut wildcard_ips = HashMap::new();
    for root_domain in &root_scope {
        if crate::scan::normalize::NormalizedHostname::new(root_domain).is_some_and(|h| h.is_ip()) {
            continue;
        }
        let ips = dns_resolver.wildcard_ips(root_domain).await;
        if !ips.is_empty() {
            println!(
                "⚠️  Wildcard DNS catch-all detected for domain: '{}'",
                root_domain
            );
            wildcard_ips.insert(root_domain.clone(), ips);
        }
    }
    let wildcard_ips = Arc::new(wildcard_ips);

    // Create the scan run.
    let mut scan_run = ScanRun::new(root_scope.clone(), config_hash);
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
        for root_domain in root_scope.iter().filter(|root| {
            !crate::scan::normalize::NormalizedHostname::new(root).is_some_and(|h| h.is_ip())
        }) {
            let ct_subdomains = crtsh::query_crtsh(&http_client, root_domain).await?;
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
    let mut set = JoinSet::new();
    let mut inflight = 0usize;

    // Drop main scheduler instance so channel closes when all worker tasks finish
    let main_scheduler = scheduler;

    loop {
        if inflight == 0 && work_rx.is_empty() {
            break;
        }

        tokio::select! {
            Some(work) = work_rx.recv(), if inflight < args.concurrency => {
                inflight += 1;
                let context = worker::WorkerContext {
                    client: probe_client.clone(), resolver: dns_resolver.clone(),
                    strategy: args.scheme_strategy, scan_id: scan_run.id,
                    bus: event_tx.clone(), scheduler: main_scheduler.clone(),
                    wildcard_ips: Arc::clone(&wildcard_ips),
                };

                set.spawn(worker::probe(work, context));
            }
            Some(result) = set.join_next(), if inflight > 0 => {
                result??;
                inflight -= 1;
            }
            else => break,
        }
    }

    let target_limit_exceeded = main_scheduler.limit_exceeded();
    drop(main_scheduler);

    // Drop event_tx & work_tx to close processor cleanly
    drop(event_tx);
    event_processor_handle.await??;

    // Drop db_tx to flush remaining SQLite records and await writer completion
    drop(db_tx);
    db_writer_handle.await??;

    if target_limit_exceeded {
        return Err(format!(
            "Scan exceeded --max-targets {}. Increase the limit to include all discovered hosts.",
            args.max_targets
        )
        .into());
    }

    // Mark the run complete after all observation bundles are written.
    scan_run.complete();
    db::finish_scan_run(&conn, &scan_run.id)?;

    println!("🎉 ScanRun {} completed successfully!", scan_run.id);

    if args.triage {
        let observations = db::get_scan_observations(&conn, &scan_run.id)?;
        let scope = ScopePolicy::new(root_scope);
        let triage_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(10)
            .user_agent("recon_test/1.0.0")
            .danger_accept_invalid_certs(true)
            .build()?;
        let review = triage::run(
            &triage_client,
            &scope,
            &observations,
            TriageConfig::from(&args),
            scan_run.id,
        )
        .await?;
        if args.llm_analyze {
            let provider = match args.llm_backend {
                LlmBackend::Ollama => Some(llm::LlmProvider::Ollama {
                    url: args.ollama_url.clone(),
                    model: args.ollama_model.clone(),
                }),
                LlmBackend::Anthropic => args
                    .anthropic_api_key
                    .as_ref()
                    .filter(|key| !key.trim().is_empty())
                    .map(|key| llm::LlmProvider::Anthropic {
                        api_key: key.clone(),
                        model: args.anthropic_model.clone(),
                        max_tokens: args.llm_max_tokens,
                    }),
            };
            if let Some(provider) = provider {
                println!("🤖 Analyzing verified review candidates with AI...");
                match triage::ai::analyze(&http_client, &provider, &review).await {
                    Ok(result) => {
                        match triage::ai::write(&result, std::path::Path::new(&args.triage_dir)) {
                            Ok(()) => println!(
                                "🤖 AI suggestions saved for {} finding(s).",
                                result.analyzed_findings
                            ),
                            Err(error) => {
                                eprintln!("⚠️  Could not save candidate AI triage: {error}")
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("⚠️  Candidate AI triage unavailable: {error}");
                        if let Err(write_error) = triage::ai::write_unavailable(
                            review.scan_id,
                            std::path::Path::new(&args.triage_dir),
                        ) {
                            eprintln!("⚠️  Could not save AI triage status: {write_error}");
                        }
                    }
                }
            } else {
                eprintln!("⚠️  Candidate AI triage skipped: ANTHROPIC_API_KEY is missing.");
                if let Err(error) = triage::ai::write_unavailable(
                    review.scan_id,
                    std::path::Path::new(&args.triage_dir),
                ) {
                    eprintln!("⚠️  Could not save AI triage status: {error}");
                }
            }
        }
    }

    reporting::report(args, &conn, &scan_run, &http_client).await
}
