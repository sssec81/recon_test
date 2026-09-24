use crate::cli::{self, Args, LlmBackend};
use crate::probes::crtsh;
use crate::probes::crtsh::DiscoveryProvider;
use crate::probes::dns::AsyncDnsResolver;
use crate::probes::historical::{CommonCrawlProvider, WaybackProvider, in_scope_historical_urls};
use crate::report::{llm, reporting};
use crate::scan::events;
use crate::scan::network::{ProbePolicy, RequestScheduler, ScanContext};
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
    let probe_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(10)
        .user_agent("recon_test/1.0.0")
        .danger_accept_invalid_certs(true)
        .build()?;
    let target_scheduler = RequestScheduler::new(
        probe_client.clone(),
        scope_policy.clone(),
        args.concurrency,
        args.triage_max_requests
            .saturating_add(
                args.verification_max_opportunities
                    .saturating_mul(args.verification_requests_per_opportunity.min(2)),
            )
            .saturating_add(args.max_targets.saturating_mul(8)),
        20,
        5,
        Some(
            std::time::Instant::now()
                + Duration::from_secs(args.triage_max_minutes.saturating_mul(60).max(60)),
        ),
    );
    let scan_context = ScanContext {
        scope: scope_policy.clone(),
        target_http: Arc::new(target_scheduler.clone()),
        probes: Arc::new(ProbePolicy::new(
            scope_policy.clone(),
            args.concurrency,
            Some(
                std::time::Instant::now()
                    + Duration::from_secs(args.triage_max_minutes.saturating_mul(60).max(60)),
            ),
        )),
        deadline: Some(
            std::time::Instant::now()
                + Duration::from_secs(args.triage_max_minutes.saturating_mul(60).max(60)),
        ),
    };
    let _scan_deadline = scan_context.deadline;
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

    // Passive provider responses only enrich inventory.  They never enqueue an
    // active target request; any later active use remains scheduler-controlled.
    if args.passive {
        println!("📜 Ingesting passive discovery providers...");
        for root_domain in root_scope.iter().filter(|root| {
            !crate::scan::normalize::NormalizedHostname::new(root).is_some_and(|h| h.is_ip())
        }) {
            let provider = crtsh::CrtShProvider;
            println!("  [{}] querying…", provider.name());
            let provider_result = provider.discover(&http_client, root_domain).await;
            let status = provider_result.status;
            db::save_provider_status(
                &conn,
                &scan_run.id,
                status.provider,
                status.ok,
                status.attempts,
                status.discovered_count,
                status.error_category,
            )?;
            if status.ok {
                println!(
                    "  [{}] OK: {} discovery candidate(s) in {} attempt(s)",
                    status.provider, status.discovered_count, status.attempts
                );
            } else {
                println!(
                    "  [{}] FAILED after {} attempt(s): {:?}. Passive hostname discovery may be incomplete.",
                    status.provider, status.attempts, status.error_category
                );
            }
            let ct_subdomains = provider_result.names;
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

            let wayback = WaybackProvider::default();
            let common_crawl = CommonCrawlProvider::default();
            for provider in [
                &wayback as &dyn DiscoveryProvider,
                &common_crawl as &dyn DiscoveryProvider,
            ] {
                println!("  [{}] querying passive URL history…", provider.name());
                let result = provider.discover(&http_client, root_domain).await;
                let status = result.status;
                db::save_provider_status(
                    &conn,
                    &scan_run.id,
                    status.provider,
                    status.ok,
                    status.attempts,
                    status.discovered_count,
                    status.error_category,
                )?;
                if status.ok {
                    let mut accepted = 0usize;
                    for raw_url in in_scope_historical_urls(&scan_context.scope, result.urls) {
                        db::save_endpoint_observation(
                            &conn,
                            &scan_run.id,
                            &raw_url,
                            status.provider,
                            Some(root_domain),
                        )?;
                        accepted += 1;
                    }
                    println!(
                        "  [{}] OK: {} in-scope historical URL observation(s) retained ({} returned)",
                        status.provider, accepted, status.discovered_count
                    );
                } else {
                    println!(
                        "  [{}] FAILED after {} attempt(s): {:?}. Passive URL discovery may be incomplete.",
                        status.provider, status.attempts, status.error_category
                    );
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
                    client: (*scan_context.target_http).clone(), probes: (*scan_context.probes).clone(), resolver: dns_resolver.clone(),
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

    db::classify_scan_inventory(&conn, &scan_run.id)?;
    if args.controlled_verification {
        crate::verification::run(
            scan_context.target_http.as_ref(),
            &scan_context.scope,
            &conn,
            scan_run.id,
            crate::verification::VerificationConfig {
                max_opportunities: args.verification_max_opportunities,
                max_requests_per_opportunity: args.verification_requests_per_opportunity.min(2),
            },
        )
        .await?;
    }

    if args.triage {
        let observations = db::get_scan_observations(&conn, &scan_run.id)?;
        let review = triage::run(
            scan_context.target_http.as_ref(),
            &scan_context.scope,
            &observations,
            TriageConfig::from(&args),
            scan_run.id,
            Some(&conn),
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
