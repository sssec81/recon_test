use crate::cli::{Args, LlmBackend};
use crate::report::{diff, exporter, llm};
use crate::storage::db;
use crate::storage::models::ScanRun;
use rusqlite::Connection;
use uuid::Uuid;

pub async fn report(
    args: Args,
    conn: &Connection,
    scan_run: &ScanRun,
    http_client: &reqwest::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let scan_id = scan_run.id;
    // Export observations when requested.
    if args.export_json.is_some() || args.export_csv.is_some() {
        let scan_observations = db::get_scan_observations(conn, &scan_id)?;

        if let Some(json_path) = args.export_json {
            exporter::export_json(&scan_observations, &json_path)?;
            println!(
                "💾 Exported {} observation(s) from ScanRun {} to JSON: '{}'",
                scan_observations.len(),
                scan_id,
                json_path
            );
        }

        if let Some(csv_path) = args.export_csv {
            exporter::export_csv(&scan_observations, &csv_path)?;
            println!(
                "💾 Exported {} observation(s) from ScanRun {} to CSV: '{}'",
                scan_observations.len(),
                scan_id,
                csv_path
            );
        }
    }

    // Compare this run with historical results when requested.
    let diff_run_ids = if args.diff_last {
        if let Some(previous) = db::get_previous_compatible_scan(conn, scan_run)? {
            Some((previous, scan_id))
        } else {
            println!("ℹ️  Not enough historical ScanRuns found to perform auto-diff.");
            None
        }
    } else if let Some(ref diff_args) = args.diff {
        if diff_args.len() == 2 {
            let id_a = Uuid::parse_str(&diff_args[0]).ok();
            let id_b = Uuid::parse_str(&diff_args[1]).ok();
            if let (Some(a), Some(b)) = (id_a, id_b) {
                Some((a, b))
            } else {
                eprintln!("❌ Invalid UUID parameters supplied for --diff.");
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Some((id_a, id_b)) = diff_run_ids {
        println!(
            "\n📊 Calculating Scan Diff Analysis (Scan A: {} ➔ Scan B: {})...",
            id_a, id_b
        );
        match diff::compare_scan_runs(conn, &id_a, &id_b) {
            Ok(diff_result) => {
                println!(
                    "  [+] Added Subdomains ({}): {:?}",
                    diff_result.new_subdomains.len(),
                    diff_result.new_subdomains
                );
                println!(
                    "  [-] Removed Subdomains ({}): {:?}",
                    diff_result.removed_subdomains.len(),
                    diff_result.removed_subdomains
                );
                println!(
                    "  [+] New Endpoints ({}): {:?}",
                    diff_result.new_endpoints.len(),
                    diff_result.new_endpoints
                );
                println!(
                    "  [-] Removed Endpoints ({}): {:?}",
                    diff_result.removed_endpoints.len(),
                    diff_result.removed_endpoints
                );
                println!(
                    "  [+] New Services ({}): {:?}",
                    diff_result.new_services.len(),
                    diff_result.new_services
                );
                println!(
                    "  [-] Removed Services ({}): {:?}",
                    diff_result.removed_services.len(),
                    diff_result.removed_services
                );
                println!(
                    "  [Δ] Changed TLS ({}): {:?}",
                    diff_result.changed_tls.len(),
                    diff_result.changed_tls
                );
                println!(
                    "  [Δ] Status Changes ({}):",
                    diff_result.status_changes.len()
                );
                for sc in &diff_result.status_changes {
                    println!(
                        "      - {:<24} : {:?} ➔ {:?}",
                        sc.endpoint_url, sc.old_status, sc.new_status
                    );
                }
                println!("  [Δ] DNS IP Changes ({}):", diff_result.ip_changes.len());
                for ipc in &diff_result.ip_changes {
                    println!(
                        "      - {:<24} : {:?} ➔ {:?}",
                        ipc.hostname, ipc.old_ips, ipc.new_ips
                    );
                }
                println!(
                    "  [+] New Technologies Detected ({}): {:?}",
                    diff_result.new_technologies.len(),
                    diff_result.new_technologies
                );

                if let Some(diff_json_path) = args.export_diff_json {
                    exporter::export_diff_json(&diff_result, &diff_json_path)?;
                    println!(
                        "💾 Exported ScanDiff observations to JSON: '{}'",
                        diff_json_path
                    );
                }
            }
            Err(e) => eprintln!("❌ Failed to calculate scan diff: {}", e),
        }
    }

    // Generate optional AI summaries.
    if args.llm_analyze && args.triage {
        println!(
            "ℹ️  Triage mode kept AI off raw scan metadata; candidate-only AI analysis is planned for a later phase."
        );
    }
    if args.llm_analyze && !args.triage {
        let provider = match args.llm_backend {
            LlmBackend::Ollama => llm::LlmProvider::Ollama {
                url: args.ollama_url.clone(),
                model: args.ollama_model.clone(),
            },
            LlmBackend::Anthropic => {
                if let Some(key) = args
                    .anthropic_api_key
                    .as_ref()
                    .filter(|k| !k.trim().is_empty())
                {
                    llm::LlmProvider::Anthropic {
                        api_key: key.clone(),
                        model: args.anthropic_model.clone(),
                        max_tokens: args.llm_max_tokens,
                    }
                } else {
                    eprintln!(
                        "❌ Error: ANTHROPIC_API_KEY is required when --llm-backend is set to 'anthropic'. Set ANTHROPIC_API_KEY env var or pass --anthropic-api-key."
                    );
                    return Err("Missing ANTHROPIC_API_KEY".into());
                }
            }
        };

        let scan_observations = db::get_scan_observations(conn, &scan_id)?;
        let backend_name = match &provider {
            llm::LlmProvider::Ollama { model, url } => format!("Ollama ({}) at '{}'", model, url),
            llm::LlmProvider::Anthropic { model, .. } => format!("Anthropic Claude ({})", model),
        };
        println!(
            "\n🤖 Generating AI Attack Surface Assessment via {}...",
            backend_name
        );

        match llm::analyze_scan_observations(http_client, &provider, &scan_observations).await {
            Ok(ai_summary) => {
                println!("\n=== 🤖 AI Attack Surface Assessment ===");
                println!("{}", ai_summary.trim());
                println!("======================================");
            }
            Err(e) => eprintln!("⚠️  AI analysis failed: {}", e),
        }

        if let Some((id_a, id_b)) = diff_run_ids
            && let Ok(diff_result) = diff::compare_scan_runs(conn, &id_a, &id_b)
        {
            println!(
                "\n🤖 Generating AI Scan Diff Threat Assessment via {}...",
                backend_name
            );
            match llm::analyze_scan_diff(http_client, &provider, &diff_result).await {
                Ok(diff_ai_summary) => {
                    println!("\n=== 🤖 AI Scan Diff Assessment ===");
                    println!("{}", diff_ai_summary.trim());
                    println!("=================================");
                }
                Err(e) => eprintln!("⚠️  AI diff analysis failed: {}", e),
            }
        }
    }

    Ok(())
}
