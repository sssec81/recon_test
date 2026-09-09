use crate::diff::ScanDiffResult;
use crate::models::HttpObservation;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    response: String,
}

pub async fn analyze_scan_observations(
    client: &Client,
    ollama_url: &str,
    model: &str,
    observations: &[HttpObservation],
) -> Result<String, Box<dyn std::error::Error>> {
    if observations.is_empty() {
        return Ok("No scan observations available for AI analysis.".to_string());
    }

    let total_count = observations.len();
    let max_items = 100;
    let mut obs_summary = String::new();
    for obs in observations.iter().take(max_items) {
        let status = obs.status_code.map(|s| s.to_string()).unwrap_or_else(|| "ERR".to_string());
        let title = obs.title.as_deref().unwrap_or("No Title");
        let server = obs.server_header.as_deref().unwrap_or("Unknown");
        obs_summary.push_str(&format!(
            "- Host: {} | URL: {} | Status: {} | Title: {} | Server: {}\n",
            obs.hostname, obs.url, status, title, server
        ));
    }
    if total_count > max_items {
        obs_summary.push_str(&format!("... and {} additional observation(s) omitted for brevity.\n", total_count - max_items));
    }

    let prompt = format!(
        "You are an expert cybersecurity attack surface analyst. Analyze these bug bounty recon observations and output a concise report summarizing:\n\
        1. High-value or anomalous targets (e.g. unexpected tech stacks, non-standard titles, dev/staging environments)\n\
        2. Web server header distribution\n\
        3. Prioritized next steps for security testing\n\n\
        Observations:\n{}",
        obs_summary
    );

    let req_body = OllamaRequest {
        model: model.to_string(),
        prompt,
        stream: false,
    };

    let llm_client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| client.clone());

    let url = format!("{}/api/generate", ollama_url.trim_end_matches('/'));
    let response = llm_client
        .post(&url)
        .json(&req_body)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Ollama API returned status {}", response.status()).into());
    }

    let ollama_res: OllamaResponse = response.json().await?;
    Ok(ollama_res.response)
}

pub async fn analyze_scan_diff(
    client: &Client,
    ollama_url: &str,
    model: &str,
    diff: &ScanDiffResult,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        "You are a cybersecurity intelligence analyst monitoring attack surface changes. Analyze this scan diff between Scan A ({}) and Scan B ({}):\n\n\
        - New Subdomains ({}): {:?}\n\
        - Removed Subdomains ({}): {:?}\n\
        - Status Code Changes ({}): {:?}\n\
        - DNS IP Changes ({}): {:?}\n\
        - New Technologies Detected ({}): {:?}\n\n\
        Provide a concise security threat summary highlighting high-risk attack surface expansions and security implications.",
        diff.scan_id_a,
        diff.scan_id_b,
        diff.new_subdomains.len(), diff.new_subdomains,
        diff.removed_subdomains.len(), diff.removed_subdomains,
        diff.status_changes.len(), diff.status_changes,
        diff.ip_changes.len(), diff.ip_changes,
        diff.new_technologies.len(), diff.new_technologies
    );

    let req_body = OllamaRequest {
        model: model.to_string(),
        prompt,
        stream: false,
    };

    let llm_client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| client.clone());

    let url = format!("{}/api/generate", ollama_url.trim_end_matches('/'));
    let response = llm_client
        .post(&url)
        .json(&req_body)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Ollama API returned status {}", response.status()).into());
    }

    let ollama_res: OllamaResponse = response.json().await?;
    Ok(ollama_res.response)
}
