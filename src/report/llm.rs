use crate::report::diff::ScanDiffResult;
use crate::storage::models::HttpObservation;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum LlmProvider {
    Ollama {
        url: String,
        model: String,
    },
    Anthropic {
        api_key: String,
        model: String,
        max_tokens: u32,
    },
}

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

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
}

async fn analyze_with_ollama(
    client: &Client,
    url: &str,
    model: &str,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let req_body = OllamaRequest {
        model: model.to_string(),
        prompt: prompt.to_string(),
        stream: false,
    };

    let llm_client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| client.clone());

    let endpoint = format!("{}/api/generate", url.trim_end_matches('/'));
    let response = llm_client.post(&endpoint).json(&req_body).send().await?;

    if !response.status().is_success() {
        return Err(format!("Ollama API returned status {}", response.status()).into());
    }

    let ollama_res: OllamaResponse = response.json().await?;
    Ok(ollama_res.response)
}

async fn analyze_with_anthropic(
    client: &Client,
    api_key: &str,
    model: &str,
    max_tokens: u32,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let req_body = AnthropicRequest {
        model: model.to_string(),
        max_tokens,
        messages: vec![AnthropicMessage {
            role: "user".to_string(),
            content: prompt.to_string(),
        }],
    };

    let llm_client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| client.clone());

    let response = llm_client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&req_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let err_text = response.text().await.unwrap_or_default();
        return Err(format!("Anthropic API returned status {}: {}", status, err_text).into());
    }

    let anthropic_res: AnthropicResponse = response.json().await?;
    let mut combined_text = String::new();
    for block in anthropic_res.content {
        if block.block_type == "text"
            && let Some(t) = block.text
        {
            combined_text.push_str(&t);
        }
    }

    if combined_text.is_empty() {
        Ok("No text content returned from Anthropic API.".to_string())
    } else {
        Ok(combined_text)
    }
}

pub async fn generate_text(
    client: &Client,
    provider: &LlmProvider,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match provider {
        LlmProvider::Ollama { url, model } => analyze_with_ollama(client, url, model, prompt).await,
        LlmProvider::Anthropic {
            api_key,
            model,
            max_tokens,
        } => analyze_with_anthropic(client, api_key, model, *max_tokens, prompt).await,
    }
}

pub async fn analyze_scan_observations(
    client: &Client,
    provider: &LlmProvider,
    observations: &[HttpObservation],
) -> Result<String, Box<dyn std::error::Error>> {
    if observations.is_empty() {
        return Ok("No scan observations available for AI analysis.".to_string());
    }

    let total_count = observations.len();
    let max_items = 100;
    let mut obs_summary = String::new();
    for obs in observations.iter().take(max_items) {
        let status = obs
            .status_code
            .map(|s| s.to_string())
            .unwrap_or_else(|| "ERR".to_string());
        let title = obs.title.as_deref().unwrap_or("No Title");
        let server = obs.server_header.as_deref().unwrap_or("Unknown");
        obs_summary.push_str(&format!(
            "- Host: {} | URL: {} | Status: {} | Title: {} | Server: {}\n",
            obs.hostname, obs.url, status, title, server
        ));
    }
    if total_count > max_items {
        obs_summary.push_str(&format!(
            "... and {} additional observation(s) omitted for brevity.\n",
            total_count - max_items
        ));
    }

    let prompt = format!(
        "You are an elite bug bounty triage assistant. Your job is ONLY to categorize raw HTTP metadata. You DO NOT perform vulnerability scans.\n\n\
        CRITICAL RULES TO PREVENT HALLUCINATIONS:\n\
        - DO NOT claim or invent specific vulnerabilities (e.g. 'arbitrary file upload', 'path traversal', 'weak passwords', 'stale SSL certificates'). You only have basic HTTP header and status code metadata, NOT source code or request body payload responses.\n\
        - DO NOT claim data is exposed in plaintext or that unauthenticated endpoints exist unless explicitly visible in the title/header metadata.\n\
        - ONLY group targets by actionable signals: (A) Login/Auth Portals (HTTP 200/403 with login keywords), (B) 503/502/404 Service Error/Dangling CNAME candidates, (C) Distinct Non-Cloudflare Servers (e.g. Nginx, IIS, Atlassian).\n\n\
        Target Observations:\n{}",
        obs_summary
    );

    generate_text(client, provider, &prompt).await
}

pub async fn analyze_scan_diff(
    client: &Client,
    provider: &LlmProvider,
    diff: &ScanDiffResult,
) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        "You are a cybersecurity intelligence analyst monitoring attack surface changes. Analyze this scan diff between Scan A ({}) and Scan B ({}):\n\n\
        - New Subdomains ({}): {:?}\n\
        - Removed Subdomains ({}): {:?}\n\
        - New Endpoints ({}): {:?}\n\
        - Removed Endpoints ({}): {:?}\n\
        - New Services ({}): {:?}\n\
        - Removed Services ({}): {:?}\n\
        - Changed TLS Services ({}): {:?}\n\
        - Status Code Changes ({}): {:?}\n\
        - DNS IP Changes ({}): {:?}\n\
        - New Technologies Detected ({}): {:?}\n\n\
        Provide a concise security threat summary highlighting high-risk attack surface expansions and security implications.",
        diff.scan_id_a,
        diff.scan_id_b,
        diff.new_subdomains.len(),
        diff.new_subdomains,
        diff.removed_subdomains.len(),
        diff.removed_subdomains,
        diff.new_endpoints.len(),
        diff.new_endpoints,
        diff.removed_endpoints.len(),
        diff.removed_endpoints,
        diff.new_services.len(),
        diff.new_services,
        diff.removed_services.len(),
        diff.removed_services,
        diff.changed_tls.len(),
        diff.changed_tls,
        diff.status_changes.len(),
        diff.status_changes,
        diff.ip_changes.len(),
        diff.ip_changes,
        diff.new_technologies.len(),
        diff.new_technologies
    );

    generate_text(client, provider, &prompt).await
}
