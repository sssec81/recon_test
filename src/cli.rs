use crate::probes::scanner::SchemeStrategy;
use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Async Bug Bounty Subdomain Recon Engine v1.0.0
#[derive(Parser, Debug)]
#[command(
    author,
    version = "1.0.0",
    about = "Async Rust Recon Engine v1.0 with Scan Diffing & Attack Surface Change Tracking"
)]
pub struct Args {
    /// Single target subdomain to probe
    #[arg(short, long)]
    pub target: Option<String>,

    /// Authorized root scope domains (e.g. --scope example.com)
    #[arg(short, long)]
    pub scope: Vec<String>,

    /// Path to a text file containing target subdomains (one per line)
    #[arg(short, long)]
    pub file: Option<String>,

    /// Maximum concurrent scan tasks
    #[arg(short, long, default_value_t = 20)]
    pub concurrency: usize,

    /// Enable passive Certificate Transparency reconnaissance
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub passive: bool,

    /// Probing scheme strategy
    #[arg(long, value_enum, default_value_t = SchemeStrategy::HttpsFirst)]
    pub scheme_strategy: SchemeStrategy,

    /// Automatically diff current scan against the previous scan run
    #[arg(long, default_value_t = false)]
    pub diff_last: bool,

    /// Specific scan UUIDs to compare (--diff <SCAN_ID_A> <SCAN_ID_B>)
    #[arg(long, num_args = 2)]
    pub diff: Option<Vec<String>>,

    /// Enable AI attack surface analysis
    #[arg(long, default_value_t = false)]
    pub llm_analyze: bool,

    /// LLM backend provider for AI analysis
    #[arg(long, value_enum, default_value_t = LlmBackend::Ollama)]
    pub llm_backend: LlmBackend,

    /// Ollama model name to use for local AI analysis
    #[arg(long, default_value = "llama3:8b")]
    pub ollama_model: String,

    /// Ollama server base URL endpoint
    #[arg(long, default_value = "http://localhost:11434")]
    pub ollama_url: String,

    /// Anthropic API key (or set ANTHROPIC_API_KEY environment variable)
    #[arg(long, env = "ANTHROPIC_API_KEY")]
    pub anthropic_api_key: Option<String>,

    /// Anthropic model name to use for cloud AI analysis
    #[arg(long, default_value = "claude-3-5-haiku-20241022")]
    pub anthropic_model: String,

    /// Maximum completion tokens for LLM analysis
    #[arg(long, default_value_t = 1024)]
    pub llm_max_tokens: u32,

    /// Export scan observations to JSON file
    #[arg(long)]
    pub export_json: Option<String>,

    /// Export scan observations to CSV file
    #[arg(long)]
    pub export_csv: Option<String>,

    /// Export scan diff analysis to JSON file
    #[arg(long)]
    pub export_diff_json: Option<String>,

    /// SQLite database storage file
    #[arg(long, default_value = "recon_data.db")]
    pub db: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum LlmBackend {
    Ollama,
    Anthropic,
}

pub fn load_targets_from_file(file_path: &str) -> std::io::Result<Vec<String>> {
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
