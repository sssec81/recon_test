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
    #[arg(short, long, default_value_t = 20, value_parser = parse_positive_usize)]
    pub concurrency: usize,

    /// Maximum distinct hosts scheduled in one scan
    #[arg(long, default_value_t = 10000, value_parser = parse_positive_usize)]
    pub max_targets: usize,

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

    /// Run bounded crawl and evidence-backed candidate triage after recon
    #[arg(long, default_value_t = false)]
    pub triage: bool,

    /// Maximum pages/assets to crawl during triage
    #[arg(long, default_value_t = 250, value_parser = parse_positive_usize)]
    pub triage_max_pages: usize,

    /// Maximum link depth from discovered web endpoints
    #[arg(long, default_value_t = 2)]
    pub triage_max_depth: usize,

    /// Maximum HTTP requests including verification requests
    #[arg(long, default_value_t = 1000, value_parser = parse_positive_usize)]
    pub triage_max_requests: usize,

    /// Time limit for the triage phase in minutes
    #[arg(long, default_value_t = 240, value_parser = parse_positive_u64)]
    pub triage_max_minutes: u64,

    /// Maximum candidates in the final review queue
    #[arg(long, default_value_t = 5, value_parser = parse_positive_usize)]
    pub triage_max_findings: usize,

    /// Delay between triage HTTP requests in milliseconds
    #[arg(long, default_value_t = 200)]
    pub triage_delay_ms: u64,

    /// Directory for local triage evidence and review queues
    #[arg(long, default_value = "triage_output")]
    pub triage_dir: String,

    /// Run Phase 3 bounded, non-destructive verification of existing intelligence
    #[arg(long, default_value_t = false)]
    pub controlled_verification: bool,

    /// Maximum Phase 3 opportunities actively checked per scan
    #[arg(long, default_value_t = 10, value_parser = parse_positive_usize)]
    pub verification_max_opportunities: usize,

    /// Maximum Phase 3 requests per opportunity (hard-capped at 2)
    #[arg(long, default_value_t = 2, value_parser = parse_positive_usize)]
    pub verification_requests_per_opportunity: usize,

    /// Maximum Phase 4 candidates shown and exported in the primary review queue
    #[arg(long, default_value_t = 10, value_parser = parse_positive_usize)]
    pub review_max_candidates: usize,

    /// Minimum deterministic investigation score for the primary review queue
    #[arg(long, default_value_t = 20, value_parser = parse_review_score)]
    pub review_min_score: u16,

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

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    let count = value
        .parse::<usize>()
        .map_err(|_| "expected a positive integer".to_string())?;
    if count == 0 {
        Err("value must be at least 1".to_string())
    } else {
        Ok(count)
    }
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    let count = value
        .parse::<u64>()
        .map_err(|_| "expected a positive integer".to_string())?;
    if count == 0 {
        Err("value must be at least 1".to_string())
    } else {
        Ok(count)
    }
}

fn parse_review_score(value: &str) -> Result<u16, String> {
    let score = value
        .parse::<u16>()
        .map_err(|_| "expected an integer from 0 through 100".to_string())?;
    if score <= 100 {
        Ok(score)
    } else {
        Err("review minimum score must be from 0 through 100".into())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_zero_concurrency() {
        assert!(Args::try_parse_from(["recon_test", "-t", "example.com", "-c", "0"]).is_err());
        assert!(
            Args::try_parse_from(["recon_test", "-t", "example.com", "--max-targets", "0"])
                .is_err()
        );
        assert!(
            Args::try_parse_from([
                "recon_test",
                "-t",
                "example.com",
                "--review-min-score",
                "101"
            ])
            .is_err()
        );
    }
}
