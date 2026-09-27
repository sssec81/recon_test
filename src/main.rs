mod analyst;
mod cli;
mod correlation;
mod probes;
mod report;
mod review;
mod scan;
mod sqli;
mod storage;
mod triage;
mod verification;
mod web_verification;

use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    scan::app::run(cli::Args::parse()).await
}
