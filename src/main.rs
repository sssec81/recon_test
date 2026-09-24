mod cli;
mod correlation;
mod probes;
mod report;
mod review;
mod scan;
mod storage;
mod triage;
mod verification;

use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    scan::app::run(cli::Args::parse()).await
}
