mod cli;
mod probes;
mod report;
mod scan;
mod storage;

use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    scan::app::run(cli::Args::parse()).await
}
