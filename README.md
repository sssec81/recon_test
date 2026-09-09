# recon_test 🚀

An asynchronous, modular Rust bug bounty recon scanner powered by `tokio`, `reqwest`, `rusqlite`, and `clap`.

## Features
- **Concurrent Async Probing**: High-speed subdomain probing with Tokio and `reqwest`.
- **Concurrency Rate Limiting**: Built-in `Semaphore` limit (`-c, --concurrency`) to prevent socket exhaustion.
- **Rich Metadata Extraction**: Captures HTTP status code, Round-Trip Time (RTT ms), `Server` header, and HTML `<title>` tag.
- **SQLite Storage**: Persistent local storage in SQLite (`recon_data.db`) with automatic schema migration.
- **Flexible Inputs**: Supports single target (`-t`) or target domain lists from a text file (`-f`).
- **Data Exporting**: Export scan results directly to JSON (`--export-json`) or CSV (`--export-csv`).

## Installation & Build
```bash
# Clone the repository
git clone https://github.com/sssec81/recon_test.git
cd recon_test

# Build release binary
cargo build --release
```

## Usage Examples

### Scan a single target:
```bash
cargo run -- -t example.com
```

### Scan target list from a file with 10 concurrent workers:
```bash
cargo run -- -f targets.txt -c 10
```

### Scan and export results to JSON & CSV:
```bash
cargo run -- -f targets.txt --export-json results.json --export-csv results.csv
```

## License
MIT
