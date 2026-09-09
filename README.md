# recon_test 🚀

An asynchronous, modular Rust bug bounty recon scanner powered by `tokio`, `reqwest`, `rusqlite`, and `clap`.

## Features
- **Concurrent Async Probing**: High-speed subdomain probing with Tokio and `reqwest`.
- **Concurrency Rate Limiting**: Built-in `Semaphore` limit (`-c, --concurrency`) to prevent socket exhaustion.
- **Scope Enforcement & Scheduler**: Strict `ScopePolicy` filter (`-s, --scope`) and fan-in hostname deduplication.
- **Passive Recon (crt.sh)**: Automatic Certificate Transparency log querying (enabled by default with `--passive true`).
- **TLS SAN Feedback Expansion**: Automatically extracts Subject Alternative Names (SANs) from TLS certs and queues in-scope targets dynamically.
- **Web Tech Fingerprinting**: Technology detection with confidence scores and evidence tracing.
- **Attack Surface Scan Diffing**: Historical diff engine (`--diff-last` or `--diff <SCAN_A> <SCAN_B>`) tracking new/removed subdomains, status code shifts, DNS IP changes, and new technologies.
- **Local AI Analysis (Ollama Integration)**: Native AI threat & attack surface assessment using local LLMs (e.g. `llama3:8b` via `--llm-analyze`).
- **SQLite Storage**: Persistent local storage in SQLite (`recon_data.db`) in WAL mode with FK safety and thread-safe batch writing.
- **Data Exporting**: Export scan results directly to JSON (`--export-json`), CSV (`--export-csv`), or diff JSON (`--export-diff-json`).

## Installation & Build
```bash
# Clone the repository
git clone https://github.com/sssec81/recon_test.git
cd recon_test

# Build release binary
cargo build --release
```

## CLI Options & Usage Examples

| Flag | Description | Default |
| --- | --- | --- |
| `-t, --target <TARGET>` | Single target domain or IP | None |
| `-s, --scope <SCOPE>...` | Authorized root scope domain(s) | Target input domain |
| `-f, --file <PATH>` | File containing target subdomains (one per line) | None |
| `-c, --concurrency <N>` | Maximum concurrent scan tasks | `20` |
| `--passive [true\|false]` | Ingest passive Certificate Transparency logs via crt.sh | `true` |
| `--scheme-strategy <STRATEGY>` | Probing scheme (`https-first`, `https-only`, `both-parallel`) | `https-first` |
| `--diff-last` | Automatically diff current scan run against previous finished run | `false` |
| `--diff <UUID_A> <UUID_B>` | Compare specific historical scan runs | None |
| `--llm-analyze` | Enable local AI attack surface analysis via Ollama | `false` |
| `--ollama-model <MODEL>` | Local Ollama model name | `llama3:8b` |
| `--ollama-url <URL>` | Local Ollama API endpoint | `http://localhost:11434` |
| `--export-json <PATH>` | Export scan observations to JSON file | None |
| `--export-csv <PATH>` | Export scan observations to CSV file | None |
| `--export-diff-json <PATH>` | Export scan diff results to JSON file | None |
| `--db <PATH>` | SQLite database file | `recon_data.db` |

### Scan single target with active scope and passive CT logs:
```bash
cargo run -- -t example.com --scope example.com --passive true
```

### Run scan with automatic local AI attack surface analysis (Ollama):
```bash
cargo run -- -t example.com --scope example.com --llm-analyze
```

### Rescan, auto-diff against previous run, and generate AI diff analysis:
```bash
cargo run -- -t example.com --diff-last --llm-analyze
```

## License
MIT
