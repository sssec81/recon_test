# recon_test 🚀

An asynchronous, modular Rust bug bounty recon scanner powered by `tokio`, `reqwest`, `rusqlite`, and `clap`.

## Code layout

| Directory | Responsibility |
| --- | --- |
| `src/main.rs`, `src/cli.rs` | Entry point, CLI arguments, and target file loading |
| `src/scan/` | Scan coordination, scheduling, per-host work, event assembly, and scope checks |
| `src/probes/` | Certificate, DNS, TCP, TLS, HTTP, and technology probes |
| `src/storage/` | Observation models and SQLite persistence |
| `src/report/` | Scan comparison, export, and optional AI analysis |
| `src/triage/` | Bounded crawl, deterministic candidate checks, verification, and local review packages |

## Features
- **Concurrent Async Probing**: High-speed subdomain probing with Tokio and `reqwest`.
- **Concurrency Rate Limiting**: Built-in `Semaphore` limit (`-c, --concurrency`) to prevent socket exhaustion.
- **Scope Enforcement & Scheduler**: `ScopePolicy` filter (`-s, --scope`), in-scope HTTP redirects, and fan-in hostname deduplication.
- **Passive Recon (crt.sh)**: Automatic Certificate Transparency log querying (enabled by default with `--passive true`).
- **TLS SAN Feedback Expansion**: Automatically extracts Subject Alternative Names (SANs) from TLS certs and queues in-scope targets dynamically.
- **Web Tech Fingerprinting**: Technology detection with confidence scores and evidence tracing.
- **Attack Surface Scan Diffing**: Historical diff engine (`--diff-last` or `--diff <SCAN_A> <SCAN_B>`) tracking subdomains, endpoints, services, TLS metadata, status codes, DNS IPs, and technologies. `--diff-last` uses the previous completed scan with the same scope, seed targets, passive setting, and scheme strategy.
- **Optional AI Analysis**: Attack surface assessment using local Ollama or Anthropic models via `--llm-analyze`.
- **SQLite Storage**: Persistent local storage in SQLite (`recon_data.db`) in WAL mode with scan-specific service, TLS, and hostname discovery history.
- **Data Exporting**: Export scan results directly to JSON (`--export-json`), CSV (`--export-csv`), or diff JSON (`--export-diff-json`).
- **Optional Evidence Triage**: Crawl discovered in-scope web pages, identify a small set of review candidates, repeat safe checks, and save evidence locally with `--triage`.

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
| `-t, --target <TARGET>` | Single target domain or IP (required unless `--file` is used) | None |
| `-s, --scope <SCOPE>...` | Authorized root scope domain(s) | Target input domain |
| `-f, --file <PATH>` | File containing target subdomains (one per line) | None |
| `-c, --concurrency <N>` | Maximum concurrent scan tasks | `20` |
| `--passive [true\|false]` | Ingest passive Certificate Transparency logs via crt.sh | `true` |
| `--scheme-strategy <STRATEGY>` | Probing scheme (`https-first`, `https-only`, `both-parallel`) | `https-first` |
| `--diff-last` | Diff against the previous compatible finished run | `false` |
| `--diff <UUID_A> <UUID_B>` | Compare specific historical scan runs | None |
| `--llm-analyze` | Enable optional AI attack surface analysis | `false` |
| `--ollama-model <MODEL>` | Local Ollama model name | `llama3:8b` |
| `--ollama-url <URL>` | Local Ollama API endpoint | `http://localhost:11434` |
| `--llm-backend <BACKEND>` | AI backend (`ollama` or `anthropic`) | `ollama` |
| `--anthropic-api-key <KEY>` | Anthropic API key (or use `ANTHROPIC_API_KEY`) | None |
| `--anthropic-model <MODEL>` | Anthropic model name | `claude-3-5-haiku-20241022` |
| `--llm-max-tokens <N>` | Maximum AI response tokens | `1024` |
| `--triage` | Run bounded evidence triage after recon | `false` |
| `--triage-max-pages <N>` | Maximum pages or scripts fetched in triage | `250` |
| `--triage-max-depth <N>` | Maximum crawl depth from discovered endpoints | `2` |
| `--triage-max-requests <N>` | Total triage request budget, including checks | `1000` |
| `--triage-max-minutes <N>` | Triage phase time limit in minutes | `240` |
| `--triage-max-findings <N>` | Maximum review queue entries | `5` |
| `--triage-delay-ms <N>` | Delay between triage requests | `200` |
| `--triage-dir <PATH>` | Local review and evidence directory | `triage_output` |
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

For Anthropic analysis, set `ANTHROPIC_API_KEY` and add `--llm-backend anthropic`.

### Build a local review queue

```bash
cargo run --release -- -t example.com --scope example.com --passive false --triage
```

Triage starts after recon. Its time and request limits apply to the triage phase only. It follows in-scope GET links and scripts, skips common state-changing paths, and does not submit forms. Output is saved under `triage_output/<scan-id>/review.md`, `review.json`, `endpoints.json`, `anomalies.json`, and `evidence/`. The endpoint inventory records route templates, query and form field names, discovery sources, observed statuses, and content types. Review packages contain response metadata, a short text excerpt, and a body hash. They do not contain full response bodies. Treat local evidence as potentially sensitive.

Triage recognizes directory indexes, detailed server errors, and object identifiers in URLs. It also compares responses from the same route and parameter set; a repeatable 5xx response against a successful natural control becomes a review candidate. Directory, server-error, and response-anomaly checks are repeated before they enter the queue or gain confidence. An object identifier is only a **candidate for manual authorization testing**; it does not prove an access-control flaw. `Confirmed` is reserved for manual validation. `--llm-analyze` is skipped when `--triage` is enabled because candidate-only AI triage is planned for a later phase.

### Rescan, auto-diff against previous run, and generate AI diff analysis:
```bash
cargo run -- -t example.com --diff-last --llm-analyze
```

## Database migration

Existing databases remain usable. Older service and TLS rows stay in their legacy tables because they did not contain a scan ID; new observations use scan-specific tables. Re-scan a target to build comparable service and TLS history.

Passive discovery errors now fail the run instead of producing an incomplete successful scan. Use `--passive false` when crt.sh is unavailable.

## License
MIT
