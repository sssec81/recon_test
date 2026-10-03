# Authorized short live-trial runbook

Status: **blocked pending completed authorization fields**. This document
prepares a command; it does not authorize or start a scan.

## Preconditions

Complete `trial-config.yaml` from the program policy or written authorization.
Do not proceed unless all of these are true:

1. The single seed hostname and `scope_root` are explicitly authorized.
2. Descendants of `scope_root` are authorized. The current scope policy includes
   the root and its subdomains; it has no exact-host-only mode.
3. Automated scanning and the six bounded GET-based verifier types are allowed.
4. The program permits at least 5 requests/second per host. Triage adds a
   1-second delay, but the shared verification scheduler is fixed at a maximum
   of 5 requests/second per host.
5. Every program exclusion is reviewed against the selected hostname and test
   types. If an exclusion cannot be represented by the CLI, do not run.
6. A human operator can monitor the entire 12-minute window and stop promptly.

## Fixed request ceiling

The maximum target-HTTP contact budget is 129:

- reconnaissance allowance: `1 max target × 8 = 8`;
- triage: 75;
- Phase 3 controls: `3 × 2 = 6`;
- SQLi controls: `2 × 6 = 12`;
- web controls: `2 × (XSS 3 + redirect 2 + traversal 4 + CORS 2 + SSRF 3) = 28`.

Redirect hops consume the shared budget. Passive discovery and AI analysis are
disabled. Only HTTPS is attempted.

## Command template

Create the output directory first, then replace the three `REQUIRED_*`
placeholders. Keep the target and scope values unquoted data—not shell code.

```bash
mkdir -p evaluation/live-trial/runs/REQUIRED_TIMESTAMP

target/release/recon_test \
  --target REQUIRED_AUTHORIZED_HOSTNAME \
  --scope REQUIRED_AUTHORIZED_SCOPE_ROOT \
  --concurrency 1 \
  --max-targets 1 \
  --passive false \
  --scheme-strategy https-only \
  --triage \
  --triage-max-pages 25 \
  --triage-max-depth 1 \
  --triage-max-requests 75 \
  --triage-max-minutes 12 \
  --triage-max-findings 5 \
  --triage-delay-ms 1000 \
  --controlled-verification \
  --verification-max-opportunities 3 \
  --verification-requests-per-opportunity 2 \
  --sqli-verification \
  --sqli-max-parameters 2 \
  --sqli-requests-per-parameter 6 \
  --xss-verification \
  --redirect-verification \
  --traversal-verification \
  --cors-verification \
  --ssrf-verification \
  --web-verification-max-candidates 2 \
  --review-max-candidates 5 \
  --review-min-score 30 \
  --db evaluation/live-trial/runs/REQUIRED_TIMESTAMP/recon_data.db \
  --triage-dir evaluation/live-trial/runs/REQUIRED_TIMESTAMP/artifacts \
  --export-json evaluation/live-trial/runs/REQUIRED_TIMESTAMP/http_observations.json \
  --export-csv evaluation/live-trial/runs/REQUIRED_TIMESTAMP/http_observations.csv
```

## Monitoring and stop procedure

Watch console output throughout the run. Stop with `Ctrl-C` on any configured
stop condition. Do not restart automatically. Preserve the partial database and
logs, record why the run stopped, and review only the deterministic local report.
Do not enable AI analysis or manually escalate payloads during this trial.

## SSRF interpretation

An SSRF candidate at `Repeatable` proves only a stable response differential
between reserved and loopback URL inputs. It does not prove outbound access.
Do not use a callback service during this short trial unless that exact service
and interaction are separately authorized in writing.
