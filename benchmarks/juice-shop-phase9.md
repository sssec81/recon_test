# OWASP Juice Shop Phase 9 benchmark

Controlled target: OWASP Juice Shop 20.2.0, Docker image digest
`sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`.

This benchmark measures vulnerable input sinks, not Juice Shop challenge count.
Several challenges can share one sink, and many challenges require authenticated
or state-changing workflows outside the GET-only Phase 9 verifier policy.

## Capability matrix

| Module | Juice Shop sink/challenges | Request shape | Current eligibility | Expected result |
|---|---|---|---|---|
| 9A SQLi | `/rest/products/search?q` — Database Schema, User Credentials | GET query | Eligible | Detect one SQLi behavior |
| 9A SQLi | `/rest/user/login` — Login Admin/Bender/Jim and related login challenges | POST JSON body | Static intelligence only | Do not execute |
| 9A SQLi | order/basket workflows — Christmas Special | Authenticated/state-changing | Out of policy | Do not execute |
| 9B XSS | `/rest/track-order/:id` — Reflected XSS | GET path parameter, JSON consumed by frontend | Outside HTML/query verifier | Do not claim coverage |
| 9B XSS | DOM XSS and persisted/header XSS challenges | Browser DOM or state-changing input | Outside current verifier | Do not execute |
| 9C Redirect | `/redirect?to` — Allowlist Bypass, Outdated Allowlist | GET query | Eligible | Detect blocked external `Location` without following it |
| 9D Traversal | `/ftp/:file` — Poison Null Byte/Missing Encoding family | Path parameter and encoding bypass | Outside query traversal verifier | Do not claim coverage |
| 9E CORS | Global `Access-Control-Allow-Origin: *` without credentials | GET header control | Eligible negative control | Suppress |
| 9F SSRF | `/profile/image/url` — SSRF | Authenticated POST body | Static intelligence only | Do not execute |

## Acceptance criteria

- SQLi and open-redirect behaviors are retained as investigation candidates.
- XSS, traversal, CORS, and SSRF do not produce false positive candidates.
- The redirect verifier never contacts the external destination.
- POST and authenticated workflows remain passive request intelligence.
- Suppressed module categories do not contaminate candidates retained by another module.
- Persisted verification URLs contain parameter names only; values are redacted.
- Malformed minified-code URL candidates remain zero.

## Verified result

Scan `2eaf8e2a-eb19-4e65-afc6-64dd31d8210a` passed the matrix on the image above:

- SQL injection: 4 eligible GET parameters checked; one behavior retained at
  `/rest/products/search?q`.
- Open redirect: one eligible parameter checked; the substring-allowlist bypass
  at `/redirect?to` retained without contacting the external destination.
- Reflected XSS: 4 query candidates checked; all suppressed. The Juice Shop
  reflected-XSS challenge is a separate path/JSON/browser-rendering shape.
- CORS: 10 endpoints checked; all suppressed because hostile origins were not
  reflected with credential permission.
- Traversal and SSRF: zero eligible GET/query shapes. Their Juice Shop sinks are
  path/encoding and authenticated POST-body workflows respectively.
- Static intelligence: 9 structured HTTP calls, 114 bounded URL literals, 68
  method-aware request-shape rows (`54 GET`, `12 POST`, `2 PUT`), and zero known
  malformed minified-code URLs.
- Final ranked output: two `ControlVerified` Phase 9 behaviors (SQLi and open
  redirect) plus two generic Phase 3 surfaces. Manual validation remains required.

## Reference command

```bash
cargo run --release -- \
  --target 127.0.0.1 \
  --scope 127.0.0.1 \
  --passive false \
  --scheme-strategy both-parallel \
  --triage \
  --controlled-verification \
  --sqli-verification \
  --xss-verification \
  --redirect-verification \
  --traversal-verification \
  --cors-verification \
  --ssrf-verification \
  --web-verification-max-candidates 10 \
  --triage-max-pages 200 \
  --triage-max-depth 4 \
  --triage-max-requests 500 \
  --triage-max-minutes 10 \
  --triage-delay-ms 0 \
  --sqli-max-parameters 10 \
  --sqli-requests-per-parameter 6 \
  --review-max-candidates 20 \
  --review-min-score 20
```
