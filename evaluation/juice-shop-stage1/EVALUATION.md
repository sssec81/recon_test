# Controlled evaluation — OWASP Juice Shop

Date: 2026-10-03 (Asia/Katmandu)

## Environment

- Target: OWASP Juice Shop 20.2.0 on `127.0.0.1:8080`
- Image digest: `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`
- Scan ID: `b3fa0a4f-2d7d-42ab-ae52-79fdab463d3b`
- Passive discovery: disabled
- Limits: 200 pages, depth 4, 500 triage requests, 10 minutes, 10 candidates per web verifier
- Preflight: 114/114 Rust tests passed; formatting passed

## Stage 1 result

The local controlled scan completed successfully. It produced 55 HTTP observations and four ranked review candidates. No public target was contacted intentionally; the scanner's redirect verifier retained the external redirect response without following the destination.

## Stage 2 detection evaluation

The unit of evaluation is an eligible sink in the repository's pinned Juice Shop capability matrix, not the application's total challenge count.

| Expected eligible behavior | Result | Classification |
| --- | --- | --- |
| SQL injection behavior at `/rest/products/search?q` | Retained, `ControlVerified` | True positive |
| Open redirect behavior at `/redirect?to` | Retained, `ControlVerified` | True positive |
| Reflected XSS query candidates | 4 checked, 0 retained | True negative set |
| CORS endpoints | 10 checked, 0 retained | True negative set |
| Traversal | 0 eligible GET/query shapes | Out of policy; not a miss |
| SSRF | 0 eligible GET/query shapes | Out of policy; not a miss |

Eligible positive-sink metrics:

- True positives: 2
- False negatives (missed eligible positive sinks): 0
- Recall: 100% (2/2)
- Precision among retained vulnerability-behavior candidates: 100% (2/2)
- False-positive behavior candidates: 0

Two additional generic surfaces were ranked: `/rest/admin` and `/rest/user/login`. They are labeled `Repeatable` review surfaces, not vulnerability findings. If all queue entries are treated as actionable alerts, candidate-level precision is 50% (2/4); this is useful queue-noise context, not a detector false-positive count.

## Evidence and safeguards

- SQLi: stable baseline, two repeatable quote-triggered 500 responses, and a boolean differential.
- Redirect: blocked external `Location` behavior retained; the external destination was not contacted.
- XSS and CORS controls did not promote candidates.
- Persisted verification query values are represented as `%3Credacted%3E`.
- POST, authenticated, browser-DOM, and path-encoding workflows were not actively executed.
- All scanner conclusions require manual validation and do not claim confirmed vulnerabilities.

## Decision gate

Stages 1 and 2 pass for this single benchmark. This is not yet evidence of general accuracy: add at least one more intentionally vulnerable application and benign controls before a live trial. Stages 3 and 4 require an explicitly authorized scope, program rules, excluded assets, rate/concurrency limits, and a stop condition.
