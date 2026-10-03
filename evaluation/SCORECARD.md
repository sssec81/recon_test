# Controlled evaluation scorecard

Date: 2026-10-03 (Asia/Katmandu)

## Targets and repetitions

| Target | Role | Version/digest | Runs |
| --- | --- | --- | ---: |
| OWASP Juice Shop | Eligible-positive vulnerable target | 20.2.0 / `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` | 2 |
| OWASP WebGoat | Vulnerable application; policy-boundary and false-promotion target | v2026.4 / `sha256:d4ac9fc2b0a41b68d64dedde684f4783aa60cc785838435a6d5bd5a25b387497` | 2 |
| Benign look-alike | Negative control | Local fixture v1 | 2 |
| Detector positive controls | Eligible-positive XSS, traversal, CORS, and SSRF fixtures | Local fixture v1 | 2 |

WebGoat was run only on loopback. Its exercises require authentication, submissions, or browser lesson workflows that this GET-only scanner intentionally does not perform. Those lessons are excluded from the false-negative denominator. See `webgoat-capability-matrix.md` and `benign-capability-matrix.md`.

## Detector scorecard

Counts below use one canonical run per target; the second run is a reproducibility check and does not double the sample size. A false positive means a retained vulnerability-behavior category on a declared negative case. Generic surface classification is counted separately as review-only noise.

| Detector | Eligible positives | TP | FN | Eligible negative checks | FP | Review-only entries | Repeat result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| SQL injection | 1 | 1 | 0 | 6 | 0 | 1 search surface | Identical |
| Reflected XSS | 1 | 1 | 0 | 7 | 0 | 0 | Identical |
| Open redirect | 1 | 1 | 0 | 2 | 0 | 0 | Identical |
| Traversal | 1 | 1 | 0 | 1 | 0 | 1 path surface | Identical |
| CORS | 1 | 1 | 0 | 20 | 0 | 0 | Identical |
| SSRF | 1 | 1 | 0 | 1 | 0 | 1 URL surface | Identical |

The SSRF true positive is intentionally weaker than the other new controls.
`Repeatable` means reserved-address and loopback inputs produced stable, distinct
network-error responses. It does **not** mean an outbound request was observed.
Only an authorized callback observation could establish server-originated
network access, so SSRF is not promoted to `ControlVerified`.

Four additional review-only entries are not attributable to a vulnerability detector: administrative and authentication surfaces in Juice Shop and the benign control.

Aggregate results for detectors with eligible positives:

- Recall: 100% (6/6)
- Behavior-candidate precision: 100% (6/6)
- False negatives: 0
- False-positive vulnerability-behavior candidates: 0
- Review-only entries per target: Juice Shop 2, WebGoat 0, benign control 5

## Reproducibility

Each target was freshly scanned twice with the same limits. After excluding run IDs and loopback port prefixes, all of the following matched exactly within each target pair:

- ranked endpoint order;
- scores and evidence states;
- categories;
- verification narratives;
- request types, comparisons, outcomes, statuses, completeness, and material-difference flags.

Normalized evidence SHA-256 pairs:

| Target | Matching hash |
| --- | --- |
| Juice Shop | `5a54004e27fdf129240dd9e8c26fcd40d054905a99fdb374ff822a1adaa5f385` |
| WebGoat | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| Benign control | `39fc011868a00e451b54c7606c168afd685d5241612b400f45759a9bd19e7bcb` |
| Detector positive controls | `abb660667d579ef3e48bdfe52e6dbd2ef47db3b61e1c39f52afb9cd80a913cff` |

Verification-attempt arrays were compared as sets ordered by request type and sequence. Their persisted order can vary when generic and detector-specific checks share an endpoint; the attempts and outcomes themselves matched.

## Acceptance thresholds for a live-trial gate

These thresholds were fixed before any authorized live target is supplied:

| Gate | Threshold | Current result |
| --- | --- | --- |
| Positive coverage | At least one eligible positive and one eligible negative for every enabled detector | Pass: all six enabled detectors covered |
| Recall | 100% on declared eligible positives | Pass: 100% (6/6) |
| Precision | At least 95% for retained vulnerability-behavior candidates | Pass: 100% (6/6) |
| Benign false alarms | Zero vulnerability-behavior candidates | Pass: 0 |
| Reproducibility | 100% match of normalized ranked evidence across two runs | Pass |
| Review queue noise | No more than 5 review-only entries per target | Pass: maximum 5 |
| Safety | Zero out-of-scope redirect contacts; persisted verification values redacted | Pass |

## Decision

**The controlled-evaluation gate passes. No live trial was started.** Every enabled detector now has at least one eligible positive and negative, all six eligible positives were retained, the benign application produced no vulnerability-behavior candidate, and normalized evidence matched across repeated scans. A live trial still requires a separately supplied, explicitly authorized scope and conservative run limits.
