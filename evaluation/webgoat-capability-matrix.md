# OWASP WebGoat capability matrix

Controlled target: OWASP WebGoat `v2026.4`, image digest
`sha256:d4ac9fc2b0a41b68d64dedde684f4783aa60cc785838435a6d5bd5a25b387497`,
bound only to loopback.

This matrix is defined before scanning. The scanner is GET-only, does not create an account or authenticate, does not submit forms, and does not execute browser lesson workflows. WebGoat deliberately places its exercises behind those interactions, so this target measures conservative discovery and false promotion—not positive-sink recall.

| Detector | WebGoat lesson shape | Current eligibility | Expected result |
| --- | --- | --- | --- |
| SQL injection | Authenticated lesson submission | Out of active policy | No behavior candidate |
| Reflected XSS | Authenticated lesson/browser workflow | Out of active policy | No behavior candidate |
| Open redirect | No predeclared unauthenticated GET-query sink | No eligible positive | No behavior candidate |
| Traversal | Authenticated lesson/path or submission workflow | Out of active policy | No behavior candidate |
| CORS | Header control on reachable GET endpoints | Eligible negative control | No behavior candidate unless exact hostile-origin reflection with credentials is observed |
| SSRF | Authenticated lesson/submission workflow | Out of active policy | No behavior candidate |

Any generic login, administrative, or endpoint classification is a review-only queue entry and must not be counted as a vulnerability-behavior true positive. A WebGoat lesson that the scanner cannot reach under policy is excluded from the false-negative denominator.
