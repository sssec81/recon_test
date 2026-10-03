# Benign look-alike capability matrix

Controlled target: `evaluation/fixtures/benign_app.py`, bound to `127.0.0.1:8000`.

The fixture deliberately exposes security-looking paths and parameters while implementing stable, non-vulnerable behavior.

| Detector | Endpoint pattern | Eligibility | Expected result |
| --- | --- | --- | --- |
| SQL injection | `/rest/products/search?q` | Eligible negative | Suppress; responses contain no database differential |
| Reflected XSS | `/rest/products/search?q` | Eligible negative | Suppress; input is not reflected |
| Open redirect | `/redirect?to` | Eligible negative | Suppress; external destinations return 400 without `Location` |
| Traversal | `/files/view?path` | Eligible negative | Suppress; path input never accesses a file |
| CORS | Reachable GET endpoints | Eligible negative | Suppress; no permissive CORS headers are emitted |
| SSRF | `/api/profile?url` | Eligible negative | Suppress; URL input is ignored and no outbound request occurs |

`/admin` and `/login` intentionally resemble sensitive surfaces. If ranked, they count only as review-only queue entries. Every retained vulnerability-behavior category is a false positive.
