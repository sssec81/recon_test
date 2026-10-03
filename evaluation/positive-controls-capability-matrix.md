# Controlled positive-fixture capability matrix

Target: `evaluation/fixtures/positive_controls.py`, bound to `127.0.0.1:8000`.

The matrix is defined before execution. Each route implements only the minimum deterministic behavior required to exercise one detector. The SSRF fixture simulates backend connection failures and makes no outbound request.

| Detector | Endpoint | Positive behavior | Expected evidence state |
| --- | --- | --- | --- |
| Reflected XSS | `/xss?q=baseline` | Returns the decoded query value unescaped in an HTML response | `ControlVerified` |
| Traversal | `/view?file=index` | Repeated traversal probes return a Unix passwd signature; missing-file control remains clean | `ControlVerified` |
| CORS | `/account` | Reflects the supplied hostile `Origin` and permits credentials | `ControlVerified` |
| SSRF | `/fetch?url=original` | Returns distinct simulated connection errors for reserved and loopback destinations | `Repeatable` |

Acceptance criteria:

- Exactly one retained behavior candidate for each of the four detectors.
- No real outbound fetch occurs in the SSRF fixture.
- Persisted query values remain redacted.
- Candidate categories, evidence states, scores, and verification outcomes match across two fresh scans.

## Verified result

Scans `341f2291-75fd-414e-9737-7b34b2f4ad29` and
`a6ecf88e-c4e6-43d5-8eca-f05407f01cad` both retained exactly four behavior
candidates:

| Detector | Retained | Evidence state | Score |
| --- | ---: | --- | ---: |
| Reflected XSS | 1 | `ControlVerified` | 59 |
| Traversal | 1 | `ControlVerified` | 63 |
| CORS | 1 | `ControlVerified` | 39 |
| SSRF | 1 | `Repeatable` | 54 |

All verification query values were persisted as `%3Credacted%3E`. After sorting
verification attempts by request type and sequence, both normalized reports
have SHA-256
`abb660667d579ef3e48bdfe52e6dbd2ef47db3b61e1c39f52afb9cd80a913cff`.
