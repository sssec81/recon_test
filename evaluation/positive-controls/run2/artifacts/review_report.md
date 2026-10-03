# Recon Test — Human Review Report

## Scan Summary

- Scan ID: `a6ecf88e-c4e6-43d5-8eca-f05407f01cad`
- Scope: 127.0.0.1
- Started: 2026-10-03T16:57:21.866383+00:00
- Finished: 2026-10-03T16:57:34.392793+00:00
- Canonical endpoints: 8
- Live endpoints: 8
- Historical-only endpoints: 0
- JavaScript-derived endpoints: 4
- Source-map-derived endpoints: 0
- Investigation opportunities: 19
- Verification attempts: 54
- Correlated candidates: 8
- Suppressed candidates: 4
- Ranked candidates: 4

Ranked evidence states:
- ControlVerified: 3
- Repeatable: 1

## Ranked Investigation Candidates

### #1 — http://127.0.0.1:8000/view

Investigation priority: 63 / 100

Evidence state: ControlVerified

This is an investigation-priority score, not vulnerability severity.

#### Categories

- FileOrPathHandling
- PathTraversalBehavior

#### Endpoint context

- Unknown

#### Parameters

- `file` → File

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

#### Score explanation

- +5 complete response fingerprint
- +30 strongest evidence state is ControlVerified
- +10 confirmed-live endpoint
- +7 file or path parameter semantic
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- A persisted baseline observation was available.
- An equivalent repeat request completed and remained materially stable.
- FileOrPathHandling uses the persisted GET query parameter `file` request shape; live binding: yes.
- PathTraversalBehavior uses the persisted GET query parameter `file` request shape; live binding: yes.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- A benign control produced a material response difference.
- Equivalent response behavior was repeatable.
- Parameter `file` was classified as File.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Arbitrary file access beyond the repeated signature was not established.
- Exploitability was not established.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.

#### Manual validation

- Confirm path normalization and file-boundary behavior manually within authorization.
- Review file/path constraints, authorization, and path boundaries manually.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #2 — http://127.0.0.1:8000/xss

Investigation priority: 59 / 100

Evidence state: ControlVerified

This is an investigation-priority score, not vulnerability severity.

#### Categories

- ReflectedXssBehavior
- SearchSurface

#### Endpoint context

- Unknown

#### Parameters

- `q` → Search

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

#### Score explanation

- +5 complete response fingerprint
- +30 strongest evidence state is ControlVerified
- +10 confirmed-live endpoint
- +3 search or query parameter semantic
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- A benign same-origin control produced a material response difference.
- A persisted baseline observation was available.
- An equivalent repeat request completed and remained materially stable.
- ReflectedXssBehavior uses the persisted GET query parameter `q` request shape; live binding: yes.
- SearchSurface uses the persisted GET query parameter `q` request shape; live binding: yes.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- A benign control produced a material response difference.
- Equivalent response behavior was repeatable.
- Parameter `q` was classified as Search.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Browser script execution and exploitable HTML context were not established.
- Exploitability was not established.
- No injection testing was performed.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.

#### Manual validation

- Confirm the HTML context and browser behavior manually without escalating the payload.
- Review how input affects backend behavior manually; the scanner performed no injection testing.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #3 — http://127.0.0.1:8000/fetch

Investigation priority: 54 / 100

Evidence state: Repeatable

This is an investigation-priority score, not vulnerability severity.

#### Categories

- SsrfBehavior
- UrlHandling

#### Endpoint context

- Unknown

#### Parameters

- `url` → Url

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

#### Score explanation

- +5 complete response fingerprint
- +20 strongest evidence state is Repeatable
- +10 confirmed-live endpoint
- +8 URL or redirect parameter semantic
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- A persisted baseline observation was available.
- An equivalent repeat request completed and remained materially stable.
- Reserved-address and loopback probes produced distinct network-error responses; this is a response differential, not callback-confirmed outbound access.
- SsrfBehavior uses the persisted GET query parameter `url` request shape; live binding: yes.
- UrlHandling uses the persisted GET query parameter `url` request shape; live binding: yes.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- Equivalent response behavior was repeatable.
- Parameter `url` was classified as Url.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- No vulnerability was confirmed by the scanner.
- Outbound server-side network access was not established.
- Vulnerability severity was not established.
- Whether URL-like input causes security-sensitive outbound behavior was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.
- SSRF evidence is response-based only; no authorized callback observed a server-originated request.

#### Manual validation

- Determine manually what the URL-like input controls and whether it causes security-sensitive outbound or redirect behavior.
- Use an authorized callback service to confirm outbound server behavior manually.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #4 — http://127.0.0.1:8000/account

Investigation priority: 39 / 100

Evidence state: ControlVerified

This is an investigation-priority score, not vulnerability severity.

#### Categories

- CorsBehavior

#### Endpoint context

- Account

#### Parameters

No classified parameters contributed to this candidate.

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

#### Score explanation

- +3 Account endpoint context
- +30 strongest evidence state is ControlVerified
- +6 crawl-derived code evidence family

#### Verification

- A persisted baseline observation was available.
- CorsBehavior uses the persisted GET path parameter `` request shape; live binding: yes.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- A benign control produced a material response difference.
- Equivalent response behavior was repeatable.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- Exposure of sensitive credentialed response data was not established.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.

#### Manual validation

- Confirm whether credentialed cross-origin reads expose sensitive data.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---
