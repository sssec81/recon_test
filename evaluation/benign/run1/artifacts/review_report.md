# Recon Test — Human Review Report

## Scan Summary

- Scan ID: `614b51e5-2dd4-47cd-8046-145c3752d5eb`
- Scope: 127.0.0.1
- Started: 2026-10-03T16:38:22.049226+00:00
- Finished: 2026-10-03T16:38:36.800791+00:00
- Canonical endpoints: 11
- Live endpoints: 11
- Historical-only endpoints: 0
- JavaScript-derived endpoints: 4
- Source-map-derived endpoints: 0
- Investigation opportunities: 25
- Verification attempts: 62
- Correlated candidates: 11
- Suppressed candidates: 6
- Ranked candidates: 5

Ranked evidence states:
- ControlVerified: 1
- Repeatable: 4

## Ranked Investigation Candidates

### #1 — http://127.0.0.1:8000/rest/products/search

Investigation priority: 59 / 100

Evidence state: ControlVerified

This is an investigation-priority score, not vulnerability severity.

#### Categories

- SearchSurface

#### Endpoint context

- Search

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
- SearchSurface uses the persisted GET query parameter `q` request shape; live binding: yes.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- A benign control produced a material response difference.
- Equivalent response behavior was repeatable.
- Parameter `q` was classified as Search.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- No injection testing was performed.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.

#### Manual validation

- Review how input affects backend behavior manually; the scanner performed no injection testing.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #2 — http://127.0.0.1:8000/api/profile

Investigation priority: 54 / 100

Evidence state: Repeatable

This is an investigation-priority score, not vulnerability severity.

#### Categories

- UrlHandling

#### Endpoint context

- Api
- UserProfile

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
- No benign control comparison was applicable or completed.
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
- Vulnerability severity was not established.
- Whether URL-like input causes security-sensitive outbound behavior was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.
- Only repeatability was established; no control comparison was applicable.

#### Manual validation

- Determine manually what the URL-like input controls and whether it causes security-sensitive outbound or redirect behavior.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #3 — http://127.0.0.1:8000/files/view

Investigation priority: 53 / 100

Evidence state: Repeatable

This is an investigation-priority score, not vulnerability severity.

#### Categories

- FileOrPathHandling

#### Endpoint context

- Document

#### Parameters

- `path` → Path

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

#### Score explanation

- +5 complete response fingerprint
- +20 strongest evidence state is Repeatable
- +10 confirmed-live endpoint
- +7 file or path parameter semantic
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- A persisted baseline observation was available.
- An equivalent repeat request completed and remained materially stable.
- FileOrPathHandling uses the persisted GET query parameter `path` request shape; live binding: yes.
- No benign control comparison was applicable or completed.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- Equivalent response behavior was repeatable.
- Parameter `path` was classified as Path.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.
- Only repeatability was established; no control comparison was applicable.

#### Manual validation

- Review file/path constraints, authorization, and path boundaries manually.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #4 — http://127.0.0.1:8000/admin

Investigation priority: 50 / 100

Evidence state: Repeatable

This is an investigation-priority score, not vulnerability severity.

#### Categories

- AdministrativeSurface

#### Endpoint context

- Admin

#### Parameters

No classified parameters contributed to this candidate.

#### Provenance

- page_or_script — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_link — retained inventory provenance

#### Score explanation

- +5 complete response fingerprint
- +4 Admin endpoint context
- +20 strongest evidence state is Repeatable
- +10 confirmed-live endpoint
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- A persisted baseline observation was available.
- AdministrativeSurface uses the persisted GET endpoint request shape; live binding: yes.
- An equivalent repeat request completed and remained materially stable.
- No benign control comparison was applicable or completed.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- Equivalent response behavior was repeatable.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.
- Only repeatability was established; no control comparison was applicable.

#### Manual validation

- Confirm whether the functionality is intentionally exposed and authorization is enforced.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #5 — http://127.0.0.1:8000/login

Investigation priority: 49 / 100

Evidence state: Repeatable

This is an investigation-priority score, not vulnerability severity.

#### Categories

- AuthenticationSurface

#### Endpoint context

- Authentication

#### Parameters

No classified parameters contributed to this candidate.

#### Provenance

- page_or_script — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_link — retained inventory provenance

#### Score explanation

- +5 complete response fingerprint
- +3 Authentication endpoint context
- +20 strongest evidence state is Repeatable
- +10 confirmed-live endpoint
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- A persisted baseline observation was available.
- An equivalent repeat request completed and remained materially stable.
- AuthenticationSurface uses the persisted GET endpoint request shape; live binding: yes.
- No benign control comparison was applicable or completed.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- Equivalent response behavior was repeatable.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.
- Only repeatability was established; no control comparison was applicable.

#### Manual validation

- Review authentication/session transitions, expected authorization, and error behavior manually.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---
