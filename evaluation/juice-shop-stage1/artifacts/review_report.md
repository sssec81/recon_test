# Recon Test — Human Review Report

## Scan Summary

- Scan ID: `b3fa0a4f-2d7d-42ab-ae52-79fdab463d3b`
- Scope: 127.0.0.1
- Started: 2026-10-03T15:46:30.934134+00:00
- Finished: 2026-10-03T15:46:56.241987+00:00
- Canonical endpoints: 124
- Live endpoints: 54
- Historical-only endpoints: 0
- JavaScript-derived endpoints: 117
- Source-map-derived endpoints: 0
- Investigation opportunities: 26
- Verification attempts: 62
- Correlated candidates: 124
- Suppressed candidates: 120
- Ranked candidates: 4

Ranked evidence states:
- ControlVerified: 2
- Repeatable: 2

## Ranked Investigation Candidates

### #1 — http://127.0.0.1:8080/rest/products/search

Investigation priority: 59 / 100

Evidence state: ControlVerified

This is an investigation-priority score, not vulnerability severity.

#### Categories

- SearchSurface
- SqlInjectionBehavior

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

- A persisted baseline observation was available.
- SqlInjectionBehavior uses the persisted GET query parameter `q` request shape; live binding: yes.
- The original live query response repeated stably before SQL controls.
- Two bounded quote probes reproduced a database-specific error differential.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- A benign control produced a material response difference.
- Equivalent response behavior was repeatable.
- Parameter `q` was classified as Search.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Backend query execution and exploitability were not established.
- Exploitability was not established.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.

#### Manual validation

- Reproduce the paired database-error differential manually on the authorized target; do not infer data access from this signal alone.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #2 — http://127.0.0.1:8080/redirect

Investigation priority: 51 / 100

Evidence state: ControlVerified

This is an investigation-priority score, not vulnerability severity.

#### Categories

- OpenRedirectBehavior
- RedirectBehavior

#### Endpoint context

- Redirect

#### Parameters

- `to` → Unknown

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance
- verification — retained inventory provenance

#### Score explanation

- +30 strongest evidence state is ControlVerified
- +10 confirmed-live endpoint
- +6 crawl-derived code evidence family
- +5 live HTTP evidence family

#### Verification

- OpenRedirectBehavior uses the persisted GET query parameter `to` request shape; live binding: yes.
- The control established input influence on response behavior; destination safety was not tested.

#### Historical changes

No material historical signal was recorded.

#### Established by scanner

- A benign control produced a material response difference.
- Equivalent response behavior was repeatable.
- Parameter `to` was classified as Unknown.
- The endpoint was observed during live HTTP inventory.

#### Not established

- Exploitability was not established.
- External navigation impact was not established; the destination was not contacted.
- No vulnerability was confirmed by the scanner.
- Vulnerability severity was not established.
- Whether a security trust boundary can be bypassed was not established.
- Whether arbitrary external destinations are accepted was not established.

#### Limitations

- Historical comparison was unavailable because no eligible previous same-scope scan existed.

#### Manual validation

- Confirm destination validation manually; the scanner did not contact the external destination.
- Review destination validation manually within program scope and confirm the intended trust boundary.

Manual validation required: **YES**

Scanner conclusion: **Investigation candidate only. No vulnerability is confirmed.**

---

### #3 — http://127.0.0.1:8080/rest/admin

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

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

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

### #4 — http://127.0.0.1:8080/rest/user/login

Investigation priority: 49 / 100

Evidence state: Repeatable

This is an investigation-priority score, not vulnerability severity.

#### Categories

- AuthenticationSurface

#### Endpoint context

- Authentication
- UserProfile

#### Parameters

No classified parameters contributed to this candidate.

#### Provenance

- javascript — referenced by fetched JavaScript
- javascript_call — retained inventory provenance
- triage_fetch — retained inventory provenance
- triage_script — retained inventory provenance

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
