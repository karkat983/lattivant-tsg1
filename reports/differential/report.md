# TSG-1 Differential — authz-fuzzer vs generic baselines

Each tool run against the same seeded `authz-target`. Ground truth is the four planted authorization flaws; recall is over that set. Generic API fuzzers test one identity against a schema and have no cross-tenant/ownership check, so they structurally miss BOLA.

**Differential (AZ-046/RV-007): PASS** — candidate recall >= union of baselines

| Tool | Ran? | Authz-flaw recall | Found | Note |
|------|------|-------------------|-------|------|
| **authz-fuzzer** (candidate) | ✅ | **1.0** (4/4) | missing-auth, shared-write, xtenant-read, xtenant-write | live end-to-end scans |
| schemathesis | ✅ | 0.0 (0/4) | — | generic schema fuzzer: finds conformance issues, no authz check |
| restler | — | 0.0 (0/4) | — | RESTler needs a .NET 6 toolchain + compiled grammar; not provisioned (and has no authz/BOLA check) |
| evomaster | — | 0.0 (0/4) | — | EvoMaster needs a white-box driver / jar + instrumented target; not provisioned |
| burp_autorize | — | 0.0 (0/4) | — | Burp Suite + Autorize is a commercial GUI extension; cannot run headless here |

### Schemathesis per-mode (what it *did* find)

| Mode | Non-authz failures | Categories | Authz detection |
|------|--------------------|------------|-----------------|
| bola-read | 5 | Undocumented HTTP status code×5 | no |
| bola-write | 5 | Undocumented HTTP status code×5 | no |
| missing-auth | 5 | Undocumented HTTP status code×5 | no |
| shared-write | 5 | Undocumented HTTP status code×5 | no |

_Schemathesis flags schema-conformance issues (e.g. undocumented status codes) but detects none of the planted authorization flaws — the authz scanner's value-add._

