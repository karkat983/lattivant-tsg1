# TSG-1 Differential — authz-fuzzer vs generic baselines

Each tool run against the same seeded `authz-target`. Ground truth is the four planted authorization flaws; recall is over that set. Generic API fuzzers test one identity against a schema and have no cross-tenant/ownership check, so they structurally miss BOLA.

**Differential (AZ-046/RV-007): PASS** — candidate recall >= union of baselines

| Tool | Ran? | Authz-flaw recall | Found | Note |
|------|------|-------------------|-------|------|
| **authz-fuzzer** (candidate) | ✅ | **1.0** (4/4) | missing-auth, shared-write, xtenant-read, xtenant-write | live end-to-end scans |
| schemathesis | ✅ | 0.0 (0/4) | — | generic schema fuzzer: finds conformance issues, no authz check |
| evomaster | ✅ | 0.0 (0/4) | — | black-box (white-box cannot instrument a Rust target): finds robustness/protocol faults (XSS, HTTP violations), no authz check |
| restler | — | 0.0 (0/4) | — | RESTler needs Docker (daemon not running here) or a .NET toolchain (absent); and has no authz/BOLA check |
| burp_autorize | — | 0.0 (0/4) | — | Burp Suite + Autorize is a commercial GUI extension; cannot run headless here |

### schemathesis per-mode (what it *did* find)

| Mode | Non-authz failures | Categories | Authz detection |
|------|--------------------|------------|-----------------|
| bola-read | 5 | Undocumented HTTP status code×5 | no |
| bola-write | 5 | Undocumented HTTP status code×5 | no |
| missing-auth | 5 | Undocumented HTTP status code×5 | no |
| shared-write | 5 | Undocumented HTTP status code×5 | no |

### evomaster per-mode (what it *did* find)

| Mode | Non-authz failures | Categories | Authz detection |
|------|--------------------|------------|-----------------|
| bola-read | 2 | Fault301×1, Fault109×1 | no |
| bola-write | 1 | Fault109×1 | no |
| missing-auth | 1 | Fault109×1 | no |
| shared-write | 2 | Fault301×1, Fault109×1 | no |

_The generic fuzzers flag schema-conformance and robustness faults (undocumented status codes, XSS, HTTP violations) but detect none of the planted authorization flaws — the authz scanner's value-add._

