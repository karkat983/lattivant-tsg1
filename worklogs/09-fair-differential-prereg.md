# Worklog 09 — fair differential + status-vs-effect: PRE-REGISTRATION

Date: 2026-10-18. Committed **before any tool is run against the target** for this
experiment. Tools were installed and their `--help`/docs/source read first (to name the
real switches below); none had been pointed at the target. This file is not edited after
the first run; deviations go in `RESULTS_FAIR_DIFFERENTIAL.md`.

## Why this exists

The earlier differential (`reports/differential/`, worklogs 03–06) ran every baseline with
**one identity** (`tok-bravo-admin`) and without the baselines' authorization checkers
(RESTler `NamespaceRule` off, Schemathesis `object_level_authorization` not enabled,
EvoMaster's multi-user security phase not configured). A single-identity tool cannot
detect cross-identity flaws, so "each 0/4" was a configuration result, not a capability
result. This experiment gives each baseline two identities and its own authz checks.

## Target

The Rust reference target `authz-fuzzer/scanner/crates/authz-target` (the one the live lab
and the earlier differential use), bound to 127.0.0.1 only. Tenants `alpha`, `bravo`;
tokens `tok-alpha-admin`, `tok-alpha-viewer`, `tok-bravo-admin`. Seeded orders:
`order-1` (alpha private), `order-shared` (alpha, shared read-only with bravo),
`order-public` (public), `order-bravo` (bravo private).

Planned target changes, applied identically for every tool:
1. **OpenAPI response schemas** (POST → 201 with the order object incl. `id`; GET/PATCH →
   200; DELETE → 204; 401/403/404 documented). Without them no tool can infer that
   `POST /orders` produces the `{id}` that `/orders/{id}` consumes, which is what the
   baselines' cross-user checkers need. The earlier run injected a dummy `responses` for
   RESTler only.
2. **Four status-vs-effect modes** (Task 4): `silent-write` (cross-tenant PATCH/DELETE →
   403 but applied), `lying-success` (cross-tenant PATCH/DELETE → 200/204, nothing
   applied), `admin-legit` (writes allowed only to same-tenant admins; a viewer's order
   written by an alpha admin is policy-allowed), `leaky-404` (cross-tenant GET → 404 whose
   body is the owner's order).

## Hypotheses

- **H1.** With two identities and their authorization checkers enabled, each generic
  baseline (RESTler, EvoMaster, Schemathesis) detects **fewer** of the 4 planted
  authorization flaws than authz-fuzzer.
- **H2.** On the 4 status-vs-effect rows, a status-code oracle misclassifies **at least one**
  row that authz-fuzzer classifies correctly.

## Tools and fair configuration (fixed now)

| Tool | Identities | Authz checks enabled | Budget / seed |
|---|---|---|---|
| authz-fuzzer | manifest identities (as the live lab) | its oracle (built in) | as live lab |
| RESTler (source build, .NET 8) | 2 users via `token_refresh_command` (user 1 = owner, user 2 = attacker) | `--enable_checkers NamespaceRule UseAfterFree ResourceHierarchy LeakageRule InvalidDynamicObject`; namespacerule `trigger_on_dynamic_objects: true`, `trigger_objects: ["order-1","order-shared","order-public"]`; fuzzing dictionary seeded with the same ids | `fuzz --time_budget 0.05` (3 min) per mode; RESTler default `random_seed` 12345 |
| EvoMaster 6.2.0 (black-box) | 2 users in a WFC `auth:` config (fixed `Authorization` headers) | security phase (`--security true`, the default) | `--maxTime 120s`, `--seed 42` |
| Schemathesis 4.32.0 | 2 users in a WFC auth file, `[auth.wfc] peers = [both]` | `--checks all` (includes `object_level_authorization`, `ignored_auth`) | all phases, `--max-examples 50`, `--seed 42` |

Identity pair per run: owner/user 1 = `alpha-admin`, attacker/user 2 = `bravo-admin`, for
every mode except `admin-legit`, where owner = `alpha-viewer` and actor = `alpha-admin`
(the case policy allows). authz-fuzzer gets the same pair in its manifest.

One run per tool per mode (fixed seeds where the tool has one). Single runs are a stated
limitation; fuzzers are stochastic.

## What counts as an authorization finding (per tool, fixed now)

- **authz-fuzzer:** a finding at **Verified** confidence (its CI-gate tier, as in the live
  lab). Probable findings are reported separately and also scored as a secondary verdict.
- **RESTler:** a bug bucket from `NameSpaceRuleChecker` (cross-identity class). Other
  checkers' buckets are reported but are not authorization findings.
- **Schemathesis:** `object_level_authorization` failures (cross-identity class) and
  `ignored_auth` failures (unauthenticated class).
- **EvoMaster:** faults `SECURITY_WRONG_AUTHORIZATION` and `SECURITY_EXISTENCE_LEAKAGE`
  (cross-identity class) and `SECURITY_IGNORE_ANONYMOUS` (unauthenticated class).

A finding's **signature** is (tool category incl. sub-title where the tool gives one,
operation `METHOD /path-template`).

## Metrics

**Task 3, H1 — recall over the 4 planted flaws** (k/4 per tool). Tool T detects flaw X iff
the run against X's server reports a finding of the relevant class on X's operations whose
signature is **absent** from T's run against the hardened server (`none`) with the same
identities (so findings the planted flaw did not cause are not credited):

| Flaw | Server mode | Relevant class | Operations |
|---|---|---|---|
| xtenant-read | bola-read | cross-identity | GET /orders/{id} |
| xtenant-write | bola-write | cross-identity | PATCH, DELETE /orders/{id} |
| missing-auth | missing-auth | unauthenticated | GET /orders/{id} |
| shared-write | shared-write | cross-identity | PATCH, DELETE /orders/{id} |

**Task 3 — false findings on trap modes:** the number of distinct authorization-finding
signatures (either class) a tool reports on the trap runs: the hardened server `none`,
which carries the delegated (`order-shared`) and public (`order-public`) traps, and
`admin-legit`. For authz-fuzzer the traps are the live lab's `none`, `delegated-read` and
`public-read` modes plus `admin-legit`.

**Task 4, H2 — verdict per row.** A row is *flagged* if the tool reports a finding of the
cross-identity class on the row's operations in that mode's run:

| Row | Operations | Correct verdict | Correct if |
|---|---|---|---|
| silent-write | PATCH, DELETE | verified violation | flagged, and the signature is absent from the hardened control run |
| lying-success | PATCH, DELETE | no write violation | not flagged |
| admin-legit | GET, PATCH, DELETE | no finding | not flagged |
| leaky-404 | GET | information disclosure | flagged, and the signature is absent from the hardened control run |

For authz-fuzzer, *flagged* = a Verified finding (primary). It is also scored with Probable
findings counted (secondary). By its oracle source (`authz-oracle/src/write.rs`), a 2xx
write with no state change yields a Probable finding. So the secondary verdict for
lying-success is expected to be "flagged", and it is reported, not hidden.

## Null / negative results (stated now)

- **H1 null:** any baseline reaches authz-fuzzer's recall (e.g. RESTler's NamespaceRule
  catching bola-write, or Schemathesis's `object_level_authorization` catching bola-read
  makes that cell a match). H1 is then reported as not supported for that baseline.
  Recall ties, and baseline flaws authz-fuzzer misses, are reported as such.
- **H2 null:** every baseline classifies all 4 rows exactly as authz-fuzzer does.
- If a tool cannot be run: `NOT_RUN` with the error. It is excluded from H1/H2 and never
  counted as 0.

## Out of scope

Burp Autorize (commercial GUI, not headless). EvoMaster white-box (cannot instrument a Rust
binary). No host other than 127.0.0.1 is contacted by any tool.
