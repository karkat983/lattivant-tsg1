# Worklog 05 — RESTler provisioned and run live (RV-008)

Date: 2026-10-17

## Scope delivered
Installed the .NET 8 SDK, built RESTler from source, and ran it against the
seeded target in every vuln mode — completing RV-008 as a measured result.
All three generic baselines now run live; each scores 0/4 on authorization flaws.

## Files changed
- `test-suite/lab/differential.py` — `_restler_env`, `_normalize_spec_for_restler`,
  `_run_restler` (compile grammar → test → parse testing_summary.json bug_buckets).
- `test-suite/tests/test_differential.py` — spec-normalization test (32→33+).
- Updated RV-008 catalog reason; `RESULTS.md`; refreshed `reports/differential/*`.

## Commands run (actual status)
- `brew install dotnet@8` → **8.0.131** (keg-only).
- `git clone microsoft/restler-fuzzer` (targets net8.0); `python3 build-restler.py`
  → **BUILD_EXIT=0**, `restler_bin/restler/Restler.dll` produced.
- `dotnet Restler.dll compile --api_spec <normalized spec>` → **succeeded**
  (the raw target spec omits per-operation `responses`, which RESTler's NSwag
  parser requires; a default `responses` is injected for RESTler only).
- `dotnet Restler.dll test ... --token_refresh_command ...` → **TEST_EXIT=0**,
  `No bugs were found`, `bug_buckets: {}`.
- `python3 lab/differential.py` (all three baselines) →
  authz-fuzzer **4/4**; Schemathesis **0/4**; EvoMaster **0/4**; RESTler **0/4**
  (0 bugs). **Differential PASS.**
- `python3 -m unittest discover -s tests` → **OK, 33 tests**.

## Honest limits
- RESTler needed a `python` shim (engine calls `python`, the host has only
  `python3`) and a spec normalization (inject `responses`) to parse the minimal
  spec. Neither changes which operations are tested; both are documented.
- RESTler coverage was low (0/4 valid-status) in `test` mode because it does not
  chain create→get for this API without a resource dictionary; this is noted
  per-mode. It does not affect the authz-flaw result: RESTler has no
  cross-tenant/ownership check, so its authz recall is 0/4 by construction.
- Only Burp Autorize (RV-010) remains NOT_RUN — a commercial GUI extension that
  cannot run headless. Documented, not faked.
- Tooling (dotnet@8 SDK, RESTler build, EvoMaster jar, Schemathesis venv) lives
  outside the repo; the committed report captures the run and the driver finds
  each tool via env vars, else reports NOT_RUN with an install hint.

## Next authorized step (one)
The three automatable baselines are complete. A deeper RESTler `fuzz` run with a
seeded resource dictionary (to raise coverage) would strengthen the "even with
coverage, no BOLA" claim, but would not change the differential verdict.
