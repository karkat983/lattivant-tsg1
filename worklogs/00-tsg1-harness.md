# Worklog 00 — TSG-1 harness: build + first measured results

Date: 2026-10-17

## Scope delivered
Built an executable test suite from the pasted Lattivant TSG-1 research
package and ran it against the Lattivant product to measure current
effectiveness. Deliverables: the `tsg1` harness (model, stats, oracles, catalog,
runner, report, CLI), the full 326-scenario registry, component adapters backing
the built AuthZ-Fuzzer scenarios with real evidence, ground-truth manifests, a
committed full-catalog report, and harness self-tests.

## Files changed (new `test-suite/` git repo; sole author = repo owner)
- `tsg1/{__init__,model,stats,oracles,catalog,runner,report,cli,__main__}.py`
- `tsg1/adapters/{__init__,_scanner,_evidence,authz_fuzzer,platform_rls,research_validity,scale_chaos}.py`
- `catalog/build_catalog.py` -> `catalog/scenarios.jsonl` (326)
- `manifests/{AZ-002,AZ-006,AZ-047}.json`
- `tests/test_harness.py`
- `reports/full/{report.md,results.json}`
- `README.md`, `RESULTS.md`

## Commands run (actual status)
- `cargo test --workspace` in `authz-fuzzer/scanner` → **exit 0, 202 passed, 0 failed**.
- `python3 -m unittest discover -s tests` → **OK, 14 tests**.
- `python3 catalog/build_catalog.py` → wrote 326 scenarios.
- `python3 -m tsg1 run --all` → 326 scenarios: **22 PASS, 0 FAIL, 184 SKIPPED,
  120 NOT_RUN, 0 ERROR; S0 gate CLEAN**.

## Validation evidence
Every PASS cites the named scanner conformance tests that back it (recorded in
`results.json` as `command` + `backing_tests_*`). The harness refuses to pass a
scenario whose backing test is absent (→ NOT_RUN) or whose dependency is unbuilt
(→ SKIPPED); self-tests assert these guarantees.

## Unresolved risks / conflicts (surfaced, not silently resolved)
1. **AGENTS.md vs reality.** `/Users/karthikkt/Documents/AGENTS.md` describes a
   Python "Judge Lab" MVP and references `specs/` that do not exist. The on-disk
   project is the Rust/Java Lattivant platform matching TSG-1. Kept AGENTS.md's
   *discipline* (no fabrication, untrusted-input handling, real exit codes,
   honest NOT_RUN, commit discipline, no live targets); did not treat its
   product-identity claim as describing this repo.
2. **"286" vs 326.** The guide's prose says 286 but enumerates 326 (matches its
   own G.1 matrix). Registry keeps all 326; flagged in RESULTS.md.
3. **Evidence is conformance-test-backed, not live end-to-end.** PASS == "the
   built control has passing tests for this property," not "a seeded target was
   scanned live." The integrated lab (TSG-1 C.3) is the next step.
4. **Only AuthZ-Fuzzer is substantially built.** 173 SPEC + 11 partial scenarios
   await AgentTrace R1–R4 / Evidence Graph / Investigator / MCP scanner.

## Next authorized step (one)
Stand up the integrated demonstration lab (TSG-1 C.3): run the `authz-target`
mock server + the Rust scanner against a seeded OpenAPI spec and score emitted
SARIF/JSON findings against ground-truth manifests — upgrading AZ-\* from
conformance-backed to live end-to-end evidence, and unlocking the differential-
vs-baseline scenarios.
