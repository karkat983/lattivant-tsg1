# Worklog 01 — integrated live lab (end-to-end AuthZ-Fuzzer)

Date: 2026-10-17

## Scope delivered
Stood up the TSG-1 C.3 integrated demonstration lab for the one
substantially-built detection component. The lab runs the `authz-target`
reference API over a real socket in each vulnerability mode, scans it with the
built Rust `authz` binary, and scores the emitted SARIF/JSON findings against
per-mode ground truth using the harness oracles — upgrading AZ-002/003/030/047
from conformance-test-backed to live end-to-end evidence.

## Files changed
- `lab/live_lab.py` — driver (serve target, fetch `/openapi.json`, write scan
  manifest, run `authz scan`, parse findings, score via `tsg1.oracles`).
- `lab/__init__.py`
- `tests/test_live_lab.py` — 8 no-network scoring tests.
- `reports/live-lab/{report.md,results.json,<mode>/…}` — committed live run.
- `RESULTS.md` — added the live-lab section.

## Commands run (actual status)
- `cargo build -p authz-target -p authz-cli` → built `authz`, `authz-target`.
- `python3 lab/live_lab.py` → **5/5 modes scored as expected**:
  none=0 findings (gate exit 0); bola-read=1 verified `cross_tenant_access` read
  (exit 2); bola-write=2 verified writes (exit 2); missing-auth caught
  `missing_authentication` (exit 2); read-only scope vs write-vuln server emitted
  0 write findings (exit 0).
- `python3 -m unittest discover -s tests` → **OK, 22 tests**.

## Validation evidence
Each mode's `reports/live-lab/<mode>/` holds the exact `openapi.json`,
`manifest.json`, `out.json` and `out.sarif` from the run; the scan command and a
content digest of each report are recorded in `results.json`. The fixture
mirrors the scanner's own canonical integration test
(`authz-cli/tests/scan_live_target.rs`): two identities (alpha owner + bravo
cross-tenant) and a per-mode mutation scope.

## Notes / honest limits
- A first fixture (an extra same-tenant viewer identity + write probes in every
  mode) produced 3 false findings in `none` mode. That was a fixture/authz-model
  mismatch (the target authorizes per tenant, not per identity), not a product
  defect; corrected to the canonical two-identity fixture and `none` is clean.
- `shared-write` is not exercised: the seeded `order-1` is shared with no tenant,
  so the vuln cannot trigger; omitted rather than reported as pass/fail.
- This covers only the AuthZ-Fuzzer. The SPEC-blocked detector families
  (AgentTrace R1–R4, Evidence Graph, Investigator, MCP scanner) still have no
  live lab because the components are not built.

## Next authorized step (one)
Extend the live lab with additional seeded resources (a shared order, a second
tenant's order, a public order) to exercise `shared-write`, delegated-access and
public-object traps live (AZ-005, AZ-004), and add the differential-vs-baseline
tools once network access / installs are permitted.
