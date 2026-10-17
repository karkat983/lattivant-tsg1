# Worklog 03 — differential vs baseline (AZ-046 / RV-007..010)

Date: 2026-10-17

## Scope delivered
Added a real differential between the built authz scanner and generic
API-testing baselines on the same seeded `authz-target`, scoring recall over the
four planted authorization flaws.

## Files changed
- `test-suite/lab/differential.py` — driver: runs the candidate (via the live
  lab) and Schemathesis per vuln mode, classifies findings, scores AZ-046/RV-007
  with the differential oracle; records honest NOT_RUN for RESTler/EvoMaster/Burp.
- `test-suite/tests/test_differential.py` — 4 no-network tests.
- `test-suite/reports/differential/{report.md,results.json}`.
- Updated AZ-046 / RV-007 catalog adapter reasons to point at the differential.
- `RESULTS.md`.

## Commands run (actual status)
- `pip install schemathesis` (in a venv) → **schemathesis 4.31.1** on Python 3.14.
- `python3 lab/differential.py` →
  - authz-fuzzer: **4/4** planted flaws (recall 1.0).
  - Schemathesis: **0/4** authz flaws; it reported 5 "Undocumented HTTP status
    code" conformance failures per mode and no authorization detection.
  - RESTler / EvoMaster / Burp Autorize: NOT_RUN (precise reasons).
  - **Differential AZ-046/RV-007: PASS** (candidate ≥ union of baselines).
- `python3 -m unittest discover -s tests` → **OK, 31 tests**.

## Notes / honest limits
- Only Schemathesis could run headless. RESTler needs a .NET 6 toolchain,
  EvoMaster a white-box driver, and Burp Autorize is a commercial GUI — all
  recorded as NOT_RUN, not faked. None of the three has a cross-tenant/BOLA
  check either, so their authz-flaw recall would structurally be 0.
- The differential measures recall over the planted *authorization* flaws only;
  Schemathesis's 5 conformance findings/mode are real but orthogonal (they
  concern the spec not documenting response codes), and are reported as such.
- Schemathesis lives in an ephemeral venv; the committed report captures the run,
  and `differential.py` finds the binary via `$TSG1_SCHEMATHESIS` or PATH, else
  reports RV-007 NOT_RUN with an install hint.

## Next authorized step (one)
Provision RESTler (dotnet) and EvoMaster (jar + a thin white-box driver for the
reference target) in a container to complete RV-008/RV-009 live, and add a
stateful-sequence differential (create→share→cross-tenant-write).
