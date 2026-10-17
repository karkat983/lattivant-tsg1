# Worklog 04 — differential adds EvoMaster live; RESTler blocked

Date: 2026-10-17

## Scope delivered
Completed RV-009 (EvoMaster) as a live baseline in the differential, and
recorded RV-008 (RESTler) as honestly blocked with the exact environment reason.

## Environment findings
- Docker binary present but **daemon not running** and **Docker Desktop not
  installed** (`open -a Docker` → "Unable to find application named 'Docker'").
- **No dotnet** → cannot build/run RESTler natively either.
- **Java 17** present and GitHub reachable → EvoMaster 6.2.0 jar runs black-box.

## Files changed
- `test-suite/lab/differential.py` — added `_run_evomaster` (black-box per vuln
  mode, parses the generated faults test suite), generalized the per-mode report
  section; RESTler note updated to the real reason.
- `test-suite/tests/test_differential.py` — fault-code classifier test.
- Updated RV-008/RV-009 catalog adapter reasons; `RESULTS.md`.
- Refreshed `reports/differential/{report.md,results.json}`.

## Commands run (actual status)
- Downloaded `evomaster.jar` 6.2.0 (115 MB); `java -jar evomaster.jar --help` ok
  on Java 17.
- `python3 lab/differential.py` (with $TSG1_SCHEMATHESIS and $TSG1_EVOMASTER):
  - authz-fuzzer **4/4**; Schemathesis **0/4** (5 undocumented-status/mode);
    EvoMaster black-box **0/4** (Fault301 XSS, Fault109 HTTP-violation);
    RESTler + Burp NOT_RUN. **Differential PASS.**
- `python3 -m unittest discover -s tests` → **OK, 32 tests**.

## Honest limits
- EvoMaster ran in **black-box** mode; white-box is not applicable to a Rust
  target (it instruments JVM/Node/.NET bytecode). Stated in the report.
- RESTler (RV-008) is genuinely unavailable here: no Docker daemon, no .NET.
  Left NOT_RUN with the exact reason; not faked. It has no authz/BOLA check
  either, so its authz recall would also be 0/4.
- The differential conclusion is unchanged and now rests on two real baselines:
  generic coverage/fault fuzzers do not detect cross-tenant BOLA.

## Next authorized step (one)
If a Docker daemon or .NET SDK is later available, run RESTler (RV-008) against
the same target to complete the baseline set; otherwise the differential is as
complete as this environment allows.
