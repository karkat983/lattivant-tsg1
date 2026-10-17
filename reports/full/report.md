# TSG-1 Run Report (selected scenarios)

_Generated 2026-10-17T07:53:17.853081+00:00_

## Honesty header

- Catalog scenarios: **326** (built/partial/spec = 142/11/173)
- Scenarios actually **measured** (PASS or FAIL on real evidence): **22**
- PASS **22** / FAIL **0** (pass-rate of measured: 1.0)
- SKIPPED (spec-blocked) 184 · NOT_RUN (no adapter) 120 · ERROR 0
- S0 isolation/safety release gate: **CLEAN ✅**

> A green suite means 'survived everything we actually ran', never 'secure' or 'all 326 scenarios executed'. Per TSG-1, no fixed corpus certifies robustness.

## Measured results (22)

| ID | Sev | Oracle | Outcome | Metrics | Reason |
|----|-----|--------|---------|---------|--------|
| AZ-001 | S1 | isolation | ✅ pass | isolation_escape_count=0; backing_tests_total=2; backing_tests_passed=2 | no cross-tenant disclosure |
| AZ-002 | S0 | isolation | ✅ pass | isolation_escape_count=0; backing_tests_total=3; backing_tests_passed=3 | no cross-tenant disclosure |
| AZ-004 | S2 | manifest | ✅ pass | false_findings=0; backing_tests_total=1; backing_tests_passed=1 | correctly silent on benign case |
| AZ-006 | S2 | manifest | ✅ pass | false_findings=0; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| AZ-007 | S2 | manifest | ✅ pass | false_findings=0; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| AZ-017 | S1 | isolation | ✅ pass | isolation_escape_count=0; backing_tests_total=1; backing_tests_passed=1 | no cross-tenant disclosure |
| AZ-029 | S0 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| AZ-030 | S0 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AZ-031 | S1 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AZ-033 | S2 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=4; backing_tests_passed=4 | invariant held |
| AZ-036 | S0 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AZ-043 | S2 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=4; backing_tests_passed=4 | invariant held |
| AZ-044 | S1 | manifest | ✅ pass | false_findings=0; backing_tests_total=5; backing_tests_passed=5 | correctly silent on benign case |
| AZ-045 | S2 | metamorphic | ✅ pass | verdict_changes=0; backing_tests_total=2; backing_tests_passed=2 | verdict invariant across all transforms |
| AZ-047 | S1 | manifest | ✅ pass | false_findings=0; backing_tests_total=3; backing_tests_passed=3 | correctly silent on benign case |
| AZ-048 | S0 | isolation | ✅ pass | isolation_escape_count=0; backing_tests_total=1; backing_tests_passed=1 | no cross-tenant disclosure |
| PL-027 | S0 | isolation | ✅ pass | isolation_escape_count=0; backing_tests_total=2; backing_tests_passed=2 | no cross-tenant disclosure |
| PL-029 | S1 | invariant | ✅ pass | invariant_violations=0; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| RV-005 | S2 | metamorphic | ✅ pass | verdict_changes=0; backing_tests_total=1; backing_tests_passed=1 | verdict invariant across all transforms |
| RV-006 | S1 | metamorphic | ✅ pass | verdict_changes=0; backing_tests_total=1; backing_tests_passed=1 | verdict invariant across all transforms |
| RV-019 | S2 | metamorphic | ✅ pass | verdict_changes=0; backing_tests_total=2; backing_tests_passed=2 | verdict invariant across all transforms |
| RV-025 | S1 | metamorphic | ✅ pass | verdict_changes=0; backing_tests_total=2; backing_tests_passed=2 | verdict invariant across all transforms |

## Spec-blocked / skipped (184)

Top blocking capabilities:
- `evidence_graph` blocks 59 scenario(s)
- `investigator` blocks 27 scenario(s)
- `R-rules` blocks 13 scenario(s)
- `side_effect_tap` blocks 11 scenario(s)
- `post_checker` blocks 11 scenario(s)
- `agenttrace` blocks 10 scenario(s)
- `detectors` blocks 9 scenario(s)
- `mcp_scanner` blocks 8 scenario(s)
- `R4_taint` blocks 7 scenario(s)
- `span_side_effect_join` blocks 5 scenario(s)
- `correlator` blocks 5 scenario(s)
- `long_horizon` blocks 4 scenario(s)
- `labeling` blocks 4 scenario(s)
- `R2` blocks 3 scenario(s)
- `R3` blocks 3 scenario(s)
- `content_store` blocks 3 scenario(s)
- `R1` blocks 2 scenario(s)
- `grpc_adapter` blocks 1 scenario(s)
- `ws_adapter` blocks 1 scenario(s)
- `evidence_graph_join` blocks 1 scenario(s)

## Not run — honest reasons (120)

| ID | Sev | Reason |
|----|-----|--------|
| AZ-003 | S1 | no adapter wired yet |
| AZ-005 | S2 | no adapter wired yet |
| AZ-008 | S2 | no adapter wired yet |
| AZ-009 | S1 | no adapter wired yet |
| AZ-010 | S1 | no adapter wired yet |
| AZ-013 | S0 | no adapter wired yet |
| AZ-014 | S1 | no adapter wired yet |
| AZ-015 | S1 | no adapter wired yet |
| AZ-016 | S1 | no adapter wired yet |
| AZ-018 | S1 | no adapter wired yet |
| AZ-019 | S1 | no adapter wired yet |
| AZ-020 | S1 | no adapter wired yet |
| AZ-021 | S2 | no adapter wired yet |
| AZ-022 | S1 | no adapter wired yet |
| AZ-023 | S0 | requires a bulk-export/report endpoint in the target plus a row-provenance oracle (not present in scanner fixtures) |
| AZ-024 | S1 | no adapter wired yet |
| AZ-025 | S2 | no adapter wired yet |
| AZ-026 | S1 | no adapter wired yet |
| AZ-027 | S0 | no adapter wired yet |
| AZ-028 | S0 | no adapter wired yet |
| AZ-032 | S0 | requires signed scope-file verification; the scope guard tests cover allowlist/budget but not signature tamper |
| AZ-034 | S1 | no adapter wired yet |
| AZ-035 | S1 | no adapter wired yet |
| AZ-037 | S2 | no adapter wired yet |
| AZ-038 | S2 | no adapter wired yet |
| AZ-039 | S2 | no adapter wired yet |
| AZ-040 | S2 | no adapter wired yet |
| AZ-041 | S1 | the scanner is Rust (no unsafe C++ parser); no C++ libFuzzer harness exists to exercise |
| AZ-042 | S2 | no adapter wired yet |
| AZ-046 | S1 | requires external baselines (Burp Autorize / Schemathesis / RESTler) for a differential — not installed; offline |
| EG-031 | S2 | no adapter wired yet |
| EG-033 | S2 | no adapter wired yet |
| EW-001 | S2 | no adapter wired yet |
| EW-002 | S1 | no adapter wired yet |
| EW-003 | S1 | no adapter wired yet |
| EW-004 | S1 | no adapter wired yet |
| EW-005 | S1 | no adapter wired yet |
| EW-007 | S1 | no adapter wired yet |
| EW-008 | S2 | no adapter wired yet |
| EW-009 | S2 | no adapter wired yet |
| EW-010 | S2 | no adapter wired yet |
| EW-011 | S2 | no adapter wired yet |
| EW-012 | S1 | no adapter wired yet |
| EW-013 | S1 | no adapter wired yet |
| EW-014 | S1 | no adapter wired yet |
| EW-015 | S2 | no adapter wired yet |
| EW-016 | S2 | no adapter wired yet |
| EW-019 | S2 | no adapter wired yet |
| EW-020 | S1 | no adapter wired yet |
| EW-021 | S2 | no adapter wired yet |
| EW-022 | S1 | no adapter wired yet |
| EW-023 | S2 | no adapter wired yet |
| EW-024 | S2 | no adapter wired yet |
| EW-026 | S2 | no adapter wired yet |
| GC-003 | S1 | no adapter wired yet |
| GC-011 | S1 | no adapter wired yet |
| GC-013 | S1 | no adapter wired yet |
| GC-018 | S1 | no adapter wired yet |
| GC-021 | S1 | no adapter wired yet |
| PL-001 | S0 | requires live PostgreSQL with RLS policies (plan-cache role confusion path); test profile uses H2, no RLS exercised |
| PL-002 | S0 | requires live PostgreSQL RLS (leaky-operator via planner stats) |
| PL-003 | S0 | requires live PostgreSQL RLS (function-inlining user-ID change) |
| PL-004 | S0 | requires live PostgreSQL RLS (MERGE policy coverage) |
| PL-005 | S0 | requires live PostgreSQL RLS (subquery/WITH/security-invoker view) |
| PL-006 | S0 | requires live PostgreSQL RLS (partition/inheritance leaky operator) |
| PL-007 | S0 | requires live PostgreSQL RLS (stale policy after role change) |
| PL-008 | S1 | requires a PostgreSQL RLS differential-fuzzing harness vs an independent isolation oracle (not built) |
| PL-009 | S1 | no adapter wired yet |
| PL-010 | S1 | no adapter wired yet |
| PL-011 | S2 | no adapter wired yet |
| PL-012 | S1 | no adapter wired yet |
| PL-013 | S2 | no adapter wired yet |
| PL-014 | S1 | no adapter wired yet |
| PL-015 | S0 | requires the lattivant-platform event-envelope idempotency harness with a cross-tenant replay path (not wired) |
| PL-016 | S1 | no adapter wired yet |
| PL-017 | S2 | no adapter wired yet |
| PL-018 | S2 | no adapter wired yet |
| PL-020 | S0 | requires the PII-redaction pipeline + a labeled split-field corpus (not wired) |
| PL-021 | S0 | requires the PII-redaction pipeline + encoded-PII corpus (not wired) |
| PL-022 | S1 | no adapter wired yet |
| PL-023 | S1 | requires a labeled PII corpus to measure redaction precision/recall |
| PL-024 | S0 | requires the content-addressed evidence store collision harness |
| PL-025 | S1 | no adapter wired yet |
| PL-026 | S1 | no adapter wired yet |
| PL-028 | S0 | no adapter wired yet |
| PL-030 | S1 | no adapter wired yet |
| PL-031 | S1 | no adapter wired yet |
| PL-033 | S1 | no adapter wired yet |
| PL-035 | S2 | no adapter wired yet |
| PL-037 | S0 | requires a collector egress-allowlist harness against an internal endpoint (not wired) |
| PL-038 | S1 | no adapter wired yet |
| PL-039 | S2 | no adapter wired yet |
| PL-040 | S1 | no adapter wired yet |
| RV-007 | S1 | requires external baseline Schemathesis (not installed; offline) |
| RV-008 | S2 | requires external baseline RESTler (not installed; offline) |
| RV-009 | S2 | requires external baseline EvoMaster (not installed; offline) |
| RV-010 | S2 | requires external baseline Burp Autorize (not installed; offline) |
| RV-018 | S1 | requires a >=20-seed multi-trial experiment over built detectors; the detector stack (R1-R4 / EvidenceGraph) is not built |
| RV-020 | S1 | requires an attempted-vs-achieved relabeled corpus scored over detector outputs (detectors not built) |
| RV-021 | S1 | requires LM-edge detector outputs to measure dedup inflation (EastWest LM scoring not wired to a labeled set) |
| RV-022 | S1 | requires dual-policy labeled corpus over detector outputs |
| SC-001 | S2 | requires running ingest stack + load generator to measure >=2000 events/sec (docker-compose not provisioned offline) |
| SC-004 | S3 | requires `docker compose up` cold-start timing (stack not provisioned offline) |
| SC-005 | S2 | no adapter wired yet |
| SC-006 | S2 | no adapter wired yet |
| SC-010 | S1 | requires a running PostgreSQL to kill mid-incident (chaos; stack not provisioned offline) |
| SC-011 | S1 | requires a running NATS JetStream to kill mid-stream (chaos) |
| SC-012 | S1 | requires a running MinIO to kill mid-write (chaos) |
| SC-013 | S1 | no adapter wired yet |
| SC-014 | S2 | no adapter wired yet |
| SC-015 | S1 | no adapter wired yet |
| SC-017 | S1 | no adapter wired yet |
| SC-018 | S1 | no adapter wired yet |
| SC-019 | S2 | no adapter wired yet |
| SC-021 | S3 | no adapter wired yet |
| SC-022 | S2 | no adapter wired yet |
| SC-024 | S2 | no adapter wired yet |
| SC-026 | S2 | no adapter wired yet |
| SC-029 | S1 | no adapter wired yet |
| SC-030 | S2 | no adapter wired yet |

