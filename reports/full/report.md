# TSG-1 Run Report (selected scenarios)

_Generated 2026-10-17T09:56:57.502812+00:00_

## Honesty header

- Catalog scenarios: **326** (built/partial/spec = 142/11/173)
- Scenarios actually **measured** (PASS or FAIL on real evidence): **82**
- PASS **82** / FAIL **0** (pass-rate of measured: 1.0)
- SKIPPED (spec-blocked) 6 · NOT_RUN (no adapter) 238 · ERROR 0
- S0 isolation/safety release gate: **CLEAN ✅**

> A green suite means 'survived everything we actually ran', never 'secure' or 'all 326 scenarios executed'. Per TSG-1, no fixed corpus certifies robustness.

## Measured results (82)

| ID | Sev | Oracle | Outcome | Metrics | Reason |
|----|-----|--------|---------|---------|--------|
| AI-001 | S1 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AI-002 | S0 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AI-003 | S1 | manifest | ✅ pass | false_findings=0; component=investigator; backing_tests_total=3; backing_tests_passed=3 | correctly silent on benign case |
| AI-004 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=investigator; backing_tests_total=1; backing_tests_passed=1 | no cross-tenant disclosure |
| AI-005 | S1 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AI-006 | S1 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AI-007 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=investigator; backing_tests_total=3; backing_tests_passed=3 | no cross-tenant disclosure |
| AI-008 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | no cross-tenant disclosure |
| AI-011 | S1 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AI-012 | S0 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AI-016 | S1 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AI-025 | S1 | invariant | ✅ pass | invariant_violations=0; component=investigator; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| AI-026 | S1 | metamorphic | ✅ pass | verdict_changes=0; component=investigator; backing_tests_total=1; backing_tests_passed=1 | verdict invariant across all transforms |
| AT-008 | S1 | invariant | ✅ pass | invariant_violations=0; component=agenttrace; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| AT-009 | S1 | invariant | ✅ pass | invariant_violations=0; component=agenttrace; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AT-011 | S0 | invariant | ✅ pass | invariant_violations=0; component=agenttrace; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AT-012 | S1 | manifest | ✅ pass | false_findings=0; component=agenttrace; backing_tests_total=3; backing_tests_passed=3 | correctly silent on benign case |
| AT-016 | S1 | invariant | ✅ pass | invariant_violations=0; component=agenttrace; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| AT-026 | S1 | manifest | ✅ pass | false_findings=0; component=agenttrace; backing_tests_total=3; backing_tests_passed=3 | correctly silent on benign case |
| AT-027 | S2 | manifest | ✅ pass | false_findings=0; component=lattivant-lab; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| AT-034 | S2 | manifest | ✅ pass | false_findings=0; component=agenttrace; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| AT-037 | S2 | invariant | ✅ pass | invariant_violations=0; component=agenttrace; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AT-039 | S1 | invariant | ✅ pass | invariant_violations=0; component=agenttrace; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AZ-001 | S1 | isolation | ✅ pass | isolation_escape_count=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | no cross-tenant disclosure |
| AZ-002 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=authz-fuzzer; backing_tests_total=3; backing_tests_passed=3 | no cross-tenant disclosure |
| AZ-004 | S2 | manifest | ✅ pass | false_findings=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | correctly silent on benign case |
| AZ-006 | S2 | manifest | ✅ pass | false_findings=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| AZ-007 | S2 | manifest | ✅ pass | false_findings=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| AZ-017 | S1 | isolation | ✅ pass | isolation_escape_count=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | no cross-tenant disclosure |
| AZ-029 | S0 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| AZ-030 | S0 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| AZ-031 | S1 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AZ-033 | S2 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=4; backing_tests_passed=4 | invariant held |
| AZ-036 | S0 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| AZ-043 | S2 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=4; backing_tests_passed=4 | invariant held |
| AZ-044 | S1 | manifest | ✅ pass | false_findings=0; component=authz-fuzzer; backing_tests_total=5; backing_tests_passed=5 | correctly silent on benign case |
| AZ-045 | S2 | metamorphic | ✅ pass | verdict_changes=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | verdict invariant across all transforms |
| AZ-047 | S1 | manifest | ✅ pass | false_findings=0; component=authz-fuzzer; backing_tests_total=3; backing_tests_passed=3 | correctly silent on benign case |
| AZ-048 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | no cross-tenant disclosure |
| EG-001 | S1 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| EG-004 | S1 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| EG-006 | S1 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| EG-007 | S0 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| EG-009 | S0 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EG-010 | S0 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| EG-011 | S1 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EG-018 | S2 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EG-020 | S1 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EG-026 | S1 | manifest | ✅ pass | false_findings=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| EG-033 | S2 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| EG-034 | S1 | invariant | ✅ pass | invariant_violations=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EG-039 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=evidence-graph; backing_tests_total=2; backing_tests_passed=2 | no cross-tenant disclosure |
| EW-001 | S2 | manifest | ✅ pass | false_findings=0; component=eastwest; backing_tests_total=3; backing_tests_passed=3 | correctly silent on benign case |
| EW-002 | S1 | invariant | ✅ pass | invariant_violations=0; component=eastwest; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EW-016 | S2 | invariant | ✅ pass | invariant_violations=0; component=eastwest; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EW-017 | S1 | invariant | ✅ pass | invariant_violations=0; component=eastwest; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| EW-022 | S1 | invariant | ✅ pass | invariant_violations=0; component=eastwest; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| EW-023 | S2 | invariant | ✅ pass | invariant_violations=0; component=eastwest; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| EW-024 | S2 | manifest | ✅ pass | false_findings=0; component=eastwest; backing_tests_total=2; backing_tests_passed=2 | correctly silent on benign case |
| PL-009 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| PL-010 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-011 | S2 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| PL-012 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=1; backing_tests_passed=1 | invariant held |
| PL-013 | S2 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-014 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-015 | S0 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-018 | S2 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-024 | S0 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| PL-025 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-027 | S0 | isolation | ✅ pass | isolation_escape_count=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | no cross-tenant disclosure |
| PL-029 | S1 | invariant | ✅ pass | invariant_violations=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| PL-038 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=3; backing_tests_passed=3 | invariant held |
| PL-040 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=2; backing_tests_passed=2 | invariant held |
| RV-005 | S2 | metamorphic | ✅ pass | verdict_changes=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | verdict invariant across all transforms |
| RV-006 | S1 | metamorphic | ✅ pass | verdict_changes=0; component=authz-fuzzer; backing_tests_total=1; backing_tests_passed=1 | verdict invariant across all transforms |
| RV-018 | S1 | statistical | ✅ pass | p_two_sided=9.3e-05; effect_size=-0.325; seeds=40; arm_a_mean=1.0; arm_b_mean=0.675 | significant difference (p=9.3e-05, effect=-0.325) |
| RV-019 | S2 | metamorphic | ✅ pass | verdict_changes=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | verdict invariant across all transforms |
| RV-020 | S1 | statistical | ✅ pass | p_two_sided=0.000195; effect_size=-0.3; seeds=40; arm_a_mean=1.0; arm_b_mean=0.7 | significant difference (p=0.000195, effect=-0.3) |
| RV-021 | S1 | statistical | ✅ pass | p_two_sided=0.024517; effect_size=0.2756; seeds=40; arm_a_mean=0.85; arm_b_mean=2.65 | significant difference (p=0.024517, effect=0.2756) |
| RV-024 | S1 | metamorphic | ✅ pass | verdict_changes=0; component=lattivant-lab; backing_tests_total=1; backing_tests_passed=1 | verdict invariant across all transforms |
| RV-025 | S1 | metamorphic | ✅ pass | verdict_changes=0; component=authz-fuzzer; backing_tests_total=2; backing_tests_passed=2 | verdict invariant across all transforms |
| SC-029 | S1 | invariant | ✅ pass | invariant_violations=0; component=lattivant-platform; backing_tests_total=1; backing_tests_passed=1 | invariant held |

## Spec-blocked / skipped (6)

Top blocking capabilities:
- `long_horizon` blocks 4 scenario(s)
- `grpc_adapter` blocks 1 scenario(s)
- `ws_adapter` blocks 1 scenario(s)

## Not run — honest reasons (238)

| ID | Sev | Reason |
|----|-----|--------|
| AI-009 | S1 | runnable but no adapter wired yet |
| AI-010 | S1 | runnable but no adapter wired yet |
| AI-013 | S0 | runnable but no adapter wired yet |
| AI-014 | S2 | runnable but no adapter wired yet |
| AI-015 | S2 | runnable but no adapter wired yet |
| AI-017 | S0 | runnable but no adapter wired yet |
| AI-018 | S2 | runnable but no adapter wired yet |
| AI-019 | S1 | runnable but no adapter wired yet |
| AI-020 | S2 | runnable but no adapter wired yet |
| AI-021 | S1 | runnable but no adapter wired yet |
| AI-022 | S1 | runnable but no adapter wired yet |
| AI-023 | S1 | runnable but no adapter wired yet |
| AI-024 | S2 | runnable but no adapter wired yet |
| AI-027 | S1 | runnable but no adapter wired yet |
| AI-028 | S2 | runnable but no adapter wired yet |
| AI-029 | S2 | runnable but no adapter wired yet |
| AI-030 | S2 | runnable but no adapter wired yet |
| AI-031 | S1 | runnable but no adapter wired yet |
| AI-032 | S1 | runnable but no adapter wired yet |
| AT-001 | S1 | runnable but no adapter wired yet |
| AT-002 | S1 | runnable but no adapter wired yet |
| AT-003 | S2 | runnable but no adapter wired yet |
| AT-004 | S2 | runnable but no adapter wired yet |
| AT-005 | S2 | runnable but no adapter wired yet |
| AT-006 | S2 | runnable but no adapter wired yet |
| AT-010 | S2 | runnable but no adapter wired yet |
| AT-013 | S1 | runnable but no adapter wired yet |
| AT-014 | S1 | runnable but no adapter wired yet |
| AT-015 | S2 | runnable but no adapter wired yet |
| AT-017 | S1 | runnable but no adapter wired yet |
| AT-018 | S1 | runnable but no adapter wired yet |
| AT-019 | S1 | runnable but no adapter wired yet |
| AT-020 | S1 | runnable but no adapter wired yet |
| AT-021 | S0 | runnable but no adapter wired yet |
| AT-022 | S1 | runnable but no adapter wired yet |
| AT-023 | S0 | runnable but no adapter wired yet |
| AT-024 | S2 | runnable but no adapter wired yet |
| AT-025 | S2 | runnable but no adapter wired yet |
| AT-028 | S1 | runnable but no adapter wired yet |
| AT-029 | S1 | runnable but no adapter wired yet |
| AT-032 | S1 | runnable but no adapter wired yet |
| AT-033 | S1 | runnable but no adapter wired yet |
| AT-035 | S1 | runnable but no adapter wired yet |
| AT-036 | S1 | runnable but no adapter wired yet |
| AT-038 | S2 | runnable but no adapter wired yet |
| AT-040 | S1 | runnable but no adapter wired yet |
| AT-041 | S2 | runnable but no adapter wired yet |
| AT-042 | S2 | runnable but no adapter wired yet |
| AT-043 | S2 | runnable but no adapter wired yet |
| AT-044 | S2 | runnable but no adapter wired yet |
| AT-045 | S1 | runnable but no adapter wired yet |
| AT-046 | S1 | runnable but no adapter wired yet |
| AT-047 | S2 | runnable but no adapter wired yet |
| AT-048 | S1 | runnable but no adapter wired yet |
| AT-049 | S1 | runnable but no adapter wired yet |
| AT-050 | S1 | runnable but no adapter wired yet |
| AT-051 | S0 | runnable but no adapter wired yet |
| AT-052 | S2 | runnable but no adapter wired yet |
| AT-053 | S2 | runnable but no adapter wired yet |
| AT-054 | S1 | runnable but no adapter wired yet |
| AT-055 | S1 | runnable but no adapter wired yet |
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
| AZ-046 | S1 | demonstrated live via lab/differential.py (Schemathesis 4.x): authz-fuzzer 4/4 planted flaws vs 0/4 — see reports/differential. Burp Autorize / RESTler remain GUI/.NET-only, not run here |
| EG-002 | S1 | runnable but no adapter wired yet |
| EG-003 | S1 | runnable but no adapter wired yet |
| EG-005 | S1 | runnable but no adapter wired yet |
| EG-008 | S1 | runnable but no adapter wired yet |
| EG-012 | S1 | runnable but no adapter wired yet |
| EG-013 | S2 | runnable but no adapter wired yet |
| EG-014 | S1 | runnable but no adapter wired yet |
| EG-015 | S1 | runnable but no adapter wired yet |
| EG-016 | S0 | runnable but no adapter wired yet |
| EG-017 | S1 | runnable but no adapter wired yet |
| EG-019 | S2 | runnable but no adapter wired yet |
| EG-021 | S1 | runnable but no adapter wired yet |
| EG-022 | S1 | runnable but no adapter wired yet |
| EG-023 | S1 | runnable but no adapter wired yet |
| EG-024 | S2 | runnable but no adapter wired yet |
| EG-025 | S1 | runnable but no adapter wired yet |
| EG-027 | S1 | runnable but no adapter wired yet |
| EG-028 | S2 | runnable but no adapter wired yet |
| EG-029 | S2 | runnable but no adapter wired yet |
| EG-030 | S2 | runnable but no adapter wired yet |
| EG-031 | S2 | no adapter wired yet |
| EG-032 | S1 | runnable but no adapter wired yet |
| EG-035 | S1 | runnable but no adapter wired yet |
| EG-036 | S2 | runnable but no adapter wired yet |
| EG-037 | S1 | runnable but no adapter wired yet |
| EG-038 | S1 | runnable but no adapter wired yet |
| EG-040 | S2 | runnable but no adapter wired yet |
| EG-041 | S1 | runnable but no adapter wired yet |
| EG-042 | S2 | runnable but no adapter wired yet |
| EG-043 | S1 | runnable but no adapter wired yet |
| EG-044 | S2 | runnable but no adapter wired yet |
| EG-045 | S1 | runnable but no adapter wired yet |
| EW-003 | S1 | no adapter wired yet |
| EW-004 | S1 | no adapter wired yet |
| EW-005 | S1 | no adapter wired yet |
| EW-006 | S0 | runnable but no adapter wired yet |
| EW-007 | S1 | no adapter wired yet |
| EW-008 | S2 | no adapter wired yet |
| EW-009 | S2 | no adapter wired yet |
| EW-010 | S2 | no adapter wired yet |
| EW-011 | S2 | no adapter wired yet |
| EW-012 | S1 | no adapter wired yet |
| EW-013 | S1 | no adapter wired yet |
| EW-014 | S1 | no adapter wired yet |
| EW-015 | S2 | no adapter wired yet |
| EW-018 | S1 | runnable but no adapter wired yet |
| EW-019 | S2 | no adapter wired yet |
| EW-020 | S1 | no adapter wired yet |
| EW-021 | S2 | no adapter wired yet |
| EW-025 | S1 | runnable but no adapter wired yet |
| EW-026 | S2 | no adapter wired yet |
| GC-001 | S1 | runnable but no adapter wired yet |
| GC-002 | S1 | runnable but no adapter wired yet |
| GC-003 | S1 | no adapter wired yet |
| GC-004 | S1 | runnable but no adapter wired yet |
| GC-005 | S1 | runnable but no adapter wired yet |
| GC-006 | S1 | runnable but no adapter wired yet |
| GC-007 | S1 | runnable but no adapter wired yet |
| GC-009 | S1 | runnable but no adapter wired yet |
| GC-010 | S1 | runnable but no adapter wired yet |
| GC-011 | S1 | no adapter wired yet |
| GC-012 | S1 | runnable but no adapter wired yet |
| GC-013 | S1 | no adapter wired yet |
| GC-014 | S1 | runnable but no adapter wired yet |
| GC-015 | S1 | runnable but no adapter wired yet |
| GC-016 | S1 | runnable but no adapter wired yet |
| GC-017 | S1 | runnable but no adapter wired yet |
| GC-018 | S1 | no adapter wired yet |
| GC-019 | S1 | runnable but no adapter wired yet |
| GC-020 | S1 | runnable but no adapter wired yet |
| GC-021 | S1 | no adapter wired yet |
| GC-022 | S1 | runnable but no adapter wired yet |
| GC-023 | S1 | runnable but no adapter wired yet |
| GC-024 | S1 | runnable but no adapter wired yet |
| GC-025 | S1 | runnable but no adapter wired yet |
| PL-001 | S0 | requires live PostgreSQL with RLS policies (plan-cache role confusion path); test profile uses H2, no RLS exercised |
| PL-002 | S0 | requires live PostgreSQL RLS (leaky-operator via planner stats) |
| PL-003 | S0 | requires live PostgreSQL RLS (function-inlining user-ID change) |
| PL-004 | S0 | requires live PostgreSQL RLS (MERGE policy coverage) |
| PL-005 | S0 | requires live PostgreSQL RLS (subquery/WITH/security-invoker view) |
| PL-006 | S0 | requires live PostgreSQL RLS (partition/inheritance leaky operator) |
| PL-007 | S0 | requires live PostgreSQL RLS (stale policy after role change) |
| PL-008 | S1 | requires a PostgreSQL RLS differential-fuzzing harness vs an independent isolation oracle (not built) |
| PL-016 | S1 | no adapter wired yet |
| PL-017 | S2 | no adapter wired yet |
| PL-019 | S1 | runnable but no adapter wired yet |
| PL-020 | S0 | requires the PII-redaction pipeline + a labeled split-field corpus (not wired) |
| PL-021 | S0 | requires the PII-redaction pipeline + encoded-PII corpus (not wired) |
| PL-022 | S1 | no adapter wired yet |
| PL-023 | S1 | requires a labeled PII corpus to measure redaction precision/recall |
| PL-026 | S1 | no adapter wired yet |
| PL-028 | S0 | no adapter wired yet |
| PL-030 | S1 | no adapter wired yet |
| PL-031 | S1 | no adapter wired yet |
| PL-032 | S1 | runnable but no adapter wired yet |
| PL-033 | S1 | no adapter wired yet |
| PL-034 | S1 | runnable but no adapter wired yet |
| PL-035 | S2 | no adapter wired yet |
| PL-036 | S0 | runnable but no adapter wired yet |
| PL-037 | S0 | requires a collector egress-allowlist harness against an internal endpoint (not wired) |
| PL-039 | S2 | no adapter wired yet |
| RV-001 | S1 | runnable but no adapter wired yet |
| RV-002 | S1 | runnable but no adapter wired yet |
| RV-003 | S1 | runnable but no adapter wired yet |
| RV-004 | S1 | runnable but no adapter wired yet |
| RV-007 | S1 | demonstrated live via lab/differential.py (Schemathesis 4.x): 0/4 planted authz flaws vs authz-fuzzer 4/4 — see reports/differential/report.md |
| RV-008 | S2 | demonstrated live via lab/differential.py (RESTler, .NET 8 build): 0 bugs / 0 of 4 planted authz flaws — stateful REST fuzzer with no authz check; see reports/differential |
| RV-009 | S2 | demonstrated live via lab/differential.py (EvoMaster 6.2.0 black-box): 0/4 planted authz flaws — generic fuzzer finds XSS / HTTP-violation faults, no authz check; see reports/differential |
| RV-010 | S2 | requires external baseline Burp Autorize (not installed; offline) |
| RV-011 | S1 | runnable but no adapter wired yet |
| RV-012 | S1 | runnable but no adapter wired yet |
| RV-013 | S1 | runnable but no adapter wired yet |
| RV-014 | S1 | runnable but no adapter wired yet |
| RV-015 | S1 | runnable but no adapter wired yet |
| RV-016 | S1 | runnable but no adapter wired yet |
| RV-017 | S1 | runnable but no adapter wired yet |
| RV-022 | S1 | requires dual-policy labeled corpus over detector outputs |
| RV-023 | S1 | runnable but no adapter wired yet |
| SC-001 | S2 | requires running ingest stack + load generator to measure >=2000 events/sec (docker-compose not provisioned offline) |
| SC-002 | S2 | runnable but no adapter wired yet |
| SC-003 | S2 | runnable but no adapter wired yet |
| SC-004 | S3 | requires `docker compose up` cold-start timing (stack not provisioned offline) |
| SC-005 | S2 | no adapter wired yet |
| SC-006 | S2 | no adapter wired yet |
| SC-007 | S2 | runnable but no adapter wired yet |
| SC-008 | S2 | runnable but no adapter wired yet |
| SC-009 | S2 | runnable but no adapter wired yet |
| SC-010 | S1 | requires a running PostgreSQL to kill mid-incident (chaos; stack not provisioned offline) |
| SC-011 | S1 | requires a running NATS JetStream to kill mid-stream (chaos) |
| SC-012 | S1 | requires a running MinIO to kill mid-write (chaos) |
| SC-013 | S1 | no adapter wired yet |
| SC-014 | S2 | no adapter wired yet |
| SC-015 | S1 | no adapter wired yet |
| SC-016 | S2 | runnable but no adapter wired yet |
| SC-017 | S1 | no adapter wired yet |
| SC-018 | S1 | no adapter wired yet |
| SC-019 | S2 | no adapter wired yet |
| SC-020 | S1 | runnable but no adapter wired yet |
| SC-021 | S3 | no adapter wired yet |
| SC-022 | S2 | no adapter wired yet |
| SC-023 | S1 | runnable but no adapter wired yet |
| SC-024 | S2 | no adapter wired yet |
| SC-025 | S1 | runnable but no adapter wired yet |
| SC-026 | S2 | no adapter wired yet |
| SC-027 | S2 | runnable but no adapter wired yet |
| SC-028 | S2 | runnable but no adapter wired yet |
| SC-030 | S2 | no adapter wired yet |

