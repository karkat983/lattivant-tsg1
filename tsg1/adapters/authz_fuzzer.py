"""Adapters for AuthZ-Fuzzer scenarios (AZ-*), backed by the Rust scanner's
own conformance tests. Evidence = named `cargo test` cases that exercise the
scenario's control. See _evidence.make_test_backed_adapter for the mapping
rules. Scenarios without a genuine backing test are intentionally left
unregistered, so the runner reports them NOT_RUN rather than inventing a pass.
"""
from __future__ import annotations

from ._evidence import (make_test_backed_adapter as _wire,
                        make_unavailable_adapter as _na)

# scenario_id -> (backing scanner test short-names, evidence description)
AZ_BACKING: dict[str, tuple[list[str], str]] = {
    "AZ-001": (["cross_tenant_identical_body_is_verified_disclosure",
                "cross_tenant_relation"],
               "owner-diff isolation oracle verifies a planted cross-identity read"),
    "AZ-002": (["bola_read_mode_leaks_to_any_authenticated",
                "bola_write_mode_lets_cross_tenant_write",
                "cross_tenant_write_that_changes_state_is_verified_even_on_403"],
               "cross-tenant BOLA detection in read and write modes"),
    "AZ-004": (["declared_public_read_is_allowed_even_cross_tenant"],
               "public ACL treated as non-leak (FP trap)"),
    "AZ-006": (["four_oh_four_camouflage_is_correct",
                "four_oh_four_that_leaks_owner_content_is_a_finding"],
               "404 distinguished from a 404 that leaks owner content"),
    "AZ-007": (["empty_body_detection",
                "different_2xx_data_is_probable_not_verified"],
               "body-content predicate, not status code"),
    "AZ-029": (["host_must_be_exactly_allowlisted",
                "empty_host_allowlist_fails_scope",
                "admits_in_scope_safe_request"],
               "scope guard: out-of-scope host refused, in-scope admitted"),
    "AZ-030": (["bad_method_is_rejected",
                "declared_allowed_write_is_not_a_finding"],
               "method/mutation policy enforcement"),
    "AZ-031": (["cancellation_blocks_everything"],
               "kill-switch halts all work once tripped"),
    "AZ-033": (["budget_is_enforced", "budget_exhaustion_is_reported",
                "burst_is_consumed_then_refills_over_time",
                "concurrent_reservations_do_not_exceed_max"],
               "rate-limit / request-budget honoring"),
    "AZ-036": (["host_must_be_exactly_allowlisted"],
               "SSRF: server URL outside allowlist is blocked"),
    "AZ-043": (["empty_set_still_valid_sarif", "ci_gate_respects_min_confidence",
                "default_gate_fails_only_on_verified_high", "gate_policy_parsed"],
               "SARIF conformance + CI gate fires only on verified/probable"),
    "AZ-044": (["different_2xx_data_is_probable_not_verified",
                "consistent_verified_reproductions_stay_verified",
                "all_probable_reproductions_cap_at_probable",
                "flaky_violation_is_downgraded_to_probable",
                "a_stricter_policy_can_fail_on_probable"],
               "verified/probable/speculative tier calibration"),
    "AZ-045": (["evidence_uri_is_content_addressed_and_stable",
                "canonical_body_is_key_order_independent"],
               "replay/evidence determinism (content-addressed, stable)"),
    "AZ-047": (["hardened_read_authorization", "hardened_write_is_owner_only",
                "clean_set_passes"],
               "hardened twin yields zero verified findings (FP budget)"),
    "AZ-048": (["cross_tenant_denied_for_read_and_write"],
               "confused-deputy: cross-tenant access denied for read and write"),
    "AZ-017": (["body_ownership_field_is_detected"],
               "mass-assignment: ownership field in request body is detected"),
}

# run-first / other AZ scenarios with no honest backing in the built scanner
AZ_UNAVAILABLE: dict[str, str] = {
    "AZ-023": "requires a bulk-export/report endpoint in the target plus a "
              "row-provenance oracle (not present in scanner fixtures)",
    "AZ-032": "requires signed scope-file verification; the scope guard tests "
              "cover allowlist/budget but not signature tamper",
    "AZ-041": "the scanner is Rust (no unsafe C++ parser); no C++ libFuzzer "
              "harness exists to exercise",
    "AZ-046": "measured outside the catalog: with two identities and each tool's authz "
              "checks on, authz-fuzzer found 4/4 planted flaws vs RESTler 2/4, "
              "Schemathesis 2/4, EvoMaster 0/4; " + "see RESULTS_FAIR_DIFFERENTIAL.md (fair two-identity differential, lab/fair_differential.py). The earlier "
              "single-identity 0/4 differential is superseded",
}

for _sid, (_tests, _desc) in AZ_BACKING.items():
    _wire(_sid, _tests, _desc)
for _sid, _reason in AZ_UNAVAILABLE.items():
    _na(_sid, _reason)
