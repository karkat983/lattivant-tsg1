"""Adapters for Research-Validity scenarios (RV-*).

Metamorphic relations that the built scanner already enforces are wired to its
conformance tests. Differential-vs-external-tool and multi-trial/detector
experiments are reported NOT_RUN with precise reasons: the baseline tools are
not installed (offline) and the detectors they would compare against are not
built, so a pass here would be fabricated.
"""
from __future__ import annotations

from ._evidence import (make_test_backed_adapter as _wire,
                        make_unavailable_adapter as _na)

RV_BACKING: dict[str, tuple[list[str], str]] = {
    "RV-005": (["differently_named_params_normalize_equal"],
               "rename of non-semantic fields leaves the authz verdict unbroken"),
    "RV-006": (["fingerprint_ignores_resource_id_but_splits_on_violation"],
               "permuting object IDs preserves the BOLA verdict (metamorphic)"),
    "RV-025": (["differently_named_params_normalize_equal",
                "fingerprint_ignores_resource_id_but_splits_on_violation"],
               "oracle-free authz via metamorphic relations (rename + permute)"),
    "RV-019": (["evidence_uri_is_content_addressed_and_stable",
                "canonical_body_is_key_order_independent"],
               "verdict invariant across input orderings (seed-stability proxy)"),
}

RV_UNAVAILABLE: dict[str, str] = {
    "RV-007": "measured outside the catalog: Schemathesis 4.32.0 with two identities "
              "and --checks all found 2/4 planted authz flaws (3 trap false findings) "
              "vs authz-fuzzer 4/4; " + "see RESULTS_FAIR_DIFFERENTIAL.md (fair two-identity differential, lab/fair_differential.py)",
    "RV-008": "measured outside the catalog: RESTler (two users, namespacerule on) "
              "found 2/4 planted authz flaws (3 trap false findings) vs "
              "authz-fuzzer 4/4; " + "see RESULTS_FAIR_DIFFERENTIAL.md (fair two-identity differential, lab/fair_differential.py)",
    "RV-009": "measured outside the catalog: EvoMaster 6.2.0 black-box with its "
              "security phase and two users found 0/4 planted authz flaws vs "
              "authz-fuzzer 4/4; " + "see RESULTS_FAIR_DIFFERENTIAL.md (fair two-identity differential, lab/fair_differential.py)",
    "RV-010": "requires external baseline Burp Autorize (not installed; offline)",
    "RV-022": "requires dual-policy labeled corpus over detector outputs",
}

for _sid, (_tests, _desc) in RV_BACKING.items():
    _wire(_sid, _tests, _desc)
for _sid, _reason in RV_UNAVAILABLE.items():
    _na(_sid, _reason)
