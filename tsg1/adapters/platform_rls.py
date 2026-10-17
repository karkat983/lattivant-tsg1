"""Adapters for Platform scenarios (PL-*).

Only platform controls with genuine backing evidence in the built Rust scanner
are wired. The PostgreSQL-RLS CVE scenarios (PL-001..008) are deliberately NOT
wired here: the scanner does not host Postgres row-level-security policies, and
the Java reference target runs on H2 in its test profile, so those scenarios
would need a live Postgres + RLS harness. Leaving them unregistered makes the
runner report them NOT_RUN with an honest reason instead of a borrowed pass.
"""
from __future__ import annotations

from ._evidence import (make_test_backed_adapter as _wire,
                        make_unavailable_adapter as _na)

# PostgreSQL-RLS CVE scenarios and other platform controls needing a live
# stack: reported NOT_RUN with the precise prerequisite, never a borrowed pass.
PL_UNAVAILABLE: dict[str, str] = {
    "PL-001": "requires live PostgreSQL with RLS policies (plan-cache role "
              "confusion path); test profile uses H2, no RLS exercised",
    "PL-002": "requires live PostgreSQL RLS (leaky-operator via planner stats)",
    "PL-003": "requires live PostgreSQL RLS (function-inlining user-ID change)",
    "PL-004": "requires live PostgreSQL RLS (MERGE policy coverage)",
    "PL-005": "requires live PostgreSQL RLS (subquery/WITH/security-invoker view)",
    "PL-006": "requires live PostgreSQL RLS (partition/inheritance leaky operator)",
    "PL-007": "requires live PostgreSQL RLS (stale policy after role change)",
    "PL-008": "requires a PostgreSQL RLS differential-fuzzing harness vs an "
              "independent isolation oracle (not built)",
    "PL-020": "requires the PII-redaction pipeline + a labeled split-field "
              "corpus (not wired)",
    "PL-021": "requires the PII-redaction pipeline + encoded-PII corpus (not wired)",
    "PL-023": "requires a labeled PII corpus to measure redaction precision/recall",
    "PL-037": "requires a collector egress-allowlist harness against an internal "
              "endpoint (not wired)",
}

PL_BACKING: dict[str, tuple[list[str], str]] = {
    # secret / telemetry hygiene — scanner redacts secrets in captured evidence
    "PL-029": (["capture_redacts_request_and_response_headers",
                "env_store_only_resolves_env_scheme"],
               "secret redaction in captured request/response evidence"),
    # dogfood: the scanner's own authorization oracle on cross-tenant access
    "PL-027": (["cross_tenant_denied_for_read_and_write", "clean_set_passes"],
               "scanner's own oracle denies cross-tenant access (dogfood)"),
}

for _sid, (_tests, _desc) in PL_BACKING.items():
    _wire(_sid, _tests, _desc)
for _sid, _reason in PL_UNAVAILABLE.items():
    _na(_sid, _reason)
