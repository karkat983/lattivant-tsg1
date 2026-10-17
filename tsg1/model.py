"""Core data model for TSG-1 scenarios, manifests, and results.

Mirrors the Scenario DSL (TSG-1 C.1), ground-truth manifest (C.2), and the
Result object produced by the runner (C.6). Stdlib-only dataclasses.
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any


# --- TSG-1 A.2 test classes -------------------------------------------------
class TestClass(str, enum.Enum):
    FUNCTIONAL = "functional"        # (i)
    ADVERSARIAL = "adversarial"      # (ii)
    PLATFORM = "platform"            # (iii)
    SCALE = "scale"                  # (iv)
    RESEARCH = "research"            # (v)
    SAFETY = "safety"                # (vi)
    GRAND = "grand"                  # (vii)


# roman-numeral tags used in the catalog map to the enum above
ROMAN_TO_CLASS = {
    "i": TestClass.FUNCTIONAL,
    "ii": TestClass.ADVERSARIAL,
    "iii": TestClass.PLATFORM,
    "iv": TestClass.SCALE,
    "v": TestClass.RESEARCH,
    "vi": TestClass.SAFETY,
    "vii": TestClass.GRAND,
}


# --- TSG-1 A.3 severity tiers ----------------------------------------------
class Severity(str, enum.Enum):
    S0 = "S0"  # catastrophic: cross-tenant disclosure, RLS escape, scope bypass
    S1 = "S1"  # critical: detector fully evaded; provenance forgery on causal path
    S2 = "S2"  # major: elevated FPR/FNR, SLO breach, flaky oracle
    S3 = "S3"  # minor: cosmetic / logging / recoverable


# --- build status -----------------------------------------------------------
class BuildStatus(str, enum.Enum):
    BUILT = "built"              # runs today on built components
    SPEC = "spec"               # blocked until named component is built
    PARTIAL = "partial"         # built core, some aspect depends on a spec piece


# --- TSG-1 A.4 oracle types -------------------------------------------------
class OracleType(str, enum.Enum):
    ISOLATION = "isolation"          # owner-diff; cross-tenant leak detection
    MANIFEST = "manifest"            # verdict vs ground-truth label
    METAMORPHIC = "metamorphic"      # transform must NOT change verdict
    INVARIANT = "invariant"          # property that must always hold
    DIFFERENTIAL = "differential"    # vs a baseline tool / implementation
    STATISTICAL = "statistical"      # multi-trial significance + CIs


# --- run outcome ------------------------------------------------------------
class Outcome(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"      # SPEC-blocked or precondition unmet
    NOT_RUN = "not_run"      # adapter/tooling unavailable; honestly unmeasured
    ERROR = "error"          # harness error while executing


@dataclass
class Scenario:
    """A catalog entry (TSG-1 Section B). Minimal, machine-readable."""
    id: str
    title: str
    test_classes: list[str]          # roman numerals, e.g. ["ii"] or ["i", "ii"]
    build_status: str                # BuildStatus value
    component: str                   # az|at|ew|eg|ai|pl|sc|rv|gc
    oracle: str                      # OracleType value
    metric: str
    severity: str                    # Severity value
    reference: str
    spec_blockers: list[str] = field(default_factory=list)
    run_first: bool = False          # part of TSG-1 Section H run-first 40
    ci_tier: str = "nightly"         # per_pr|nightly|weekly_soak|release_gate
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_json(d: dict[str, Any]) -> "Scenario":
        return Scenario(**d)


@dataclass
class Manifest:
    """Ground-truth manifest (TSG-1 C.2) for a scenario we actually execute."""
    manifest: str                    # scenario id
    expected_rule: str = ""          # e.g. R3, BOLA, RLS
    label: str = "benign"            # attempted|achieved|benign
    tenant_id: str = ""
    supporting_event_ids: list[str] = field(default_factory=list)
    negative_controls: list[str] = field(default_factory=list)
    fp_weight: float = 1.0
    fn_weight: float = 2.0

    @staticmethod
    def from_json(d: dict[str, Any]) -> "Manifest":
        return Manifest(**d)


@dataclass
class Result:
    """Outcome of running one scenario (TSG-1 C.6)."""
    id: str
    outcome: str                     # Outcome value
    severity: str
    oracle: str
    reason: str = ""                 # why skipped / why failed
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    command: str = ""                # exact command run, if any
    exit_status: int | None = None   # exact exit code, if a process was run
    replay_ref: str = ""             # content digest of recorded stream
    duration_s: float = 0.0

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def digest(obj: Any) -> str:
    """Stable content digest for replay-reference and determinism checks."""
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
