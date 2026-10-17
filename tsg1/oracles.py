"""The six TSG-1 oracle types (A.4).

An oracle takes a normalized *observation* produced by a component adapter plus
the scenario's ground-truth manifest, and returns an OracleVerdict (passed +
evidence). Oracles never fabricate: when evidence is insufficient they return
passed=False with an explicit reason, honoring the rule that ambiguous or
missing evidence must not silently become PASS.

Normalized observation shape (what adapters emit):
    {
      "findings": [ {"rule": str, "tenant_id": str, "label": str,
                     "supporting_event_ids": [str], "target": str}, ... ],
      "isolation_escapes": int,          # cross-tenant disclosures observed
      "invariant_violations": [str],     # names of violated invariants
      "pairs": [ {"expected_positive": bool, "predicted_positive": bool}, ... ],
      "variants": [ {"label": str, "verdict": str}, ... ],   # metamorphic
      "baseline": {...}, "candidate": {...},                 # differential
      "trials_a": [float], "trials_b": [float],              # statistical
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .model import Manifest, OracleType
from .stats import ConfusionMatrix, mann_whitney_u


@dataclass
class OracleVerdict:
    passed: bool
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)


# --- (1) isolation oracle: owner-diff; any cross-tenant disclosure fails ----
def isolation_oracle(obs: dict[str, Any], manifest: Manifest) -> OracleVerdict:
    escapes = int(obs.get("isolation_escapes", 0))
    detail = obs.get("isolation_detail", [])
    passed = escapes == 0
    return OracleVerdict(
        passed=passed,
        reason=("no cross-tenant disclosure" if passed
                else f"{escapes} isolation escape(s) observed"),
        evidence={"isolation_escapes": escapes, "detail": detail},
        metrics={"isolation_escape_count": escapes},
    )


# --- (2) manifest oracle: emitted finding vs ground-truth label -------------
def manifest_oracle(obs: dict[str, Any], manifest: Manifest) -> OracleVerdict:
    findings = obs.get("findings", [])
    want_label = manifest.label  # attempted|achieved|benign
    matched = []
    for f in findings:
        if manifest.expected_rule and f.get("rule") != manifest.expected_rule:
            continue
        if manifest.tenant_id and f.get("tenant_id") not in ("", manifest.tenant_id):
            continue
        matched.append(f)

    if want_label == "benign":
        # negative control: nothing should fire for this rule/tenant
        passed = len(matched) == 0
        return OracleVerdict(
            passed=passed,
            reason=("correctly silent on benign case" if passed
                    else f"{len(matched)} false finding(s) on benign case"),
            evidence={"matched_findings": matched},
            metrics={"false_findings": len(matched)},
        )

    # positive case: a finding with the correct attempted/achieved label
    label_ok = [f for f in matched if f.get("label") == want_label]
    passed = len(label_ok) >= 1
    return OracleVerdict(
        passed=passed,
        reason=("correct finding with correct label" if passed
                else f"expected rule={manifest.expected_rule} "
                     f"label={want_label}; got {len(matched)} rule match, "
                     f"{len(label_ok)} label match"),
        evidence={"matched": matched, "label_matched": label_ok},
        metrics={"label_correct": int(passed)},
    )


# --- (3) metamorphic oracle: transforms must NOT change the verdict ---------
def metamorphic_oracle(obs: dict[str, Any], manifest: Manifest) -> OracleVerdict:
    variants = obs.get("variants", [])
    if len(variants) < 2:
        return OracleVerdict(False, "need >=2 variants to test invariance",
                             evidence={"variants": variants})
    verdicts = {v.get("verdict") for v in variants}
    passed = len(verdicts) == 1
    return OracleVerdict(
        passed=passed,
        reason=("verdict invariant across all transforms" if passed
                else f"verdict changed across transforms: {sorted(verdicts)}"),
        evidence={"variants": variants, "distinct_verdicts": sorted(verdicts)},
        metrics={"verdict_changes": len(verdicts) - 1},
    )


# --- (4) invariant oracle: a property that must always hold -----------------
def invariant_oracle(obs: dict[str, Any], manifest: Manifest) -> OracleVerdict:
    violations = obs.get("invariant_violations", [])
    passed = len(violations) == 0
    return OracleVerdict(
        passed=passed,
        reason=("invariant held" if passed
                else f"invariant violated: {violations}"),
        evidence={"violations": violations},
        metrics={"invariant_violations": len(violations)},
    )


# --- (5) differential oracle: candidate vs baseline -------------------------
def differential_oracle(obs: dict[str, Any], manifest: Manifest) -> OracleVerdict:
    """Candidate must find >= the union of baselines on planted flaws.

    Uses sets of detected flaw ids so the comparison is apples-to-apples.
    """
    candidate = set(obs.get("candidate_found", []))
    baselines = obs.get("baseline_found", {})  # name -> [flaw ids]
    union = set()
    for ids in baselines.values():
        union |= set(ids)
    missed_by_candidate = union - candidate
    extra_by_candidate = candidate - union
    passed = missed_by_candidate == set()
    return OracleVerdict(
        passed=passed,
        reason=("candidate recall >= union of baselines" if passed
                else f"candidate missed {sorted(missed_by_candidate)} "
                     f"found by baselines"),
        evidence={"candidate_found": sorted(candidate),
                  "baseline_union": sorted(union),
                  "candidate_missed": sorted(missed_by_candidate),
                  "candidate_extra": sorted(extra_by_candidate)},
        metrics={"relative_recall": (len(candidate & union) / len(union)
                                     if union else None),
                 "candidate_extra_count": len(extra_by_candidate)},
    )


# --- (6) statistical oracle: multi-trial significance + effect size ---------
def statistical_oracle(obs: dict[str, Any], manifest: Manifest) -> OracleVerdict:
    a = obs.get("trials_a", [])
    b = obs.get("trials_b", [])
    min_seeds = int(obs.get("min_seeds", 20))  # RV-018 gate
    if min(len(a), len(b)) < min_seeds:
        return OracleVerdict(
            False,
            f"insufficient trials: need >={min_seeds} per arm, "
            f"got {len(a)}/{len(b)} (gate fails closed, not PASS)",
            evidence={"n_a": len(a), "n_b": len(b)},
        )
    mw = mann_whitney_u(a, b)
    alpha = float(obs.get("alpha", 0.05))
    passed = mw.p_two_sided <= alpha
    return OracleVerdict(
        passed=passed,
        reason=(f"significant difference (p={mw.p_two_sided}, "
                f"effect={mw.effect_size_rank_biserial})" if passed
                else f"no significant difference (p={mw.p_two_sided})"),
        evidence={"mann_whitney": mw.__dict__},
        metrics={"p_two_sided": mw.p_two_sided,
                 "effect_size": mw.effect_size_rank_biserial},
    )


ORACLES: dict[str, Callable[[dict[str, Any], Manifest], OracleVerdict]] = {
    OracleType.ISOLATION.value: isolation_oracle,
    OracleType.MANIFEST.value: manifest_oracle,
    OracleType.METAMORPHIC.value: metamorphic_oracle,
    OracleType.INVARIANT.value: invariant_oracle,
    OracleType.DIFFERENTIAL.value: differential_oracle,
    OracleType.STATISTICAL.value: statistical_oracle,
}


def confusion_from_pairs(pairs: list[dict[str, Any]]) -> ConfusionMatrix:
    cm = ConfusionMatrix()
    for p in pairs:
        cm.add(bool(p.get("expected_positive")), bool(p.get("predicted_positive")))
    return cm
