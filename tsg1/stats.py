"""Dependency-free statistics for TSG-1 metrics.

Implements exactly what the guide and AGENTS.md statistical-validity rules
require: confusion matrix, coverage, accuracy (with stated denominator),
Cohen's kappa (or undefined), false-accept / false-reject rates, Wilson 95%
bounds, Mann-Whitney U (normal approximation with tie correction), and
TPR@fixed-FPR. No numpy/scipy; all closed-form or simple loops so results are
reproducible and auditable.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Any


# --- normal distribution helpers -------------------------------------------
def _phi(x: float) -> float:
    """Standard normal CDF via erf."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


# 95% two-sided z
Z_95 = 1.959963984540054


@dataclass
class WilsonInterval:
    p_hat: float
    lower: float
    upper: float
    n: int
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def wilson_interval(successes: int, n: int, z: float = Z_95) -> WilsonInterval:
    """Wilson score interval for a binomial proportion.

    Returns an undefined-but-reported interval when n == 0 (per the guide's
    rule that missing statistical evidence must never silently become PASS).
    """
    if n <= 0:
        return WilsonInterval(p_hat=float("nan"), lower=float("nan"),
                              upper=float("nan"), n=0,
                              note="undefined: zero denominator")
    p = successes / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return WilsonInterval(p_hat=round(p, 6),
                          lower=round(max(0.0, center - half), 6),
                          upper=round(min(1.0, center + half), 6),
                          n=n)


# --- binary confusion matrix ------------------------------------------------
@dataclass
class ConfusionMatrix:
    """Binary reliability matrix with the guide's conventions (TSG-1 E / stats).

    Convention (AGENTS.md): for a judge, reference=REJECT & prediction=ACCEPT is
    a *false accept*; the inverse is a *false reject*. We generalize to a
    detector: positive == "malicious / should fire".
        tp: should-fire and fired
        fp: should-not-fire but fired   (false positive / over-defense)
        fn: should-fire but did not     (false negative / evasion)
        tn: should-not-fire and did not
    """
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    def add(self, expected_positive: bool, predicted_positive: bool) -> None:
        if expected_positive and predicted_positive:
            self.tp += 1
        elif expected_positive and not predicted_positive:
            self.fn += 1
        elif not expected_positive and predicted_positive:
            self.fp += 1
        else:
            self.tn += 1

    # --- rates with explicit denominators -------------------------------
    def tpr(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    def fpr(self) -> float | None:
        d = self.fp + self.tn
        return self.fp / d if d else None

    def false_accept_rate(self) -> float | None:
        """P(predicted ACCEPT | reference REJECT) == fp / (fp + tn) == FPR."""
        return self.fpr()

    def false_reject_rate(self) -> float | None:
        """P(predicted REJECT | reference ACCEPT) == fn / (fn + tp) == 1-TPR."""
        d = self.tp + self.fn
        return self.fn / d if d else None

    def accuracy(self) -> float | None:
        return (self.tp + self.tn) / self.n if self.n else None

    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    def cohen_kappa(self) -> float | None:
        """Cohen's kappa; None (undefined) when it cannot be computed."""
        n = self.n
        if n == 0:
            return None
        po = (self.tp + self.tn) / n
        p_yes = ((self.tp + self.fp) / n) * ((self.tp + self.fn) / n)
        p_no = ((self.fn + self.tn) / n) * ((self.fp + self.tn) / n)
        pe = p_yes + p_no
        if abs(1.0 - pe) < 1e-12:
            return None  # undefined (perfect chance agreement)
        return (po - pe) / (1.0 - pe)

    def summary(self) -> dict[str, Any]:
        tpr = self.tpr()
        fpr = self.fpr()
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "n": self.n,
            "accuracy": _round(self.accuracy()),
            "precision": _round(self.precision()),
            "tpr": _round(tpr),
            "fpr": _round(fpr),
            "false_accept_rate": _round(self.false_accept_rate()),
            "false_reject_rate": _round(self.false_reject_rate()),
            "cohen_kappa": _round(self.cohen_kappa()),
            "tpr_wilson95": (wilson_interval(self.tp, self.tp + self.fn).as_dict()
                             if (self.tp + self.fn) else
                             wilson_interval(0, 0).as_dict()),
            "fpr_wilson95": (wilson_interval(self.fp, self.fp + self.tn).as_dict()
                             if (self.fp + self.tn) else
                             wilson_interval(0, 0).as_dict()),
        }


def _round(x: float | None, nd: int = 6) -> float | None:
    if x is None:
        return None
    if isinstance(x, float) and math.isnan(x):
        return float("nan")
    return round(x, nd)


# --- Mann-Whitney U (normal approx with tie correction) ---------------------
@dataclass
class MannWhitney:
    u: float
    n1: int
    n2: int
    z: float
    p_two_sided: float
    effect_size_rank_biserial: float
    note: str = ""


def mann_whitney_u(a: list[float], b: list[float]) -> MannWhitney:
    """Mann-Whitney U with a normal approximation and tie correction.

    Used for TSG-1 RV-018: every headline metric should be backed by a
    significance test (the SoK-fuzzing critique). Returns a reported note when
    samples are too small for the approximation to be meaningful.
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return MannWhitney(u=float("nan"), n1=n1, n2=n2, z=float("nan"),
                           p_two_sided=float("nan"),
                           effect_size_rank_biserial=float("nan"),
                           note="undefined: empty sample")
    combined = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    # assign average ranks (1-based) with tie handling
    ranks = [0.0] * len(combined)
    i = 0
    tie_term = 0.0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        t = j - i + 1
        if t > 1:
            tie_term += t ** 3 - t
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1
    r1 = sum(r for r, (_, g) in zip(ranks, combined) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)
    mu = n1 * n2 / 2.0
    n = n1 + n2
    sigma_sq = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    if sigma_sq <= 0:
        return MannWhitney(u=u, n1=n1, n2=n2, z=float("nan"),
                           p_two_sided=float("nan"),
                           effect_size_rank_biserial=float("nan"),
                           note="undefined: zero variance (all ties)")
    # continuity correction
    z = (abs(u - mu) - 0.5) / math.sqrt(sigma_sq)
    z = -z if (u - mu) < 0 else z
    p = 2.0 * (1.0 - _phi(abs(z)))
    rbc = 1.0 - (2.0 * u1) / (n1 * n2)  # rank-biserial from u1
    note = "" if min(n1, n2) >= 4 else "small sample: normal approx unreliable"
    return MannWhitney(u=round(u, 4), n1=n1, n2=n2, z=round(z, 4),
                       p_two_sided=round(p, 6),
                       effect_size_rank_biserial=round(rbc, 4), note=note)


# --- TPR @ fixed FPR --------------------------------------------------------
def tpr_at_fixed_fpr(pos_scores: list[float], neg_scores: list[float],
                     target_fpr: float = 0.01) -> dict[str, Any]:
    """Pick the lowest threshold whose empirical FPR <= target_fpr, report TPR.

    Fix the operating point BEFORE measuring (TSG-1 E.2), avoiding the
    saturation trap. Higher score == more suspicious; fire when score >= thr.
    """
    if not pos_scores or not neg_scores:
        return {"tpr": None, "threshold": None, "achieved_fpr": None,
                "target_fpr": target_fpr, "note": "undefined: empty sample"}
    thresholds = sorted(set(pos_scores + neg_scores), reverse=True)
    best = None
    for thr in thresholds:
        fp = sum(1 for s in neg_scores if s >= thr)
        fpr = fp / len(neg_scores)
        if fpr <= target_fpr:
            tp = sum(1 for s in pos_scores if s >= thr)
            tpr = tp / len(pos_scores)
            best = {"tpr": round(tpr, 6), "threshold": thr,
                    "achieved_fpr": round(fpr, 6), "target_fpr": target_fpr}
        else:
            break
    if best is None:
        return {"tpr": 0.0, "threshold": None, "achieved_fpr": 0.0,
                "target_fpr": target_fpr,
                "note": "no threshold meets target FPR without any true positive"}
    return best
