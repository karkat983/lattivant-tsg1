"""Adapters for the statistical scenarios RV-018 / RV-020 / RV-021.

Each is scored by the TSG-1 statistical oracle (>=20 seeds, Mann-Whitney U) over
a real multi-seed experiment of live `authz` scans (lab/stat_experiments.py).

Reproducibility: the committed experiment output (reports/stat/results.json) is
used when present, so a harness run reuses the recorded real trials; otherwise
the experiment is run live. Either way the oracle does the statistics on real
per-trial measurements — no fabricated distributions.
"""
from __future__ import annotations

import functools
import json
import os

from ..runner import LabContext, Observation, REGISTRY

_RESULTS = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "reports", "stat", "results.json"))


@functools.lru_cache(maxsize=1)
def _trials() -> list[dict]:
    if os.path.exists(_RESULTS):
        return json.load(open(_RESULTS, encoding="utf-8"))["trials"]
    # fall back to a live run (needs the components + cargo-built authz binary)
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    from lab import stat_experiments
    return stat_experiments.run_experiment()


def _arms():
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    from lab import stat_experiments
    return stat_experiments.arms(_trials())


def _register(sid: str, desc: str) -> None:
    @REGISTRY.register(sid)
    def _adapter(scenario, lab: LabContext, _sid=sid, _desc=desc) -> Observation:
        try:
            a = _arms()
        except Exception as exc:
            return Observation(not_run_reason=f"stat experiment unavailable: "
                                              f"{type(exc).__name__}: {exc}")
        arm_a, arm_b = a[_sid]
        n = min(len(arm_a), len(arm_b))
        return Observation(
            data={"trials_a": arm_a, "trials_b": arm_b,
                  "min_seeds": 20, "alpha": 0.05},
            command="python3 lab/stat_experiments.py  (reports/stat/results.json)",
            stdout_tail=f"{_desc} | n={n} per arm",
            extra_metrics={"seeds": n,
                           "arm_a_mean": round(sum(arm_a) / len(arm_a), 4),
                           "arm_b_mean": round(sum(arm_b) / len(arm_b), 4)})


_register("RV-018", "stat gate: scanner vs status-only baseline correctness")
_register("RV-020", "label-error: corrected vs naive labeling accuracy")
_register("RV-021", "eval-inflation: deduped vs raw finding count")
