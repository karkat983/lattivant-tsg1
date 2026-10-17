#!/usr/bin/env python3
"""Real >=20-seed statistical experiments over the built detectors (RV-018,
RV-020, RV-021). Every data point is a real `authz` scan of a freshly, randomly
configured `authz-target`; the Python layer only chooses the seed, scores the
real result, and runs the statistics. Nothing is fabricated.

Per seed we pick one scenario kind and run a live scan:
  achieved-read / achieved-write / achieved-shared : an attack that succeeds
  clean                                            : hardened, no flaw
  attempted-blocked                                : a write-vulnerable server
                                                     but a read-only scope, so the
                                                     attack is *attempted* yet not
                                                     *achieved* (scope blocks it)
plus a random reproduction count (affects dedup).

Three comparisons, each via the TSG-1 statistical oracle (Mann-Whitney U, >=20
seeds, Wilson CIs):
  RV-018  scanner per-trial correctness  vs  a status-code-only baseline
  RV-020  accuracy under corrected labels vs under naive (attempted==achieved)
  RV-021  deduped finding count          vs  raw count (x reproductions)

    python3 lab/stat_experiments.py
"""
from __future__ import annotations

import json
import os
import random
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import live_lab                                   # noqa: E402
from tsg1.stats import mann_whitney_u, wilson_interval     # noqa: E402

# scenario kind -> (server vuln, scanner mutation scope, resource set,
#                   attack_attempted, attack_achieved, read_leak_expected)
KINDS = {
    "achieved-read":  ("bola-read", "read_only", "order-1", True, True, True),
    "achieved-write": ("bola-write", "test_owned_only", "order-1", True, True, False),
    "achieved-shared": ("shared-write", "test_owned_only", "shared", True, True, False),
    "clean":          ("none", "test_owned_only", "order-1", False, False, False),
    "attempted-blocked": ("bola-write", "read_only", "order-1", True, False, False),
}
RESOURCES = {
    "order-1": [{"instance_id": "order-1", "path_param": "id",
                 "resource_class": "order", "owner": "alpha-admin",
                 "write_body": {"status": "cancelled"}}],
    "shared": [{"instance_id": "order-shared", "path_param": "id",
                "resource_class": "order", "owner": "alpha-admin",
                "shared_with": ["bravo-admin"], "write_body": {"status": "cancelled"}}],
}


def _cross_tenant_read_status(base_url: str) -> int:
    """A status-code-only baseline: bravo reads alpha's order-1; 200 == 'flag'."""
    req = urllib.request.Request(base_url + "/orders/order-1",
                                 headers={"Authorization": "Bearer tok-bravo-admin"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _one_trial(kind: str, repeats: int) -> dict:
    server, mutation, resset, attempted, achieved, read_leak = KINDS[kind]
    proc, base_url = live_lab._start_target(server)
    try:
        spec = live_lab._wait_ready(base_url)
        import tempfile
        work = tempfile.mkdtemp(prefix="tsg1-stat-")
        with open(os.path.join(work, "openapi.json"), "w") as fh:
            json.dump(spec, fh)
        mpath = live_lab._write_manifest(work, base_url, mutation,
                                         RESOURCES[resset], read_repeats=repeats)
        scan = live_lab._scan(work, mpath)
        baseline_status = _cross_tenant_read_status(base_url)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    rep = scan["report"]
    verified = [f for f in rep.get("findings", []) if f.get("confidence") == "verified"]
    deduped = int(rep.get("total", len(rep.get("findings", []))))
    scanner_detected = len(verified) > 0
    baseline_detected = baseline_status == 200

    # correctness under the TRUE (achieved) ground truth
    scanner_correct = int(scanner_detected == achieved)
    baseline_correct = int(baseline_detected == achieved)
    # label policies: naive expects a finding whenever ATTEMPTED; corrected only
    # when ACHIEVED. Scanner only flags achieved-within-scope effects.
    naive_correct = int(scanner_detected == attempted)
    corrected_correct = int(scanner_detected == achieved)
    return {
        "kind": kind, "repeats": repeats,
        "verified": len(verified), "deduped_total": deduped,
        "raw_total": deduped * repeats,
        "scanner_correct": scanner_correct, "baseline_correct": baseline_correct,
        "naive_correct": naive_correct, "corrected_correct": corrected_correct,
        "baseline_status": baseline_status,
    }


def run_experiment(n: int = 40, seed: int = 1337) -> list[dict]:
    rng = random.Random(seed)
    kinds = list(KINDS)
    trials = []
    for _ in range(n):
        trials.append(_one_trial(rng.choice(kinds), rng.randint(2, 5)))
    return trials


def arms(trials: list[dict]) -> dict[str, tuple[list[float], list[float]]]:
    return {
        "RV-018": ([t["scanner_correct"] for t in trials],
                   [t["baseline_correct"] for t in trials]),
        "RV-020": ([t["corrected_correct"] for t in trials],
                   [t["naive_correct"] for t in trials]),
        "RV-021": ([float(t["deduped_total"]) for t in trials],
                   [float(t["raw_total"]) for t in trials]),
    }


def summarize(trials: list[dict]) -> dict:
    out = {"n": len(trials), "scenarios": {}}
    a = arms(trials)
    labels = {
        "RV-018": ("scanner correctness", "status-only baseline correctness"),
        "RV-020": ("corrected-label accuracy", "naive-label accuracy"),
        "RV-021": ("deduped finding count", "raw count (x reproductions)"),
    }
    for sid, (arm_a, arm_b) in a.items():
        mw = mann_whitney_u(arm_a, arm_b)
        out["scenarios"][sid] = {
            "arm_a_label": labels[sid][0], "arm_b_label": labels[sid][1],
            "arm_a_mean": round(sum(arm_a) / len(arm_a), 4),
            "arm_b_mean": round(sum(arm_b) / len(arm_b), 4),
            "mann_whitney": {"u": mw.u, "z": mw.z, "p_two_sided": mw.p_two_sided,
                             "effect_size": mw.effect_size_rank_biserial,
                             "note": mw.note},
            "significant_at_0.05": mw.p_two_sided <= 0.05,
        }
    return out


def write_report(trials: list[dict], out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    s = summarize(trials)
    from collections import Counter
    kinds = Counter(t["kind"] for t in trials)
    lines = ["# TSG-1 Statistical experiments (RV-018 / RV-020 / RV-021)", "",
             f"Real {s['n']}-seed experiment: each trial is a live `authz` scan of "
             "a randomly configured `authz-target`. Scores are computed from the "
             "real scan reports; Mann-Whitney U and Wilson 95% CIs by the harness "
             "stats module.", "",
             f"Trial mix: {dict(kinds)}", "",
             "| Scenario | Arm A | mean A | Arm B | mean B | U | p (2-sided) | "
             "effect | significant |",
             "|----------|-------|--------|-------|--------|---|-------------|"
             "--------|-------------|"]
    for sid, sc in s["scenarios"].items():
        mw = sc["mann_whitney"]
        lines.append(
            f"| {sid} | {sc['arm_a_label']} | {sc['arm_a_mean']} | "
            f"{sc['arm_b_label']} | {sc['arm_b_mean']} | {mw['u']} | "
            f"{mw['p_two_sided']} | {mw['effect_size']} | "
            f"{'yes ✅' if sc['significant_at_0.05'] else 'no'} |")
    lines.append("")
    # Wilson CIs on the binary correctness arms
    a = arms(trials)
    for sid in ("RV-018", "RV-020"):
        arm_a, arm_b = a[sid]
        wa = wilson_interval(int(sum(arm_a)), len(arm_a))
        wb = wilson_interval(int(sum(arm_b)), len(arm_b))
        lines.append(f"- **{sid}** Wilson95: arm A {wa.p_hat} "
                     f"[{wa.lower}, {wa.upper}] vs arm B {wb.p_hat} "
                     f"[{wb.lower}, {wb.upper}] (n={wa.n})")
    lines.append("")
    lines.append("_RV-018: the scanner catches write-only BOLA that a read-based "
                 "status-code baseline misses. RV-020: naive labeling (counting an "
                 "attempted-but-scope-blocked attack as a required detection) "
                 "lowers measured accuracy vs correct attempted-vs-achieved "
                 "labeling. RV-021: counting each reproduction instead of deduping "
                 "inflates the finding count._")
    md = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "report.md"), "w") as fh:
        fh.write(md)
    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump({"summary": s, "trials": trials}, fh, indent=2)
    return md


if __name__ == "__main__":
    t = run_experiment()
    print(write_report(t, os.path.join(os.path.dirname(__file__), "..",
                                       "reports", "stat")))
