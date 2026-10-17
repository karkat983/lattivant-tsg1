"""Aggregate Results into a JSON summary and a Markdown report (TSG-1 E / G).

The report never blurs the line between measured and unmeasured: PASS/FAIL are
real oracle verdicts on real observations; SKIPPED/NOT_RUN/ERROR are listed
separately with reasons, so 'green' can never be mistaken for 'all 326 ran'.
"""
from __future__ import annotations

import datetime as _dt
import json
from collections import Counter, defaultdict
from typing import Any

from .model import Outcome, Result, Scenario

ROMAN_ORDER = ["i", "ii", "iii", "iv", "v", "vi", "vii"]


def summarize(results: list[Result], scenarios: list[Scenario]) -> dict[str, Any]:
    by_id = {s.id: s for s in scenarios}
    outcome_counts = Counter(r.outcome for r in results)
    # S0 isolation/safety invariants must be zero failures (release gate)
    s0_failures = [r.id for r in results
                   if r.severity == "S0" and r.outcome == Outcome.FAIL.value]
    measured = [r for r in results
                if r.outcome in (Outcome.PASS.value, Outcome.FAIL.value)]
    passed = [r for r in measured if r.outcome == Outcome.PASS.value]

    # coverage matrix component x class (catalog), and ran x class
    comp_class = defaultdict(lambda: Counter())
    ran_by_component = Counter()
    for s in scenarios:
        for c in s.test_classes:
            comp_class[s.component][c] += 1
    for r in results:
        if r.outcome in (Outcome.PASS.value, Outcome.FAIL.value):
            ran_by_component[by_id[r.id].component] += 1

    return {
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "total_scenarios": len(scenarios),
        "results_count": len(results),
        "outcome_counts": dict(outcome_counts),
        "measured": len(measured),
        "pass": len(passed),
        "fail": len(measured) - len(passed),
        "pass_rate_of_measured": (round(len(passed) / len(measured), 4)
                                  if measured else None),
        "s0_failures": s0_failures,
        "release_gate_s0_clean": len(s0_failures) == 0,
        "ran_by_component": dict(ran_by_component),
        "catalog_by_build": dict(Counter(s.build_status for s in scenarios)),
        "comp_class_matrix": {k: dict(v) for k, v in comp_class.items()},
    }


def _fmt_metrics(m: dict[str, Any]) -> str:
    if not m:
        return ""
    parts = []
    for k, v in m.items():
        if isinstance(v, dict):
            continue
        parts.append(f"{k}={v}")
    return "; ".join(parts)


def to_markdown(results: list[Result], scenarios: list[Scenario],
                title: str = "TSG-1 Run Report") -> str:
    by_id = {s.id: s for s in scenarios}
    s = summarize(results, scenarios)
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"_Generated {s['generated_utc']}_")
    lines.append("")
    lines.append("## Honesty header")
    lines.append("")
    lines.append(f"- Catalog scenarios: **{s['total_scenarios']}** "
                 f"(built/partial/spec = "
                 f"{s['catalog_by_build'].get('built',0)}/"
                 f"{s['catalog_by_build'].get('partial',0)}/"
                 f"{s['catalog_by_build'].get('spec',0)})")
    lines.append(f"- Scenarios actually **measured** (PASS or FAIL on real "
                 f"evidence): **{s['measured']}**")
    lines.append(f"- PASS **{s['pass']}** / FAIL **{s['fail']}** "
                 f"(pass-rate of measured: {s['pass_rate_of_measured']})")
    oc = s["outcome_counts"]
    lines.append(f"- SKIPPED (spec-blocked) {oc.get('skipped',0)} · "
                 f"NOT_RUN (no adapter) {oc.get('not_run',0)} · "
                 f"ERROR {oc.get('error',0)}")
    gate = "CLEAN ✅" if s["release_gate_s0_clean"] else \
           f"FAILED ❌ ({s['s0_failures']})"
    lines.append(f"- S0 isolation/safety release gate: **{gate}**")
    lines.append("")
    lines.append("> A green suite means 'survived everything we actually ran', "
                 "never 'secure' or 'all 326 scenarios executed'. Per TSG-1, no "
                 "fixed corpus certifies robustness.")
    lines.append("")

    # measured results table
    measured = [r for r in results
                if r.outcome in (Outcome.PASS.value, Outcome.FAIL.value)]
    lines.append(f"## Measured results ({len(measured)})")
    lines.append("")
    if measured:
        lines.append("| ID | Sev | Oracle | Outcome | Metrics | Reason |")
        lines.append("|----|-----|--------|---------|---------|--------|")
        for r in sorted(measured, key=lambda r: r.id):
            icon = "✅" if r.outcome == "pass" else "❌"
            lines.append(f"| {r.id} | {r.severity} | {r.oracle} | "
                         f"{icon} {r.outcome} | {_fmt_metrics(r.metrics)} | "
                         f"{r.reason} |")
    else:
        lines.append("_None measured in this run._")
    lines.append("")

    # skipped / not-run grouped by reason bucket
    skipped = [r for r in results if r.outcome == Outcome.SKIPPED.value]
    notrun = [r for r in results if r.outcome == Outcome.NOT_RUN.value]
    errored = [r for r in results if r.outcome == Outcome.ERROR.value]

    lines.append(f"## Spec-blocked / skipped ({len(skipped)})")
    lines.append("")
    blocker_counts: Counter = Counter()
    for r in skipped:
        for b in by_id[r.id].spec_blockers:
            blocker_counts[b] += 1
    if blocker_counts:
        lines.append("Top blocking capabilities:")
        for b, n in blocker_counts.most_common():
            lines.append(f"- `{b}` blocks {n} scenario(s)")
    lines.append("")

    if notrun:
        lines.append(f"## Not run — honest reasons ({len(notrun)})")
        lines.append("")
        lines.append("| ID | Sev | Reason |")
        lines.append("|----|-----|--------|")
        for r in sorted(notrun, key=lambda r: r.id):
            lines.append(f"| {r.id} | {r.severity} | {r.reason} |")
        lines.append("")

    if errored:
        lines.append(f"## Harness errors ({len(errored)})")
        lines.append("")
        for r in sorted(errored, key=lambda r: r.id):
            lines.append(f"- **{r.id}**: {r.reason}")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_reports(results: list[Result], scenarios: list[Scenario],
                  out_dir: str, title: str = "TSG-1 Run Report") -> dict[str, str]:
    import os
    os.makedirs(out_dir, exist_ok=True)
    summary = summarize(results, scenarios)
    json_path = os.path.join(out_dir, "results.json")
    md_path = os.path.join(out_dir, "report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary,
                   "results": [r.to_json() for r in results]},
                  fh, indent=2, ensure_ascii=False)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(results, scenarios, title))
    return {"json": json_path, "markdown": md_path}
