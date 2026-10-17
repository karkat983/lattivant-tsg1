"""TSG-1 harness CLI.

    python -m tsg1 list   [--component C] [--build built|spec|partial] [--run-first]
    python -m tsg1 run    [--ids A,B] [--component C] [--build B] [--run-first]
                          [--all] [--out runs/DIR]
    python -m tsg1 report runs/DIR/results.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

from .catalog import filter_scenarios, load_catalog
from .model import Outcome
from .report import to_markdown, write_reports


#: capability (a catalog spec_blocker) -> component whose passing cargo suite
#: provides it. A capability is enabled only when that component is present and
#: its tests pass. Capabilities with no built component (long-horizon memory,
#: gRPC/WebSocket adapters) are intentionally absent, so those scenarios skip.
_CAP_PROVIDERS: dict[str, str] = {
    "R1": "agenttrace", "R2": "agenttrace", "R3": "agenttrace",
    "R4": "agenttrace", "R-rules": "agenttrace", "R4_taint": "agenttrace",
    "side_effect_tap": "agenttrace", "span_side_effect_join": "agenttrace",
    "mcp_scanner": "agenttrace", "labeling": "agenttrace",
    "evidence_graph": "evidence-graph", "evidence_graph_join": "evidence-graph",
    "correlator": "evidence-graph", "content_store": "evidence-graph",
    "investigator": "investigator", "post_checker": "investigator",
    "detectors": "agenttrace", "agenttrace": "agenttrace",
}


def _detect_capabilities() -> set[str]:
    """Enable each capability whose backing component is built and green.

    Detected by actually running (or parsing a captured run of) the component's
    cargo tests — never assumed. Absent/failing component -> capability stays
    off, so its scenarios skip honestly.
    """
    from .adapters._cargo import component_results
    caps: set[str] = set()
    ok_components: dict[str, bool] = {}
    for cap, comp in _CAP_PROVIDERS.items():
        if comp not in ok_components:
            run = component_results(comp)
            ok_components[comp] = run.available and (run.exit_status == 0)
        if ok_components[comp]:
            caps.add(cap)
    return caps


def _load_registry_and_lab():
    # importing adapters populates the global REGISTRY as a side effect
    from . import adapters  # noqa: F401
    from .runner import REGISTRY, LabContext
    from .adapters import load_manifests
    lab = LabContext(capabilities=_detect_capabilities(),
                     manifests=load_manifests())
    return REGISTRY, lab


def cmd_list(args: argparse.Namespace) -> int:
    scenarios = load_catalog()
    sel = filter_scenarios(scenarios,
                           component=args.component,
                           build_status=args.build,
                           severity=args.severity,
                           run_first=True if args.run_first else None)
    print(f"{'ID':<8} {'BUILD':<8} {'SEV':<4} {'ORACLE':<13} TITLE")
    for s in sel:
        rf = "*" if s.run_first else " "
        print(f"{s.id:<8} {s.build_status:<8} {s.severity:<4} "
              f"{s.oracle:<13} {rf}{s.title}")
    print(f"\n{len(sel)} / {len(scenarios)} scenarios")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    scenarios = load_catalog()
    ids = [x.strip() for x in args.ids.split(",")] if args.ids else None
    if args.all:
        sel = scenarios
    else:
        sel = filter_scenarios(scenarios, ids=ids,
                               component=args.component,
                               build_status=args.build,
                               severity=args.severity,
                               run_first=True if args.run_first else None)
    if not sel:
        print("no scenarios matched selection", file=sys.stderr)
        return 2

    from .runner import run_many
    registry, lab = _load_registry_and_lab()
    results = run_many(sel, lab, registry)

    out = args.out or os.path.join(
        "runs", _dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    paths = write_reports(results, sel, out,
                          title="TSG-1 Run Report (selected scenarios)")
    oc = {}
    for r in results:
        oc[r.outcome] = oc.get(r.outcome, 0) + 1
    print(f"ran {len(results)} scenarios")
    for k in (Outcome.PASS.value, Outcome.FAIL.value, Outcome.SKIPPED.value,
              Outcome.NOT_RUN.value, Outcome.ERROR.value):
        print(f"  {k:<9}: {oc.get(k, 0)}")
    print(f"reports: {paths['markdown']}  |  {paths['json']}")
    # non-zero exit if any S0 failure (release-gate semantics)
    s0_fail = [r.id for r in results
               if r.severity == "S0" and r.outcome == Outcome.FAIL.value]
    if s0_fail:
        print(f"S0 FAILURES (release gate): {s0_fail}", file=sys.stderr)
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    with open(args.results, encoding="utf-8") as fh:
        payload = json.load(fh)
    from .model import Result
    scenarios = load_catalog()
    by_id = {s.id: s for s in scenarios}
    results = [Result(**r) for r in payload["results"]]
    sel = [by_id[r.id] for r in results if r.id in by_id]
    print(to_markdown(results, sel))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tsg1", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="list catalog scenarios")
    pl.add_argument("--component")
    pl.add_argument("--build", choices=["built", "spec", "partial"])
    pl.add_argument("--severity", choices=["S0", "S1", "S2", "S3"])
    pl.add_argument("--run-first", action="store_true")
    pl.set_defaults(func=cmd_list)

    pr = sub.add_parser("run", help="run selected scenarios")
    pr.add_argument("--ids")
    pr.add_argument("--component")
    pr.add_argument("--build", choices=["built", "spec", "partial"])
    pr.add_argument("--severity", choices=["S0", "S1", "S2", "S3"])
    pr.add_argument("--run-first", action="store_true")
    pr.add_argument("--all", action="store_true")
    pr.add_argument("--out")
    pr.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="re-render a results.json as markdown")
    rp.add_argument("results")
    rp.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
