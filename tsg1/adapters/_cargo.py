"""Run (or parse captured runs of) each Lattivant component's cargo test suite
and expose a {test_name -> status} map, so adapters can back scenarios with the
component's own conformance tests. Generalizes the authz-fuzzer helper to every
Rust component.

Reproducibility: if $TSG1_COMPTESTS_DIR holds `<key>.log` files from a captured
`cargo test` run, those are parsed (and the command recorded); otherwise
`cargo test --workspace` is run in the component directory. Nothing is
fabricated — a component that is absent or whose tests did not run yields an
unavailable result, and a scenario whose backing test is missing is NOT_RUN.
"""
from __future__ import annotations

import functools
import os
import re
import subprocess
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.normpath(os.path.join(_HERE, "..", "..", ".."))

# component key -> cargo workspace directory (relative to the Lattivant root)
COMPONENT_DIR = {
    "authz-fuzzer": "authz-fuzzer/scanner",
    "agenttrace": "agenttrace",
    "eastwest": "eastwest",
    "evidence-graph": "evidence-graph",
    "investigator": "investigator",
    "lattivant-platform": "lattivant-platform",
    "lattivant-lab": "lattivant-lab",
}

_LINE = re.compile(r"^test\s+([A-Za-z0-9_:]+)\s+\.\.\.\s+(ok|FAILED|ignored)\b")
_SUMMARY = re.compile(r"test result:\s+\w+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed")


@dataclass
class CargoRun:
    key: str
    by_short: dict[str, list[str]] = field(default_factory=dict)
    passed: int = 0
    failed: int = 0
    command: str = ""
    exit_status: int | None = None
    available: bool = False
    note: str = ""

    def lookup(self, short_name: str) -> str | None:
        st = self.by_short.get(short_name)
        if not st:
            return None
        if all(s == "ok" for s in st):
            return "ok"
        if any(s == "FAILED" for s in st):
            return "FAILED"
        return "mixed"


def _parse(text: str, key: str) -> CargoRun:
    run = CargoRun(key=key)
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m:
            short = m.group(1).split("::")[-1]
            run.by_short.setdefault(short, []).append(m.group(2))
        ms = _SUMMARY.search(line)
        if ms:
            run.passed += int(ms.group(1))
            run.failed += int(ms.group(2))
    return run


@functools.lru_cache(maxsize=None)
def component_results(key: str) -> CargoRun:
    rel = COMPONENT_DIR.get(key)
    if not rel:
        return CargoRun(key=key, note=f"unknown component {key}")
    comp_dir = os.path.join(_REPO, rel)

    captured_dir = os.environ.get("TSG1_COMPTESTS_DIR")
    # authz-fuzzer may use its own captured-log env var for back-compat
    log = None
    if key == "authz-fuzzer" and os.environ.get("TSG1_SCANNER_LOG"):
        log = os.environ["TSG1_SCANNER_LOG"]
    elif captured_dir:
        cand = os.path.join(captured_dir, f"{key}.log")
        if os.path.exists(cand):
            log = cand
    if log and os.path.exists(log):
        text = open(log, encoding="utf-8", errors="replace").read()
        run = _parse(text, key)
        run.command = f"(parsed captured log) {log}"
        m = re.search(r"EXIT=(\d+)", text)
        run.exit_status = int(m.group(1)) if m else (0 if run.failed == 0 else 1)
        run.available = bool(run.by_short)
        return run

    if not os.path.isdir(comp_dir):
        return CargoRun(key=key, note=f"component dir not found: {comp_dir}")
    cmd = ["cargo", "test", "--workspace"]
    try:
        proc = subprocess.run(cmd, cwd=comp_dir, capture_output=True,
                              text=True, timeout=1800)
    except FileNotFoundError:
        return CargoRun(key=key, note="cargo not installed", command=" ".join(cmd))
    except subprocess.TimeoutExpired:
        return CargoRun(key=key, note="cargo test timed out", command=" ".join(cmd))
    run = _parse(proc.stdout + "\n" + proc.stderr, key)
    run.command = " ".join(cmd) + f"  (cwd={rel})"
    run.exit_status = proc.returncode
    run.available = bool(run.by_short)
    return run
