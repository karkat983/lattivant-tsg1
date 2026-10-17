"""Run (or parse a captured run of) the authz-fuzzer Rust scanner test suite
and expose a {test_name -> passed?} map that adapters use as evidence.

Reproducibility: if TSG1_SCANNER_LOG points at a captured `cargo test` log, we
parse that exact log (so a harness run reuses the recorded evidence and records
the command that produced it). Otherwise we invoke `cargo test --workspace` in
the scanner directory. Either way nothing is fabricated: a scenario whose
backing test is absent from the output is reported NOT_RUN, never PASS.
"""
from __future__ import annotations

import functools
import os
import re
import subprocess
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.normpath(
    os.path.join(_HERE, "..", "..", "..", "authz-fuzzer", "scanner"))

# "test oracle::read::tests::cross_tenant_... ... ok"  /  "... FAILED"
_LINE = re.compile(r"^test\s+([A-Za-z0-9_:]+)\s+\.\.\.\s+(ok|FAILED|ignored)\b")
_SUMMARY = re.compile(
    r"test result:\s+\w+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored")


@dataclass
class ScannerRun:
    by_full: dict[str, str] = field(default_factory=dict)       # path -> status
    by_short: dict[str, list[str]] = field(default_factory=dict)  # fn -> [status]
    passed: int = 0
    failed: int = 0
    ignored: int = 0
    command: str = ""
    exit_status: int | None = None
    available: bool = False
    note: str = ""

    def lookup(self, short_name: str) -> str | None:
        """Return 'ok'/'FAILED'/'mixed' for a short test name, or None if absent."""
        st = self.by_short.get(short_name)
        if not st:
            return None
        if all(s == "ok" for s in st):
            return "ok"
        if any(s == "FAILED" for s in st):
            return "FAILED"
        return "mixed"


def _parse(text: str) -> ScannerRun:
    run = ScannerRun()
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m:
            full, status = m.group(1), m.group(2)
            run.by_full[full] = status
            short = full.split("::")[-1]
            run.by_short.setdefault(short, []).append(status)
        ms = _SUMMARY.search(line)
        if ms:
            run.passed += int(ms.group(1))
            run.failed += int(ms.group(2))
            run.ignored += int(ms.group(3))
    return run


@functools.lru_cache(maxsize=1)
def scanner_results() -> ScannerRun:
    log = os.environ.get("TSG1_SCANNER_LOG")
    if log and os.path.exists(log):
        with open(log, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        run = _parse(text)
        run.command = f"(parsed captured log) {log}"
        m = re.search(r"EXIT=(\d+)", text)
        run.exit_status = int(m.group(1)) if m else (0 if run.failed == 0 else 1)
        run.available = bool(run.by_full)
        if not run.available:
            run.note = "captured log parsed but no test lines found"
        return run

    if not os.path.isdir(SCANNER_DIR):
        run = ScannerRun(note=f"scanner dir not found: {SCANNER_DIR}")
        return run
    cmd = ["cargo", "test", "--workspace"]
    try:
        proc = subprocess.run(cmd, cwd=SCANNER_DIR, capture_output=True,
                              text=True, timeout=1800)
    except FileNotFoundError:
        return ScannerRun(note="cargo not installed", command=" ".join(cmd))
    except subprocess.TimeoutExpired:
        return ScannerRun(note="cargo test timed out (1800s)",
                          command=" ".join(cmd))
    run = _parse(proc.stdout + "\n" + proc.stderr)
    run.command = " ".join(cmd) + f"  (cwd={SCANNER_DIR})"
    run.exit_status = proc.returncode
    run.available = bool(run.by_full)
    return run
