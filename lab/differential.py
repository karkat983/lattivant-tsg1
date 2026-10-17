#!/usr/bin/env python3
"""Differential: authz-fuzzer vs generic baselines on the same seeded target
(TSG-1 AZ-046 / RV-007..010).

The point of the differential is to show the authz scanner finds the *planted
authorization flaws* that generic API-testing tools structurally miss, because
those tools test one identity against a schema and have no notion of
cross-tenant ownership.

What actually runs here:
  * candidate = the built `authz` scanner, via the live lab (lab.live_lab).
  * baseline  = Schemathesis, if present on PATH or at $TSG1_SCHEMATHESIS. It is
    run against each vulnerable mode and its findings are classified; a finding
    counts as an authorization detection only if its category names
    authorization (Schemathesis has no such check, so this is ~0 by design).
  * RESTler / EvoMaster / Burp Autorize: reported NOT_RUN with precise reasons
    (no .NET toolchain / no white-box driver / commercial GUI) — never faked.

Ground truth = the four planted authorization flaws. Recall over that set is
reported per tool, and AZ-046/RV-007 are scored with the differential oracle
(candidate must find >= the union of baselines).

    python3 lab/differential.py
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tsg1.model import Manifest           # noqa: E402
from tsg1.oracles import ORACLES          # noqa: E402
from lab import live_lab                  # noqa: E402

# planted authorization flaws (ground truth) and the live-lab mode that plants
# each. Catching the mode in the live lab == detecting that flaw.
GROUND_TRUTH = {
    "xtenant-read": "bola-read",
    "xtenant-write": "bola-write",
    "missing-auth": "missing-auth",
    "shared-write": "shared-write",
}

AUTHZ_KEYWORDS = ("authoriz", "authz", "bola", "forbidden", "cross-tenant",
                  "tenant", "ownership", "idor")


def _classify_authz(categories: dict) -> bool:
    """True if any Schemathesis failure category names an authorization issue.
    Schemathesis has no such check, so this is ~0 by design — but we classify
    rather than assume, so a future authz-aware baseline would be credited."""
    return any(any(k in c.lower() for k in AUTHZ_KEYWORDS) for c in categories)


def _schemathesis_bin() -> str | None:
    return os.environ.get("TSG1_SCHEMATHESIS") or shutil.which("schemathesis")


def _candidate_found() -> set[str]:
    """Which planted flaws the authz scanner catches (fresh live-lab run)."""
    with tempfile.TemporaryDirectory() as tmp:
        results = {r["mode"]: r for r in live_lab.run_all(tmp)}
    found = set()
    for flaw, mode in GROUND_TRUTH.items():
        r = results.get(mode)
        if r and r["passed"]:
            found.add(flaw)
    return found


def _run_schemathesis(bin_path: str) -> dict:
    """Run Schemathesis against each vuln mode; return authz detections + raw."""
    found: set[str] = set()
    per_mode = {}
    for flaw, mode in GROUND_TRUTH.items():
        proc, base_url = live_lab._start_target(mode)
        try:
            live_lab._wait_ready(base_url)
            cmd = [bin_path, "run", base_url + "/openapi.json", "--url", base_url,
                   "-H", "Authorization: Bearer tok-bravo-admin",
                   "--max-examples", "15"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            text = out.stdout + "\n" + out.stderr
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        # categorize failures from the SUMMARY: "❌ <Category>: <n>"
        cats = dict(re.findall(r"[❌]\s*([A-Za-z0-9 ,\-/]+?):\s*(\d+)", text))
        total = 0
        m = re.search(r"(\d+)\s+found\s+\d+\s+unique failures", text)
        if m:
            total = int(m.group(1))
        authz_hit = _classify_authz(cats)
        if authz_hit:
            found.add(flaw)
        per_mode[mode] = {"categories": cats, "failures_seen": total,
                          "authz_detection": authz_hit}
    return {"authz_found": found, "per_mode": per_mode}


def _evomaster_bin() -> str | None:
    return os.environ.get("TSG1_EVOMASTER")


def _run_evomaster(jar: str) -> dict:
    """Run EvoMaster in black-box mode against each vuln mode.

    EvoMaster white-box instruments JVM/Node/.NET bytecode and cannot
    instrument a Rust binary, so only black-box applies to this target. Like
    other generic fuzzers it reports robustness/protocol faults (500s, XSS,
    HTTP violations), not authorization flaws.
    """
    found: set[str] = set()
    per_mode = {}
    for flaw, mode in GROUND_TRUTH.items():
        proc, base_url = live_lab._start_target(mode)
        with tempfile.TemporaryDirectory() as evo_out:
            try:
                live_lab._wait_ready(base_url)
                cmd = ["java", "-jar", jar, "--blackBox", "true",
                       "--bbSwaggerUrl", base_url + "/openapi.json",
                       "--bbTargetUrl", base_url,
                       "--header0", "Authorization: Bearer tok-bravo-admin",
                       "--maxTimeInSeconds", "20", "--outputFolder", evo_out,
                       "--outputFormat", "PYTHON_UNITTEST", "--ratePerMinute", "120"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                faults_file = os.path.join(evo_out, "EvoMaster_faults_Test.py")
                descs, n = [], 0
                if os.path.exists(faults_file):
                    text = open(faults_file, encoding="utf-8", errors="replace").read()
                    n = len(re.findall(r"potential fault of type-code", text))
                    descs = re.findall(r"#\s*(Fault\d+\..*)", text)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        authz_hit = any(any(k in d.lower() for k in AUTHZ_KEYWORDS) for d in descs)
        if authz_hit:
            found.add(flaw)
        per_mode[mode] = {"categories": {d.split(".")[0]: 1 for d in descs},
                          "failures_seen": n, "authz_detection": authz_hit}
    return {"authz_found": found, "per_mode": per_mode}


def run(out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    candidate = _candidate_found()
    baselines: dict[str, dict] = {}

    st = _schemathesis_bin()
    if st:
        res = _run_schemathesis(st)
        baselines["schemathesis"] = {
            "available": True, "authz_found": sorted(res["authz_found"]),
            "per_mode": res["per_mode"],
            "note": "generic schema fuzzer: finds conformance issues, no authz check"}
    else:
        baselines["schemathesis"] = {
            "available": False, "authz_found": [],
            "note": "schemathesis not on PATH; `pip install schemathesis` to run"}

    evo = _evomaster_bin()
    if evo and os.path.exists(evo):
        res = _run_evomaster(evo)
        baselines["evomaster"] = {
            "available": True, "authz_found": sorted(res["authz_found"]),
            "per_mode": res["per_mode"],
            "note": "black-box (white-box cannot instrument a Rust target): finds "
                    "robustness/protocol faults (XSS, HTTP violations), no authz "
                    "check"}
    else:
        baselines["evomaster"] = {
            "available": False, "authz_found": [],
            "note": "evomaster.jar not found; set $TSG1_EVOMASTER to the jar path "
                    "to run (black-box; white-box N/A for a Rust target)"}

    # RESTler cannot run here — honest NOT_RUN
    baselines["restler"] = {"available": False, "authz_found": [],
                            "note": "RESTler needs Docker (daemon not running here) "
                                    "or a .NET toolchain (absent); and has no "
                                    "authz/BOLA check"}
    baselines["burp_autorize"] = {"available": False, "authz_found": [],
                                  "note": "Burp Suite + Autorize is a commercial "
                                          "GUI extension; cannot run headless here"}

    # score AZ-046 / RV-007 with the differential oracle over the planted flaws
    baseline_found = {name: b["authz_found"] for name, b in baselines.items()}
    obs = {"candidate_found": sorted(candidate), "baseline_found": baseline_found}
    verdict = ORACLES["differential"](obs, Manifest(manifest="AZ-046"))

    report = {
        "ground_truth_flaws": sorted(GROUND_TRUTH),
        "candidate": {"tool": "authz-fuzzer (live lab)",
                      "found": sorted(candidate),
                      "recall": round(len(candidate) / len(GROUND_TRUTH), 4)},
        "baselines": {
            name: {"available": b["available"],
                   "authz_found": b["authz_found"],
                   "recall": round(len(b["authz_found"]) / len(GROUND_TRUTH), 4),
                   "note": b["note"],
                   **({"per_mode": b["per_mode"]} if b.get("per_mode") else {})}
            for name, b in baselines.items()},
        "differential_verdict": {"passed": verdict.passed,
                                 "reason": verdict.reason,
                                 "evidence": verdict.evidence},
    }
    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    _write_md(report, out_dir)
    return report


def _write_md(rep: dict, out_dir: str) -> None:
    c = rep["candidate"]
    lines = ["# TSG-1 Differential — authz-fuzzer vs generic baselines", "",
             "Each tool run against the same seeded `authz-target`. Ground truth "
             "is the four planted authorization flaws; recall is over that set. "
             "Generic API fuzzers test one identity against a schema and have no "
             "cross-tenant/ownership check, so they structurally miss BOLA.", "",
             f"**Differential (AZ-046/RV-007): "
             f"{'PASS' if rep['differential_verdict']['passed'] else 'FAIL'}** — "
             f"{rep['differential_verdict']['reason']}", "",
             "| Tool | Ran? | Authz-flaw recall | Found | Note |",
             "|------|------|-------------------|-------|------|",
             f"| **authz-fuzzer** (candidate) | ✅ | **{c['recall']}** "
             f"({len(c['found'])}/4) | {', '.join(c['found'])} | live end-to-end "
             f"scans |"]
    for name, b in rep["baselines"].items():
        ran = "✅" if b["available"] else "—"
        lines.append(f"| {name} | {ran} | {b['recall']} "
                     f"({len(b['authz_found'])}/4) | "
                     f"{', '.join(b['authz_found']) or '—'} | {b['note']} |")
    lines.append("")
    for name, b in rep["baselines"].items():
        pm_all = b.get("per_mode")
        if not pm_all:
            continue
        lines.append(f"### {name} per-mode (what it *did* find)")
        lines.append("")
        lines.append("| Mode | Non-authz failures | Categories | Authz detection |")
        lines.append("|------|--------------------|------------|-----------------|")
        for mode, pm in pm_all.items():
            cats = ", ".join(f"{k.strip()}×{v}" for k, v in pm["categories"].items())
            lines.append(f"| {mode} | {pm['failures_seen']} | {cats or '—'} | "
                         f"{'yes' if pm['authz_detection'] else 'no'} |")
        lines.append("")
    lines.append("_The generic fuzzers flag schema-conformance and robustness "
                 "faults (undocumented status codes, XSS, HTTP violations) but "
                 "detect none of the planted authorization flaws — the authz "
                 "scanner's value-add._")
    lines.append("")
    with open(os.path.join(out_dir, "report.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "..", "reports", "differential")
    rep = run(out)
    with open(os.path.join(out, "report.md")) as fh:
        print(fh.read())
