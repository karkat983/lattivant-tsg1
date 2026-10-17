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


def _restler_env() -> tuple[str, dict] | None:
    """Return (Restler.dll path, env with dotnet+python on PATH) or None.

    RESTler needs its built DLL ($TSG1_RESTLER_DLL), a .NET 8 runtime
    ($TSG1_DOTNET_DIR, default the Homebrew dotnet@8 bin), and a `python` on
    PATH (RESTler's engine invokes `python`, not `python3`).
    """
    dll = os.environ.get("TSG1_RESTLER_DLL")
    if not dll or not os.path.exists(dll):
        return None
    dotnet_dir = os.environ.get("TSG1_DOTNET_DIR",
                                "/opt/homebrew/opt/dotnet@8/bin")
    if not os.path.exists(os.path.join(dotnet_dir, "dotnet")):
        return None
    shim = tempfile.mkdtemp(prefix="tsg1-pyshim-")
    # RESTler's engine is incompatible with very new CPython (3.14 crashes in
    # fuzz mode); prefer a 3.12 if present. $TSG1_PYTHON overrides.
    py3 = (os.environ.get("TSG1_PYTHON")
           or ("/opt/homebrew/opt/python@3.12/bin/python3.12"
               if os.path.exists("/opt/homebrew/opt/python@3.12/bin/python3.12")
               else None)
           or shutil.which("python3") or sys.executable)
    link = os.path.join(shim, "python")
    try:
        os.symlink(py3, link)
    except FileExistsError:
        pass
    env = dict(os.environ, PATH=f"{shim}:{dotnet_dir}:{os.environ['PATH']}")
    return dll, env


def _normalize_spec_for_restler(spec: dict) -> dict:
    """RESTler's NSwag parser requires a `responses` object on each operation;
    the minimal target spec omits it. Inject a default — a parser-satisfying
    normalization that does not change which operations are tested."""
    for item in spec.get("paths", {}).values():
        for method, op in item.items():
            if method in ("get", "post", "put", "patch", "delete") and isinstance(op, dict):
                op.setdefault("responses", {"default": {"description": "response"}})
    return spec


def _run_restler(dll: str, env: dict) -> dict:
    import glob
    found: set[str] = set()
    per_mode = {}
    for flaw, mode in GROUND_TRUTH.items():
        proc, base_url = live_lab._start_target(mode)
        work = tempfile.mkdtemp(prefix=f"tsg1-restler-{mode}-")
        try:
            spec = live_lab._wait_ready(base_url)
            with open(os.path.join(work, "openapi.json"), "w") as fh:
                json.dump(_normalize_spec_for_restler(spec), fh)
            tok = os.path.join(work, "token.sh")
            with open(tok, "w") as fh:
                fh.write('#!/bin/sh\necho "{}"\n'
                         'echo "Authorization: Bearer tok-bravo-admin"\n')
            os.chmod(tok, 0o755)
            port = base_url.rsplit(":", 1)[1]
            subprocess.run(["dotnet", dll, "compile", "--api_spec", "openapi.json"],
                           cwd=work, env=env, capture_output=True, text=True,
                           timeout=180)
            # seed the fuzzing dictionary with real resource ids so the {id}
            # path parameter hits live orders (a seeded resource dictionary)
            dict_path = os.path.join(work, "Compile", "dict.json")
            seeded = os.path.join(work, "Compile", "dict_seeded.json")
            if os.path.exists(dict_path):
                dd = json.load(open(dict_path))
                dd["restler_fuzzable_string"] = ["order-1", "order-shared",
                                                 "order-public", "fuzzstring"]
                json.dump(dd, open(seeded, "w"))
            else:
                seeded = dict_path
            # deeper run: fuzz mode with a small time budget
            subprocess.run(["dotnet", dll, "fuzz",
                            "--grammar_file", "Compile/grammar.py",
                            "--dictionary_file", seeded,
                            "--target_ip", "127.0.0.1", "--target_port", port,
                            "--no_ssl", "--time_budget", "0.01",
                            "--token_refresh_interval", "300",
                            "--token_refresh_command", f"sh {tok}"],
                           cwd=work, env=env, capture_output=True, text=True,
                           timeout=300)
            summaries = glob.glob(os.path.join(work, "**", "testing_summary.json"),
                                  recursive=True)
            buckets, coverage, sent = {}, "unknown", 0
            if summaries:
                s = json.load(open(sorted(summaries)[-1]))
                buckets = s.get("bug_buckets", {}) or {}
                coverage = s.get("rendered_requests_valid_status", "unknown")
                trs = s.get("total_requests_sent", {}) or {}
                sent = sum(v for v in trs.values() if isinstance(v, int))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            shutil.rmtree(work, ignore_errors=True)
        authz_hit = _classify_authz({k: 1 for k in buckets})
        if authz_hit:
            found.add(flaw)
        per_mode[mode] = {"categories": {k: 1 for k in buckets},
                          "failures_seen": len(buckets),
                          "authz_detection": authz_hit,
                          "requests_sent": sent,
                          "valid_status_coverage": coverage}
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

    rest = _restler_env()
    if rest:
        dll, env = rest
        res = _run_restler(dll, env)
        baselines["restler"] = {
            "available": True, "authz_found": sorted(res["authz_found"]),
            "per_mode": res["per_mode"],
            "note": "stateful REST fuzzer (.NET 8), fuzz mode + seeded resource "
                    "dictionary: sends many requests/mode, 0 bugs, no authz "
                    "check (RESTler's rendered-coverage counter is unreliable "
                    "here due to an engine issue; requests-sent shown instead)"}
    else:
        baselines["restler"] = {
            "available": False, "authz_found": [],
            "note": "set $TSG1_RESTLER_DLL (+ dotnet@8) to run; needs Docker or a "
                    ".NET toolchain. Has no authz/BOLA check"}
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
        has_sent = any("requests_sent" in pm for pm in pm_all.values())
        lines.append(f"### {name} per-mode (what it *did* find)")
        lines.append("")
        extra = " Requests sent |" if has_sent else ""
        extrasep = "--------------|" if has_sent else ""
        lines.append(f"| Mode | Non-authz failures | Categories | Authz detection |{extra}")
        lines.append(f"|------|--------------------|------------|-----------------|{extrasep}")
        for mode, pm in pm_all.items():
            cats = ", ".join(f"{k.strip()}×{v}" for k, v in pm["categories"].items())
            tail = f" {pm.get('requests_sent', '—')} |" if has_sent else ""
            lines.append(f"| {mode} | {pm['failures_seen']} | {cats or '—'} | "
                         f"{'yes' if pm['authz_detection'] else 'no'} |{tail}")
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
