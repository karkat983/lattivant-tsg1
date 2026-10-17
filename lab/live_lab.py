#!/usr/bin/env python3
"""Integrated live lab (TSG-1 C.3) for the AuthZ-Fuzzer.

Runs the `authz-target` reference orders API in each vulnerability mode, points
the Rust scanner at its live `/openapi.json`, runs a real scan, and scores the
emitted SARIF/JSON findings against per-mode ground truth using the TSG-1
oracles. This upgrades the AZ-* evidence from "the control has passing unit
tests" to "a live seeded target was scanned end-to-end and the planted flaw was
found (or, for the hardened mode, nothing was)".

The fixture mirrors the scanner's own canonical integration test
(`authz-cli/tests/scan_live_target.rs`): two identities (the alpha owner and a
cross-tenant bravo caller) and a per-mode mutation scope, so read-only probes
never emit write findings. The seeded order is shared with no tenant, so the
shared-write vuln is not exercised (noted, not faked).

Entirely local: the target binds 127.0.0.1 on an OS-chosen port. Nothing is
fabricated — an unreachable target or missing binary is an error, not a pass.

    python3 lab/live_lab.py            # run all modes, write reports/live-lab/
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tsg1.model import Manifest, digest           # noqa: E402
from tsg1.oracles import ORACLES                  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.normpath(
    os.path.join(_HERE, "..", "..", "authz-fuzzer", "scanner"))
TARGET_BIN = os.path.join(SCANNER_DIR, "target", "debug", "authz-target")
SCAN_BIN = os.path.join(SCANNER_DIR, "target", "debug", "authz")

# Each row: key -> {server vuln mode, mutation scope, TSG-1 scenario, oracle,
# ground-truth label/expectation}. Mirrors scan_live_target.rs coverage plus a
# scope-safety row (read-only scope vs a write-vulnerable server).
MODES: dict[str, dict] = {
    "none": {"server": "none", "mutation": "test_owned_only",
             "scenario": "AZ-047", "oracle": "manifest", "label": "benign",
             "expect_rule": "", "expect": "zero verified findings"},
    "bola-read": {"server": "bola-read", "mutation": "read_only",
                  "scenario": "AZ-002", "oracle": "isolation", "label": "achieved",
                  "expect_rule": "cross_tenant_access",
                  "expect": "verified cross-tenant read leak"},
    "bola-write": {"server": "bola-write", "mutation": "test_owned_only",
                   "scenario": "AZ-002", "oracle": "isolation", "label": "achieved",
                   "expect_rule": "", "expect": "verified cross-tenant write"},
    "missing-auth": {"server": "missing-auth", "mutation": "read_only",
                     "scenario": "AZ-003", "oracle": "manifest", "label": "achieved",
                     "expect_rule": "missing_authentication",
                     "expect": "verified missing-authentication read"},
    "readonly-scope-vs-write-vuln": {
        "server": "bola-write", "mutation": "read_only",
        "scenario": "AZ-030", "oracle": "invariant", "label": "benign",
        "expect_rule": "", "expect": "read-only scope emits NO write finding"},
}

TOKENS = {"ALPHA_ADMIN": "tok-alpha-admin", "BRAVO_ADMIN": "tok-bravo-admin"}


def _ensure_binaries() -> None:
    if os.path.exists(TARGET_BIN) and os.path.exists(SCAN_BIN):
        return
    subprocess.run(["cargo", "build", "-p", "authz-target", "-p", "authz-cli"],
                   cwd=SCANNER_DIR, check=True)


def _start_target(server_vuln: str) -> tuple[subprocess.Popen, str]:
    proc = subprocess.Popen([TARGET_BIN, "--port", "0", "--vuln", server_vuln],
                            cwd=SCANNER_DIR, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    base_url = ""
    assert proc.stdout is not None
    for _ in range(50):
        line = proc.stdout.readline()
        m = re.search(r"http://(127\.0\.0\.1:\d+)", line)
        if m:
            base_url = "http://" + m.group(1)
            break
    if not base_url:
        proc.terminate()
        raise RuntimeError(f"target did not report a bound address ({server_vuln})")
    return proc, base_url


def _wait_ready(base_url: str, timeout_s: float = 5.0) -> dict:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/openapi.json", timeout=1) as r:
                return json.loads(r.read().decode())
        except Exception as exc:
            last = exc
            time.sleep(0.1)
    raise RuntimeError(f"openapi not ready at {base_url}: {last}")


def _write_manifest(workdir: str, base_url: str, mutation: str) -> str:
    manifest = {
        "target": {"name": "orders", "base_url": base_url},
        "spec": "openapi.json",
        "host_allowlist": ["127.0.0.1"],
        "mutation": mutation,
        "permitted_methods": ["PATCH", "DELETE"],
        "limits": {"max_requests": 1000, "time_budget_secs": 60,
                   "max_concurrency": 2, "rate_limit_rps": 1000},
        "reproductions": {"read_repeats": 2, "required": 2},
        "request_timeout_ms": 5000,
        "identities": [
            {"id": "alpha-admin", "tenant": "alpha", "role": "admin",
             "credential_ref": "env:ALPHA_ADMIN", "is_public": False},
            {"id": "bravo-admin", "tenant": "bravo", "role": "admin",
             "credential_ref": "env:BRAVO_ADMIN", "is_public": False},
        ],
        "resources": [
            {"instance_id": "order-1", "path_param": "id",
             "resource_class": "order", "owner": "alpha-admin",
             "write_body": {"status": "cancelled"}},
        ],
        "gate": {"min_confidence": "verified", "min_severity": "high"},
    }
    path = os.path.join(workdir, "manifest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return path


def _scan(workdir: str, manifest_path: str) -> dict:
    env = dict(os.environ, **TOKENS)
    sarif = os.path.join(workdir, "out.sarif")
    rep = os.path.join(workdir, "out.json")
    cmd = [SCAN_BIN, "scan", "--manifest", manifest_path,
           "--sarif", sarif, "--json", rep]
    proc = subprocess.run(cmd, cwd=SCANNER_DIR, env=env,
                          capture_output=True, text=True, timeout=120)
    with open(rep, encoding="utf-8") as fh:
        report = json.load(fh)
    return {"exit": proc.returncode, "report": report,
            "stdout": proc.stdout.strip(),
            "command": "authz scan --manifest manifest.json --sarif out.sarif "
                       "--json out.json"}


def _observation_for(cfg: dict, report: dict) -> tuple[dict, dict]:
    findings = report.get("findings", [])
    verified = [f for f in findings if f.get("confidence") == "verified"]
    reads = [f for f in verified if not f.get("is_write")]
    writes = [f for f in verified if f.get("is_write")]
    metrics = {"findings_total": report.get("total", len(findings)),
               "verified": len(verified),
               "verified_reads": len(reads), "verified_writes": len(writes),
               "violations": sorted({f.get("violation") for f in verified})}

    if cfg["oracle"] == "isolation":
        if cfg["server"] == "bola-read":
            escapes = 0 if reads else 1          # expect a verified read leak
        elif cfg["server"] == "bola-write":
            escapes = 0 if writes else 1         # expect a verified write
        else:
            escapes = 0 if verified else 1
        return ({"isolation_escapes": escapes,
                 "isolation_detail": [f["operation"] for f in verified]}, metrics)

    if cfg["oracle"] == "invariant":
        # read-only scope must emit no write finding at all
        return ({"invariant_violations": [f["operation"]["method"] for f in writes]},
                metrics)

    # manifest oracle: carry each finding's real violation as its rule
    obs_findings = [{"rule": f.get("violation"), "tenant_id": f.get("tenant", ""),
                     "label": "achieved"} for f in verified]
    return {"findings": obs_findings}, metrics


def run_all(out_dir: str) -> list[dict]:
    _ensure_binaries()
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for mode, cfg in MODES.items():
        workdir = os.path.join(out_dir, mode)
        os.makedirs(workdir, exist_ok=True)
        proc, base_url = _start_target(cfg["server"])
        try:
            openapi = _wait_ready(base_url)
            with open(os.path.join(workdir, "openapi.json"), "w") as fh:
                json.dump(openapi, fh, indent=2)
            manifest_path = _write_manifest(workdir, base_url, cfg["mutation"])
            scan = _scan(workdir, manifest_path)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        obs, metrics = _observation_for(cfg, scan["report"])
        gt = Manifest(manifest=cfg["scenario"], expected_rule=cfg["expect_rule"],
                      label=cfg["label"], tenant_id="alpha")
        verdict = ORACLES[cfg["oracle"]](obs, gt)
        results.append({
            "mode": mode, "server_vuln": cfg["server"], "mutation": cfg["mutation"],
            "scenario": cfg["scenario"], "oracle": cfg["oracle"],
            "expect": cfg["expect"], "passed": verdict.passed,
            "reason": verdict.reason, "metrics": metrics,
            "gate_exit": scan["exit"], "command": scan["command"],
            "stdout_tail": scan["stdout"][-400:], "replay_ref": digest(scan["report"]),
        })
    return results


def write_report(results: list[dict], out_dir: str) -> str:
    passed = sum(1 for r in results if r["passed"])
    lines = ["# TSG-1 Integrated Live Lab — AuthZ-Fuzzer end-to-end", "",
             "Real scans of the `authz-target` reference orders API across its "
             "vulnerability modes, scored against ground truth by the TSG-1 "
             "oracles. Evidence is live SARIF/JSON findings over a real socket, "
             "not unit tests.", "",
             f"**{passed}/{len(results)} modes scored as expected.** "
             "(Gate exit 0 = CI gate passed, 2 = gate failed because a planted "
             "flaw was correctly found.)", "",
             "| Mode | Server | Scope | Scenario | Oracle | Expected | Result "
             "| Verified (r/w) | Violations | Gate | Detail |",
             "|------|--------|-------|----------|--------|----------|--------"
             "|----------------|------------|------|--------|"]
    for r in results:
        icon = "✅" if r["passed"] else "❌"
        m = r["metrics"]
        lines.append(
            f"| {r['mode']} | {r['server_vuln']} | {r['mutation']} | "
            f"{r['scenario']} | {r['oracle']} | {r['expect']} | {icon} | "
            f"{m['verified']} ({m['verified_reads']}/{m['verified_writes']}) | "
            f"{','.join(m['violations']) or '—'} | {r['gate_exit']} | "
            f"{r['reason']} |")
    lines.append("")
    lines.append("_Note: the seeded order is shared with no tenant, so the "
                 "`shared-write` vuln is not exercised and is omitted rather "
                 "than reported as a pass/fail._")
    lines.append("")
    md = "\n".join(lines) + "\n"
    with open(os.path.join(out_dir, "report.md"), "w") as fh:
        fh.write(md)
    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump(results, fh, indent=2)
    return md


if __name__ == "__main__":
    out = os.path.join(_HERE, "..", "reports", "live-lab")
    res = run_all(out)
    print(write_report(res, out))
