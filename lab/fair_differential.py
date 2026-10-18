#!/usr/bin/env python3
"""Fair differential + status-vs-effect experiment (worklog 09).

Pre-registration: worklogs/09-fair-differential-prereg.md. Unlike lab/differential.py, every
baseline here gets two identities and its own authorization checks:

  * RESTler (source build): two users via token_refresh_command, checkers namespacerule,
    useafterfree, resourcehierarchy, leakagerule, invaliddynamicobject; namespacerule
    trigger_objects = the seeded order ids; fuzzing dictionary seeded with the same ids.
  * EvoMaster 6.2.0 black-box: two users in a WFC auth config, security phase on (default).
  * Schemathesis 4.32.0: two users in a WFC auth file as peers, --checks all (includes
    object_level_authorization and ignored_auth).
  * authz-fuzzer: the built `authz` scanner with the same identities in its manifest.

    python3 lab/fair_differential.py run --tools schemathesis,evomaster --modes all
    python3 lab/fair_differential.py score          # tables from the committed raw files

`run` starts a fresh `authz-target` per (tool, mode) on 127.0.0.1, runs the tool, and saves
its raw output, the exact command and a normalized findings.json under
reports/fair-differential/<tool>/<mode>/. `score` reads only those files. A tool that is
not installed, or that fails, is recorded as NOT_RUN with the error, never as zero.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import live_lab  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "reports", "fair-differential"))
AUTH = os.path.join(OUT, "auth")
TOOLS_HOME = os.path.expanduser("~/tools/fair-differential")

# (mode, server vuln, identity pair). Pair "alpha-bravo": owner alpha-admin, other identity
# bravo-admin. Pair "viewer-admin": owner alpha-viewer, actor alpha-admin (admin-legit only).
MODES: dict[str, dict] = {
    "none": {"server": "none", "pair": "alpha-bravo"},
    "bola-read": {"server": "bola-read", "pair": "alpha-bravo"},
    "bola-write": {"server": "bola-write", "pair": "alpha-bravo"},
    "missing-auth": {"server": "missing-auth", "pair": "alpha-bravo"},
    "shared-write": {"server": "shared-write", "pair": "alpha-bravo"},
    "admin-legit": {"server": "admin-legit", "pair": "viewer-admin"},
    "silent-write": {"server": "silent-write", "pair": "alpha-bravo"},
    "lying-success": {"server": "lying-success", "pair": "alpha-bravo"},
    "leaky-404": {"server": "leaky-404", "pair": "alpha-bravo"},
}
PAIRS = {"alpha-bravo": ("alpha-admin", "bravo-admin"),
         "viewer-admin": ("alpha-viewer", "alpha-admin")}

GET, WRITES = ["GET /orders/{id}"], ["PATCH /orders/{id}", "DELETE /orders/{id}"]
INSTANCE = GET + WRITES
# Task 3: planted flaw -> (server mode, relevant finding class, operations)
FLAWS = {
    "xtenant-read": ("bola-read", "cross", GET),
    "xtenant-write": ("bola-write", "cross", WRITES),
    "missing-auth": ("missing-auth", "unauth", GET),
    "shared-write": ("shared-write", "cross", WRITES),
}
# Task 4 rows: mode -> (operations, should be flagged, correct verdict text)
ROWS = {
    "silent-write": (WRITES, True, "verified violation"),
    "lying-success": (WRITES, False, "no write violation"),
    "admin-legit": (INSTANCE, False, "no finding"),
    "leaky-404": (GET, True, "information disclosure"),
}
BASELINE_TRAPS = ["none", "admin-legit"]
CANDIDATE_TRAPS = ["none", "delegated-read", "public-read", "admin-legit"]

# finding classes per tool (pre-registered)
EVOMASTER_CLASSES = {304: "cross", 306: "cross", 307: "unauth"}
EVOMASTER_NAMES = {300: "SECURITY_SQL_INJECTION", 301: "SECURITY_XSS", 302: "SECURITY_SSRF",
                   303: "SECURITY_MASS_ASSIGNMENT", 304: "SECURITY_EXISTENCE_LEAKAGE",
                   305: "SECURITY_NOT_RECOGNIZED_AUTHENTICATED",
                   306: "SECURITY_WRONG_AUTHORIZATION", 307: "SECURITY_IGNORE_ANONYMOUS",
                   308: "SECURITY_ANONYMOUS_MODIFICATIONS", 309: "SECURITY_LEAKED_STACK_TRACES",
                   310: "SECURITY_HIDDEN_ACCESSIBLE_ENDPOINT"}
SCHEMATHESIS_CLASSES = {"ObjectLevelAuthorizationViolation": "cross", "IgnoredAuth": "unauth"}
SCANNER_CLASSES = {"cross_tenant_access": "cross", "bola": "cross",
                   "shared_resource_write": "cross", "information_disclosure": "cross",
                   "missing_authentication": "unauth"}


def _json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _dump(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def normalize_op(method: str, path: str) -> str:
    """'PATCH', '/orders/order-7' or '/orders/{}' -> 'PATCH /orders/{id}'."""
    path = path.split("?", 1)[0]
    if re.fullmatch(r"/orders/[^/]+", path):
        path = "/orders/{id}"
    return f"{method.upper()} {path}"


# --- parsers: raw tool output -> normalized findings ------------------------------------

def parse_restler(bug_dir: str) -> list[dict]:
    path = os.path.join(bug_dir, "Bugs.json")
    if not os.path.exists(path):
        return []
    out = []
    for bug in _json(path).get("bugs", []):
        detail = _json(os.path.join(bug_dir, bug["filepath"]))
        checker = bug["checker_name"]
        out.append({"category": f"{checker}_{bug['error_code']}",
                    "cls": "cross" if checker == "NameSpaceRuleChecker" else None,
                    "operation": normalize_op(detail["verb"], detail["endpoint"]),
                    "title": f"{checker} {detail.get('status_code', '')} {detail.get('status_text', '')}".strip(),
                    "reproducible": bug.get("reproducible"), "source": bug["filepath"]})
    return out


def parse_evomaster(report: dict) -> list[dict]:
    out = []
    for fault in (report.get("faults") or {}).get("foundFaults", []):
        method, _, path = fault["operationId"].partition(":")
        for cat in fault.get("faultCategories", []):
            code = cat["code"]
            out.append({"category": f"{code}:{EVOMASTER_NAMES.get(code, 'other')}",
                        "cls": EVOMASTER_CLASSES.get(code),
                        "operation": normalize_op(method, path),
                        "title": EVOMASTER_NAMES.get(code, f"fault {code}"),
                        "source": fault.get("testCaseId")})
    return out


def parse_schemathesis(report: dict) -> list[dict]:
    out = []
    for failure in report.get("failures", []):
        for op in failure.get("operations", []):
            method, _, path = op.partition(" ")
            out.append({"category": f"{failure['type']}:{failure['title']}",
                        "cls": SCHEMATHESIS_CLASSES.get(failure["type"]),
                        "operation": normalize_op(method, path),
                        "title": f"{failure.get('code', '')} {failure['title']}".strip(),
                        "count": failure.get("count")})
    return out


def parse_scanner(report: dict) -> list[dict]:
    out = []
    for f in report.get("findings", []):
        op = f["operation"]
        out.append({"category": f["violation"], "cls": SCANNER_CLASSES.get(f["violation"]),
                    "operation": normalize_op(op["method"], op.get("normalized_path", "")),
                    "title": f.get("summary", ""), "confidence": f.get("confidence"),
                    "is_write": f.get("is_write"), "source": f.get("id")})
    return out


# --- running -----------------------------------------------------------------------------

def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _wait_for_ports(limit: int = 3000) -> None:
    """EvoMaster opens many short connections; wait until the TIME_WAIT backlog drains."""
    for _ in range(120):
        out = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True).stdout
        if out.count("TIME_WAIT") < limit:
            return
        time.sleep(2)


def _record(run_dir: str, tool: str, mode: str, status: str, command: list[str] | str,
            findings: list[dict], extra: dict | None = None, error: str = "") -> dict:
    run = {"tool": tool, "mode": mode, "server": MODES.get(mode, {}).get("server", mode),
           "pair": MODES.get(mode, {}).get("pair", "alpha-bravo"), "status": status,
           "error": error, "command": command if isinstance(command, str) else " ".join(command),
           "finished_at": dt.datetime.now().isoformat(timespec="seconds"), **(extra or {})}
    with open(os.path.join(run_dir, "run.json"), "w") as fh:
        json.dump(run, fh, indent=2)
    with open(os.path.join(run_dir, "findings.json"), "w") as fh:
        json.dump(findings, fh, indent=2)
    return run


def _redact(path: str) -> str:
    return path.replace(os.path.expanduser("~"), "~").replace(OUT, "reports/fair-differential")


def run_schemathesis(mode: str, run_dir: str) -> dict:
    exe = os.environ.get("TSG1_SCHEMATHESIS", os.path.join(TOOLS_HOME, "schemathesis-venv/bin/schemathesis"))
    if not os.path.exists(exe):
        return _record(run_dir, "schemathesis", mode, "NOT_RUN", "", [], error=f"not found: {exe}")
    u1, u2 = PAIRS[MODES[mode]["pair"]]
    cfg = os.path.join(run_dir, "schemathesis.toml")
    with open(cfg, "w") as fh:
        fh.write(f'[auth.wfc]\npath = "{AUTH}/wfc_{MODES[mode]["pair"]}.yaml"\npeers = ["{u1}", "{u2}"]\n')
    proc, base = live_lab._start_target(MODES[mode]["server"])
    report_dir = tempfile.mkdtemp(prefix="st-report-")
    cmd = [exe, "--config-file", cfg, "run", base + "/openapi.json", "--url", base, "--checks", "all",
           "--max-examples", "50", "--seed", "42", "--report", "json,ndjson", "--report-dir", report_dir]
    try:
        live_lab._wait_ready(base)
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    finally:
        _stop(proc)
    _write(os.path.join(run_dir, "stdout.txt"), res.stdout + "\n" + res.stderr)
    reports = glob.glob(os.path.join(report_dir, "json-*.json"))
    if not reports:
        return _record(run_dir, "schemathesis", mode, "NOT_RUN", [_redact(c) for c in cmd], [],
                       error=f"no JSON report (exit {res.returncode})")
    shutil.copy(reports[0], os.path.join(run_dir, "report.json"))
    for nd in glob.glob(os.path.join(report_dir, "ndjson-*.ndjson")):
        with open(nd, "rb") as src, gzip.open(os.path.join(run_dir, "events.ndjson.gz"), "wb") as dst:
            shutil.copyfileobj(src, dst)
    shutil.rmtree(report_dir, ignore_errors=True)
    report = _json(os.path.join(run_dir, "report.json"))
    return _record(run_dir, "schemathesis", mode, "OK", [_redact(c) for c in cmd],
                   parse_schemathesis(report), {"exit": res.returncode, "version": report.get("schemathesis_version"),
                                                "test_cases": report.get("test_cases")})


def run_evomaster(mode: str, run_dir: str, tool: str = "evomaster", extra_phase: str | None = None) -> dict:
    """extra_phase: None = pre-registered config; "1.0" = sensitivity run (evomaster-sec) giving the
    post-search SECURITY phase up to 100% of the search budget instead of the default 10%."""
    jar = os.environ.get("TSG1_EVOMASTER", os.path.join(TOOLS_HOME, "evomaster-6.2.0/evomaster.jar"))
    if not os.path.exists(jar):
        return _record(run_dir, tool, mode, "NOT_RUN", "", [], error=f"not found: {jar}")
    cfg = os.path.join(run_dir, "em.yaml")
    with open(cfg, "w") as fh:
        with open(os.path.join(AUTH, f"wfc_{MODES[mode]['pair']}.yaml"), encoding="utf-8") as src:
            fh.write("configs: {}\n" + src.read())
    _wait_for_ports()
    proc, base = live_lab._start_target(MODES[mode]["server"])
    out = tempfile.mkdtemp(prefix="evo-out-")
    cmd = ["java", "-jar", jar, "--blackBox", "true", "--schema", base + "/openapi.json", "--base", base,
           "--configPath", cfg, "--maxTime", "120s", "--seed", "42", "--ratePerMinute", "1800",
           "--outputFolder", out, "--outputFormat", "PYTHON_UNITTEST", "--writeWFCReport", "true"]
    if extra_phase:
        cmd += ["--extraPhaseBudgetPercentage", extra_phase]
    try:
        live_lab._wait_ready(base)
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    finally:
        _stop(proc)
    stdout = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", res.stdout + "\n" + res.stderr)
    _write(os.path.join(run_dir, "stdout.txt"), stdout)
    for name in ("report.json", "EvoMaster_faults_Test.py", "EvoMaster_others_Test.py",
                 "EvoMaster_successes_Test.py"):
        if os.path.exists(os.path.join(out, name)):
            shutil.copy(os.path.join(out, name), os.path.join(run_dir, name))
    shutil.rmtree(out, ignore_errors=True)
    rep_path = os.path.join(run_dir, "report.json")
    if res.returncode != 0 or not os.path.exists(rep_path):
        tail = [ln for ln in stdout.splitlines() if "Exception" in ln or "ERROR" in ln][:2]
        return _record(run_dir, tool, mode, "NOT_RUN", [_redact(c) for c in cmd], [],
                       error=f"exit {res.returncode}: {' | '.join(tail)[:300]}")
    security = [ln.strip() for ln in stdout.splitlines() if "Phase 'SECURITY'" in ln or "Phase SECURITY" in ln]
    return _record(run_dir, tool, mode, "OK", [_redact(c) for c in cmd],
                   parse_evomaster(_json(rep_path)), {"exit": res.returncode,
                                                                "security_phase": security})


def _restler_env() -> tuple[str, dict, str] | None:
    dll = os.environ.get("TSG1_RESTLER_DLL", os.path.join(TOOLS_HOME, "restler_bin/restler/Restler.dll"))
    dotnet_dir = os.environ.get("TSG1_DOTNET_DIR", "/opt/homebrew/opt/dotnet@8/bin")
    py = os.environ.get("TSG1_PYTHON", "/opt/homebrew/opt/python@3.12/bin/python3.12")
    if not (os.path.exists(dll) and os.path.exists(os.path.join(dotnet_dir, "dotnet")) and os.path.exists(py)):
        return None
    shim = tempfile.mkdtemp(prefix="restler-pyshim-")
    os.symlink(py, os.path.join(shim, "python"))       # RESTler's engine calls `python`
    env = dict(os.environ, PATH=f"{shim}:{dotnet_dir}:{os.environ['PATH']}",
               DOTNET_ROOT=os.path.join(os.path.dirname(dotnet_dir), "libexec"))
    return dll, env, py


SEEDED_IDS = ["order-1", "order-shared", "order-public"]
RESTLER_CHECKERS = "namespacerule,useafterfree,resourcehierarchy,leakagerule,invaliddynamicobject"


def run_restler(mode: str, run_dir: str) -> dict:
    found = _restler_env()
    if found is None:
        return _record(run_dir, "restler", mode, "NOT_RUN", "", [], error="RESTler/dotnet@8/python3.12 not found")
    dll, env, py = found     # --python_path: RESTler otherwise picks `python3` (3.15 on this host)
    work = tempfile.mkdtemp(prefix=f"restler-{mode}-")
    tokens = os.path.join(AUTH, f"restler_tokens_{MODES[mode]['pair']}.sh")
    proc, base = live_lab._start_target(MODES[mode]["server"])
    port = base.rsplit(":", 1)[1]
    try:
        spec = live_lab._wait_ready(base)
        _dump(spec, os.path.join(work, "openapi.json"))
        comp = subprocess.run(["dotnet", dll, "--python_path", py, "compile", "--api_spec", "openapi.json"],
                              cwd=work, env=env,
                              capture_output=True, text=True, timeout=600)
        _write(os.path.join(run_dir, "compile.txt"), comp.stdout + comp.stderr)
        d = _json(os.path.join(work, "Compile", "dict.json"))
        d["restler_fuzzable_string"] = SEEDED_IDS + ["fuzzstring"]
        _dump(d, os.path.join(run_dir, "dict_seeded.json"))
        settings = {"checkers": {"namespacerule": {"trigger_on_dynamic_objects": True,
                                                   "trigger_objects": SEEDED_IDS}}}
        _dump(settings, os.path.join(run_dir, "settings.json"))
        cmd = ["dotnet", dll, "--python_path", py, "fuzz", "--grammar_file", "Compile/grammar.py",
               "--dictionary_file", os.path.join(run_dir, "dict_seeded.json"),
               "--settings", os.path.join(run_dir, "settings.json"),
               "--target_ip", "127.0.0.1", "--target_port", port, "--no_ssl", "--time_budget", "0.05",
               "--token_refresh_interval", "300", "--token_refresh_command", f"sh {tokens}",
               "--enable_checkers", RESTLER_CHECKERS]
        res = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=7200)
    finally:
        _stop(proc)
    _write(os.path.join(run_dir, "stdout.txt"), res.stdout + res.stderr)
    exp = sorted(glob.glob(os.path.join(work, "Fuzz", "RestlerResults", "experiment*")))
    if res.returncode != 0 or not exp:
        shutil.rmtree(work, ignore_errors=True)
        return _record(run_dir, "restler", mode, "NOT_RUN", [_redact(c) for c in cmd], [],
                       error=f"exit {res.returncode}: {res.stdout.strip().splitlines()[-1:]}")
    logs, bugs = os.path.join(exp[-1], "logs"), os.path.join(exp[-1], "bug_buckets")
    for name in ("main.txt", "testing_summary.json", "request_rendering.txt"):
        if os.path.exists(os.path.join(logs, name)):
            shutil.copy(os.path.join(logs, name), os.path.join(run_dir, name))
    for log in glob.glob(os.path.join(logs, "NameSpaceRuleChecker.*.txt")):
        with open(log, "rb") as src, gzip.open(os.path.join(run_dir, "NameSpaceRuleChecker.txt.gz"), "wb") as dst:
            shutil.copyfileobj(src, dst)
    if os.path.isdir(bugs):
        shutil.copytree(bugs, os.path.join(run_dir, "bug_buckets"), dirs_exist_ok=True)
    findings = parse_restler(os.path.join(run_dir, "bug_buckets"))
    summary = _json(os.path.join(run_dir, "testing_summary.json"))
    shutil.rmtree(work, ignore_errors=True)
    cmd_shown = [_redact(c).replace(run_dir, ".") for c in cmd]
    return _record(run_dir, "restler", mode, "OK", cmd_shown, findings,
                   {"exit": res.returncode, "rendered_valid": summary.get("rendered_requests_valid_status"),
                    "requests_sent": summary.get("total_requests_sent")})


def _scanner_manifest(workdir: str, base: str, mutation: str, identities: list[dict],
                      resources: list[dict]) -> str:
    manifest = {
        "target": {"name": "orders", "base_url": base}, "spec": "openapi.json",
        "host_allowlist": ["127.0.0.1"], "mutation": mutation, "permitted_methods": ["PATCH", "DELETE"],
        "limits": {"max_requests": 1000, "time_budget_secs": 60, "max_concurrency": 2, "rate_limit_rps": 1000},
        "reproductions": {"read_repeats": 2, "required": 2}, "request_timeout_ms": 5000,
        "identities": identities, "resources": resources,
        "gate": {"min_confidence": "verified", "min_severity": "high"},
    }
    path = os.path.join(workdir, "manifest.json")
    _dump(manifest, path)
    return path


def _ident(name: str, role: str) -> dict:
    return {"id": name, "tenant": name.split("-")[0], "role": role,
            "credential_ref": "env:" + name.upper().replace("-", "_"), "is_public": False}


# authz-fuzzer runs for modes outside the live lab, with the same identity pairs as the baselines
SCANNER_EXTRA = {
    "silent-write": ("test_owned_only", [_ident("alpha-admin", "admin"), _ident("bravo-admin", "admin")], "alpha-admin"),
    "lying-success": ("test_owned_only", [_ident("alpha-admin", "admin"), _ident("bravo-admin", "admin")], "alpha-admin"),
    "leaky-404": ("read_only", [_ident("alpha-admin", "admin"), _ident("bravo-admin", "admin")], "alpha-admin"),
    "admin-legit": ("test_owned_only", [_ident("alpha-viewer", "viewer"), _ident("alpha-admin", "admin")], "alpha-viewer"),
}


def run_scanner(mode: str, run_dir: str) -> dict:
    """authz-fuzzer on one mode: live-lab modes use live_lab's own fixture; the rest use
    SCANNER_EXTRA (same identities as the baselines)."""
    live_lab._ensure_binaries()
    if mode in live_lab.MODES:
        cfg = live_lab.MODES[mode]
        server, mutation = cfg["server"], cfg["mutation"]
        resources = live_lab.RESOURCES[cfg.get("resources", "order-1")]
        identities = None
    else:
        mutation, identities, owner = SCANNER_EXTRA[mode]
        server = MODES[mode]["server"]
        resources = [{"instance_id": "order-1", "path_param": "id", "resource_class": "order",
                      "owner": owner, "write_body": {"status": "cancelled"}}]
    proc, base = live_lab._start_target(server)
    try:
        _dump(live_lab._wait_ready(base), os.path.join(run_dir, "openapi.json"))
        if identities is None:
            manifest = live_lab._write_manifest(run_dir, base, mutation, resources)
        else:
            manifest = _scanner_manifest(run_dir, base, mutation, identities, resources)
        env = dict(os.environ, ALPHA_ADMIN="tok-alpha-admin", BRAVO_ADMIN="tok-bravo-admin",
                   ALPHA_VIEWER="tok-alpha-viewer")
        cmd = [live_lab.SCAN_BIN, "scan", "--manifest", manifest, "--sarif", os.path.join(run_dir, "out.sarif"),
               "--json", os.path.join(run_dir, "out.json")]
        res = subprocess.run(cmd, cwd=live_lab.SCANNER_DIR, env=env, capture_output=True, text=True, timeout=300)
    finally:
        _stop(proc)
    _write(os.path.join(run_dir, "stdout.txt"), res.stdout + res.stderr)
    if not os.path.exists(os.path.join(run_dir, "out.json")):
        return _record(run_dir, "authz-fuzzer", mode, "NOT_RUN", "authz scan", [], error=res.stderr[-300:])
    report = _json(os.path.join(run_dir, "out.json"))
    return _record(run_dir, "authz-fuzzer", mode, "OK",
                   "authz scan --manifest manifest.json --sarif out.sarif --json out.json",
                   parse_scanner(report), {"exit": res.returncode, "server": server, "mutation": mutation})


RUNNERS = {"restler": run_restler, "evomaster": run_evomaster, "schemathesis": run_schemathesis,
           "authz-fuzzer": run_scanner,
           # sensitivity run, added after the pre-registered EvoMaster runs showed the SECURITY
           # phase timing out at 12 s in every mode (see RESULTS_FAIR_DIFFERENTIAL.md)
           "evomaster-sec": lambda mode, d: run_evomaster(mode, d, "evomaster-sec", "1.0")}
SCANNER_MODES = list(live_lab.MODES) + list(SCANNER_EXTRA)


def run(tools: list[str], modes: list[str]) -> None:
    for tool in tools:
        tool_modes = SCANNER_MODES if (tool == "authz-fuzzer" and modes == ["all"]) else (
            list(MODES) if modes == ["all"] else modes)
        for mode in tool_modes:
            run_dir = os.path.join(OUT, tool, mode)
            shutil.rmtree(run_dir, ignore_errors=True)
            os.makedirs(run_dir)
            started = time.time()
            try:
                r = RUNNERS[tool](mode, run_dir)
            except Exception as exc:  # recorded, never turned into a zero
                r = _record(run_dir, tool, mode, "NOT_RUN", "", [], error=f"{type(exc).__name__}: {exc}")
            r["wall_s"] = round(time.time() - started, 1)
            _dump(r, os.path.join(run_dir, "run.json"))
            n = sum(1 for f in _json(os.path.join(run_dir, "findings.json")) if f.get("cls"))
            print(f"{tool:13} {mode:30} {r['status']:7} authz-class findings={n} wall={r['wall_s']}s "
                  f"{r.get('error', '')[:120]}", flush=True)


# --- scoring (pre-registered rules) ------------------------------------------------------

def load_runs() -> dict[str, dict[str, dict]]:
    runs: dict[str, dict[str, dict]] = {}
    for path in glob.glob(os.path.join(OUT, "*", "*", "run.json")):
        r = _json(path)
        r["findings"] = _json(os.path.join(os.path.dirname(path), "findings.json"))
        runs.setdefault(r["tool"], {})[r["mode"]] = r
    return runs


def authz_findings(run: dict, tier: str = "verified") -> list[dict]:
    """Authorization-class findings; for authz-fuzzer, at the given confidence tier."""
    out = [f for f in run["findings"] if f.get("cls")]
    if run["tool"] == "authz-fuzzer":
        allowed = {"verified"} if tier == "verified" else {"verified", "probable"}
        out = [f for f in out if f.get("confidence") in allowed]
    return out


def signatures(findings: list[dict]) -> set[tuple[str, str]]:
    return {(f["category"], f["operation"]) for f in findings}


def detects(run: dict | None, control: dict | None, cls: str, ops: list[str], tier: str = "verified") -> bool | None:
    if run is None or run["status"] != "OK" or control is None or control["status"] != "OK":
        return None
    ctrl = signatures(authz_findings(control, tier))
    return any(f["cls"] == cls and f["operation"] in ops and (f["category"], f["operation"]) not in ctrl
               for f in authz_findings(run, tier))


def flagged(run: dict | None, ops: list[str], tier: str = "verified") -> list[dict] | None:
    if run is None or run["status"] != "OK":
        return None
    return [f for f in authz_findings(run, tier) if f["cls"] == "cross" and f["operation"] in ops]


def score(runs: dict[str, dict[str, dict]]) -> dict:
    result: dict = {"task3": {}, "task4": {}}
    for tool, by_mode in sorted(runs.items()):
        control = by_mode.get("none")
        recall = {flaw: detects(by_mode.get(mode), control, cls, ops)
                  for flaw, (mode, cls, ops) in FLAWS.items()}
        traps = CANDIDATE_TRAPS if tool == "authz-fuzzer" else BASELINE_TRAPS
        trap_sigs = {m: sorted(signatures(authz_findings(by_mode[m])))
                     for m in traps if m in by_mode and by_mode[m]["status"] == "OK"}
        ran = [r for r in recall.values() if r is not None]
        result["task3"][tool] = {
            "recall": recall, "k": sum(1 for r in ran if r), "n": len(ran),
            "false_findings": sum(len(v) for v in trap_sigs.values()), "trap_signatures": trap_sigs,
            "traps_run": sorted(trap_sigs), "not_run": sorted(m for m, r in by_mode.items() if r["status"] != "OK")}
        rows = {}
        for mode, (ops, should, verdict) in ROWS.items():
            cell = {}
            for tier in (["verified", "probable"] if tool == "authz-fuzzer" else ["verified"]):
                hits = flagged(by_mode.get(mode), ops, tier)
                if hits is None:
                    cell[tier] = {"verdict": "NOT_RUN"}
                    continue
                ctrl = flagged(control, ops, tier) or []
                ctrl_sigs = signatures(ctrl)
                attributable = [f for f in hits if (f["category"], f["operation"]) not in ctrl_sigs]
                is_flagged = bool(attributable) if should else bool(hits)
                cell[tier] = {"flagged": is_flagged, "correct": is_flagged == should,
                              "findings": sorted(signatures(hits)),
                              "also_in_control": sorted(signatures(hits) & ctrl_sigs)}
            rows[mode] = cell
        result["task4"][tool] = rows
    return result


TOOL_ORDER = ["authz-fuzzer", "restler", "evomaster", "schemathesis", "evomaster-sec"]
VERSIONS = {"authz-fuzzer": "authz-fuzzer branch fair-differential (debug build)",
            "restler": "RESTler source @6d984de (.NET 8.0.131)", "evomaster": "EvoMaster 6.2.0",
            "evomaster-sec": "EvoMaster 6.2.0 (sensitivity: security-phase budget 100%)",
            "schemathesis": "Schemathesis 4.32.0"}
CONFIGS = {"authz-fuzzer": "<tool>/<mode>/manifest.json",
           "restler": "auth/restler_tokens_<pair>.sh, restler/<mode>/settings.json, dict_seeded.json",
           "evomaster": "evomaster/<mode>/em.yaml (= auth/wfc_<pair>.yaml)",
           "evomaster-sec": "evomaster-sec/<mode>/em.yaml",
           "schemathesis": "schemathesis/<mode>/schemathesis.toml (+ auth/wfc_<pair>.yaml)"}


def _tools(runs: dict) -> list[str]:
    return [t for t in TOOL_ORDER if t in runs]


def write_reports(runs: dict, result: dict) -> None:
    t3, t4 = result["task3"], result["task4"]
    lines = ["# Fair differential — authz flaw recall with two identities (Task 3)", "",
             "Generated by `python3 lab/fair_differential.py report` from the committed raw runs in this "
             "folder; scoring rules are pre-registered in `worklogs/09-fair-differential-prereg.md`. "
             "A flaw counts as detected only if the tool reports a finding of the relevant class on the "
             "flaw's operations whose signature is absent from the same tool's run on the hardened "
             "server (`none`). False findings = distinct authorization-finding signatures on the trap runs.",
             "", "| Tool | Version | Config | Authz-flaw recall (k/N) | False findings on traps | Exact command (mode `none`) |",
             "|---|---|---|---|---|---|"]
    for tool in _tools(runs):
        s = t3[tool]
        cmd = runs[tool].get("none", {}).get("command", "") or "—"
        recall = f"{s['k']}/{s['n']}" if s["n"] == 4 else (f"{s['k']}/{s['n']} (of 4 run)" if s["n"] else "NOT_RUN")
        traps = ", ".join(s["traps_run"])
        lines.append(f"| {tool} | {VERSIONS.get(tool, '')} | `{CONFIGS.get(tool, '')}` | **{recall}** | "
                     f"{s['false_findings']} (traps: {traps}) | `{cmd}` |")
    lines += ["", "## Per flaw", "", "| Flaw (server mode) | " + " | ".join(_tools(runs)) + " |",
              "|---|" + "---|" * len(_tools(runs))]
    for flaw, (mode, cls, ops) in FLAWS.items():
        cells = []
        for tool in _tools(runs):
            v = t3[tool]["recall"][flaw]
            cells.append("NOT_RUN" if v is None else ("detected" if v else "missed"))
        lines.append(f"| {flaw} (`{mode}`) | " + " | ".join(cells) + " |")
    lines += ["", "## Trap-run authorization findings (false findings)", ""]
    for tool in _tools(runs):
        for mode, sigs in t3[tool]["trap_signatures"].items():
            for cat, op in sigs:
                lines.append(f"- {tool} / `{mode}`: `{cat}` on `{op}`")
    if not any(t3[t]["trap_signatures"].get(m) for t in _tools(runs) for m in t3[t]["trap_signatures"]):
        lines.append("- none")
    lines += ["", "## Runs that did not complete", ""]
    nr = [(t, m, r["error"]) for t in _tools(runs) for m, r in runs[t].items() if r["status"] != "OK"]
    lines += [f"- {t} / `{m}`: NOT_RUN — {e}" for t, m, e in nr] or ["- none"]
    _write(os.path.join(OUT, "report.md"), "\n".join(lines) + "\n")

    sv = ["# Status vs effect (Task 4)", "",
          "Generated by `python3 lab/fair_differential.py report`. Each cell is backed by "
          "`<tool>/<row>/` (raw output, `findings.json`, `run.json`). *Flagged* = the tool reported a "
          "cross-identity authorization finding on the row's operations (pre-registered). authz-fuzzer "
          "is scored at its Verified tier; its Probable-tier verdict is shown in brackets.", "",
          "| Row | Correct verdict | " + " | ".join(_tools(runs)) + " |", "|---|---|" + "---|" * len(_tools(runs))]
    for row, (ops, should, verdict) in ROWS.items():
        cells = []
        for tool in _tools(runs):
            cell = t4[tool][row]
            v = cell["verified"]
            if v.get("verdict") == "NOT_RUN":
                cells.append("NOT_RUN")
                continue
            txt = ("✅ " if v["correct"] else "❌ ") + ("flagged" if v["flagged"] else "not flagged")
            if v.get("also_in_control"):
                txt += " (same finding on hardened)"
            if "probable" in cell:
                p = cell["probable"]
                txt += f" [probable tier: {'✅' if p['correct'] else '❌'} {'flagged' if p['flagged'] else 'not flagged'}]"
            cells.append(txt)
        sv.append(f"| `{row}` | {verdict} | " + " | ".join(cells) + " |")
    sv += ["", "Correct per tool (Verified tier for authz-fuzzer):", ""]
    for tool in _tools(runs):
        cells = [t4[tool][r]["verified"] for r in ROWS]
        run_cells = [c for c in cells if c.get("verdict") != "NOT_RUN"]
        sv.append(f"- {tool}: {sum(1 for c in run_cells if c['correct'])}/{len(run_cells)} rows correct")
    sv += ["", "Findings behind each flagged cell:", ""]
    for tool in _tools(runs):
        for row in ROWS:
            for tier, c in t4[tool][row].items():
                for cat, op in c.get("findings", []):
                    sv.append(f"- {tool} / `{row}` ({tier}): `{cat}` on `{op}`")
    _write(os.path.join(OUT, "status-vs-effect.md"), "\n".join(sv) + "\n")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--tools", default="authz-fuzzer,schemathesis,evomaster,restler")
    r.add_argument("--modes", default="all")
    sub.add_parser("score")
    sub.add_parser("report")
    args = p.parse_args()
    if args.cmd == "run":
        run(args.tools.split(","), args.modes.split(","))
        return
    runs = load_runs()
    result = score(runs)
    _dump(result, os.path.join(OUT, "scores.json"))
    if args.cmd == "report":
        write_reports(runs, result)
    print(json.dumps({t: {k: v for k, v in s.items() if k != "trap_signatures"}
                      for t, s in result["task3"].items()}, indent=1, default=str))


if __name__ == "__main__":
    main()
