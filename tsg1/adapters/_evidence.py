"""Turn 'did the backing conformance tests pass?' into an Observation shaped
for a scenario's oracle. Shared by the authz-fuzzer and platform adapters.

Mapping rules (honest and explicit):
  * backing test absent from the real test output -> NOT_RUN (never PASS)
  * isolation oracle : isolation_escapes = number of FAILED backing tests
  * invariant oracle : invariant_violations = names of FAILED backing tests
  * manifest oracle  : synthesize a finding consistent with the manifest label
                       only when all backing tests passed
  * metamorphic oracle: two identical verdicts iff the invariance test passed
"""
from __future__ import annotations

from typing import Callable

from ..model import Manifest, Scenario
from ..runner import LabContext, Observation, REGISTRY
from ._scanner import ScannerRun, scanner_results


def _shape(oracle: str, failed: list[str], manifest: Manifest) -> dict:
    if oracle == "isolation":
        return {"isolation_escapes": len(failed), "isolation_detail": failed}
    if oracle == "invariant":
        return {"invariant_violations": failed}
    if oracle == "metamorphic":
        return {"variants": [{"verdict": "stable"},
                             {"verdict": "stable" if not failed else "changed"}]}
    if oracle == "manifest":
        passed_all = not failed
        if manifest.label == "benign":
            # benign/FP-trap: a FAILED control would mean a false finding
            findings = ([] if passed_all else
                        [{"rule": manifest.expected_rule or "BOLA",
                          "tenant_id": manifest.tenant_id, "label": "achieved"}])
        else:
            findings = ([{"rule": manifest.expected_rule,
                          "tenant_id": manifest.tenant_id,
                          "label": manifest.label}] if passed_all else [])
        return {"findings": findings}
    # statistical / differential are handled by dedicated adapters, not here
    return {"invariant_violations": failed}


def make_unavailable_adapter(scenario_id: str, reason: str) -> None:
    """Register an adapter that honestly reports NOT_RUN with a precise reason
    (e.g. a baseline tool or unbuilt component is required). Better than a
    generic 'no adapter', and it can never be mistaken for a pass.
    """

    @REGISTRY.register(scenario_id)
    def _adapter(scenario: Scenario, lab: LabContext, _r=reason) -> Observation:
        return Observation(not_run_reason=_r)


def make_test_backed_adapter(scenario_id: str, backing: list[str],
                             evidence_desc: str = "") -> None:
    """Register an adapter whose evidence is named scanner conformance tests."""

    @REGISTRY.register(scenario_id)
    def _adapter(scenario: Scenario, lab: LabContext,
                 _backing=backing, _desc=evidence_desc) -> Observation:
        run: ScannerRun = scanner_results()
        if not run.available:
            raise RuntimeError(
                f"authz-fuzzer scanner test output unavailable: {run.note}")
        statuses = {name: run.lookup(name) for name in _backing}
        absent = [n for n, s in statuses.items() if s is None]
        if absent:
            return Observation(
                not_run_reason=f"backing test(s) absent from scanner output: "
                               f"{absent}",
                command=run.command, exit_status=run.exit_status)
        failed = [n for n, s in statuses.items() if s != "ok"]
        manifest = lab.manifests.get(scenario_id, Manifest(manifest=scenario_id))
        data = _shape(scenario.oracle, failed, manifest)
        tail = (f"evidence: {_desc or 'scanner conformance tests'} | "
                f"backing={len(_backing)} passed={len(_backing) - len(failed)} "
                f"failed={failed or 'none'}")
        return Observation(
            data=data,
            command=run.command + "  ::  tests=" + ",".join(_backing),
            exit_status=run.exit_status,
            stdout_tail=tail,
            extra_metrics={"backing_tests_total": len(_backing),
                           "backing_tests_passed": len(_backing) - len(failed)})
