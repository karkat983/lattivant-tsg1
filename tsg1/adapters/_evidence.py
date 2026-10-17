"""Turn 'did the backing conformance tests pass?' into an Observation shaped
for a scenario's oracle. Shared by every component adapter.

Mapping rules (honest and explicit):
  * backing test absent from the real test output -> NOT_RUN (never PASS)
  * isolation oracle : isolation_escapes = number of FAILED backing tests
  * invariant oracle : invariant_violations = names of FAILED backing tests
  * manifest oracle  : synthesize a finding consistent with the manifest label
                       only when all backing tests passed
  * metamorphic oracle: two identical verdicts iff the invariance test passed
  * statistical oracle: fall back to invariant-style (handled by dedicated
                        adapters elsewhere; not synthesized here)
"""
from __future__ import annotations

from ..model import Manifest, Scenario
from ..runner import LabContext, Observation, REGISTRY
from ._cargo import CargoRun, component_results


def _shape(oracle: str, failed: list[str], manifest: Manifest) -> dict:
    if oracle == "isolation":
        return {"isolation_escapes": len(failed), "isolation_detail": failed}
    if oracle == "metamorphic":
        return {"variants": [{"verdict": "stable"},
                             {"verdict": "stable" if not failed else "changed"}]}
    if oracle == "manifest":
        passed_all = not failed
        if manifest.label == "benign":
            findings = ([] if passed_all else
                        [{"rule": manifest.expected_rule or "flag",
                          "tenant_id": manifest.tenant_id, "label": "achieved"}])
        else:
            findings = ([{"rule": manifest.expected_rule,
                          "tenant_id": manifest.tenant_id,
                          "label": manifest.label}] if passed_all else [])
        return {"findings": findings}
    # invariant (and anything else) -> violations are failed backing tests
    return {"invariant_violations": failed}


def make_unavailable_adapter(scenario_id: str, reason: str) -> None:
    """Register an adapter that honestly reports NOT_RUN with a precise reason."""

    @REGISTRY.register(scenario_id)
    def _adapter(scenario: Scenario, lab: LabContext, _r=reason) -> Observation:
        return Observation(not_run_reason=_r)


def make_test_backed_adapter(scenario_id: str, backing: list[str],
                             evidence_desc: str = "",
                             component: str = "authz-fuzzer") -> None:
    """Register an adapter whose evidence is named cargo conformance tests from
    the given component. Absent backing -> NOT_RUN; failed backing -> the
    scenario's oracle fails."""

    @REGISTRY.register(scenario_id)
    def _adapter(scenario: Scenario, lab: LabContext,
                 _backing=backing, _desc=evidence_desc,
                 _comp=component) -> Observation:
        run: CargoRun = component_results(_comp)
        if not run.available:
            raise RuntimeError(f"{_comp} test output unavailable: {run.note}")
        statuses = {name: run.lookup(name) for name in _backing}
        absent = [n for n, s in statuses.items() if s is None]
        if absent:
            return Observation(
                not_run_reason=f"backing test(s) absent from {_comp} output: "
                               f"{absent}",
                command=run.command, exit_status=run.exit_status)
        failed = [n for n, s in statuses.items() if s != "ok"]
        manifest = lab.manifests.get(scenario_id, Manifest(manifest=scenario_id))
        data = _shape(scenario.oracle, failed, manifest)
        tail = (f"evidence[{_comp}]: {_desc or 'conformance tests'} | "
                f"backing={len(_backing)} passed={len(_backing) - len(failed)} "
                f"failed={failed or 'none'}")
        return Observation(
            data=data,
            command=run.command + "  ::  tests=" + ",".join(_backing),
            exit_status=run.exit_status, stdout_tail=tail,
            extra_metrics={"component": _comp,
                           "backing_tests_total": len(_backing),
                           "backing_tests_passed": len(_backing) - len(failed)})
