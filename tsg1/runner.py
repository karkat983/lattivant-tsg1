"""Scenario runner (TSG-1 C.6).

Honest execution model:
  * A scenario is RUNNABLE only if every one of its spec_blockers is present in
    the lab's available capabilities AND an adapter is registered for it.
  * SPEC/partial scenarios whose blockers are absent return SKIPPED with the
    exact missing capability — never PASS.
  * BUILT scenarios with no adapter return NOT_RUN ("no adapter") — we do not
    pretend to have measured them.
  * Only a registered adapter that actually produced an observation yields
    PASS/FAIL, scored by the scenario's oracle.

Adapters are registered by scenario id. Each returns an Observation: the
normalized dict the oracles consume, plus optional command / exit_status /
replay evidence recorded verbatim into the Result.
"""
from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from .model import Manifest, Outcome, Result, Scenario, digest
from .oracles import ORACLES


@dataclass
class Observation:
    data: dict[str, Any] = field(default_factory=dict)   # fed to the oracle
    command: str = ""
    exit_status: int | None = None
    stdout_tail: str = ""
    extra_metrics: dict[str, Any] = field(default_factory=dict)
    # set when the scenario cannot honestly be scored (e.g. backing test or
    # baseline tool absent). The runner returns NOT_RUN, never PASS/FAIL.
    not_run_reason: str = ""


Adapter = Callable[[Scenario, "LabContext"], Observation]


@dataclass
class LabContext:
    """What the lab can actually do right now.

    capabilities: capability names that are BUILT and available. A scenario's
    spec_blockers must all be in here for it to run. Built scenarios have empty
    blockers and need only an adapter.
    """
    capabilities: set[str] = field(default_factory=set)
    config: dict[str, Any] = field(default_factory=dict)
    manifests: dict[str, Manifest] = field(default_factory=dict)


class AdapterRegistry:
    def __init__(self) -> None:
        self._by_id: dict[str, Adapter] = {}

    def register(self, scenario_id: str) -> Callable[[Adapter], Adapter]:
        def deco(fn: Adapter) -> Adapter:
            self._by_id[scenario_id] = fn
            return fn
        return deco

    def get(self, scenario_id: str) -> Adapter | None:
        return self._by_id.get(scenario_id)

    @property
    def ids(self) -> set[str]:
        return set(self._by_id)


REGISTRY = AdapterRegistry()


def _missing_blockers(scenario: Scenario, lab: LabContext) -> list[str]:
    return [b for b in scenario.spec_blockers if b not in lab.capabilities]


def run_scenario(scenario: Scenario, lab: LabContext,
                 registry: AdapterRegistry = REGISTRY) -> Result:
    t0 = time.time()
    base = dict(id=scenario.id, severity=scenario.severity, oracle=scenario.oracle)

    missing = _missing_blockers(scenario, lab)
    adapter = registry.get(scenario.id)

    # SPEC / partial scenario whose dependencies are not built -> honest skip
    if missing:
        return Result(outcome=Outcome.SKIPPED.value,
                      reason=f"spec-blocked: needs {missing}",
                      duration_s=round(time.time() - t0, 4), **base)

    if adapter is None:
        reason = ("no adapter wired yet" if scenario.build_status == "built"
                  else "runnable but no adapter wired yet")
        return Result(outcome=Outcome.NOT_RUN.value, reason=reason,
                      duration_s=round(time.time() - t0, 4), **base)

    manifest = lab.manifests.get(scenario.id, Manifest(manifest=scenario.id))
    try:
        obs = adapter(scenario, lab)
    except Exception as exc:  # harness error, reported truthfully
        return Result(outcome=Outcome.ERROR.value,
                      reason=f"{type(exc).__name__}: {exc}",
                      evidence={"traceback": traceback.format_exc()[-2000:]},
                      duration_s=round(time.time() - t0, 4), **base)

    if obs.not_run_reason:
        return Result(outcome=Outcome.NOT_RUN.value, reason=obs.not_run_reason,
                      command=obs.command, exit_status=obs.exit_status,
                      duration_s=round(time.time() - t0, 4), **base)

    oracle_fn = ORACLES.get(scenario.oracle)
    if oracle_fn is None:
        return Result(outcome=Outcome.ERROR.value,
                      reason=f"unknown oracle '{scenario.oracle}'",
                      duration_s=round(time.time() - t0, 4), **base)

    verdict = oracle_fn(obs.data, manifest)
    metrics = dict(verdict.metrics)
    metrics.update(obs.extra_metrics)
    return Result(
        outcome=(Outcome.PASS.value if verdict.passed else Outcome.FAIL.value),
        reason=verdict.reason,
        metrics=metrics,
        evidence={**verdict.evidence,
                  **({"stdout_tail": obs.stdout_tail} if obs.stdout_tail else {})},
        command=obs.command,
        exit_status=obs.exit_status,
        replay_ref=digest({"obs": obs.data, "manifest": manifest.__dict__}),
        duration_s=round(time.time() - t0, 4),
        **base,
    )


def run_many(scenarios: list[Scenario], lab: LabContext,
             registry: AdapterRegistry = REGISTRY) -> list[Result]:
    return [run_scenario(s, lab, registry) for s in scenarios]
