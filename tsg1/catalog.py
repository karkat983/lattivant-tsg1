"""Load and filter the scenario registry (catalog/scenarios.jsonl)."""
from __future__ import annotations

import json
import os
from typing import Iterable

from .model import Scenario

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT = os.path.normpath(os.path.join(_HERE, "..", "catalog", "scenarios.jsonl"))


def load_catalog(path: str = _DEFAULT) -> list[Scenario]:
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"catalog not found at {path}; run `python catalog/build_catalog.py`")
    out: list[Scenario] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Scenario.from_json(json.loads(line)))
    return out


def filter_scenarios(scenarios: Iterable[Scenario], *,
                     ids: list[str] | None = None,
                     component: str | None = None,
                     build_status: str | None = None,
                     severity: str | None = None,
                     run_first: bool | None = None,
                     ci_tier: str | None = None) -> list[Scenario]:
    out = []
    idset = set(ids) if ids else None
    for s in scenarios:
        if idset is not None and s.id not in idset:
            continue
        if component and s.component != component:
            continue
        if build_status and s.build_status != build_status:
            continue
        if severity and s.severity != severity:
            continue
        if run_first is not None and s.run_first != run_first:
            continue
        if ci_tier and s.ci_tier != ci_tier:
            continue
        out.append(s)
    return out
