"""Adapters bridge TSG-1 scenarios to the real Lattivant components.

Importing this package registers every adapter on the global REGISTRY. Each
adapter runs a real check against a built component and returns a normalized
Observation the oracle can score. Adapters never fabricate: when a component is
unavailable they raise, so the scenario is reported as ERROR, not PASS.

Submodules are imported for their registration side effects.
"""
from __future__ import annotations

import json
import os

from ..model import Manifest

_MANIFEST_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "manifests"))


def load_manifests() -> dict[str, Manifest]:
    """Load every ground-truth manifest JSON under manifests/."""
    out: dict[str, Manifest] = {}
    if not os.path.isdir(_MANIFEST_DIR):
        return out
    for fn in sorted(os.listdir(_MANIFEST_DIR)):
        if fn.endswith(".json"):
            with open(os.path.join(_MANIFEST_DIR, fn), encoding="utf-8") as fh:
                d = json.load(fh)
            out[d.get("manifest", fn[:-5])] = Manifest.from_json(d)
    return out


# import adapter submodules for their @REGISTRY.register side effects
from . import authz_fuzzer      # noqa: E402,F401
from . import platform_rls      # noqa: E402,F401
from . import research_validity  # noqa: E402,F401
from . import scale_chaos       # noqa: E402,F401
# component mappings last so genuine test-backed adapters win over any
# earlier make_unavailable registration for the same scenario id
from . import _mappings         # noqa: E402,F401
from . import stat_rv           # noqa: E402,F401
