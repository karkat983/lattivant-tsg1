"""TSG-1 harness: executable test suite for the Lattivant detection platform.

Implements the orchestration design of the Vigilattice Adversarial Test-Suite
Guide (TSG-1): a scenario catalog, a scenario DSL, ground-truth manifests, six
oracle types, a runner that honestly skips SPEC-blocked scenarios, and a report
generator that distinguishes measured results from skipped/not-run.

Dependency-free (stdlib only), deterministic, offline by default.
"""

__version__ = "0.1.0"
