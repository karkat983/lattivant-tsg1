"""Self-tests for the TSG-1 harness (stdlib unittest, no external deps).

    python -m unittest discover -s tests

These test the harness logic itself — not the Lattivant components — so they
run anywhere, offline, without cargo. They assert the honesty guarantees:
SPEC-blocked -> SKIPPED, missing backing -> NOT_RUN, only real observations
score PASS/FAIL, and the stats are correct.
"""
import unittest

from tsg1.catalog import load_catalog
from tsg1.model import Manifest, Outcome, Scenario
from tsg1.oracles import ORACLES
from tsg1.runner import LabContext, Observation, AdapterRegistry, run_scenario
from tsg1.stats import (ConfusionMatrix, mann_whitney_u, tpr_at_fixed_fpr,
                        wilson_interval)


class StatsTests(unittest.TestCase):
    def test_wilson_zero_denominator_is_undefined(self):
        w = wilson_interval(0, 0)
        self.assertEqual(w.n, 0)
        self.assertIn("undefined", w.note)

    def test_confusion_rates_and_kappa(self):
        cm = ConfusionMatrix(tp=9, fp=0, fn=1, tn=100)
        self.assertAlmostEqual(cm.tpr(), 0.9)
        self.assertEqual(cm.fpr(), 0.0)
        self.assertAlmostEqual(cm.false_reject_rate(), 0.1)
        self.assertIsNotNone(cm.cohen_kappa())

    def test_mann_whitney_separates(self):
        mw = mann_whitney_u(list(range(10)), list(range(100, 110)))
        self.assertLess(mw.p_two_sided, 0.05)
        self.assertEqual(mw.effect_size_rank_biserial, 1.0)

    def test_tpr_at_fixed_fpr_picks_operating_point(self):
        res = tpr_at_fixed_fpr([0.9, 0.95], [0.1, 0.2], 0.01)
        self.assertEqual(res["tpr"], 1.0)
        self.assertEqual(res["achieved_fpr"], 0.0)


class CatalogTests(unittest.TestCase):
    def test_catalog_loads_all_326_unique(self):
        cat = load_catalog()
        self.assertEqual(len(cat), 326)
        self.assertEqual(len({s.id for s in cat}), 326)

    def test_run_first_is_40(self):
        cat = load_catalog()
        self.assertEqual(sum(1 for s in cat if s.run_first), 40)


class RunnerHonestyTests(unittest.TestCase):
    def _scn(self, **kw):
        base = dict(id="X-001", title="t", test_classes=["ii"],
                    build_status="built", component="c", oracle="invariant",
                    metric="m", severity="S1", reference="r")
        base.update(kw)
        return Scenario(**base)

    def test_spec_blocked_is_skipped_not_pass(self):
        reg = AdapterRegistry()
        scn = self._scn(build_status="spec", spec_blockers=["evidence_graph"])
        r = run_scenario(scn, LabContext(capabilities=set()), reg)
        self.assertEqual(r.outcome, Outcome.SKIPPED.value)
        self.assertIn("evidence_graph", r.reason)

    def test_built_without_adapter_is_not_run(self):
        reg = AdapterRegistry()
        r = run_scenario(self._scn(), LabContext(), reg)
        self.assertEqual(r.outcome, Outcome.NOT_RUN.value)

    def test_adapter_not_run_reason_wins(self):
        reg = AdapterRegistry()

        @reg.register("X-001")
        def _a(s, lab):
            return Observation(not_run_reason="baseline tool absent")
        r = run_scenario(self._scn(), LabContext(), reg)
        self.assertEqual(r.outcome, Outcome.NOT_RUN.value)
        self.assertIn("baseline", r.reason)

    def test_real_observation_scores_pass(self):
        reg = AdapterRegistry()

        @reg.register("X-001")
        def _a(s, lab):
            return Observation(data={"invariant_violations": []})
        r = run_scenario(self._scn(), LabContext(), reg)
        self.assertEqual(r.outcome, Outcome.PASS.value)
        self.assertTrue(r.replay_ref.startswith("sha256:"))

    def test_real_observation_scores_fail(self):
        reg = AdapterRegistry()

        @reg.register("X-001")
        def _a(s, lab):
            return Observation(data={"invariant_violations": ["broke"]})
        r = run_scenario(self._scn(), LabContext(), reg)
        self.assertEqual(r.outcome, Outcome.FAIL.value)

    def test_adapter_exception_is_error_not_pass(self):
        reg = AdapterRegistry()

        @reg.register("X-001")
        def _a(s, lab):
            raise RuntimeError("component unavailable")
        r = run_scenario(self._scn(), LabContext(), reg)
        self.assertEqual(r.outcome, Outcome.ERROR.value)


class OracleTests(unittest.TestCase):
    def test_isolation_escape_fails(self):
        v = ORACLES["isolation"]({"isolation_escapes": 1}, Manifest(manifest="x"))
        self.assertFalse(v.passed)

    def test_statistical_gate_fails_closed_below_min_seeds(self):
        v = ORACLES["statistical"]({"trials_a": [1, 2], "trials_b": [3, 4]},
                                   Manifest(manifest="x"))
        self.assertFalse(v.passed)
        self.assertIn("insufficient", v.reason)


if __name__ == "__main__":
    unittest.main()
