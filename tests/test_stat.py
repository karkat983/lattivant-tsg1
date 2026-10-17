"""Self-tests for the statistical experiments (no network, no scans).

Checks arm construction and that the committed experiment, when present, is
significant under the statistical oracle — using the recorded real trials.
"""
import os
import unittest

from lab.stat_experiments import arms
from tsg1.model import Manifest
from tsg1.oracles import ORACLES

_RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "reports", "stat", "results.json")


def _trial(kind, verified, deduped, repeats):
    return {"kind": kind, "repeats": repeats, "verified": verified,
            "deduped_total": deduped, "raw_total": deduped * repeats,
            "scanner_correct": 1,
            "baseline_correct": 1 if kind in ("achieved-read", "clean") else 0,
            "naive_correct": 1 if kind != "attempted-blocked" else 0,
            "corrected_correct": 1}


class ArmTests(unittest.TestCase):
    def test_arms_shapes(self):
        trials = [_trial("achieved-write", 1, 1, 3) for _ in range(5)]
        a = arms(trials)
        self.assertEqual(set(a), {"RV-018", "RV-020", "RV-021"})
        for arm_a, arm_b in a.values():
            self.assertEqual(len(arm_a), 5)
            self.assertEqual(len(arm_b), 5)

    def test_rv021_raw_is_deduped_times_repeats(self):
        trials = [_trial("achieved-write", 1, 2, 4)]
        a_arm, b_arm = arms(trials)["RV-021"]
        self.assertEqual(a_arm[0], 2.0)
        self.assertEqual(b_arm[0], 8.0)


@unittest.skipUnless(os.path.exists(_RESULTS), "no committed stat experiment")
class CommittedExperimentTests(unittest.TestCase):
    def test_all_three_significant_via_oracle(self):
        import json
        trials = json.load(open(_RESULTS))["trials"]
        self.assertGreaterEqual(len(trials), 20)
        a = arms(trials)
        for sid, (arm_a, arm_b) in a.items():
            obs = {"trials_a": arm_a, "trials_b": arm_b,
                   "min_seeds": 20, "alpha": 0.05}
            v = ORACLES["statistical"](obs, Manifest(manifest=sid))
            self.assertTrue(v.passed, f"{sid} not significant: {v.reason}")


if __name__ == "__main__":
    unittest.main()
