"""Self-tests for the live-lab scoring logic (no network, no cargo).

Feeds synthetic scanner JSON reports to _observation_for + the oracles and
asserts the ground-truth mapping is correct, including that a benign (none)
report with any verified finding fails.
"""
import unittest

from lab.live_lab import MODES, _observation_for
from tsg1.model import Manifest
from tsg1.oracles import ORACLES


def _score(mode, report):
    cfg = MODES[mode]
    obs, metrics = _observation_for(cfg, report)
    gt = Manifest(manifest=cfg["scenario"], expected_rule=cfg["expect_rule"],
                  label=cfg["label"], tenant_id="alpha")
    return ORACLES[cfg["oracle"]](obs, gt), metrics


def _f(method, violation, is_write, conf="verified"):
    return {"operation": {"method": method, "normalized_path": "/orders/{}"},
            "violation": violation, "is_write": is_write, "confidence": conf,
            "tenant": "alpha"}


class LiveLabScoring(unittest.TestCase):
    def test_none_clean_passes(self):
        v, m = _score("none", {"total": 0, "findings": []})
        self.assertTrue(v.passed)
        self.assertEqual(m["verified"], 0)

    def test_none_with_finding_fails(self):
        v, _ = _score("none", {"findings": [_f("GET", "cross_tenant_access", False)]})
        self.assertFalse(v.passed)

    def test_bola_read_detected_passes(self):
        v, _ = _score("bola-read",
                      {"findings": [_f("GET", "cross_tenant_access", False)]})
        self.assertTrue(v.passed)

    def test_bola_read_missed_fails(self):
        v, _ = _score("bola-read", {"findings": []})
        self.assertFalse(v.passed)  # isolation escape

    def test_bola_write_detected_passes(self):
        v, _ = _score("bola-write",
                      {"findings": [_f("PATCH", "cross_tenant_access", True)]})
        self.assertTrue(v.passed)

    def test_missing_auth_label_match(self):
        v, _ = _score("missing-auth",
                      {"findings": [_f("GET", "missing_authentication", False)]})
        self.assertTrue(v.passed)

    def test_readonly_scope_write_finding_fails_invariant(self):
        v, _ = _score("readonly-scope-vs-write-vuln",
                      {"findings": [_f("PATCH", "cross_tenant_access", True)]})
        self.assertFalse(v.passed)  # a write slipped past read-only scope

    def test_readonly_scope_no_write_passes(self):
        v, _ = _score("readonly-scope-vs-write-vuln", {"findings": []})
        self.assertTrue(v.passed)


if __name__ == "__main__":
    unittest.main()
