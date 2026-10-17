"""Self-tests for the differential scoring/classification (no network).

Asserts the authz-category classifier and the differential oracle behave
correctly, without running Schemathesis or any server.
"""
import unittest

from lab.differential import (GROUND_TRUTH, _classify_authz,
                              _normalize_spec_for_restler)
from tsg1.model import Manifest
from tsg1.oracles import ORACLES


class ClassifyTests(unittest.TestCase):
    def test_conformance_category_is_not_authz(self):
        self.assertFalse(_classify_authz({"Undocumented HTTP status code": "5"}))
        self.assertFalse(_classify_authz({"Server error": "2"}))

    def test_authz_category_is_detected(self):
        self.assertTrue(_classify_authz({"Authorization bypass": "1"}))
        self.assertTrue(_classify_authz({"Cross-tenant access": "1"}))

    def test_evomaster_fault_codes_are_not_authz(self):
        # Fault301 (XSS) and Fault109 (HTTP violation) are robustness, not authz
        self.assertFalse(_classify_authz({"Fault301": 1, "Fault109": 1}))


class RestlerSpecNormalizationTests(unittest.TestCase):
    def test_injects_missing_responses_per_operation(self):
        spec = {"paths": {"/orders/{id}": {
            "get": {"operationId": "getOrder"},
            "delete": {"operationId": "deleteOrder", "responses": {"204": {}}},
        }}}
        out = _normalize_spec_for_restler(spec)
        self.assertIn("responses", out["paths"]["/orders/{id}"]["get"])
        # an existing responses block is left untouched
        self.assertEqual(out["paths"]["/orders/{id}"]["delete"]["responses"],
                         {"204": {}})


class DifferentialOracleTests(unittest.TestCase):
    def _score(self, candidate, baseline_found):
        obs = {"candidate_found": candidate, "baseline_found": baseline_found}
        return ORACLES["differential"](obs, Manifest(manifest="AZ-046"))

    def test_candidate_superset_of_baselines_passes(self):
        v = self._score(sorted(GROUND_TRUTH),
                        {"schemathesis": [], "restler": []})
        self.assertTrue(v.passed)

    def test_candidate_missing_a_baseline_find_fails(self):
        v = self._score(["xtenant-read"],
                        {"schemathesis": ["xtenant-write"]})
        self.assertFalse(v.passed)
        self.assertIn("xtenant-write", v.evidence["candidate_missed"])


if __name__ == "__main__":
    unittest.main()
