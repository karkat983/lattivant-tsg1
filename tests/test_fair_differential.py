"""No-network tests for the fair differential's parsers and pre-registered scoring."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import fair_differential as fd  # noqa: E402


def run(tool, mode, findings, status="OK"):
    return {"tool": tool, "mode": mode, "status": status, "findings": findings}


def f(category, cls, op, **kw):
    return {"category": category, "cls": cls, "operation": op, **kw}


class Parsers(unittest.TestCase):
    def test_normalize_op(self):
        self.assertEqual(fd.normalize_op("patch", "/orders/order-7"), "PATCH /orders/{id}")
        self.assertEqual(fd.normalize_op("DELETE", "/orders/{}"), "DELETE /orders/{id}")
        self.assertEqual(fd.normalize_op("POST", "/orders"), "POST /orders")

    def test_evomaster_codes_map_to_classes(self):
        report = {"faults": {"foundFaults": [
            {"operationId": "PATCH:/orders/{id}", "faultCategories": [{"code": 306}, {"code": 301}]},
            {"operationId": "GET:/orders/{id}", "faultCategories": [{"code": 307}]}]}}
        got = {(x["category"], x["cls"], x["operation"]) for x in fd.parse_evomaster(report)}
        self.assertIn(("306:SECURITY_WRONG_AUTHORIZATION", "cross", "PATCH /orders/{id}"), got)
        self.assertIn(("301:SECURITY_XSS", None, "PATCH /orders/{id}"), got)
        self.assertIn(("307:SECURITY_IGNORE_ANONYMOUS", "unauth", "GET /orders/{id}"), got)

    def test_schemathesis_failures_map_to_classes(self):
        report = {"failures": [
            {"type": "IgnoredAuth", "code": "ST401", "title": "API accepts requests without authentication",
             "operations": ["GET /orders/{id}"]},
            {"type": "ObjectLevelAuthorizationViolation", "code": "ST4xx", "title": "BOLA",
             "operations": ["GET /orders/{id}"]},
            {"type": "AcceptedNegativeData", "code": "ST201", "title": "x", "operations": ["POST /orders"]}]}
        got = {(x["cls"], x["operation"]) for x in fd.parse_schemathesis(report)}
        self.assertEqual(got, {("unauth", "GET /orders/{id}"), ("cross", "GET /orders/{id}"), (None, "POST /orders")})

    def test_restler_buckets_only_namespacerule_is_authz(self):
        with tempfile.TemporaryDirectory() as d:
            json.dump({"bugs": [{"filepath": "a.json", "checker_name": "NameSpaceRuleChecker", "error_code": "20x",
                                 "reproducible": False},
                                {"filepath": "b.json", "checker_name": "InvalidDynamicObjectChecker",
                                 "error_code": "20x", "reproducible": True}]}, open(os.path.join(d, "Bugs.json"), "w"))
            json.dump({"verb": "PATCH", "endpoint": "/orders/{id}", "status_code": "200"}, open(os.path.join(d, "a.json"), "w"))
            json.dump({"verb": "GET", "endpoint": "/orders/{id}"}, open(os.path.join(d, "b.json"), "w"))
            got = fd.parse_restler(d)
        self.assertEqual([(x["cls"], x["operation"]) for x in got], [("cross", "PATCH /orders/{id}"), (None, "GET /orders/{id}")])


class Scoring(unittest.TestCase):
    def test_detection_needs_a_signature_absent_from_the_hardened_control(self):
        noise = f("IgnoredAuth:Unexpected", "unauth", "GET /orders/{id}")
        real = f("IgnoredAuth:API accepts requests without authentication", "unauth", "GET /orders/{id}")
        control = run("st", "none", [noise])
        self.assertFalse(fd.detects(run("st", "missing-auth", [noise]), control, "unauth", fd.GET))
        self.assertTrue(fd.detects(run("st", "missing-auth", [noise, real]), control, "unauth", fd.GET))
        self.assertFalse(fd.detects(run("st", "missing-auth", [real]), control, "cross", fd.GET))   # wrong class
        self.assertIsNone(fd.detects(run("st", "missing-auth", [], "NOT_RUN"), control, "unauth", fd.GET))

    def test_scanner_detection_uses_the_verified_tier(self):
        probable = f("cross_tenant_access", "cross", "PATCH /orders/{id}", confidence="probable")
        control = run("authz-fuzzer", "none", [])
        self.assertFalse(fd.detects(run("authz-fuzzer", "bola-write", [probable]), control, "cross", fd.WRITES))
        self.assertTrue(fd.detects(run("authz-fuzzer", "bola-write", [probable]), control, "cross", fd.WRITES,
                                   tier="probable"))

    def test_task4_rows(self):
        write = f("NameSpaceRuleChecker_20x", "cross", "PATCH /orders/{id}")
        runs = {"restler": {"none": run("restler", "none", []),
                            "silent-write": run("restler", "silent-write", []),
                            "lying-success": run("restler", "lying-success", [write]),
                            "admin-legit": run("restler", "admin-legit", [write]),
                            "leaky-404": run("restler", "leaky-404", [], "NOT_RUN")}}
        rows = fd.score(runs)["task4"]["restler"]
        self.assertEqual(rows["silent-write"]["verified"], {"flagged": False, "correct": False, "findings": [],
                                                             "also_in_control": []})
        self.assertFalse(rows["lying-success"]["verified"]["correct"])
        self.assertFalse(rows["admin-legit"]["verified"]["correct"])
        self.assertEqual(rows["leaky-404"]["verified"], {"verdict": "NOT_RUN"})

    def test_task3_false_findings_count_trap_signatures(self):
        runs = {"restler": {"none": run("restler", "none", [f("NameSpaceRuleChecker_20x", "cross", "POST /orders")]),
                            "admin-legit": run("restler", "admin-legit", [f("NameSpaceRuleChecker_20x", "cross", "PATCH /orders/{id}"),
                                                                          f("other", None, "GET /orders/{id}")])}}
        t3 = fd.score(runs)["task3"]["restler"]
        self.assertEqual(t3["false_findings"], 2)
        self.assertEqual(t3["n"], 0)                     # no flaw modes run -> not counted as 0/4


if __name__ == "__main__":
    unittest.main()
