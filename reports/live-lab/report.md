# TSG-1 Integrated Live Lab — AuthZ-Fuzzer end-to-end

Real scans of the `authz-target` reference orders API across its vulnerability modes, scored against ground truth by the TSG-1 oracles. Evidence is live SARIF/JSON findings over a real socket, not unit tests.

**5/5 modes scored as expected.** (Gate exit 0 = CI gate passed, 2 = gate failed because a planted flaw was correctly found.)

| Mode | Server | Scope | Scenario | Oracle | Expected | Result | Verified (r/w) | Violations | Gate | Detail |
|------|--------|-------|----------|--------|----------|--------|----------------|------------|------|--------|
| none | none | test_owned_only | AZ-047 | manifest | zero verified findings | ✅ | 0 (0/0) | — | 0 | correctly silent on benign case |
| bola-read | bola-read | read_only | AZ-002 | isolation | verified cross-tenant read leak | ✅ | 1 (1/0) | cross_tenant_access | 2 | no cross-tenant disclosure |
| bola-write | bola-write | test_owned_only | AZ-002 | isolation | verified cross-tenant write | ✅ | 2 (0/2) | cross_tenant_access | 2 | no cross-tenant disclosure |
| missing-auth | missing-auth | read_only | AZ-003 | manifest | verified missing-authentication read | ✅ | 2 (2/0) | cross_tenant_access,missing_authentication | 2 | correct finding with correct label |
| readonly-scope-vs-write-vuln | bola-write | read_only | AZ-030 | invariant | read-only scope emits NO write finding | ✅ | 0 (0/0) | — | 0 | invariant held |

_Note: the seeded order is shared with no tenant, so the `shared-write` vuln is not exercised and is omitted rather than reported as a pass/fail._

