# TSG-1 Integrated Live Lab — AuthZ-Fuzzer end-to-end

Real scans of the `authz-target` reference orders API across its vulnerability modes, scored against ground truth by the TSG-1 oracles. Evidence is live SARIF/JSON findings over a real socket, not unit tests.

**8/8 modes scored as expected.** (Gate exit 0 = CI gate passed, 2 = gate failed because a planted flaw was correctly found.)

| Mode | Server | Scope | Scenario | Oracle | Expected | Result | Verified (r/w) | Violations | Gate | Detail |
|------|--------|-------|----------|--------|----------|--------|----------------|------------|------|--------|
| none | none | test_owned_only | AZ-047 | manifest | zero verified findings | ✅ | 0 (0/0) | — | 0 | correctly silent on benign case |
| bola-read | bola-read | read_only | AZ-002 | isolation | verified cross-tenant read leak | ✅ | 1 (1/0) | cross_tenant_access | 2 | no cross-tenant disclosure |
| bola-write | bola-write | test_owned_only | AZ-002 | isolation | verified cross-tenant write | ✅ | 2 (0/2) | cross_tenant_access | 2 | no cross-tenant disclosure |
| missing-auth | missing-auth | read_only | AZ-003 | manifest | verified missing-authentication read | ✅ | 2 (2/0) | cross_tenant_access,missing_authentication | 2 | correct finding with correct label |
| readonly-scope-vs-write-vuln | bola-write | read_only | AZ-030 | invariant | read-only scope emits NO write finding | ✅ | 0 (0/0) | — | 0 | invariant held |
| delegated-read | none | read_only | AZ-005 | manifest | delegated (shared) read NOT flagged | ✅ | 0 (0/0) | — | 0 | correctly silent on benign case |
| public-read | none | read_only | AZ-004 | manifest | public read NOT flagged | ✅ | 0 (0/0) | — | 0 | correctly silent on benign case |
| shared-write | shared-write | test_owned_only | AZ-005 | manifest | grantee write of a shared order flagged | ✅ | 2 (0/2) | shared_resource_write | 2 | correct finding with correct label |

_Seed: `order-1` (alpha private), `order-shared` (alpha, shared read-only with bravo), `order-public` (public), `order-bravo` (bravo private). Each mode probes the resource relevant to its trap._

