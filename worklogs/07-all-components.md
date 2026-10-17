# Worklog 07 — evaluate ALL components; reconcile build-status

Date: 2026-10-17

## Scope delivered
Made the suite genuinely exercise every Lattivant component, not just the AuthZ
scanner. Inventoried and ran each component's cargo test suite, enabled the
corresponding capabilities, and wired scenario→test mappings across AgentTrace,
Evidence Graph, Investigator, EastWest, Platform and Lab.

## Key finding — the detectors are built
The TSG-1 guide marked most AT-*/EG-*/AI-* scenarios "SPEC-only". In this repo
those detectors exist and pass:
- **AgentTrace**: R1 cross-tenant, R3 rug-pull, span↔side-effect join
  (`cross_tenant_claim_is_detected`, `content_change_on_approved_tool_is_flagged_as_rug_pull`,
  `fallback_join_never_reaches_verified`).
- **Evidence Graph**: correlator, entity resolution, provenance invariants
  (`correlated_with_is_never_causal`, `alias_cannot_cross_tenant`,
  `three_hop_traversal_is_time_scoped_and_returns_evidence`).
- **Investigator**: grounding post-checker, tenant isolation, 3-tool allowlist
  (`prompt_injection_cannot_fabricate_support`,
  `cross_tenant_citation_is_invisible_and_rejected`,
  `allowlist_only_recognizes_three_tools`).

## Files changed
- `tsg1/adapters/_cargo.py` — generalized cargo-results helper for any component.
- `tsg1/adapters/_evidence.py` — `make_test_backed_adapter(..., component=...)`.
- `tsg1/adapters/_mappings.py` — scenario→test backings for all components.
- `tsg1/cli.py` — `_detect_capabilities` enables a capability only when its
  backing component is present and green.
- Trimmed now-backed ids from the platform/research NOT_RUN lists.
- `RESULTS.md`, `reports/full/*`.

## Commands run (actual status)
- `cargo test --workspace` per component → **agenttrace 91, eastwest 36,
  evidence-graph 35, investigator 41, lattivant-platform 60, lattivant-lab 12,
  authz-fuzzer 202 — all exit 0 (477 tests, 0 failed)**.
- `python3 -m tsg1 run --all` → **326 scenarios: 79 PASS, 0 FAIL, 6 SKIPPED,
  241 NOT_RUN, S0 gate CLEAN**. Measured spans all 7 components.
- `python3 -m unittest discover -s tests` → **OK, 33 tests**.

## Honest limits
- Only scenarios whose oracle is isolation/invariant/manifest/metamorphic are
  conformance-backed; statistical/differential-oracle scenarios (e.g. RV-020)
  are not synthesized from unit tests and stay NOT_RUN (a first wrong wiring of
  RV-020 produced a fail-closed FAIL; corrected).
- 241 NOT_RUN are scenarios with a built component but no specific adapter, or
  that need an external harness (adaptive attacker, labeled corpus, live stack).
- 6 SKIPPED are genuinely unbuilt: long-horizon memory, gRPC, WebSocket.
- Postgres-RLS CVE scenarios (PL-001..007) remain NOT_RUN: the platform uses a
  structural validator + content store, not Postgres RLS, so those specific CVE
  paths are not exercised (app/store tenant isolation is, via PL-012..040).

## Next authorized step (one)
Wire the statistical scenarios (RV-018/020/021) as real >=20-seed experiments
over the built detectors to convert them from NOT_RUN to measured.
