# Worklog 02 — extend live-lab seed (shared / public / second-tenant orders)

Date: 2026-10-17

## Scope delivered
Extended the integrated live lab to exercise the FP traps and the shared-write
vuln end-to-end by enriching the `authz-target` seed and adding three lab rows.
Live modes scored as expected: **8/8**.

## Files changed
- `authz-fuzzer/scanner/crates/authz-target/src/state.rs` — added `Order.public`
  (additive, serde default false) and seeded `order-shared` (alpha, shared
  read-only with bravo), `order-public` (public), `order-bravo` (bravo-private);
  updated existing `Order` literals.
- `authz-fuzzer/scanner/crates/authz-target/src/app.rs` — `can_read` now allows
  reads of a public order (legitimate); added two server unit tests.
- `test-suite/lab/live_lab.py` — per-mode resource fixtures; new rows
  `delegated-read` (AZ-005), `public-read` (AZ-004), `shared-write` (AZ-005).
- `test-suite/tests/test_live_lab.py` — 5 new scoring tests.
- `test-suite/reports/live-lab/*`, `RESULTS.md`.

## Commands run (actual status)
- `cargo test -p authz-target` → **12 passed, 0 failed** (+2 new tests).
- `cargo test -p authz-cli --test scan_live_target` → **5 passed** (canonical
  self-check still green; additive seed did not break `none`-is-clean).
- `cargo build -p authz-target -p authz-cli` → ok.
- `python3 lab/live_lab.py` → **8/8 modes as expected**: delegated-read and
  public-read yield 0 findings (FP traps hold); shared-write yields 2 verified
  `shared_resource_write` findings (gate exit 2).
- `python3 -m unittest discover -s tests` → **OK, 27 tests**.

## Notes / honest limits
- The `Order.public` addition is a minimal, additive change to the reference
  target; the OpenAPI contract and existing endpoints are unchanged, and all
  prior scanner tests still pass. Committed in the `authz-fuzzer` repo (its own
  history), authored by the repo owner.
- Still AuthZ-Fuzzer only; the SPEC-blocked detector families remain unbuilt.

## Next authorized step (one)
Add the differential-vs-baseline live comparison (AZ-046 / RV-007..010) by
running Schemathesis / Burp Autorize / RESTler against the same seeded target
and scoring relative recall — requires permitting those tool installs.
