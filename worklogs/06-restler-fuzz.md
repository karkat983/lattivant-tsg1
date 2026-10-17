# Worklog 06 — deeper RESTler fuzz run with a seeded resource dictionary

Date: 2026-10-17

## Scope delivered
Upgraded the RESTler baseline from a `test` smoke pass (8 requests/mode, 0 valid)
to a `fuzz` run with a seeded resource dictionary (the real order ids), raising
the requests actually sent to the vulnerable endpoints to 161/mode. The authz
result is unchanged: RESTler finds 0 bugs and 0 of 4 planted authorization flaws.

## Files changed
- `test-suite/lab/differential.py` — `_run_restler` now seeds the fuzzing
  dictionary's `restler_fuzzable_string` with `order-1/order-shared/order-public`,
  runs `fuzz` with a time budget, and reports requests-sent; `_restler_env`
  prefers Python 3.12 for the engine ($TSG1_PYTHON overrides).
- `RESULTS.md`; refreshed `reports/differential/*`.

## Commands run (actual status)
- `brew install python@3.12` → 3.12.15 (RESTler's engine crashes on 3.14).
- Manual `dotnet Restler.dll fuzz --dictionary_file <seeded> --time_budget 0.01`
  then `python3 lab/differential.py` with all baselines →
  RESTler **161 requests/mode, 0 bugs, 0/4 authz**; Schemathesis 0/4; EvoMaster
  0/4; authz-fuzzer 4/4. **Differential PASS.**
- `python3 -m unittest discover -s tests` → **OK, 33 tests**.

## Honest limits (important)
- RESTler's own coverage counter reports 0/4 "rendered" despite sending 161
  requests, because its engine hits a `list.index(x): x not in list` error on
  this host (seen on both Python 3.14 and 3.12) while accounting renderings. The
  requests are genuinely sent (confirmed in `main.txt` / `total_requests_sent`),
  so the report shows **requests-sent** rather than RESTler's unreliable rendered
  count. This is a RESTler engine/accounting issue, documented, not worked around
  by faking numbers.
- The deeper run does not change the differential verdict: RESTler has no
  cross-tenant/ownership oracle, so more coverage still yields 0 authz flaws —
  which is exactly the point the differential makes.
- EvoMaster fault counts vary run-to-run (randomized search); still 0 authz.

## Next authorized step (one)
The three automatable baselines are complete at depth. Remaining open item is
RV-010 (Burp Autorize), which needs the commercial Burp GUI and cannot run here.
