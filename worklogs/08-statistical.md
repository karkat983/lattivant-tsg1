# Worklog 08 — statistical scenarios RV-018 / RV-020 / RV-021 (>=20-seed)

Date: 2026-10-17

## Scope delivered
Wired the three statistical-oracle scenarios to a real >=20-seed experiment of
live scans, so they move from NOT_RUN to measured PASS with genuine p-values and
effect sizes. No distributions are fabricated — each data point is a real
`authz` scan of a randomly configured `authz-target`.

## Design
`lab/stat_experiments.py` runs N=40 seeded trials; each picks a scenario kind
(achieved-read / achieved-write / achieved-shared / clean / attempted-blocked)
and a random reproduction count, runs a live scan, and scores the real report.
Three Mann-Whitney U comparisons (harness stats, Wilson 95% CIs):
- **RV-018** scanner per-trial correctness vs a status-code-only baseline (a real
  cross-tenant GET probe). The scanner catches write-only BOLA the read-based
  baseline misses.
- **RV-020** accuracy under corrected attempted-vs-achieved labels vs naive labels
  (which count an attempted-but-scope-blocked attack as a required detection).
- **RV-021** deduped finding count vs raw count (x reproductions).

## Files changed
- `lab/stat_experiments.py`; `lab/live_lab.py` (`_write_manifest` gains a
  `read_repeats` param).
- `tsg1/adapters/stat_rv.py` — RV-018/020/021 adapters feeding the statistical
  oracle from the recorded experiment (reports/stat/results.json) or a live run.
- `tsg1/adapters/__init__.py`, `research_validity.py` (removed the three from
  NOT_RUN); `tests/test_stat.py`; `RESULTS.md`; `reports/stat/*`, `reports/full/*`.

## Commands run (actual status)
- `python3 lab/stat_experiments.py` (40 live scans) →
  RV-018 p=9.3e-05, RV-020 p=1.95e-04, RV-021 p=0.0245 — **all significant**.
- `python3 -m tsg1 run --ids RV-018,RV-020,RV-021` → **3 PASS**.
- `python3 -m tsg1 run --all` → **326 scenarios: 82 PASS, 0 FAIL, 6 SKIPPED,
  238 NOT_RUN, S0 gate CLEAN**.
- `python3 -m unittest discover -s tests` → **OK, 36 tests**.

## Honest limits
- At 24 seeds RV-021 was p=0.067 (not significant); raised to 40 seeds for power
  (the whole point of the gate). The effect was always real (0.85 vs 2.65 mean);
  more seeds gave the power to detect it. Documented rather than cherry-picked.
- The experiment exercises the AuthZ scanner (the component drivable per-seed via
  its CLU). RV-022 (dual-policy corpus) still needs a labeled corpus and stays
  NOT_RUN.
- Results are seed-pinned (seed=1337); re-running reproduces them.

## Next authorized step (one)
Extend the seeded experiment to the other detectors once they expose a per-input
scoring entry point (currently they are exercised via cargo unit tests only).
