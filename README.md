# TSG-1 Harness — executable adversarial test suite for Lattivant

An executable implementation of the **Vigilattice Adversarial Test-Suite Guide
(TSG-1)**: a scenario catalog, a scenario DSL + ground-truth manifests, the six
oracle types, a runner, and a report generator — used to measure how effective
the Lattivant detection platform actually is today.

> **Vigilattice** is the research codename; **Lattivant** is the product in this
> repo (`authz-fuzzer`, `agenttrace`, `eastwest`, `evidence-graph`,
> `investigator`, `lattivant-platform`, `lattivant-lab`).

Dependency-free: pure Python stdlib (3.12+), offline, deterministic.

> The harness runs each component's `cargo test` as evidence, so it expects the
> Lattivant component repos (`authz-fuzzer`, `agenttrace`, `eastwest`,
> `evidence-graph`, `investigator`, `lattivant-platform`, `lattivant-lab`) as
> sibling directories next to `test-suite/`. The committed `reports/` capture a
> full run so results are readable without re-running.

## Layout

```
tsg1/              harness package
  model.py         Scenario / Manifest / Result, enums, content digest
  stats.py         Wilson intervals, confusion matrix, kappa, Mann-Whitney U, TPR@FPR
  oracles.py       the six oracle types (isolation/manifest/metamorphic/invariant/
                   differential/statistical)
  catalog.py       load + filter the scenario registry
  runner.py        honest runner (SPEC->SKIPPED, no-backing->NOT_RUN)
  report.py        JSON + Markdown report with an honesty header
  cli.py           `python -m tsg1 {list,run,report}`
  adapters/        bridges scenarios to all seven components (cargo-test-backed);
                   _cargo.py runs each component's suite, _mappings.py wires
                   scenario -> named conformance tests, capabilities are enabled
                   only for components that are built and green
catalog/
  build_catalog.py source of truth for all 326 scenarios
  scenarios.jsonl  generated registry
manifests/         ground-truth manifests (TSG-1 C.2)
reports/full/      committed definitive full-catalog run
tests/             harness self-tests (stdlib unittest)
```

## Run it

```bash
cd test-suite
python3 -m tsg1 list --run-first                 # the TSG-1 Section H run-first 40
python3 -m tsg1 run  --run-first --out runs/x    # run them, write a report
python3 -m tsg1 run  --all       --out reports/full
python3 lab/live_lab.py                          # integrated live lab (end-to-end scans)
python3 -m unittest discover -s tests            # harness self-tests (33)
python3 catalog/build_catalog.py                 # regenerate the registry
```

A run exits non-zero if any **S0** isolation/safety scenario FAILs (release-gate
semantics).

## How evidence works (and the honesty contract)

The harness never fabricates a result:

- **PASS / FAIL** are produced only from a *real observation*. For the built
  `authz-fuzzer` scanner, the observation is its own `cargo test` conformance
  cases (e.g. `cross_tenant_identical_body_is_verified_disclosure` backs
  `AZ-002`). The exact command and exit status are recorded in the result.
- **SKIPPED** — a SPEC-blocked scenario whose required component (R1–R4, the
  Evidence Graph correlator, the Investigator post-checker, the MCP scanner, …)
  is not built.
- **NOT_RUN** — runnable in principle but its backing test, baseline tool, or
  live stack is absent; the result carries the precise prerequisite.
- **ERROR** — the harness or a component failed while executing; reported, never
  silently passed.

If a scenario's backing test name is missing from the real test output, the
scenario is reported **NOT_RUN**, never PASS. A green suite means "survived
everything we actually ran", never "secure" or "all 326 executed".

See [RESULTS.md](RESULTS.md) for the current measured results.
