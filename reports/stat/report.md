# TSG-1 Statistical experiments (RV-018 / RV-020 / RV-021)

Real 40-seed experiment: each trial is a live `authz` scan of a randomly configured `authz-target`. Scores are computed from the real scan reports; Mann-Whitney U and Wilson 95% CIs by the harness stats module.

Trial mix: {'attempted-blocked': 12, 'achieved-shared': 7, 'clean': 7, 'achieved-read': 8, 'achieved-write': 6}

| Scenario | Arm A | mean A | Arm B | mean B | U | p (2-sided) | effect | significant |
|----------|-------|--------|-------|--------|---|-------------|--------|-------------|
| RV-018 | scanner correctness | 1.0 | status-only baseline correctness | 0.675 | 540.0 | 9.3e-05 | -0.325 | yes ✅ |
| RV-020 | corrected-label accuracy | 1.0 | naive-label accuracy | 0.7 | 560.0 | 0.000195 | -0.3 | yes ✅ |
| RV-021 | deduped finding count | 0.85 | raw count (x reproductions) | 2.65 | 579.5 | 0.024517 | 0.2756 | yes ✅ |

- **RV-018** Wilson95: arm A 1.0 [0.912378, 1.0] vs arm B 0.675 [0.520177, 0.799155] (n=40)
- **RV-020** Wilson95: arm A 1.0 [0.912378, 1.0] vs arm B 0.7 [0.5457, 0.819252] (n=40)

_RV-018: the scanner catches write-only BOLA that a read-based status-code baseline misses. RV-020: naive labeling (counting an attempted-but-scope-blocked attack as a required detection) lowers measured accuracy vs correct attempted-vs-achieved labeling. RV-021: counting each reproduction instead of deduping inflates the finding count._
