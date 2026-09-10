# Appendix — thresholds, fix-commit provenance, and computational cost

> ## ⚠ Dated document — July 2026 state
>
> The threshold analysis in this appendix was produced by `sensibilidade_limiares.py`, which
> has since been **removed** — it covered Layer 2A only and read the embedding prototype
> (which has not run since July 2026). It is replaced by `sensibilidade_regras.py`, whose
> sweep also covers the Layer 2B margin and the guard-B floor.
>
> The precision figures quoted here come from the **constructed** 44-positive / 56-negative
> set, which is abandoned: the current run has a single real population with **7 natural
> negatives**. See [`RESULTS_2026-08-31.md`](RESULTS_2026-08-31.md) §5 for the current
> sensitivity analysis.

> Derived from the artefacts already in this repository; no new data collection.
> Scripts: `sensibilidade_limiares.py` (thresholds), `bench_custo_embeddings.py` (cost).
> Sources: `prototipo_ranking_embeddings/resultados_2026-07-09/precision_eval.json`
> (100 instances, 44 pos / 56 neg), `resultados_2026-07-04/dissertation_resultados.json`
> and `gt_v2_resultados.json` (43 pairs), `cve-nvd-dataset.csv`, `ghsa-cve-nvd-dataset.csv`.

---

## A. Locating the fix commit: automatic vs. heuristic/manual

Of the **16 CVEs** used in Phase 2:

| Origin of the fix commit | CVEs | Which |
|---|:--:|---|
| **Automatic** — a `/commit/<sha40>` URL present in the NVD/GHSA references collected by `pipeline1.py` | **9 (56.2%)** | CVE-2022-39252, CVE-2024-26131, CVE-2024-26132, CVE-2024-31208, CVE-2024-34353, CVE-2025-27606, CVE-2025-48937, CVE-2025-61672, CVE-2025-66622 |
| **Heuristic/manual** — target added after Phase 1; commit located by hand in the NVD references and GHSA advisory pages | **7 (43.8%)** | CVE-2023-38690, CVE-2023-38700, CVE-2023-43656, CVE-2024-39691, CVE-2024-52505, CVE-2025-23197, CVE-2025-27146 |

Classification criterion (reproducible): a CVE counts as "automatic" when the SHA recorded
in `cves-fixing-commits-dataset.csv` appears in the `url_list` column of the mined
dataset. The 7 CVEs on the second row **do not exist** in `cve-nvd-dataset.csv` or
`ghsa-cve-nvd-dataset.csv` — they belong to `matrix-appservice-irc` (5) and
`matrix-hookshot` (2), which were added to the target list after Phase 1 had run.

**Accuracy:** **16/16 (100%)** of the located commits are the correct corrective commit —
including **7/7** of those found heuristically. This was verified by extracting, for each
CVE, a **corrective anchor** from the real diff (the line that exists only if the fix is
present); see `resultados_2026-07-04/VALIDACAO_GROUND_TRUTH.md`. In other words, the
heuristic costs *manual effort*, not *accuracy*.

**Not located:** `CVE-2025-32026` (element-web) has only an advisory page and no commit,
so it was excluded from the study. Non-location rate over the scanned set: 1 CVE.

**Limitation to declare:** the search is not fully automated for projects whose advisories
do not reference the commit. The manual step is auditable (the NVD/GHSA references are
recorded in the CSV) and was validated by the anchor, but it does not scale without a
ranked search over commit messages and diffs.

---

## B. Sensitivity of the Layer 2A and 2B thresholds

Swept over the **100 two-class instances** (which already store `ast_sim_patch` and
`ast_sim_vuln` per instance) and over the **43 pairs of ground truth v2**.

### B.1 — PATCHED threshold (τ_hi), with τ_lo = 0.35 — two-class set

| τ_hi | P | R | F1 | TP/FP/FN/TN | % uncertainty zone |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 0.65 | 0.436 | 0.932 | 0.594 | 41/53/3/3 | 6.0% |
| 0.70 | 0.441 | 0.932 | 0.599 | 41/52/3/4 | 7.0% |
| 0.75 | 0.441 | 0.932 | 0.599 | 41/52/3/4 | 7.0% |
| **0.80 (current)** | **0.477** | **0.932** | **0.631** | 41/45/3/11 | 14.0% |
| 0.85 | 0.477 | 0.932 | 0.631 | 41/45/3/11 | 14.0% |
| 0.90 | 0.458 | 0.864 | 0.598 | 38/45/6/11 | 17.0% |
| 0.95 | 0.449 | 0.795 | 0.574 | 35/43/9/13 | 22.0% |

**Reading:** the current threshold (0.80) sits at the **F1 optimum** and performance is
**stable within ±0.05** (0.80 and 0.85 are identical; 0.75 loses 0.03 of F1). Precision
stays between 0.436 and 0.477 across the whole 0.65–0.95 range, so the conclusion that
the AST layer saturates around P ≈ 0.5 **is not an artefact of the threshold choice**.

### B.2 — NOT-PATCHED threshold (τ_lo), with τ_hi = 0.80

| τ_lo | % uncertainty zone | % NOT PATCHED |
|:---:|:---:|:---:|
| 0.20–0.40 | 14.0% | 0.0% |
| **0.35 (current)** | **14.0%** | **0.0%** |
| 0.45–0.50 | 10.0% | 4.0% |

**Reading:** τ_lo is **inert** across 0.20–0.40 — no instance in the set falls below 0.40
structural similarity, because a divergent fork and its upstream share the skeleton of the
function. Layer 2A therefore almost never emits a "not patched" verdict; the separation is
done by Layer 2B. This justifies the design: **2A confirms, it does not accuse**.

### B.3 — Layer 2B margin (|δ| = |sim_post − sim_pre|)

| margin | P | R | F1 | TP/FP/FN/TN | % uncertainty zone |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 0.00 | 0.568 | 0.955 | **0.712** | 42/32/2/24 | 10.0% |
| 0.02 | 0.562 | 0.818 | 0.667 | 36/28/8/28 | 22.0% |
| **0.05 (current)** | 0.559 | 0.750 | 0.641 | 33/26/11/30 | 28.0% |
| 0.08 | 0.531 | 0.591 | 0.559 | 26/23/18/33 | 39.0% |
| 0.10 | 0.556 | 0.568 | 0.562 | 25/20/19/36 | 44.0% |
| 0.15 | 0.556 | 0.568 | 0.562 | 25/20/19/36 | 44.0% |
| 0.20 | 0.524 | 0.500 | 0.512 | 22/20/22/36 | 47.0% |

**Reading:** here the parameter **does matter** — F1 falls from 0.712 (m = 0) to 0.512
(m = 0.20). The margin is a **conservativeness control**: raising it trades recall for
audit volume (10% → 47% of the set escalated) and **barely moves precision** (0.52–0.57).
The adopted value of 0.05 is deliberately conservative (28% escalated to audit); 0.00
maximises F1. This is the empirical evidence that the *uncertainty zone is a policy dial*,
not an optimal threshold.

### B.4 — Layer 2A recall over the 43 ground-truth-v2 pairs (union aggregation)

| τ_hi | recall | TP | pairs in the uncertainty zone |
|:---:|:---:|:--:|:---:|
| 0.65 – **0.80 (current)** | 0.651 | 28 | 15 |
| 0.85 | 0.581 | 25 | 18 |
| 0.90 – 0.95 | 0.512 | 22 | 21 |

**Reading:** a complete plateau between 0.65 and 0.80 — no pair changes verdict. (The
recall here, 0.651, differs slightly from the published 0.605 because this re-derivation
aggregates `sha_match ∨ sim_2a ≥ τ` directly, without the `_STATUS_PRIORITY` table of
`pipeline_dissertation.py`; what matters is the **shape of the curve**, which is identical
either way.)

**Conclusion:** the sensitivity sweep does not need to be deferred to future work. The
Layer 2A thresholds are **robust by plateau** (±0.05 changes nothing) and the sensitive
parameter is the **Layer 2B margin**, whose curve is measured above.

---

## C. Computational cost and scale projection

`run_ecosystem.py` is **not instrumented** — no wall-clock time was recorded for the
ecosystem run. Direct measurement of the dominant stage (`bench_custo_embeddings.py`,
CPU only, no GPU: torch 2.13.0+cpu, `microsoft/unixcoder-base`, 16-line window):

| Item | Measured |
|---|---|
| Model load (once per run) | **10.2 s** |
| Embedding one window (16 lines, CPU) | **263 ms** |
| Fork×CVE pair — small file (~20 windows) | **~5.8 s** |
| Fork×CVE pair — medium file (~60 windows) | **~16.3 s** |
| Fork×CVE pair — script cap (160 windows) | **~42.7 s** |

Projection (semantic layer only, CPU, no batching):

| Scale | Estimated time |
|---|---|
| 43 pairs (this study) | **~12 min** |
| 500 pairs | ~2.3 h |
| 5,000 pairs | ~23 h |

The network is not the bottleneck: `run_ecosystem.py` makes roughly one `contents` call
per (fork, CVE, file) plus two calls per fix commit (with a commit cache), far below the
5,000 requests/hour of the authenticated GitHub API. The bottleneck is the UniXcoder
forward pass on CPU without batching — addressable with batching plus a GPU (typically
1–2 orders of magnitude), though **not measured here**.

**Claim to make in the paper:** rather than "continuous DevSecOps", state
**"periodic, incremental execution — per new CVE or as a nightly batch"**, supported by
the measured number (~12 min for the full 43-pair ecosystem on a commodity CPU), and
record batching/GPU as an unevaluated optimisation.
