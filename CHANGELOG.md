# Changelog

What changed between the first published snapshot of this package (July 2026 state,
committed 2026-08-03) and the current one (2026-09-10). Entries are ordered by how much
they move the reported numbers, not chronologically.

---

## 1. A defect that invalidated every earlier run — fixed

`already_processed()` in `pipeline_dissertation.py` keyed records on
`(upstream, cve_id, fork, fix_sha)` — **without the file path**. `select_patch_files()`
returns the production file first and the test file second, so the production record
entered the results and the **test record was then treated as "already processed" and
silently dropped**.

Consequence: the union of production + test evidence that the methodology documented
**never happened, in any run before 2026-08-31**. The bug did not crash anything and did
not appear in any log; it simply removed evidence.

Measured offline over the archived evidence (`impacto_evidencia_teste.py`, no network, so
the fork set stays comparable): **26 verdicts change**.

| Same configuration, same forks | Recall | Kappa |
|---|---:|---:|
| run 2026-08-18 (with the bug) | 0.710 | −0.024 |
| run 2026-08-31_v2 (fixed) | **0.909** | **0.590** |

**This retires a claim that appeared throughout the earlier documentation:** that the low
Kappa was a property of the population (active divergent forks track upstream, so there
are no natural negatives). It is not. Kappa rose on the *same* population once the
evidence stopped being discarded, so the low value was an implementation artefact. The
decomposition makes it explicit: observed agreement went 0.657 → 0.875 while chance
agreement went 0.665 → **0.695** — the imbalance did not decrease.

## 2. New official run: `resultados_2026-08-31_v2/`

7 upstreams · 21 forks · 17 CVEs · 51 verifications · 41 ground-truth pairs, 40 conclusive.
Replaces `resultados_2026-07-04/`, which is kept for the record and now carries a banner.

The decisive change is not the size but the composition: this population contains
**7 natural negatives**. Every earlier precision figure had been measured on a
*constructed* negative set, which was the single most serious criticism the peer reviews
raised (see `REVIEW_RESPONSE_AND_ROADMAP.md`).

## 3. A human oracle, alongside the automated one

`auditoria_manual.py` builds a per-CVE audit worklist and tallies the human verdicts.
41 pairs reviewed, single reviewer, two complete passes.
**Agreement between the automated ground truth and the reviewer: 36/41 = 87.8%.**

Every metric in the current documents names the oracle it came from, and the two are never
mixed. Declared threats travel with the numbers: single reviewer (no inter-rater
agreement), three verdicts revised on the second pass, few decisive cases.

## 4. Baselines re-measured on the same run — and a bug in the harness

`trabalhos_relacionados/_common.py` gained `RW_RUN=<folder>` so every baseline can be
pointed at one run; metrics are only comparable when they all come from the same one.

**Bug fixed in `load_gt_pairs()`:** it returned all 40 conclusive pairs as the recall
denominator, with a docstring asserting "all of them are CONFIRMED_PATCHED here" — true
until July, false as soon as real negatives appeared. The correct denominator is the
**33 CONFIRMED_PATCHED** pairs.

| Baseline | Recall (July, wrong denominator) | Recall (same run, correct) |
|---|---:|---:|
| whole-file hash (rw1) | 0.147 | **0.091** |
| patch-presence test, dual reference (rw3) | 0.324 | **0.758** |
| AST, single reference (rw2) | 0.676 | **0.879** |
| union of the layers (this pipeline) | 0.676 | **0.909** |

**Caveat that must survive into the text:** the union beats the best single layer by
**one pair** (30 vs 29 of 33). The gain is real and in the expected direction, but it is
not robust at n=33.

## 5. New: rw6, the transferable mechanism from PatchLens (FSE 2026)

`trabalhos_relacionados/rw6_patchlens2026_hunk/` reproduces the part of PatchLens that
transfers to this problem: mapping the hunk to its AST subtree and comparing at
**declaration scope** instead of file scope. Its Vulnerability Impact Condition was not
reproduced — there is no conditional compilation in the languages of this ecosystem.

Side effect worth reporting on its own: at file scope, 116 of 125 comparisons fell back to
`lev_only` because the trees exceeded `ZSS_NODE_LIMIT = 600`. That limit was deciding
*which metric was used* in 93% of cases, not merely capping memory.

## 6. New offline experiments

| Script | What it answers |
|---|---|
| `experimentos_revisores.py` | E1–E6: trivial baseline, threshold cross-validation, patch-size discriminant, bootstrap CIs + McNemar, failure analysis, operating curve |
| `experimento_regra_ab.py` | the A+B rule re-derived from the same raw records |
| `sensibilidade_regras.py` | threshold sweep (replaces `sensibilidade_limiares.py`, removed) |
| `impacto_evidencia_teste.py` | the cost of the defect in item 1 |
| `dataset_temporal.py` | adoption lag, fork creation dates, inheritance vs propagation |
| `auditoria_manual.py` | the human oracle |
| `fase1_fix_commits.py` | Phase 1 through the GitHub Advisory DB, with NVD as fallback only |

## 7. Two findings that change what the coverage metric means

**Inheritance is not propagation.** In **31 of the 51 pairs** the fork was created *after*
the fix commit: it never carried the flaw, it inherited already-fixed code. 23 of those
count as `CORRIGIDO` in the coverage figure. Of the 33 `CORRIGIDO` verdicts, only about
**10 are propagation in the strict sense**. Since RQ2 asks about propagation, the coverage
metric as defined mixes two different phenomena. (`created_at` is the repository's date on
GitHub, not the divergence point, so 31 is a floor.)

**Divergence does not predict coverage.** Pearson(behind_by, coverage) = −0.269 and
Spearman = +0.135 at n=21 — contradictory signs, no detectable monotonic relation. A
negative result, and worth reporting as one.

## 8. Performance

`pipeline_core.levenshtein()` now delegates to **rapidfuzz** (C++, bit-parallel Myers) when
available, with the pure-Python loop as fallback. Same exact distance. On
`src/client.ts` of matrix-js-sdk (~1e5 tokens) the old loop took ~40 min per comparison and
made the wider Phase 2 unfeasible; Phase 2 now runs in ~20 min.

## 9. Language and parsers

TypeScript, TSX and Go parsers registered in `pipeline_core.py`; `.tsx` files are parsed
with the TSX grammar. Supported: python, rust, kotlin, swift, typescript, tsx, go.

## 10. Documentation

- `README.md` rewritten around the current run; the July headline table is gone.
- `RESULTS_2026-08-31.md` — the current results, and the answers to RQ1 and RQ2.
- `REVIEW_RESPONSE_AND_ROADMAP.md` — the peer-review feedback, what the data already
  answers, and the improvements still to be made.
- `RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md` and `resultados_2026-07-04/` now carry dated
  banners: they reflect the July state and cite recalls that have since been superseded.

## Removed

- `sensibilidade_limiares.py` — covered Layer 2A only and read the embedding prototype.
  Replaced by `sensibilidade_regras.py`.

## Kept, but reclassified

- `prototipo_ranking_embeddings/` and `bench_custo_embeddings.py`. The embedding layer
  **has not run since July 2026** and no current figure depends on it. It is future work,
  not part of the method as reported. Calling it a "semantic" layer was also inaccurate —
  it measures proximity in a vector space, not semantic equivalence.
