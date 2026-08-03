# Reproduction of the related-work methodologies

Each subdirectory reproduces the **methodology of one related work**, applied to the
**same Matrix ecosystem fork data** (43 fork×CVE pairs,
`resultados_2026-07-04/dissertation_resultados.json`). The goal is an **empirical
comparison**: instead of merely citing the state of the art, each technique becomes an
**executable baseline** against which our pipeline is measured.

| Dir | Work | Reproduced method | Equivalent layer |
|-----|----------|--------------------|--------------------|
| `rw1_wyss2022_hash` | **Wyss et al. 2022** — *What the Fork?* (ICSE) | Clone detection by **whole-file hash** | Layer 1 (literal) |
| `rw2_vercation2025_ast` | **Cheng et al. 2025** — *VERCATION* (TSE) — **the closest work** | **Normalised AST + edit distance** (single reference) | Layer 2A |
| `rw3_pptfi2024_dualref` | **He et al. 2024** *PPTFI* / **Xu et al. 2023** *PatchDiscovery* | **Patch Presence Test (PPT) with dual reference** | Layer 2B |
| `rw4_see2025_greedy_pareto` | **See et al. 2025** (AsiaCCS) | **Greedy set cover → Pareto curve** | Macro diagnosis |
| `rw5_decan2018_timelag` | **Decan et al. 2018** / **Ponta et al. 2020** | **Technical lag / window of vulnerability** (days) | Time lag |

## How to run

```bash
# rw1-rw4: derived from the cached results (no token, no network)
python trabalhos_relacionados/rw1_wyss2022_hash/run.py
python trabalhos_relacionados/rw2_vercation2025_ast/run.py
python trabalhos_relacionados/rw3_pptfi2024_dualref/run.py
python trabalhos_relacionados/rw4_see2025_greedy_pareto/run.py
# rw5: mines commit dates (reads GITHUB_TOKEN from .env)
python trabalhos_relacionados/rw5_decan2018_timelag/run.py
```
Each script writes its JSON into the dated directory `resultados_YYYY-MM-DD/` (the date
being the day of execution; pin it with the environment variable `RW_DATE=YYYY-MM-DD`).
The latest snapshot and its consolidated reading are in
**`resultados_2026-07-08/RESUMO.md`**.

---

## RESULT 1 — False-negative reduction (the central argument)

Evaluated over the **34 fork×CVE pairs with conclusive ground truth** (all of them
*genuinely patched*). "Detects" = how many of those 34 the technique marks as patched.

| Method (source work) | Layer | Detects (of 34) | Recall | False negatives | Recovered vs. hash |
|-------------------|:------:|:---------------:|:------:|:----------------:|:-----------------:|
| **Wyss et al. 2022** (literal hash) | 1 | 5 | **0.147** | 29 | — |
| **VERCATION / Cheng et al. 2025** (AST, 1 ref.) | 2A | 23 | **0.676** | 11 | **+18** |
| **PPTFI / He et al. 2024** (PPT, dual ref.) | 2B | 11 | 0.324 | 23 → *uncertainty zone* | preserves **precision** |
| **Our pipeline** (union 2A ∪ 2B) | 1+2A+2B | **23** | **0.676** | 11 (escalated to audit) | **0 false positives** |

**Reading:** purely literal verification (Wyss) recognises only **5 of 34** real fixes
(recall 0.147) — exactly the high false-negative rate that motivates this work.
Structural AST similarity (VERCATION) **recovers 18** of those missed fixes, raising
recall to 0.676, a **≈62% reduction in false negatives**. The dual-reference PPT (PPTFI)
is conservative by design: rather than risking a verdict it routes 23 cases into the
*uncertainty zone* (human audit), never emitting a false "safe". The final pipeline
combines 2A (recall) and 2B (precision), obtaining **precision 1.000** (0 false
positives) against this ground truth.

> Note: that precision of 1.000 is measured against a ground truth containing positives
> only. Precision on constructed negatives is reported in
> `prototipo_ranking_embeddings/resultados_2026-07-09/RESUMO_auditoria.md`.

## RESULT 2 — Macro diagnosis: greedy set cover / Pareto curve (See et al. 2025)

Universe = 16 distinct vulnerabilities (upstream, CVE). Network ceiling = 11/16
(**68.8%**) — the remainder are patched by no monitored fork.

| K forks | Fork added | Gain | Coverage (universe) |
|:------:|-----------------|:-----:|:--------------------:|
| 1 | oI0ck/matrix-appservice-irc | +5 | 31.2% |
| 2 | H1d3r/element-android | +3 | 50.0% |
| 3 | microchipster/synapse | +1 | **56.2%** |
| 4 | matrix-construct/matrix-rust-sdk | +1 | 62.5% |
| 5 | maladesov/matrix-hookshot | +1 | **68.8% (ceiling)** |

This reproduces the shape of the finding "N forks guarantee a ceiling of X%".

## RESULT 3 — Time lag (Decan et al. 2018 / Ponta et al. 2020)

Adoption latency over 29 patched pairs ("last touch" approximation on the patched file):

| Statistic | Days |
|-------------|:----:|
| Minimum | −14 * |
| Median | **244** |
| Mean | 245.2 |
| Maximum | **578** |

\* The negative minimum is a known artefact of the "last touch" heuristic (a commit
touching the file for an unrelated reason). It confirms the high median inertia of the
network; precise validation would require per-line `git blame` on a manual sample.

---

## Comparison table, filled in with the empirical numbers of this study

| Work | Focus | Mining | Upstream tracking | Fork analysis | Structural verification | Macro diagnosis | Recall (34 GT) |
|----------|------|:---------:|:---------------:|:----------------:|:-----------------:|:-----------------:|:--------------:|
| Wyss 2022 [hash] | hidden clones | ✓ | × | ✓ | × (hash) | ∼ | 0.147 |
| VERCATION 2025 | vulnerable version | ✓ | ✓ | × | ✓ | × | 0.676 |
| PPTFI 2024 | patch presence | × | ✓ | × | ✓ | × | 0.324 (0 FP) |
| See 2025 [greedy] | cross-version similarity | × | ✓ | × | ✓ | ∼ | — (macro) |
| **This work** | **orchestration over forks** | ✓ | ✓ | **✓** | **✓** | **✓** | **0.676 / prec. 1.000** |

**Conclusion:** no single work covers all five columns. Our contribution is to
**orchestrate** them into one pipeline applied to divergent forks — and the numbers above
quantify the gain contributed by each layer.

---

### Data caveat

These reproductions run over the **current** dataset (element-android,
matrix-appservice-irc, synapse, matrix-hookshot, matrix-rust-sdk). Earlier drafts of this
research used a different project set (including matrix-ios-sdk, olm and vodozemac, and
excluding appservice-irc/hookshot), so numbers quoted from those drafts will not match.
The **method** of each reproduction is identical; only the fork/CVE set differs.
