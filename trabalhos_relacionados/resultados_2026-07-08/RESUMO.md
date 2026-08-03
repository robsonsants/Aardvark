# Reproduction of the related work — snapshot 2026-07-08

Execution of the five state-of-the-art methodologies over the **current dataset** of the
Matrix ecosystem (43 fork×CVE pairs — element-android, matrix-appservice-irc, synapse,
matrix-hookshot, matrix-rust-sdk). Signal source:
`resultados_2026-07-04/dissertation_resultados.json`.

Files in this directory:
`rw1_wyss2022_hash.json` · `rw2_vercation2025_ast.json` ·
`rw3_pptfi2024_dualref.json` · `rw4_see2025_greedy_pareto.json` ·
`rw5_decan2018_timelag.json`.

---

## 1. False-negative reduction (34 pairs with conclusive ground truth)

| Method (source work) | Layer | Detects (of 34) | Recall | FN | Recovered vs. hash |
|-------------------|:------:|:---------------:|:------:|:--:|:-----------------:|
| **Wyss et al. 2022** — whole-file hash | 1 | 5 | **0.147** | 29 | — |
| **VERCATION / Cheng et al. 2025** — AST, single ref. | 2A | 23 | **0.676** | 11 | **+18** |
| **PPTFI / He et al. 2024** — PPT, dual ref. | 2B | 11 | 0.324 | 23 → uncertainty | preserves precision |
| **Our pipeline (union 2A ∪ 2B)** | 1+2A+2B | **23** | **0.676** | 11 (to audit) | **0 false positives** |

Literal verification (Wyss) recognises only **5/34** real fixes; the AST layer
(VERCATION) **recovers 18** of them (**≈62% fewer false negatives**); the dual-reference
patch presence test (PPTFI) never emits a false "safe" verdict, escalating 23 cases to
audit instead.

## 2. Macro diagnosis — greedy set cover / Pareto (See et al. 2025)

Universe = 16 vulnerabilities (upstream, CVE). Ceiling = **11/16 (68.8%)**.

| K forks | Fork | Gain | Coverage (universe) |
|:------:|------|:-----:|:--------------------:|
| 1 | oI0ck/matrix-appservice-irc | +5 | 31.2% |
| 2 | H1d3r/element-android | +3 | 50.0% |
| 3 | microchipster/synapse | +1 | **56.2%** |
| 4 | matrix-construct/matrix-rust-sdk | +1 | 62.5% |
| 5 | maladesov/matrix-hookshot | +1 | **68.8% (ceiling)** |

## 3. Time lag (Decan et al. 2018 / Ponta et al. 2020) — 29 patched pairs

| Statistic | Days |
|-------------|:----:|
| Minimum | −14 * |
| Median | **244** |
| Mean | 245.2 |
| Maximum | **578** |

\* The negative minimum is an artefact of the "last touch on the file" heuristic; precise
validation would require per-line `git blame` (manual sampling).

---

## Positioning

- **The commit hash is used only as motivation** that literal matching is insufficient
  for divergent forks: that is precisely the role of **rw1** (recall 0.147). It is a
  baseline, not the main method.
- **Precision/recall metrics plus false-positive analysis** are covered by rw1–rw3
  against the ground truth.
- **Not reproduced here:** ranked clone-detection tools (CCFinder Type 1, NiCad
  Type 1–2, and a Type-3/ranking tool) that query with the *vulnerable snippet → ranked
  list of downstreams*. Those would replace the AST layer as the main method; the present
  reproductions serve as the **baseline** against which to compare them. The language
  coverage of each tool is analysed in `estudo_ferramentas_deteccao_clones.md`, since
  those limits determine what can enter the dataset.
- **Three-leg design (client/server/library):** the current dataset covers client
  (element-android), server (synapse) and library (matrix-rust-sdk), plus bridge and
  integration — a superset of the minimum design.
