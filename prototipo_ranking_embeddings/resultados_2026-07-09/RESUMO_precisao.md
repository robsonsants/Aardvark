# Precision, combiner and margin calibration — 2026-07-09

Produced by `run_precision_eval.py`. Closes the gap left by the previous experiment
(which measured recall only) by measuring **real precision** on a **two-class** set, and
by evaluating the AST+embeddings **combiner** and the **margin calibration**.

> Superseded in part: an audit of the negative labels (see `RESUMO_auditoria.md`) later
> showed that the aggregate precision reported here is depressed by mislabelled
> negatives. Read this document together with that one.

## Step 1 — Labelled set (two classes)

- **POSITIVES (44)** = `upstream@fix` + forks confirmed patched (at HEAD, from the
  ground truth).
- **NEGATIVES (56)** = `upstream@pre` (pre-fix code, **vulnerable by definition**) plus
  each fork at its **pre-adoption** version (the last commit touching the file before
  the upstream fix date — it could not have adopted a fix that did not yet exist).

Every instance receives a verdict from **AST** (Layers 2A/2B via `pipeline_core`) and
from **embeddings** (UniXcoder + tree-sitter).

## Step 2 — Precision/Recall/F1 (full set, 44 pos / 56 neg)

| Method | P | R | F1 |
|--------|:---:|:---:|:---:|
| AST 2A | 0.477 | 0.932 | 0.631 |
| AST 2B (dual reference) | 0.559 | 0.750 | 0.641 |
| **Embeddings (margin 0)** | 0.553 | 0.955 | **0.700** |
| Union (AST2A ∪ emb) | 0.489 | **1.000** | 0.657 |
| Intersection (AST2A ∩ emb) | 0.517 | 0.682 | 0.588 |

**No strategy exceeds P ≈ 0.55.** The union maximises recall (1.000) at the cost of the
worst precision; **embeddings alone give the best F1 (0.700)** and no combiner beats it.
In other words, the false-positive analysis shows that the **"zero false positives" of
the previous experiment was an artefact** of a ground truth containing only positives.

## The diagnosis that changes the reading — false positives by negative origin

| Origin of the negative | n | FP rate, AST 2A | **FP rate, embeddings** |
|--------------------|:-:|:---------:|:-----------------:|
| `upstream@pre` (**guaranteed vulnerable**) | 15 | 47% | **13%** |
| `fork@pre-adoption` (divergent fork, noisy) | 41 | 93% | 78% |

On **provably vulnerable** code (`upstream@pre`) the embeddings err on only **13%** of
instances, against 47% for the AST layer. The ~0.5 precision of the full set comes almost
entirely from the **fork pre-adoption** negatives, which are **noisy and hard**: for small
patches the pre-adoption function is nearly identical to the patched one, and divergent
forks shift the alignment. Restricted to the clean negatives:

| Method (clean negatives: 15 × `upstream@pre`) | P | R | F1 |
|--------|:---:|:---:|:---:|
| **Embeddings** | **0.955** | 0.955 | **0.955** |
| AST 2A | 0.854 | 0.932 | 0.891 |

**Embeddings beat the AST layer on precision AND recall** where the signal is clean.

## Step 3 — Margin calibration (embeddings)

| margin | P | R | F1 |
|:------:|:---:|:---:|:---:|
| **0.00** | 0.553 | 0.955 | **0.700** |
| 0.01 | 0.547 | 0.795 | 0.648 |
| 0.02 | 0.532 | 0.750 | 0.623 |
| 0.05 | 0.558 | 0.659 | 0.604 |
| 0.10 | 0.538 | 0.477 | 0.506 |

Raising the margin **destroys recall without buying precision** (precision sits on a
0.53–0.56 plateau): the margin **does not fix** the false positives — they come from the
limits of a **function-level similarity signal**, not from a threshold. By patch type:
addition P 0.571 vs removal/mixed P 0.529 (comparable; small sample).

## Conclusions

1. **Recall-only was misleading.** Once negatives exist, every method sits at P ≈ 0.5 in
   aggregate — but that aggregate is dominated by the hard divergent-fork negatives.
2. **On clean vulnerable code the embeddings are precise (P ≈ 0.96) and beat the AST
   layer** (P ≈ 0.85), confirming embeddings as the best single signal.
3. **The real problem is discriminating small patches in divergent forks**, where
   vulnerable ≈ patched at function granularity. Neither the margin nor the combiner
   solves it.
4. Indicated direction: **descend to the level of the CHANGED LINES** rather than the
   whole function — precisely what Type-3/near-miss clone tools (NiCad) and ranked
   snippet search do.

## Caveats

- The **pre-adoption negatives are noisy** (the fork may have fixed the issue earlier,
  the function may not have existed yet, the pre-adoption commit may be imprecise), so
  the aggregate precision is a **floor** and the real value is higher. A manually audited
  subset gives the definitive number — that audit was subsequently carried out; see
  `RESUMO_auditoria.md`.
- `upstream@pre` and `upstream@fix` are clean and should weigh more in the reading.

## How to run

```bash
python prototipo_ranking_embeddings/run_precision_eval.py   # reads GITHUB_TOKEN from .env
```
Output: `resultados_YYYY-MM-DD/precision_eval.json`.
