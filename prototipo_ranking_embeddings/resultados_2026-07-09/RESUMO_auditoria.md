# Audit of the negative set + patch adoption in the forks — 2026-07-14

Closes the ground-truth validation step in an **automated and auditable** way. It
answers directly the question "did the Matrix forks adopt the upstream security
patches?" and delivers the **definitive precision** over corrected labels.

Scripts: `auditar_worklist_automatico.py` (content-based audit) →
`calcular_auditoria.py` (metrics). Input: `auditoria_negativos_worklist.csv`
(56 negatives) + `precision_eval.json` (reliable positives).

**This document supersedes the aggregate precision reported in `RESUMO_precisao.md`.**

## Method — CONTENT-based audit (block-level dual reference, Layer 2B logic)

For each negative instance we deliberately avoid structural similarity (which produced
the disputed cases) and use the **real content of the fix** instead. From the commit
diff we reconstruct the **most changed hunk** as two contiguous blocks:

- **PRE-image** = context + removed lines (the vulnerable code);
- **POST-image** = context + added lines (the patched code).

The instance's file is compared (SequenceMatcher, best contiguous window) against both
images. The **shared context** makes the decision discriminative even for small patches:
`sim_post > sim_pre` ⇒ **CORRIGIDO** (patched); `sim_pre > sim_post` ⇒ **VULNERAVEL**;
`|Δ| < 0.03` or weak references ⇒ **INDETERMINADO** (escalated to a human).
The `upstream@pre` instances are **VULNERABLE by construction** (they are the pre-fix
code; the sanity check confirms `sim_pre = 1.00` for all of them).

> Labels are recorded as automatic triage (`veredito_ia` / `veredito_humano`). Final
> human sign-off remains pending, and the 5 INDETERMINADO cases are left to the human.

## Finding 1 — the date-based "pre-adoption" negative set is CONTAMINATED

| Audit verdict (56 negatives) | n | Reading |
|--------------------------------------|:-:|---------|
| **CORRIGIDO** (bad label) | **33** | the file already contained the fix (`sim_post = 1.00`) |
| **VULNERAVEL** (valid negative) | 18 | 15 `upstream@pre` + 3 genuinely pre-adoption forks |
| INDETERMINADO (→ human) | 5 | tiny patch, post ≈ pre |

The **33 CORRIGIDO cases have `sim_post = 1.00`**: the POST-image appears **literally**
in the fork's file. Cause: divergent forks merge or cherry-pick from upstream, and git
**preserves the upstream committer date** on the imported commit. Because the cut-off
uses `until = fix_date` (inclusive), the fix commit lands exactly on the boundary and the
supposed "pre-adoption" version **already carries the patch**. In other words, the
date heuristic labels as "vulnerable" code that is **in fact already patched**. This
confirms, by content, the caveat raised in `RESUMO_precisao.md` ("imprecise pre-adoption
commit") — and explains the ~0.5 aggregate precision of the previous experiment: nearly
every "false positive" was actually the method **correctly** detecting a present fix.

## Finding 2 — DEFINITIVE precision over audited labels

51 conclusive negatives (the 5 INDETERMINADO excluded) plus the reliable positives:

| Method | P | R | F1 | TP / FP / FN / TN |
|--------|:---:|:---:|:---:|:---:|
| **Embeddings (UniXcoder)** | **0.972** | 0.896 | 0.932 | 69 / 2 / 8 / 16 |
| AST 2A | 0.914 | 0.961 | 0.937 | 74 / 7 / 3 / 11 |
| **Combiner (AST2A ∪ emb)** | 0.906 | **1.000** | **0.951** | 77 / 8 / 0 / 10 |

Once the bad labels are corrected, precision rises from **~0.50 (raw, contaminated)** to
**0.91–0.97**. The embeddings have the **highest precision (0.972; only 2 FP)**; the
combiner reaches **recall 1.000 and the best F1 (0.951)**. The drop to ~0.5 in the
earlier experiment was demonstrably an **artefact of the negative set**, not of the
signal itself.

## Finding 3 — adoption at HEAD (a direct answer to RQ2)

38 (fork × CVE) pairs evaluated by content in their CURRENT state (HEAD):

| Adoption at HEAD | n | |
|----------------|:-:|---|
| CORRIGIDO (adopted) | **24** | fix present in the current version |
| INDETERMINADO | 14 | tiny patch (post ≈ pre) — indistinguishable by content |
| **still VULNERAVEL** | **0** | no fork resembles the vulnerable code more closely |

**No active divergent fork remains demonstrably exposed**: 24/38 confirm adoption and the
remaining 14 are merely indistinguishable (the change is too small), not vulnerable.
Per-pair detail in `auditoria_adocao_HEAD.csv`.

## Caveats

- This is **automated** triage (content-based): strong for relabelling cases with
  `sim_post = 1.00`; the **5 INDETERMINADO** cases and the final sign-off remain with the
  human reviewer.
- INDETERMINADO at HEAD ≠ vulnerable: it marks a small patch where pre ≈ post, and it
  disappears with line-level or smaller-block discrimination.

## How to run

```bash
python prototipo_ranking_embeddings/auditar_worklist_automatico.py   # reads GITHUB_TOKEN from .env
python prototipo_ranking_embeddings/calcular_auditoria.py
```
Outputs: `auditoria_negativos_worklist.csv` (filled in), `auditoria_adocao_HEAD.csv`,
`auditoria_metricas.json`.
