# Embedding ranker across the ECOSYSTEM — consolidated result (2026-07-09)

`run_ecosystem.py` scales the ranker (UniXcoder + **tree-sitter** extraction) to
**every CVE × fork of the 5 categories** and compares it head to head with the baselines
against the ground truth (34 conclusive pairs, all CONFIRMED_PATCHED).
Raw artefact: `ecossistema_embeddings.json`.

## Global recall (n = 34 fork×CVE pairs)

| Method (source work) | TP | Recall |
|-------------------|:--:|:------:|
| whole-file hash (Wyss 2022) | 5 | 0.147 |
| conservative dual-reference AST (PPTFI 2024) | 11 | 0.324 |
| single-reference AST (VERCATION 2025) | 23 | 0.676 |
| **UniXcoder embeddings (this work)** | **27** | **0.794** |
| **Union AST ∪ embeddings** | **34** | **1.000** |

**Embeddings are the best single method (0.794 > 0.676 for the AST layer).** But the
central result is **complementarity**: the union AST ∪ embeddings reaches **recall
1.000** — every truly patched pair is detected by at least one of the two.

## Complementarity per category (TP / n)

| Category | Upstream | Lang. | n | hash | AST | dual-ref | **emb** | **union** |
|-----------|----------|:-----:|:-:|:----:|:---:|:---------:|:-------:|:---------:|
| client | element-android | Kotlin | 9 | 3 | **9** | 9 | 6 | 9 |
| bridge | matrix-appservice-irc | TS | 10 | 2 | **10** | 2 | 6 | 10 |
| integration | matrix-hookshot | TS | 3 | 0 | 3 | 0 | 3 | 3 |
| **server** | synapse | Python | 3 | 0 | **0** | 0 | **3** | 3 |
| **library** | matrix-rust-sdk | Rust | 9 | 0 | **1** | 0 | **9** | 9 |

**Reading:**
- The **AST layer dominates** in Kotlin (element-android) and TypeScript (appservice-irc).
- The **embeddings rescue exactly where the AST layer collapses**: **synapse/Python
  (0/3 → 3/3)** and **matrix-rust-sdk/Rust (1/9 → 9/9)**. The latter is the case that, in
  the original experiment, showed only **8.3% coverage** (the uncertainty zone dominated)
  — the embeddings recover it entirely.
- Hence the **union** closes at 100%: the two methods cover disjoint failure modes.

## Interpretation

Semantic search by embeddings **does not replace** the AST layer — it **complements** it.
The defensible contribution is a pipeline of **two structural evidences** (AST +
embeddings) whose union eliminates the false negatives each one leaves on its own. This
is stronger than any single method, and it reframes the coverage gaps of the earlier
experiment (Rust and Python) as a limitation **of the AST method**, not of the ecosystem.

## Caveats

- **Precision is not measurable here:** the conclusive ground truth contains positives
  only (34 CONFIRMED_PATCHED), so this measures recall / false-negative elimination, not
  precision. Precision is addressed separately in `RESUMO_precisao.md` and
  `RESUMO_auditoria.md`.
- **Upstream sanity check: 25/36** checks pass (pre → vulnerable, post → patched). The 11
  failures are **addition patches** (the vulnerable code is not removed, only guarded, so
  `sim_vuln` stays high) and large refactorings. The margin (0.02) needs calibration per
  patch type.
- **The "100% union" is not yet a deployed classifier:** it is an upper bound (an oracle
  over which method is right). A real pipeline needs a **combiner** (e.g. if AST says
  patched → patched; otherwise consult embeddings; otherwise uncertainty zone) and
  precision validation against negative pairs.
- **tree-sitter** (reused from `pipeline_core.py`) removed the fragility of regex-based
  extraction and enabled Rust/Kotlin/TypeScript beyond Python.

## Next steps

1. Build a set with **negative pairs** (forks demonstrably NOT patched) to measure the
   **precision** of the union and of the combiner. *(Done — see `RESUMO_precisao.md` and
   `RESUMO_auditoria.md`.)*
2. Define and evaluate the AST+embeddings **combiner** (recall × precision). *(Done —
   `RESUMO_auditoria.md`: F1 0.951, recall 1.000.)*
3. Calibrate the margin for **addition patches**; investigate large refactorings.

## How to run

```bash
python prototipo_ranking_embeddings/run_ecosystem.py   # reads GITHUB_TOKEN from .env
```
