# Prototype — embedding-based search/ranking (UniXcoder) on the server leg

Implements the ranked-search pipeline using **code embeddings** as the search/ranking
engine, on the **server leg (synapse / Python)** — the language with the best tool
support (see `estudo_ferramentas_deteccao_clones.md`).

> **Consolidated ECOSYSTEM result** (`run_ecosystem.py`, tree-sitter extraction, all
> CVEs × forks of the 5 categories): embeddings have the **best single-method recall
> (0.794)** and are **complementary to the AST layer** — the **union AST ∪ embeddings
> reaches recall 1.000 (34/34)**, rescuing precisely Rust (sdk) and Python (server),
> where the AST layer collapses. Details in
> `resultados_2026-07-09/RESUMO_ecossistema.md`. The rest of this README describes the
> per-CVE prototype (`run.py`), which validates the method in detail.

## Method

For each upstream CVE (synapse):
1. download the fix commit and its parent (the pre-fix version);
2. using the **git hunk headers**, pick the **changed method** (at `class::method`
   granularity, disambiguating homonyms such as `on_POST`); the **VULNERABLE** reference
   is the pre-image of the diff and the **PATCHED** one is the post-image;
3. for each **fork**, extract the **same method** and slide a **small window** through it
   (avoiding UniXcoder's 512-token truncation);
4. **QUERY = vulnerable snippet → rank** the forks by similarity;
5. **verdict by dual reference** (patch presence): high `sim_corr` = contains the patched
   code; high `sim_vuln` = contains the vulnerable one; `delta = sim_corr − sim_vuln`
   decides (margin 0.02 → uncertainty zone). This is the **semantic analogue of Layer
   2B**, now language-agnostic.

One technical detail that mattered: synapse uses **multi-line signatures**
(`def f(\n ...\n) -> T:`); function extraction must skip the signature before capturing
the body, otherwise the method collapses to 2 lines and the result degenerates.

## How to run

```bash
# one-time install: pip install torch --index-url https://download.pytorch.org/whl/cpu ; pip install transformers requests
python prototipo_ranking_embeddings/run.py --cve all         # or --cve CVE-2024-31208
```
Reads `GITHUB_TOKEN` from `.env`. Dated output in
`resultados_YYYY-MM-DD/ranking_embeddings_synapse.json`.

## Results (snapshot 2026-07-09)

**CVE-2024-31208** — `events.py`, method `_LinkMap::exists_path_from` (sanity 0.698):

| Target | sim_vuln | sim_corr | Δ | verdict |
|------|:---:|:---:|:---:|:---:|
| UPSTREAM@pre (vulnerable) | 0.901 | 0.748 | −0.153 | **VULNERAVEL** ✓ |
| UPSTREAM@fix (patched) | 0.750 | 0.929 | +0.179 | **CORRIGIDO** ✓ |
| microchipster/synapse | 0.744 | 0.929 | +0.185 | **CORRIGIDO** |
| kakahu2015/synapse | 0.744 | 0.929 | +0.185 | **CORRIGIDO** |
| shcherbak/synapse | 0.744 | 0.929 | +0.185 | **CORRIGIDO** |

**CVE-2025-61672** — `keys.py`, method `KeyUploadServlet::on_POST` (sanity 0.64):

| Target | sim_vuln | sim_corr | Δ | verdict |
|------|:---:|:---:|:---:|:---:|
| UPSTREAM@pre | 0.847 | 0.769 | −0.078 | VULNERAVEL ✓ |
| UPSTREAM@fix | 0.796 | 0.747 | −0.049 | VULNERAVEL ✗ (see limitations) |
| microchipster/synapse | 0.796 | 0.862 | +0.066 | **CORRIGIDO** |
| kakahu2015/synapse | 0.796 | 0.862 | +0.066 | **CORRIGIDO** |
| shcherbak/synapse | 0.796 | 0.862 | +0.066 | **CORRIGIDO** |

## The finding that matters

On CVE-2024-31208 the earlier experiment (Layer 2A, AST) left the 3 synapse forks in the
**uncertainty zone** — they were **false negatives** (the ground truth confirms them
patched). The embedding ranker **classifies all 3 as patched** (Δ +0.185), with the
upstream sanity checks passing. In other words: **semantic search by embeddings resolves
false negatives the AST layer could not** — direct empirical evidence for the
clone-detection / semantic-similarity direction.

## Limitations and next steps

- **Addition patches** (e.g. CVE-2025-61672): the vulnerable code is not removed, only
  "guarded" by a new check, so `sim_vuln` stays high in the patched version and even
  upstream@fix can slip to VULNERABLE. The fork signal still works, but the margin needs
  calibration for this patch type.
- **Truncation / large functions:** mitigated by the sliding window, though massive
  refactorings remain hard.
- **Regex-based function extraction is fragile** (multi-line signatures, decorators,
  nesting). The repository **already ships tree-sitter** in `pipeline_core.py`
  (python/rust/kotlin/swift/typescript/go), and `treesit_extract.py` now uses it for
  robust extraction across the library (Rust) and client (Kotlin) legs.
- **Scale/evaluation:** run over all CVEs and top-N forks, compute **precision/recall**
  against the ground truth and compare head to head with the baselines in
  `trabalhos_relacionados/` (hash rw1, AST rw2, dual-ref rw3). *(Done — see
  `resultados_2026-07-09/RESUMO_ecossistema.md` and `RESUMO_precisao.md`.)*
