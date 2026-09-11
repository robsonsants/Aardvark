# Automated verification of security-patch propagation to divergent forks

Reproducibility package (**anonymised version**) for a study on automatically verifying
whether upstream security fixes (CVE patches) have propagated to *divergent forks* of the
Matrix ecosystem. It contains the scripts, input data, results and archived evidence
behind the reported methodology and results.

No file here identifies authors or institution, and no credentials are included
(see [Security](#security)).

> **Current run: `resultados_2026-08-31_v2/`.** Everything dated before it — including the
> whole of `resultados_2026-07-04/` — was produced by a pipeline that silently discarded
> the test-file evidence, and therefore **underestimates the method**. See
> [`CHANGELOG.md`](CHANGELOG.md) §1 for the defect and its measured effect.

> **Language note.** Documentation and script docstrings are in English. Some **file and
> directory names**, the **verdict labels** inside the data (`CORRIGIDO`, `ZONA_INCERTEZA`,
> `FILE_NOT_FOUND`) and the **CSV column names** are **kept in Portuguese on purpose** —
> they are literal values written in every versioned result file and compared against by
> the code, so translating them would desynchronise code from data. Everything you need to
> read them is in the [Glossary](#glossary-portuguese-identifiers-kept-in-the-data). Some
> inline comments and console output inside function bodies also remain in Portuguese.

---

## Where to start

| If you want | Read |
|---|---|
| the current numbers and the answers to both research questions | [`RESULTS_2026-08-31.md`](RESULTS_2026-08-31.md) |
| what changed since the first published snapshot, and why | [`CHANGELOG.md`](CHANGELOG.md) |
| the peer-review feedback and the improvements planned from it | [`REVIEW_RESPONSE_AND_ROADMAP.md`](REVIEW_RESPONSE_AND_ROADMAP.md) |
| the methodology at procedure level (July state, superseded figures) | `RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md` |

---

## Study at a glance

**Goal.** Automatically verify whether security fixes (CVE patches) from an upstream
project have propagated to its divergent forks, and characterise that propagation.

**Research questions.**

- **RQ1 — reliability:** how trustworthy is the automatic verdict? (precision, recall, F1,
  Cohen's Kappa against a ground truth)
- **RQ2 — propagation:** how much of each upstream's CVE set is fixed in its forks, and how
  does that vary across the ecosystem? (coverage per fork and per category)

**Scope of the current run.** 7 upstreams · 21 forks (the top 3 active **divergent** forks
per upstream, `ahead_by > 0`) · 17 CVEs · **51 fork×CVE verifications** · 41 ground-truth
pairs, of which 40 conclusive (**33 positive, 7 negative**).

**Method.** A layered pipeline:

| Layer | What it does |
|---|---|
| **L1** | literal content comparison against the post-patch file (baseline; nothing is hashed — see `REVIEW_RESPONSE_AND_ROADMAP.md` §4, item 5) |
| **L2A** | normalised AST + edit distance (Levenshtein + Zhang-Shasha) against the **post-patch** reference |
| **L2B** | **dual reference**: similarity to post-patch minus similarity to pre-patch. This is what catches patches that *remove* code, where L2A alone is blind |

Verdicts are `CORRIGIDO` (patched) / `VULNERAVEL` (vulnerable) / `ZONA_INCERTEZA`
(uncertainty zone) / `FILE_NOT_FOUND`. An ambiguous pair escalates to human audit instead
of being forced into a binary decision — classification with a reject option, applied to
this problem.

**Evidence per patch.** Both the highest-churn **production** file and the highest-churn
**test** file of the fix commit are evaluated, and their verdicts are unioned.

### Headline results

RQ1 — reliability, 40 conclusive pairs, automated ground truth:

| | FP | P | R | F1 | κ |
|---|---:|---:|---:|---:|---:|
| trivial classifier (always "patched") | 7 | 0.825 | 1.000 | 0.904 | 0.000 |
| union of the layers (**adopted**) | 2 | **0.938** | **0.909** | **0.923** | **0.590** |
| A+B rule (`--regra-ab`, optional) | 0 | 1.000 | 0.909 | 0.952 | 0.778 |

Baselines re-measured **on this same run**, recall against the 33 `CONFIRMED_PATCHED` pairs:

| Approach | Recall |
|---|---:|
| whole-file hash (rw1) | 0.091 |
| patch-presence test, dual reference (rw3) | 0.758 |
| AST, single reference (rw2) | 0.879 |
| **union of the layers** | **0.909** |

One reproduced baseline is worth singling out: comparing at **declaration scope** instead
of file scope (rw6, after PatchLens/FSE 2026). Under the automated oracle it dominates the
pipeline (P 1.000 · R 0.939 · F1 0.969); **under the human oracle it does not** (P 0.967 ·
R 0.879 · F1 0.921) — it makes the same precision-for-recall trade as the A+B rule. The
reversal comes down to a single contested pair. Detail in
[`RESULTS_2026-08-31.md`](RESULTS_2026-08-31.md) §3.

RQ2 — propagation: **mean coverage 61.5%**, ranging from 100% (support) and 91.7% (server)
down to **19.4% (sdk)**.

**Three caveats that travel with these numbers, and are results in their own right:**

1. **Nothing is statistically significant at n=40.** Exact McNemar puts the union against
   the trivial classifier at p=0.727; the 95% CI of Kappa is [0.196 · 0.875].
2. **The difficulty is concentrated in one upstream.** 6 of the 7 negatives and 5 of the 5
   errors are in `matrix-org/matrix-rust-sdk`. Split by that boundary, the pipeline scores
   **F1 0.615 · κ 0.235 on those 13 pairs** and **1.000 on the other 27**. The pooled 0.923
   is mostly the easy majority showing through — and on the hard subset the trivial
   classifier beats the pipeline on F1 (0.700), with only Kappa separating them.
3. **Coverage mixes propagation with inheritance.** In 31 of the 51 pairs the fork was
   created *after* the fix commit, so it never carried the flaw. Only about 10 of the 33
   `CORRIGIDO` verdicts are propagation in the strict sense.

---

## Repository layout

```
.
├── pipeline1.py                    Phase 1 — mine CVEs/CWEs/fix commits (NVD + GHSA)
├── fase1_fix_commits.py            Phase 1 (light) — GHSA first, NVD only as fallback
├── pipeline_core.py                Core: tree-sitter, AST normalisation, similarity
├── pipeline_dissertation.py        Phase 2 — per-fork verification (L1, L2A, L2B)
├── ground_truth.py                 Automated oracle + metrics (P/R/F1/Kappa)
├── auditoria_manual.py             Human oracle — audit worklist and tally
├── gt_v2_anchors.py                Ground truth v2 anchored on the corrective line (July run)
│
├── experimentos_revisores.py       E1–E6 validation experiments        (offline)
├── experimento_regra_ab.py         A+B rule re-derived from raw records (offline)
├── sensibilidade_regras.py         Threshold sensitivity sweep          (offline)
├── impacto_evidencia_teste.py      Cost of the test-evidence defect     (offline)
├── dataset_temporal.py             Adoption lag, fork dates, inheritance vs propagation
├── metricas_subconjunto_dificil.py Metrics split by upstream difficulty  (offline)
│
├── gerar_figuras_dissertacao.py    Figures: coverage / verdicts / confusion matrix
├── gerar_diagrama_processo.py      Process diagram
├── bench_custo_embeddings.py       Cost micro-benchmark (embedding prototype only)
│
├── target.csv                      Phase 1 input (owner;repo;cpe;dependency)
├── target_dissertation.csv         The upstreams, one per ecosystem category
├── cves-fixing-commits-dataset.csv Phase 2 input — CVE → fix commit
├── cpe-nvd-dataset.csv             Phase 1 outputs (mined CPEs, CVEs, GHSAs)
├── cve-nvd-dataset.csv
├── ghsa-dataset.csv
├── ghsa-cve-nvd-dataset.csv
│
├── resultados_2026-08-31_v2/       ***CURRENT RUN — source of every published figure***
│   ├── dissertation_resultados.json/.csv     Per fork × CVE × file record (everything derives from this)
│   ├── dissertation_cobertura.json           Coverage % per fork          (RQ2)
│   ├── dissertation_metricas.json            Metrics per category         (RQ2)
│   ├── gt_dissertation_resultados.json/.csv  Automated ground truth
│   ├── gt_dissertation_metricas.json         P/R/F1/Accuracy/Kappa        (RQ1)
│   ├── auditoria_manual.html/.csv            Human audit worklist (41 pairs)
│   ├── auditoria_manual_preenchida.csv       The reviewer's filled-in verdicts
│   ├── auditoria_manual_apuracao.json        Human-oracle metrics + agreement (36/41)
│   ├── metricas_subconjunto_dificil.json     Metrics split hard vs easy, both oracles
│   ├── experimentos_revisores.json           E1–E6 output
│   ├── sensibilidade_limiares.json           Threshold sweep output
│   ├── dataset_temporal.json / _pares.csv / _forks.csv   Dates, lag, ahead/behind
│   ├── figuras/                              Figures and tables (.png, .md, .tex)
│   ├── evidencias_dissertacao/               Every file actually compared (offline audit)
│   └── evidencias_gt_dissertacao/            Fork files downloaded for the ground truth
│
├── resultados_2026-08-31_v2_regraAB/  Same run re-derived under the A+B rule (offline output)
├── resultados_2026-07-04/          July run — SUPERSEDED, kept for the record
│
├── trabalhos_relacionados/         Reproduced state-of-the-art baselines
│   ├── _common.py                  Shared loader; RW_RUN=<folder> picks the run
│   ├── rw1_wyss2022_hash/          whole-file hash
│   ├── rw2_vercation2025_ast/      normalised AST + edit distance, single reference
│   ├── rw3_pptfi2024_dualref/      patch-presence test with dual reference
│   ├── rw4_see2025_greedy_pareto/  greedy set cover → Pareto curve
│   ├── rw5_decan2018_timelag/      technical lag / window of vulnerability (needs network)
│   ├── rw6_patchlens2026_hunk/     PatchLens (FSE 2026): hunk → AST subtree, declaration scope
│   ├── resultados_2026-09-02/      baselines re-measured on the current run
│   └── resultados_2026-07-08/      baselines on the July run (superseded)
│
├── prototipo_ranking_embeddings/   Embedding prototype (UniXcoder) — NOT part of the method;
│                                   has not run since July 2026, kept as future work
├── figuras/                        Process diagram (.png, .svg)
├── CHANGELOG.md                    What changed since the first snapshot, and why
├── RESULTS_2026-08-31.md           Current results; answers to RQ1 and RQ2
├── REVIEW_RESPONSE_AND_ROADMAP.md  Peer-review feedback → planned improvements
├── RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md  Methodology at procedure level (July state)
├── ANEXO_DIAGNOSTICO_C5_C6_C8.md   Threshold sensitivity, fix-commit provenance, cost (July)
└── estudo_ferramentas_deteccao_clones.md    Clone-detection tool study
```

---

## Reproducing the results

**Order matters.** Steps 5–8 all read the JSON files written by steps 3 and 4. Metrics are
only comparable when every one of them comes from the **same run** — that is why the
baselines take `RW_RUN`. If you redo the run, redo all of them.

Steps 5, 6 and 8 are **fully offline**: no network, no token. They re-derive their results
from the raw records that are already versioned here, so anyone can reproduce every number
in `RESULTS_2026-08-31.md` without a GitHub account.

### 0. Dependencies

```bash
pip install -r requirements.txt
```

Python 3.10+ (tested on 3.12). `rapidfuzz` is not strictly required but the pure-Python
fallback is orders of magnitude slower on large files. `torch`/`transformers` are needed
only to run the embedding prototype, which is not part of the method.

### 1. Credentials

```bash
cp .env.example .env      # fill in GITHUB_TOKEN and, optionally, NVD_TOKEN
```

The GitHub token only needs public-read scope. Phase 1 works without `NVD_TOKEN` but is
much slower and prone to HTTP 503 from the NVD API.

### 2. Phase 1 — mining (slow; optional)

```bash
python pipeline1.py NVD_TOKEN GITHUB_TOKEN          # full mining, NVD-first
python fase1_fix_commits.py --entrada fase2.csv \
    --saida cves-fixing-commits-dataset.csv --token YOUR_TOKEN   # light, GHSA-first
```

Only needed to redo collection from scratch. **The outputs are already versioned**
(`cve-nvd-dataset.csv`, `cves-fixing-commits-dataset.csv`, …), so every later step runs
without repeating this one.

### 3. Phase 2 — per-fork verification

```bash
python pipeline_dissertation.py --token YOUR_TOKEN --fresh \
    --outdir resultados_YYYY-MM-DD
# one upstream at a time:
python pipeline_dissertation.py --token YOUR_TOKEN --upstream element-hq/synapse
# optional variant with the two guards:
python pipeline_dissertation.py --token YOUR_TOKEN --fresh --regra-ab
```

`--fresh` recomputes from scratch; without it the script **accumulates** and skips what it
has already processed.

> Forks are selected **dynamically** through the GitHub API (most active with
> `ahead_by > 0`), so the set changes between runs. To reproduce the published numbers
> exactly, use the versioned run in `resultados_2026-08-31_v2/`.

### 4. Ground truth and metrics (the automated oracle)

```bash
python ground_truth.py --token YOUR_TOKEN \
    --results resultados_YYYY-MM-DD/dissertation_resultados.json \
    --outdir  resultados_YYYY-MM-DD
```

Reads the pairs dynamically from the Phase 2 records and searches the patch key lines in
each fork's file. Being independent of the AST method is what makes it a valid reference.

### 5. Human audit (the independent oracle) — offline

```bash
python auditoria_manual.py gerar  --run resultados_YYYY-MM-DD   # build HTML+CSV worklist
#   ... review in a browser, export auditoria_manual_preenchida.csv ...
python auditoria_manual.py apurar --run resultados_YYYY-MM-DD   # recompute P/R/F1 + agreement
```

The filled-in worklist of the published run is versioned, so `apurar` reproduces the human
oracle immediately: **agreement 36/41 = 87.8%**.

### 6. Offline analyses — no network, no token

```bash
python experimentos_revisores.py --run resultados_YYYY-MM-DD   # E1-E6, ~40 s
python experimento_regra_ab.py   --run resultados_YYYY-MM-DD   # A+B differential
python sensibilidade_regras.py   --run resultados_YYYY-MM-DD   # threshold sweep
python impacto_evidencia_teste.py --run resultados_2026-08-18  # cost of the fixed defect
python metricas_subconjunto_dificil.py --run resultados_YYYY-MM-DD  # hard vs easy split
```

### 7. Temporal dataset (needs the API)

```bash
python dataset_temporal.py --run resultados_YYYY-MM-DD --token YOUR_TOKEN
```

~138 API calls for this run. Produces adoption lag, fork creation dates and ahead/behind,
which is what separates **inheritance** from **propagation**.

### 8. State-of-the-art baselines, on the same run

```bash
RW_RUN=resultados_YYYY-MM-DD python trabalhos_relacionados/rw1_wyss2022_hash/run.py
RW_RUN=resultados_YYYY-MM-DD python trabalhos_relacionados/rw2_vercation2025_ast/run.py
RW_RUN=resultados_YYYY-MM-DD python trabalhos_relacionados/rw3_pptfi2024_dualref/run.py
RW_RUN=resultados_YYYY-MM-DD python trabalhos_relacionados/rw4_see2025_greedy_pareto/run.py
python trabalhos_relacionados/rw6_patchlens2026_hunk/run.py --run resultados_YYYY-MM-DD
# and the same measurement against the human labels, reusing the ASTs already computed:
python trabalhos_relacionados/rw6_patchlens2026_hunk/run.py --run resultados_YYYY-MM-DD     --oraculo humano --refazer-metricas
```

rw1–rw4 and rw6 are offline. **rw5 (technical lag) needs an authenticated network
connection** and will stop with a clear message if `GITHUB_TOKEN` is absent.

### 9. Figures

```bash
python gerar_figuras_dissertacao.py --dir resultados_YYYY-MM-DD
python gerar_diagrama_processo.py
```

Writes `figuras/` inside the run folder: coverage per category, verdicts per category,
confusion matrix, and the same tables in Markdown and LaTeX.

---

## Glossary (Portuguese identifiers kept in the data)

These strings are literal values in the versioned result files and are compared against
by the code, so translating them would desynchronise code from data:

| Value in the data | Meaning |
|---|---|
| `CORRIGIDO` | patched — the fork carries the fix |
| `NAO_CORRIGIDO` / `VULNERAVEL` | not patched — the fork is still vulnerable |
| `ZONA_INCERTEZA` | uncertainty zone — escalated to human audit |
| `FILE_NOT_FOUND` | the patched file no longer exists at that path in the fork's HEAD |
| `CONFIRMED_PATCHED` / `CONFIRMED_VULNERABLE` / `AMBIGUOUS` | ground-truth labels |
| `sim_2a`, `sim_patch`, `sim_vuln`, `delta` | AST similarity to the patched/vulnerable reference and their difference |
| `veredito_humano` / `veredito_ia` | human verdict / automatic verdict (audit worklist) |
| `lag_confiavel` | whether the adoption lag of that row is trustworthy (`sim`/`nao`) |
| `apto_fase2` | repository eligible for Phase 2 (has a CVE, a divergent fork and a supported language) |

CSV column names and file names use the same vocabulary:

| Portuguese | English |
|---|---|
| `cobertura` | coverage · `resultados` results · `metricas` metrics |
| `evidencias` | evidence · `veredito`/`vereditos` verdict/verdicts |
| `auditoria_manual` | manual audit · `apuracao` tally · `preenchida` filled in |
| `sensibilidade` | sensitivity · `experimento`/`experimentos` experiment(s) |
| `regra_ab` / `regraAB` | the A+B decision rule |
| `dataset_temporal` | temporal dataset · `pares` pairs · `forks` forks |
| `impacto_evidencia_teste` | impact of the test-evidence defect |
| `funcao_alvo` | target function · `arquivo` file · `linguagem` language · `categoria` category |
| `prioridade` | priority · `origem` origin · `observacao` note |
| `trabalhos_relacionados/` | related work · `prototipo_ranking_embeddings/` embedding prototype |
| `RESUMO*` | summary document · `RELATORIO_*` consolidated report · `ANEXO_*` appendix |

---

## Fixed parameters

| Parameter | Value | Where |
|---|---|---|
| PATCHED threshold (L2A) | sim ≥ 0.80 | `pipeline_core.py` |
| NOT-PATCHED threshold (L2A) | sim ≤ 0.35 | `pipeline_core.py` |
| Uncertainty-zone margin (L2B) | \|δ\| ≤ 0.05 | `pipeline_core.py` |
| Combined similarity weights | 0.45·lev + 0.55·zss | `pipeline_core.py` |
| Zhang-Shasha node limit | 600 | `pipeline_core.py` |
| Absolute similarity floor for L2B (guard B) | 0.60 | `pipeline_dissertation.py` |
| Line-match threshold (ground truth) | 0.85 | `ground_truth.py` |
| Top forks per upstream | 3 (active divergent, `ahead_by > 0`) | `pipeline_dissertation.py` |
| Fork activity window | 730 days | `pipeline_dissertation.py` |

**How these values should be read.** Cross-validation (E2) shows they are **not
overfitted** — thresholds learned out of sample perform the same. It also shows they are
**not identifiable**: every fold selects `thr_high = 0.60` when the training labels come
from the automated oracle, and four of five select `0.90` when they come from the human
one — opposite ends of the grid. At this sample size the thresholds are a **policy choice**, not a
derivation, and the operating curve (E6) is the honest way to present them.

`ZSS_NODE_LIMIT = 600` deserves separate mention: it decides *which* metric is computed,
not merely memory. In the file-scope measurement, 60 of 63 comparisons (95%) fell back to
Levenshtein because the trees exceeded it.

---

## Known limitations

- **Sample size.** At n=40 conclusive pairs, no difference between configurations is
  statistically distinguishable (exact McNemar; union vs trivial classifier p=0.727). Every
  headline figure should be read with its confidence interval.
- **The difficulty is concentrated.** 6 of 7 negatives and 5 of 5 errors are in one
  upstream. Pooled metrics flatter the method; the hard subset is 13 pairs.
- **A single human annotator.** Two complete passes, three verdicts revised on the second,
  but no inter-rater agreement. This is the largest open gap in the work.
- **Coverage mixes inheritance with propagation.** 31 of 51 pairs are forks created after
  the fix. `created_at` is the GitHub repository date, not the divergence point, so that
  count is a floor.
- **File restructuring** between the fix commit and the fork's HEAD (monorepo migration,
  moved file) breaks fixed-path verification → `FILE_NOT_FOUND` (10 of 51 here).
- **Precision on small patches.** On a monolithic file a tiny patch leaves L2A reading very
  high similarity even when the fix is absent; the corrective signal is the L2B delta.
- **Dynamic fork selection.** The top-3 divergent forks are resolved through the API at run
  time, so an identical command run later will not select an identical set. Reproduce
  published numbers from the versioned run folder.
- **Fix-commit availability bounds the corpus.** Only CVEs whose fix commit can be located
  from NVD/GHSA references are verifiable at all — the corpus is what survived, not a
  sample. (The same limitation is declared by PatchLens, FSE 2026.)
- **The embedding prototype is not part of the method** and has not run since July 2026.

Retired claims — statements that appeared in earlier versions of this package and are now
known to be wrong — are listed in [`REVIEW_RESPONSE_AND_ROADMAP.md`](REVIEW_RESPONSE_AND_ROADMAP.md) §5.

---

## Security

- `.env` is **not** in this repository and is listed in `.gitignore`; use `.env.example`
  as the template.
- Scripts read the token from `.env` or from the `GITHUB_TOKEN` environment variable. No
  token appears in any versioned code, data or log.
- Execution logs (`*.log`) are excluded by `.gitignore` because they may contain local
  paths.

## Third-party data

`resultados_*/evidencias_*/` contains source-code excerpts from public Matrix ecosystem
projects and their forks, downloaded through the GitHub API so that the ground truth can be
audited and re-validated **offline**. Each file remains under its project's original licence
and is redistributed here solely for scientific verification.
