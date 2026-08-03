# Automated verification of security-patch propagation to divergent forks

Reproducibility package (**anonymised version**) for a study on automatically verifying
whether upstream security fixes (CVE patches) have propagated to *divergent forks* of the
Matrix ecosystem. It contains **only** the scripts, input data, results and evidence that
support the final methodology and results reported in the paper.

No file here identifies authors or institution, and no credentials are included
(see [Security](#security)).

> **Language note.** Documentation and script docstrings are in English. Some **file and
> directory names**, the **verdict labels** inside the data (`CORRIGIDO`, `ZONA_INCERTEZA`,
> `FILE_NOT_FOUND`) and the **CSV column names** are **kept in Portuguese on purpose** —
> they are literal values written in every versioned result file and compared against by
> the code, so translating them would desynchronise code from data. Everything you need to
> read them is in the [Glossary](#glossary-portuguese-identifiers-kept-in-the-data). A few
> inline comments inside function bodies also remain in Portuguese.

---

## Study at a glance

**Goal.** Automatically verify whether security fixes (CVE patches) from an upstream
project have propagated to its divergent forks, and characterise that propagation.

**Final scope.** 5 categories of the Matrix ecosystem (client, server, sdk, bridge,
integration), **one upstream per category**, the **top 3 active divergent forks**
(`ahead_by > 0`) of each, and **every CVE with a locatable fix commit**:
**16 CVEs · 14 forks · 43 fork×CVE pairs**.

**Method.** A layered pipeline: **L1** literal file hash (baseline / motivation) →
**L2A** normalised AST + edit distance (Levenshtein + Zhang-Shasha) → **L2B** dual
reference (pre- vs post-patch) → **semantic layer** using code embeddings (UniXcoder).
Verdicts are `CORRIGIDO` (patched) / `VULNERAVEL` (vulnerable) / `ZONA_INCERTEZA`
(uncertainty zone), where uncertainty escalates to human audit rather than forcing a
binary decision.

**Headline results** (full detail in `RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md`):

| Method | Recall (34 conclusive pairs) |
|---|:---:|
| file hash (baseline) | 0.147 |
| patch-presence test, dual reference | 0.324 |
| AST | 0.676 |
| **embeddings (UniXcoder)** | **0.794** |
| **union AST ∪ embeddings** | **1.000** |

**Precision.** On the raw two-class set (44 positives / 56 constructed negatives) every
method lands at **P ≈ 0.5**. A content-based audit of those negatives then showed the set
was contaminated: **33 of the 56 "negatives" already contained the patch verbatim**,
because cherry-picks preserve the upstream committer date and the date-based cut-off let
the fix commit through. Over the corrected labels:

| Method | P | R | F1 |
|---|:---:|:---:|:---:|
| Embeddings (UniXcoder) | **0.972** | 0.896 | 0.932 |
| AST 2A | 0.914 | 0.961 | 0.937 |
| Combiner (AST ∪ embeddings) | 0.906 | **1.000** | **0.951** |

Ground truth v2 (anchored on the corrective line): 43/43 conclusive pairs, 0 ambiguous,
all patched. **Adoption at HEAD:** of 38 pairs, 24 confirm adoption, 14 are indeterminate
(patch too small to discriminate) and **0 remain demonstrably vulnerable**.

---

## Repository layout

```
.
├── pipeline1.py                    Phase 1 — mine CVEs/CWEs/fix commits (NVD + GHSA)
├── pipeline_core.py                Core: tree-sitter, AST normalisation, similarity
├── pipeline_dissertation.py        Phase 2 — per-fork verification (layers 1, 2A, 2B)
├── ground_truth.py                 Ground truth v1 + metrics (P/R/F1/Kappa)
├── gt_v2_anchors.py                Ground truth v2, anchored on the corrective line (offline)
├── sensibilidade_limiares.py       Threshold sensitivity sweep (offline)
├── bench_custo_embeddings.py       Cost micro-benchmark for the semantic layer
├── gerar_figuras_dissertacao.py    Figures: coverage / verdicts / confusion matrix
├── gerar_diagrama_processo.py      Process diagram (to-be)
│
├── target.csv                      Phase 1 input (owner;repo;cpe;dependency)
├── target_dissertation.csv         The 5 upstreams, one per category
├── cves-fixing-commits-dataset.csv Phase 2 input — CVE → fix commit
├── cpe-nvd-dataset.csv             Phase 1 outputs (mined CPEs, CVEs, GHSAs)
├── cve-nvd-dataset.csv
├── ghsa-dataset.csv
├── ghsa-cve-nvd-dataset.csv
│
├── prototipo_ranking_embeddings/   Semantic layer (UniXcoder)
│   ├── unixcoder_embed.py          Embeddings (<encoder-only> + normalised mean pooling)
│   ├── treesit_extract.py          Function/snippet extraction via tree-sitter
│   ├── run.py                      Single-CVE prototype
│   ├── run_ecosystem.py            Scale-up: all CVEs × forks across the 5 categories
│   ├── run_precision_eval.py       Precision evaluation (two-class set)
│   ├── montar_worklist_auditoria.py / calcular_auditoria.py / auditar_worklist_automatico.py
│   │                               Build audit worklist / recompute metrics / auto-audit
│   └── resultados_2026-07-09/      ecossistema_embeddings.json, precision_eval.json, summaries
│
├── trabalhos_relacionados/         Reproduced state-of-the-art baselines
│   ├── rw1_wyss2022_hash/          whole-file hash
│   ├── rw2_vercation2025_ast/      normalised AST + edit distance
│   ├── rw3_pptfi2024_dualref/      patch-presence test with dual reference
│   ├── rw4_see2025_greedy_pareto/  greedy set cover → Pareto curve
│   ├── rw5_decan2018_timelag/      technical lag / window of vulnerability
│   └── resultados_2026-07-08/      JSON results + RESUMO.md (summary)
│
├── resultados_2026-07-04/          Final Phase 2 results + ground truth
│   ├── dissertation_resultados.json/.csv    Per fork × CVE verdict (source of everything)
│   ├── dissertation_cobertura.json          Coverage % per fork
│   ├── dissertation_metricas.json           Metrics per category
│   ├── gt_dissertation_resultados.json/.csv Ground truth v1 (raw patch lines)
│   ├── gt_v2_resultados.json / _metricas    Ground truth v2 (anchored corrective line)
│   ├── VALIDACAO_GROUND_TRUTH.md            GT v1 vs v2, anchor table, findings
│   ├── auditoria_manual_gt.html/.csv        Human audit worklist (43 pairs)
│   ├── figuras/                             Final figures and tables (.png, .md, .tex)
│   ├── evidencias_gt_dissertacao/           Downloaded source — lets you re-validate GT v2 offline
│   └── evidencias_dissertacao/              Downloaded source — Phase 2 evidence
│
├── figuras/                        Process diagram (.png, .svg)
├── RELATORIO_EXPERIMENTOS_E_METODOLOGIA.md  Main document: experiments and methodology (PT)
├── ANEXO_DIAGNOSTICO_C5_C6_C8.md            Threshold sensitivity, fix-commit provenance, cost (PT)
└── estudo_ferramentas_deteccao_clones.md    Clone-detection tool study (PT)
```

---

## Reproducing the results

### 0. Dependencies

```bash
pip install -r requirements.txt
```

Python 3.10+ (tested on 3.12). The semantic layer downloads `microsoft/unixcoder-base`
from Hugging Face on first run (~500 MB). It runs on CPU; a GPU is optional.

### 1. Credentials

```bash
cp .env.example .env      # fill in GITHUB_TOKEN and, optionally, NVD_TOKEN
```

The GitHub token only needs public-read scope. Phase 1 works without `NVD_TOKEN` but is
much slower and prone to HTTP 503 errors from the NVD API.

### 2. Phase 1 — mining (slow; optional)

```bash
python pipeline1.py NVD_TOKEN GITHUB_TOKEN
```

Only needed to redo collection from scratch. **The outputs are already versioned**
(`cve-nvd-dataset.csv`, `cves-fixing-commits-dataset.csv`, …), so the later steps run
without repeating this one.

### 3. Phase 2 — per-fork verification (layers 1, 2A, 2B)

```bash
python pipeline_dissertation.py --token YOUR_TOKEN --fresh
# or one upstream at a time:
python pipeline_dissertation.py --token YOUR_TOKEN --upstream element-hq/synapse
```

> Forks are selected **dynamically** through the GitHub API (most active with
> `ahead_by > 0`), so the set can change between runs. To reproduce the published numbers
> exactly, use the versioned results in `resultados_2026-07-04/`.

### 4. Ground truth and metrics

```bash
python ground_truth.py --token YOUR_TOKEN     # ground truth v1 (needs network)
python gt_v2_anchors.py --check               # ground truth v2, offline, verifies the
                                              # published labels reproduce exactly
```

`gt_v2_anchors.py` rebuilds ground truth v2 from the per-CVE corrective anchors and the
archived evidence files, with no network access. 40 of the 43 labels follow directly from
files in this repository; the other 3 (CVE-2023-43656) rest on a documented manual
cross-file check, and `--no-manual` shows the result without them.

### 5. Semantic layer (embeddings)

```bash
python prototipo_ranking_embeddings/run_ecosystem.py       # scale-up + baseline comparison
python prototipo_ranking_embeddings/run_precision_eval.py  # precision on the two-class set
```

### 6. State-of-the-art baselines

```bash
python trabalhos_relacionados/rw1_wyss2022_hash/run.py
# ... likewise rw2 … rw5
```

### 7. Offline analyses (no network, no token required)

```bash
python sensibilidade_limiares.py      # threshold sweep over the versioned results
python bench_custo_embeddings.py      # per-window cost and scale projection
```

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

CSV column names and file names use the same vocabulary:

| Portuguese | English |
|---|---|
| `cobertura` | coverage |
| `resultados` | results |
| `metricas` | metrics |
| `evidencias` | evidence |
| `veredito` / `vereditos` | verdict / verdicts |
| `veredito_humano` / `veredito_ia` | human verdict / automatic verdict |
| `funcao_alvo` | target function |
| `observacao` | note |
| `arquivo` | file · `linguagem` language · `categoria` category |
| `prioridade` | priority · `origem` origin · `instancia` instance |
| `adotou_no_HEAD` | adopted at HEAD · `evidencia` evidence |
| `RESUMO*` | summary document |
| `VALIDACAO_GROUND_TRUTH.md` | ground-truth validation |
| `ANEXO_DIAGNOSTICO_*` | diagnostic appendix |
| `RELATORIO_*` | consolidated report |
| `trabalhos_relacionados/` | related work · `prototipo_ranking_embeddings/` embedding ranking prototype |

---

## Fixed parameters

| Parameter | Value |
|---|---|
| PATCHED threshold (L2A) | sim ≥ 0.80 |
| NOT-PATCHED threshold (L2A) | sim ≤ 0.35 |
| Uncertainty-zone margin (L2B) | \|δ\| ≤ 0.05 |
| Zhang-Shasha node limit | 600 |
| Embeddings | UniXcoder `<encoder-only>`, 16-line window |
| Top forks per upstream | 3 (active divergent, `ahead_by > 0`) |
| Fork activity window | 730 days |

Sensitivity of these thresholds is measured in `ANEXO_DIAGNOSTICO_C5_C6_C8.md`: the L2A
thresholds are robust by plateau (±0.05 changes no pair's verdict), and the sensitive
parameter is the L2B margin, which controls how much is escalated to human audit.

---

## Known limitations

- **Precision on small patches.** At function granularity, vulnerable ≈ patched code →
  false positives. Neither the margin nor the combiner fixes this; what fixed it here was
  correcting the labels, which does not generalise automatically.
- **Date-based negative sets are unreliable.** Cherry-picks preserve the upstream committer
  date, so a "pre-adoption" snapshot can already contain the fix. Any future negative set
  must be validated by content, not by date.
- **Three of the 43 ground-truth-v2 labels rest on a manual cross-file check**
  (CVE-2023-43656), because only the pre-migration file was archived as evidence.
- **File restructuring** between the fix commit and the fork's HEAD (monorepo migration,
  moved file) breaks fixed-path verification → `FILE_NOT_FOUND` or false-vulnerable.
- **512-token truncation** in UniXcoder, mitigated by a sliding window.
- **Fix-commit location.** 9 of the 16 CVEs were resolved automatically from NVD/GHSA
  references; 7 required manual search (all confirmed correct by the corrective anchor).
  Detail in `ANEXO_DIAGNOSTICO_C5_C6_C8.md`.
- **Kappa 0** is a property of the population (active divergent forks track upstream, so
  there are no natural negatives), not a failure of the method — which is why real
  precision is measured on constructed negatives.

---

## Security

- `.env` is **not** in this repository and is listed in `.gitignore`; use `.env.example`
  as the template.
- Scripts read the token from `.env` or from the `GITHUB_TOKEN` environment variable. No
  token appears in any versioned code, data or log.
- Execution logs (`*.log`) were omitted because they may contain local paths.

## Third-party data

`resultados_2026-07-04/evidencias_*/` contains source-code excerpts from public Matrix
ecosystem projects and their forks, downloaded through the GitHub API so that the ground
truth can be audited and re-validated **offline**. Each file remains under its project's
original licence and is redistributed here solely for scientific verification.
